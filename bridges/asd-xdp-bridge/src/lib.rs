//! NSM fast path -> XDP enforcement lane (the diagram's left-hand branch:
//! "NSM fast path (Sig/rate/beacon detect)" -> "XDP enforcement
//! (Human-approved block)" -> `siem_correlation::XdpSender`).
//!
//! Two directions, matching the two things `nsm`'s `xdp` module already
//! exposes (see `components/nsm-xdp/nsm/src/xdp/mod.rs`):
//!
//! 1. **Detections in.** `nsm` (run with `--simulate` or a real
//!    `--interface`, optionally `--xdp`) emits every detector hit as one
//!    newline-delimited JSON `Alert` per line on stdout (`alert.rs`'s
//!    `Alert::emit`). [`watch_ndjson_alerts`] tails that stream (in
//!    practice: nsm's stdout redirected to a file, or piped directly) and
//!    submits each parseable alert to [`siem_correlation::XdpSender`] as
//!    an **unconfirmed** event (`human_approved: false`, matching
//!    `XdpSender::submit`'s own convention for "fast-path signal, not yet
//!    acted on").
//! 2. **Confirmed blocks out.** nsm's XDP program only drops traffic for
//!    IPs a human (or, here, the containment playbook after a
//!    corroborated `CorrelationVerdict` clears `siem-review`'s gate) has
//!    approved -- delivered over the Unix control socket nsm starts when
//!    given `--xdp-control-socket <path>` (`BLOCK <ip>[/prefix]
//!    [ttl_secs]`, see that module's doc comment). [`NsmControlClient`]
//!    is a thin client for that protocol, used by the orchestrator's
//!    containment action once a verdict is confirmed.
//!
//! # Honest gaps
//!
//! - `nsm`'s `Alert::extra` is a detector-specific, unstructured
//!   `serde_json::Value` (compare `detect/beacon.rs`'s
//!   `{"mean_interval_s", "cv", "samples"}` against `detect/portscan.rs`'s
//!   own fields) -- there is no single schema for port/protocol across
//!   detectors. [`nsm_alert_flow_key`] pulls `dst_port`/`src_port`/`proto`
//!   out of `extra` on a best-effort basis and falls back to `0`/TCP; it
//!   is not a faithful `FlowKey` for detectors that don't carry that
//!   detail (e.g. `synflood`, which alerts on `dst_ip` alone). Correlation
//!   still keys on `host`, which is always present when `src_ip` is, so
//!   this doesn't block correlation -- it just means the `FlowKey` in the
//!   resulting `CorrelationEvent`'s audit trail is sometimes partial.
//! - This crate deliberately never calls `BLOCK` itself off a raw nsm
//!   alert -- only the orchestrator's containment action does, after a
//!   verdict clears `siem-review`. A single detector hit is fast-path
//!   *evidence*, not confirmation.

use serde::Deserialize;
use siem_correlation::{FlowKey, Protocol, XdpSender};
use std::io;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Mirrors `nsm::alert::Severity` (`components/nsm-xdp/nsm/src/alert.rs`).
/// Redefined rather than depended-on because `nsm` is a `[[bin]]`-only
/// crate with no `[lib]` target -- see this crate's module docs and
/// `README.md`'s "Why five workspaces, not one".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NsmSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Mirrors `nsm::alert::Alert`'s wire format exactly (field-for-field,
/// same `serde` derive shape), so this deserializes the real NDJSON `nsm`
/// emits.
#[derive(Debug, Clone, Deserialize)]
pub struct NsmAlert {
    pub ts_unix: u64,
    pub severity: NsmSeverity,
    pub detector: String,
    pub message: String,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

/// Best-effort `FlowKey` from an alert's `extra` payload -- see module
/// docs' "Honest gaps". Returns `None` only when `src_ip` or `dst_ip` is
/// itself missing (some detectors, e.g. synflood, only ever set one).
pub fn nsm_alert_flow_key(alert: &NsmAlert) -> Option<FlowKey> {
    let src_ip = alert.src_ip?;
    let dst_ip = alert.dst_ip.or(alert.src_ip)?;
    let src_port = alert.extra.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let dst_port = alert.extra.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let protocol = match alert.extra.get("proto").and_then(|v| v.as_u64()) {
        Some(6) => Protocol::Tcp,
        Some(17) => Protocol::Udp,
        Some(1) => Protocol::Icmp,
        Some(other) => Protocol::Other(other as u8),
        None => Protocol::Tcp, // nsm's detectors are overwhelmingly TCP-based (beacon, portscan, signature)
    };
    Some(FlowKey { src_ip, dst_ip, src_port, dst_port, protocol })
}

/// Which host this alert's evidence is *about* -- the correlation engine
/// keys on host, not flow (see `siem_correlation`'s module docs). `src_ip`
/// is the initiating side for every current `nsm` detector, so it's the
/// natural host to attribute the evidence to.
pub fn nsm_alert_host(alert: &NsmAlert) -> Option<IpAddr> {
    alert.src_ip.or(alert.dst_ip)
}

/// Submits one alert to the XDP lane. Always `human_approved: false` --
/// see module docs. No-op (returns `false`) if the alert doesn't carry
/// enough to identify a host.
pub fn submit_alert(xdp: &XdpSender, alert: &NsmAlert) -> bool {
    let Some(host) = nsm_alert_host(alert) else { return false };
    let flow = nsm_alert_flow_key(alert).unwrap_or(FlowKey {
        src_ip: host,
        dst_ip: host,
        src_port: 0,
        dst_port: 0,
        protocol: Protocol::Tcp,
    });
    xdp.submit(host, flow, format!("nsm/{}: {}", alert.detector, alert.message), false);
    true
}

/// Tails `path` (nsm's stdout redirected to a file, e.g. via `nsm ...
/// --simulate > /var/run/asd/nsm-alerts.ndjson`) as newline-delimited
/// JSON, submitting each parseable line to `xdp`. Runs until EOF is
/// reached and no more data arrives for `idle_retry` (simple polling
/// tail -- adequate for an append-only log file; a real deployment would
/// more likely pipe nsm's stdout directly into this process instead, see
/// `README.md`'s "Wiring it up for real").
pub async fn watch_ndjson_alerts(
    path: &Path,
    xdp: XdpSender,
    idle_retry: Duration,
) -> io::Result<()> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = BufReader::new(file).lines();
    loop {
        match reader.next_line().await? {
            Some(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<NsmAlert>(&line) {
                    Ok(alert) => {
                        submit_alert(&xdp, &alert);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, line = %line, "asd-xdp-bridge: unparseable nsm alert line");
                    }
                }
            }
            None => {
                tokio::time::sleep(idle_retry).await;
            }
        }
    }
}

// ---------------------------------------------------------------------
// Confirmed blocks -> nsm's XDP control socket
// ---------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum XdpControlError {
    #[error("connecting to nsm control socket at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("writing to nsm control socket: {0}")]
    Write(#[source] io::Error),
    #[error("reading nsm control socket response: {0}")]
    Read(#[source] io::Error),
    #[error("nsm control socket returned an error: {0}")]
    Remote(String),
}

/// Thin client for `nsm`'s `BLOCK`/`UNBLOCK`/`LIST`/`STATUS` Unix control
/// socket protocol (`components/nsm-xdp/nsm/src/xdp/mod.rs`,
/// `run_control_socket`). Synchronous (`std::os::unix::net::UnixStream`)
/// because this is called from `ResponseAction::execute`, which is itself
/// synchronous -- see `orchestrator`'s containment action.
pub struct NsmControlClient {
    pub socket_path: PathBuf,
}

impl NsmControlClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self { socket_path: socket_path.into() }
    }

    fn round_trip(&self, command: &str) -> Result<String, XdpControlError> {
        use std::io::{Read, Write};
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|source| XdpControlError::Connect {
            path: self.socket_path.clone(),
            source,
        })?;
        stream
            .write_all(format!("{command}\n").as_bytes())
            .map_err(XdpControlError::Write)?;
        stream.flush().map_err(XdpControlError::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(XdpControlError::Read)?;
        let response = response.trim().to_string();
        if response.starts_with("ERROR") {
            return Err(XdpControlError::Remote(response));
        }
        Ok(response)
    }

    /// `BLOCK <ip>/32 <ttl_secs>` -- the "human-approved block" the
    /// diagram's XDP enforcement box refers to. Typing/issuing `BLOCK` is
    /// itself the confirmation nsm's own rate limiter is documented to
    /// treat as authoritative (see `xdp/mod.rs`'s comment on the control
    /// socket's manual `BLOCK` command).
    pub fn block(&self, ip: IpAddr, ttl_secs: u64) -> Result<String, XdpControlError> {
        self.round_trip(&format!("BLOCK {ip}/32 {ttl_secs}"))
    }

    pub fn unblock(&self, ip: IpAddr) -> Result<String, XdpControlError> {
        self.round_trip(&format!("UNBLOCK {ip}/32"))
    }

    pub fn status(&self) -> Result<String, XdpControlError> {
        self.round_trip("STATUS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(extra: serde_json::Value) -> NsmAlert {
        NsmAlert {
            ts_unix: 0,
            severity: NsmSeverity::Medium,
            detector: "beacon".to_string(),
            message: "test".to_string(),
            src_ip: Some("198.51.100.7".parse().unwrap()),
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            extra,
        }
    }

    #[test]
    fn deserializes_real_nsm_alert_shape() {
        let line = r#"{"ts_unix":1,"severity":"Medium","detector":"beacon","message":"m","src_ip":"198.51.100.7","dst_ip":"203.0.113.9","extra":{"mean_interval_s":30.0,"cv":0.02,"samples":12}}"#;
        let a: NsmAlert = serde_json::from_str(line).expect("should parse");
        assert_eq!(a.detector, "beacon");
        assert_eq!(a.severity, NsmSeverity::Medium);
    }

    #[test]
    fn flow_key_falls_back_when_extra_has_no_ports() {
        let a = alert(serde_json::json!({}));
        let fk = nsm_alert_flow_key(&a).unwrap();
        assert_eq!(fk.dst_port, 0);
        assert_eq!(fk.protocol, Protocol::Tcp);
    }

    #[test]
    fn flow_key_uses_extra_when_present() {
        let a = alert(serde_json::json!({"dst_port": 443, "src_port": 51000, "proto": 6}));
        let fk = nsm_alert_flow_key(&a).unwrap();
        assert_eq!(fk.dst_port, 443);
        assert_eq!(fk.src_port, 51000);
        assert_eq!(fk.protocol, Protocol::Tcp);
    }
}
