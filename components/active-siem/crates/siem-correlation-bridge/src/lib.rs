//! Glue between `siem-correlation` (a deliberately standalone fan-in
//! engine, see its crate docs) and the rest of `active-siem`.
//!
//! Two directions:
//!
//! 1. **Detectors -> lanes.** `active-siem` has two real detectors today:
//!    `siem-rules` (the threshold/correlation rule engine -- catches noisy,
//!    fast, signature-shaped attacks like SSH brute force) and `siem-ml`
//!    (the autoencoder/classifier -- catches quiet, anomaly-shaped
//!    infiltration). Neither is literally an XDP enforcement point or a
//!    ClamAV scanner, but `siem_correlation`'s lane semantics map cleanly
//!    onto what they actually do:
//!      - `siem-rules`' fast-path, signature/rate-based detections ->
//!        `XdpSender`. `XdpSender::submit`'s `human_approved` flag maps
//!        naturally onto this SIEM's own review gate: a rule alert starts
//!        as an *unconfirmed* fast-path signal (confidence 0.6, matching
//!        `siem-correlation`'s own convention for a pending XDP block);
//!        once `siem-review`/`review-queue` records a human's
//!        `ExecuteContainment` verdict, it becomes confirmed
//!        (`human_approved = true`, confidence 1.0) -- see
//!        `rule_alert_to_xdp`.
//!      - `siem-ml`'s anomaly score (autoencoder reconstruction error,
//!        normalized, or classifier confidence for a non-benign class) ->
//!        `SpectralSender`. This SIEM has no real spectral-graph
//!        computation (no Laplacian, no Fiedler vector) -- `fiedler_shift`
//!        is passed as `0.0` and documented as such in
//!        `ml_score_to_spectral` rather than faked with a plausible-looking
//!        number.
//!      - **`ClamAvSender` has no real detector behind it in this
//!        codebase.** There is no file-scanning/AV component here. It's
//!        left fully wired and available (see `siem-server`'s demo, which
//!        submits one illustrative event through it, clearly marked as
//!        simulated) as the integration point a real ClamAV-style scanner
//!        would plug into -- not removed, and not backed by fabricated
//!        detection logic.
//!
//! 2. **Verdicts -> review gate.** `siem_correlation::CorrelationVerdict`
//!    (evidence fused across lanes, never emitted for anything the engine
//!    considers benign) is adapted into a
//!    `review_queue::types::FlowPrediction` and handed to
//!    `siem_review::ReviewGatedResponse::handle_flow_prediction` -- the
//!    same gate the classifier's own predictions go through, so a
//!    corroborated multi-lane verdict is *still* subject to a confidence
//!    floor and, for a single-lane-critical verdict specifically, still
//!    routed to a human (see `verdict_to_flow_prediction`) rather than
//!    trusted just because the correlation engine already did its own
//!    evidentiary gating. Defense in depth, not a replacement.

use review_queue::prelude::{now, FlowPrediction, Timestamp};
use siem_correlation::{CorrelationReason, CorrelationVerdict, FlowKey, Protocol};
use std::net::IpAddr;

/// Parses `event`'s `Flow` fields into `siem_correlation::FlowKey`.
/// Returns `None` for any other `EventKind` variant, or if `src_ip`/
/// `dst_ip` don't parse as IP addresses (both are plain `String` in
/// `siem_core`, since decoders may see malformed input).
pub fn flow_key_from_event(event: &siem_core::Event) -> Option<FlowKey> {
    let siem_core::EventKind::Flow { src_ip, dst_ip, src_port, dst_port, proto, .. } = &event.kind else {
        return None;
    };
    let src_ip: IpAddr = src_ip.parse().ok()?;
    let dst_ip: IpAddr = dst_ip.parse().ok()?;
    Some(FlowKey {
        src_ip,
        dst_ip,
        src_port: *src_port,
        dst_port: *dst_port,
        protocol: protocol_from_u8(*proto),
    })
}

/// `siem_core::EventKind::Flow::proto` is the raw IP protocol number
/// (6=TCP, 17=UDP, matching `/etc/protocols`); `siem_correlation::Protocol`
/// is a closed enum over the ones the correlation engine's lanes actually
/// reason about, `Other` for everything else.
pub fn protocol_from_u8(proto: u8) -> Protocol {
    match proto {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        1 => Protocol::Icmp,
        other => Protocol::Other(other),
    }
}

/// Submits a `siem-rules` alert as an XDP-lane correlation event. See the
/// module docs for why the rule engine's fast-path detections map onto
/// this lane and how `human_approved` corresponds to this SIEM's own
/// review gate rather than a literal XDP program.
pub fn rule_alert_to_xdp(xdp: &siem_correlation::XdpSender, host: IpAddr, flow: FlowKey, alert: &siem_core::Alert, human_approved: bool) {
    xdp.submit(host, flow, format!("{}: {}", alert.rule_id, alert.title), human_approved);
}

/// Submits an ML anomaly score as a spectral-lane correlation event.
/// `anomaly_score` should be normalized to roughly `[0, 1]` (e.g. the
/// autoencoder's reconstruction error divided by its calibrated
/// threshold, clamped) so it lines up with `SpectralSender`'s own
/// severity thresholds (`>= 0.9` Critical, `>= 0.7` High, etc.) --
/// `siem-server`'s demo shows the actual normalization it uses.
///
/// `fiedler_shift` is always `0.0` here: this SIEM's `siem-ml` autoencoder/
/// classifier does not compute a spectral-graph Laplacian or Fiedler
/// vector, so there is nothing real to report. It is not synthesized to
/// look plausible.
pub fn ml_score_to_spectral(spectral: &siem_correlation::SpectralSender, host: IpAddr, flow: FlowKey, anomaly_score: f64) {
    spectral.submit(host, flow, anomaly_score, 0.0);
}

/// Adapts a fused `CorrelationVerdict` into the `FlowPrediction`
/// `review_queue` gates on. `flow_id` must be unique per verdict (same
/// constraint as `ReviewQueue::ingest`) -- typically derived from the host
/// and the time the verdict was decided.
///
/// - `predicted_label` is the verdict's `CorrelationReason` (there is no
///   attack-category concept at the correlation layer, only "corroborated"
///   vs "single-lane-critical") -- `ReviewTrigger` only needs *some*
///   non-"Benign" label to treat this as an attack class, which either
///   variant satisfies; `CorrelationVerdict` is never emitted for anything
///   the engine considers insufficiently suspicious in the first place.
/// - `is_out_of_distribution` is `true` for `SingleLaneCritical`: a single
///   lane's own critical call, on its own, is weaker evidence than two
///   independent lanes agreeing, so it's routed through the same
///   force-review path `ReviewTrigger` uses for autoencoder-flagged
///   novelty -- extra scrutiny for the less-corroborated case, even though
///   both cases already cleared the correlation engine's own emission bar.
pub fn verdict_to_flow_prediction(verdict: &CorrelationVerdict, flow_id: impl Into<String>) -> FlowPrediction {
    let predicted_label = match verdict.reason {
        CorrelationReason::MultiLaneCorroboration => "MultiLaneCorroboration",
        CorrelationReason::SingleLaneCritical => "SingleLaneCritical",
    }
    .to_string();

    FlowPrediction {
        flow_id: flow_id.into(),
        predicted_label,
        confidence: verdict.confidence as f64,
        // No natural analog at the correlation layer: there's no single
        // "runner-up class" when evidence comes from fusing distinct lanes
        // rather than a softmax over categories.
        runner_up_label: None,
        runner_up_confidence: None,
        is_out_of_distribution: verdict.reason == CorrelationReason::SingleLaneCritical,
        observed_at: correlation_verdict_timestamp(),
    }
}

/// `CorrelationVerdict::decided_at` is a `tokio::time::Instant`
/// (monotonic, not wall-clock -- correct for measuring correlation
/// latency within one process's lifetime, useless for producing a Unix
/// timestamp). `review_queue::types::Timestamp` needs wall-clock time, so
/// this bridge uses "now" at the moment of translation instead, which is
/// accurate to within the time it took to receive the verdict off the
/// channel -- effectively instantaneous relative to the correlation
/// window (seconds to minutes).
fn correlation_verdict_timestamp() -> Timestamp {
    now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn flow_event() -> siem_core::Event {
        siem_core::Event {
            id: 1,
            timestamp_ms: 0,
            host: "sensor-1".to_string(),
            agent_id: "agent-sensor-1".to_string(),
            kind: siem_core::EventKind::Flow {
                src_ip: "198.51.100.77".to_string(),
                dst_ip: "203.0.113.9".to_string(),
                src_port: 51000,
                dst_port: 443,
                proto: 6,
                duration_ms: 1000,
                bytes_src_to_dst: 100,
                bytes_dst_to_src: 200,
                packets: 10,
                flags: "SA".to_string(),
            },
            fields: HashMap::new(),
        }
    }

    #[test]
    fn flow_key_extracted_from_flow_event() {
        let key = flow_key_from_event(&flow_event()).expect("should parse");
        assert_eq!(key.src_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)));
        assert_eq!(key.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(key.src_port, 51000);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol, Protocol::Tcp);
    }

    #[test]
    fn non_flow_event_kind_yields_none() {
        let mut event = flow_event();
        event.kind = siem_core::EventKind::Log {
            source: "sshd".to_string(),
            message: "test".to_string(),
        };
        assert!(flow_key_from_event(&event).is_none());
    }

    #[test]
    fn unparseable_ip_yields_none() {
        let mut event = flow_event();
        if let siem_core::EventKind::Flow { src_ip, .. } = &mut event.kind {
            *src_ip = "not-an-ip".to_string();
        }
        assert!(flow_key_from_event(&event).is_none());
    }

    #[test]
    fn protocol_mapping_covers_common_and_fallback_cases() {
        assert_eq!(protocol_from_u8(6), Protocol::Tcp);
        assert_eq!(protocol_from_u8(17), Protocol::Udp);
        assert_eq!(protocol_from_u8(1), Protocol::Icmp);
        assert_eq!(protocol_from_u8(47), Protocol::Other(47)); // GRE, arbitrary "other"
    }

    fn fake_verdict(reason: CorrelationReason, confidence: f32) -> CorrelationVerdict {
        let now = tokio::time::Instant::now();
        CorrelationVerdict {
            host: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
            severity: siem_correlation::Severity::Critical,
            confidence,
            sources: vec![siem_correlation::LaneSource::Xdp],
            evidence: vec![],
            reason,
            first_seen: now,
            decided_at: now,
        }
    }

    #[test]
    fn multi_lane_verdict_is_not_flagged_out_of_distribution() {
        let verdict = fake_verdict(CorrelationReason::MultiLaneCorroboration, 0.95);
        let pred = verdict_to_flow_prediction(&verdict, "corr-1");
        assert_eq!(pred.flow_id, "corr-1");
        assert_eq!(pred.predicted_label, "MultiLaneCorroboration");
        assert!((pred.confidence - 0.95).abs() < 1e-6);
        assert!(!pred.is_out_of_distribution);
    }

    #[test]
    fn single_lane_critical_verdict_is_flagged_out_of_distribution() {
        let verdict = fake_verdict(CorrelationReason::SingleLaneCritical, 1.0);
        let pred = verdict_to_flow_prediction(&verdict, "corr-2");
        assert_eq!(pred.predicted_label, "SingleLaneCritical");
        assert!(pred.is_out_of_distribution);
    }
}
