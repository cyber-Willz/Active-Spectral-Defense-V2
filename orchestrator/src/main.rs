//! active-spectral-defense: wires the five components under
//! `components/` together per `architecture_with_firewall_perimeter.svg`.
//!
//! ```text
//! Firewall (perimeter)                     [rustwall]
//!    |
//! Traffic ingestion                        [rustwall]
//!    |-----------------+-------------------+
//!    v                 v                   v
//! NSM fast path     ClamAV scan       Spectral engine    <- three lanes
//!    |                 |                   |
//! XDP enforcement   Quarantine        Anomaly scoring
//!    |                 |                   |
//!    +-----------------+-------------------+
//!                       v
//!            Correlation engine (SIEM)                   [siem-correlation]
//!                       v
//!            Containment playbook                        [this binary, `containment.rs`]
//!            /                        \
//!  rule sync (-> firewall)   containment -> anomaly scoring (-> spectral engine)
//! ```
//!
//! This binary is the "Correlation engine" + "Containment playbook" boxes
//! plus the glue feeding the three lane boxes -- the boxes themselves are
//! each component's own code, unmodified (see `README.md`).
//!
//! # What this binary does NOT do
//!
//! It does not launch `rustwall` or `nsm` as child processes -- both are
//! full network-privileged daemons (NFQUEUE / XDP) that need root and are
//! ordinarily deployed and supervised independently (systemd units,
//! containers, whatever the operator already uses). This binary expects
//! them to already be running and reachable at the paths/sockets/PID in
//! its config -- see `asd.example.toml` and README's "Wiring it up for
//! real".

mod config;
mod containment;

use asd_spectral_bridge::FlowStats;
use asd_xdp_bridge::NsmAlert;
use clap::Parser;
use config::AsdConfig;
use containment::ActiveContainment;
use review_queue::prelude::{SlaPolicy, TriggerConfig};
use siem_correlation::{CorrelationConfig, CorrelationEngine, CorrelationVerdict};
use siem_response::ResponsePolicy;
use siem_review::ReviewGatedResponse;
use burn::backend::ndarray::NdArrayDevice;
use spec_engine::QdrantSpectralSecurityEngine;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(name = "active-spectral-defense")]
struct Cli {
    /// Path to an asd.toml config -- see asd.example.toml.
    #[arg(long, default_value = "asd.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = AsdConfig::load(&cli.config)?;

    tracing::info!("active-spectral-defense starting");

    // ---------------------------------------------------------------
    // Spectral engine bootstrap. Mirrors spec_engine::run()'s own
    // Phase-0 pretraining exactly (see components/spec-engine/src/lib.rs),
    // just without the CIC-IDS2018 demo dataset's Phase 1-3 evaluation
    // steps -- this is a live IDS instance, not a benchmark run. Using
    // the sample dataset's benign rows as the pretraining baseline is a
    // stand-in: a real deployment should swap in a captured baseline
    // window of its own known-clean traffic (see spec_engine::bootstrap's
    // doc comment, which this mirrors, and README's "Honest gaps").
    tracing::info!("bootstrapping spectral engine (autoencoder pretrain + Qdrant connect)");
    let device = NdArrayDevice::Cpu;
    let dataset = spec_engine::ids2018_sample_dataset();
    let benign_rows: Vec<&spec_engine::CicRow> = dataset.iter().filter(|r| r.label == "Benign").collect();
    let (model, threshold) = spec_engine::pretrain_on_benign(&benign_rows, &device, 200, 1e-3);
    tracing::info!(threshold, "spectral engine: anomaly threshold derived");
    let spectral_engine = Arc::new(
        QdrantSpectralSecurityEngine::new(
            &cfg.spectral.qdrant_url,
            model,
            device,
            threshold,
            cfg.spectral.blast_radius_depth,
        )
        .await?,
    );

    // ---------------------------------------------------------------
    // ClamAV-style scanner + quarantine manager (real rust-clam crates).
    let mut builder = sig_engine::SignatureEngine::builder();
    for ndb_path in &cfg.clamav.signature_ndb_paths {
        let text = std::fs::read_to_string(ndb_path)?;
        builder = builder.load_ndb(&text)?;
    }
    for hdb_path in &cfg.clamav.signature_hdb_paths {
        let text = std::fs::read_to_string(hdb_path)?;
        builder = builder.load_hdb(&text)?;
    }
    let scanner = Arc::new(scanner_core::Scanner::new(builder.build()));
    let quarantine = Arc::new(rclam_quarantine::QuarantineManager::new(&cfg.clamav.quarantine_dir)?);
    tracing::info!(
        hex_sigs = scanner_signature_count(&scanner),
        "ClamAV-style scanner loaded"
    );

    // ---------------------------------------------------------------
    // Correlation engine (the diagram's fan-in box). Three typed lane
    // senders come straight out of this -- no custom fan-in plumbing,
    // see siem_correlation's own module docs.
    let (verdict_tx, verdict_rx) = mpsc::channel::<CorrelationVerdict>(256);
    let (engine, xdp_sender, clamav_sender, spectral_sender, metrics) =
        CorrelationEngine::new(CorrelationConfig::default(), verdict_tx);
    tokio::spawn(engine.run());
    let metrics_for_log = metrics.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let snap = metrics_for_log.snapshot();
            tracing::info!(?snap, "correlation engine metrics");
        }
    });

    // ---------------------------------------------------------------
    // Lane 1 + 3: NSM fast path -> XDP lane, and the same live alert
    // stream driving the spectral engine's Anomaly scoring lane. Both
    // read from nsm's one NDJSON alert stream -- see main.rs module docs
    // on why traffic fans out from one ingestion source.
    {
        let alert_log = cfg.nsm.alert_log_path.clone();
        let xdp_sender = xdp_sender.clone();
        let spectral_sender = spectral_sender.clone();
        let spectral_engine = spectral_engine.clone();
        tokio::spawn(async move {
            if let Err(e) =
                run_traffic_lanes(&alert_log, xdp_sender, spectral_sender, spectral_engine, threshold).await
            {
                tracing::error!(error = %e, "traffic lanes task exited");
            }
        });
    }

    // ---------------------------------------------------------------
    // Lane 2: ClamAV scan -> Quarantine action. Synchronous (notify +
    // Scanner are both blocking), so it gets its own OS thread rather
    // than a tokio task.
    {
        let targets: Vec<asd_clamav_bridge::HostWatchTarget> = cfg
            .clamav
            .watch_targets
            .iter()
            .map(|t| asd_clamav_bridge::HostWatchTarget { path: t.path.clone(), host: t.host })
            .collect();
        let scanner = scanner.clone();
        let quarantine = quarantine.clone();
        let clamav_sender = clamav_sender.clone();
        let running = Arc::new(AtomicBool::new(true));
        std::thread::Builder::new()
            .name("asd-clamav-lane".into())
            .spawn(move || {
                if let Err(e) = asd_clamav_bridge::run(&targets, scanner, quarantine, clamav_sender, running) {
                    tracing::error!(error = %e, "ClamAV lane exited");
                }
            })?;
    }

    // ---------------------------------------------------------------
    // Containment playbook + review gate. A verdict must clear
    // siem-review's human-review gate (confidence/margin thresholds,
    // out-of-distribution routing) *and* ResponsePolicy's own guards
    // (severity floor / allowlist / rate limit) before ActiveContainment
    // ever runs -- see siem-review's crate docs.
    let min_severity = parse_severity(&cfg.response.min_severity);
    let allowlist: HashSet<String> = cfg.response.allowlist.iter().cloned().collect();
    let policy = ResponsePolicy::new(min_severity, allowlist);
    let mut gated = ReviewGatedResponse::new(TriggerConfig::default(), SlaPolicy::FailSafe, policy)?;

    let firewall_target = asd_firewall_sync::FirewallSyncTarget {
        config_path: cfg.firewall.config_path.clone(),
        pid: cfg.firewall.pid,
    };
    let nsm_control = asd_xdp_bridge::NsmControlClient::new(cfg.nsm.control_socket_path.clone());
    let mut action = ActiveContainment::new(
        nsm_control,
        cfg.response.xdp_block_ttl_secs,
        firewall_target,
        Some(spectral_engine.clone()),
    );

    tracing::info!("active-spectral-defense running -- correlating three lanes into containment");
    handle_verdicts(verdict_rx, &mut gated, &mut action).await;

    Ok(())
}

/// The single consumer of `CorrelationVerdict`s: adapts each into a
/// `FlowPrediction` (via `siem_correlation_bridge::verdict_to_flow_prediction`,
/// same function `active-siem`'s own demo uses) and runs it through the
/// review gate + containment action.
async fn handle_verdicts(
    mut verdict_rx: mpsc::Receiver<CorrelationVerdict>,
    gated: &mut ReviewGatedResponse,
    action: &mut ActiveContainment,
) {
    let mut next_id: u64 = 1;
    while let Some(verdict) = verdict_rx.recv().await {
        let flow_id = format!("corr-{}-{}", verdict.host, next_id);
        let event_id = next_id;
        next_id += 1;

        let flow_prediction = siem_correlation_bridge::verdict_to_flow_prediction(&verdict, flow_id);
        let alert = siem_core::Alert {
            id: event_id,
            timestamp_ms: 0,
            rule_id: "asd-correlation".to_string(),
            title: format!("{:?} across {:?}", verdict.reason, verdict.sources),
            severity: correlation_severity_to_core(verdict.severity),
            mitre_technique: None,
            source_events: Vec::new(),
            context: std::collections::HashMap::new(),
        };

        match gated.handle_flow_prediction(flow_prediction, alert, &verdict.host.to_string(), action) {
            Ok(disposition) => {
                tracing::info!(host = %verdict.host, ?disposition, confidence = verdict.confidence, "verdict handled");
            }
            Err(e) => {
                tracing::error!(host = %verdict.host, error = %e, "review queue ingest failed");
            }
        }
    }
    tracing::warn!("verdict channel closed -- correlation engine must have stopped");
}

/// Tails `alert_log` (nsm's NDJSON stdout, redirected to a file) once and
/// fans each parsed alert out to both the XDP lane and the spectral
/// engine's Anomaly scoring lane -- see main.rs module docs.
async fn run_traffic_lanes(
    alert_log: &Path,
    xdp: siem_correlation::XdpSender,
    spectral: siem_correlation::SpectralSender,
    engine: Arc<QdrantSpectralSecurityEngine>,
    threshold: f32,
) -> anyhow::Result<()> {
    tracing::info!(path = %alert_log.display(), "tailing nsm alert stream");
    let file = tokio::fs::File::open(alert_log).await?;
    let mut lines = tokio::io::BufReader::new(file).lines();
    loop {
        match lines.next_line().await? {
            Some(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let alert: NsmAlert = match serde_json::from_str(&line) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::warn!(error = %e, "unparseable nsm alert line");
                        continue;
                    }
                };

                asd_xdp_bridge::submit_alert(&xdp, &alert);

                if let (Some(host), Some(flow)) =
                    (asd_xdp_bridge::nsm_alert_host(&alert), asd_xdp_bridge::nsm_alert_flow_key(&alert))
                {
                    let stats = flow_stats_from_alert(&alert);
                    if let Err(e) = asd_spectral_bridge::ingest_and_submit(
                        &engine, &spectral, host, flow, &stats, &alert.detector, threshold,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "spectral ingest failed");
                    }
                }
            }
            None => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Best-effort `FlowStats` from an nsm alert's detector-specific `extra`
/// payload. See `asd-spectral-bridge`'s docs ("Feature mapping (honest
/// gap)") -- this is a coarse approximation, not real per-packet timing.
fn flow_stats_from_alert(alert: &NsmAlert) -> FlowStats {
    let samples = alert.extra.get("samples").and_then(|v| v.as_f64()).unwrap_or(1.0);
    let mean_interval = alert.extra.get("mean_interval_s").and_then(|v| v.as_f64()).unwrap_or(1.0);
    FlowStats {
        duration_secs: (mean_interval * samples).max(0.001),
        packets_fwd: samples.max(1.0) as u64,
        packets_bwd: 0,
        // nsm's alerts don't carry byte counts -- 0.0 rather than a
        // fabricated figure; flow_byts_s/pkt_len_* derived from this
        // will read as 0 for these events, which is honest given what's
        // actually known at this integration point.
        bytes_fwd: 0.0,
        bytes_bwd: 0.0,
    }
}

fn correlation_severity_to_core(sev: siem_correlation::Severity) -> siem_core::Severity {
    match sev {
        siem_correlation::Severity::Low => siem_core::Severity::Low,
        siem_correlation::Severity::Medium => siem_core::Severity::Medium,
        siem_correlation::Severity::High => siem_core::Severity::High,
        siem_correlation::Severity::Critical => siem_core::Severity::Critical,
    }
}

fn parse_severity(s: &str) -> siem_core::Severity {
    match s.to_ascii_lowercase().as_str() {
        "info" => siem_core::Severity::Info,
        "low" => siem_core::Severity::Low,
        "medium" => siem_core::Severity::Medium,
        "high" => siem_core::Severity::High,
        "critical" => siem_core::Severity::Critical,
        other => {
            tracing::warn!(value = other, "unknown response.min_severity, defaulting to High");
            siem_core::Severity::High
        }
    }
}

fn scanner_signature_count(_scanner: &scanner_core::Scanner) -> &'static str {
    // Scanner doesn't expose signature counts itself (only
    // SignatureEngine does, and Scanner owns it privately) -- logged as a
    // fixed marker rather than reaching into private state.
    "loaded"
}
