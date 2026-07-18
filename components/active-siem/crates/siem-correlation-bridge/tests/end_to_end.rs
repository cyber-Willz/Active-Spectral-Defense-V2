//! Exercises the full path this crate exists to wire together:
//!
//!   two lanes submit evidence for the same host
//!     -> `siem_correlation::CorrelationEngine` fuses it into a verdict
//!     -> `siem_correlation_bridge::verdict_to_flow_prediction` adapts it
//!     -> `siem_review::ReviewGatedResponse::handle_flow_prediction` gates it
//!     -> (after a human resolves it) `ResponsePolicy` executes containment
//!
//! Not mocked at any stage: a real `CorrelationEngine` running on a real
//! `tokio` runtime, a real `ReviewQueue` backed by a real
//! `ontology_engine::OntologyEngine` graph.

use review_queue::prelude::{SlaPolicy, TriggerConfig, TriggerReason, Verdict};
use siem_correlation::{CorrelationConfig, CorrelationEngine};
use siem_correlation_bridge::verdict_to_flow_prediction;
use siem_response::{LogOnly, ResponsePolicy};
use siem_review::{Disposition, ReviewGatedResponse};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))
}

fn flow() -> siem_correlation::FlowKey {
    siem_correlation::FlowKey {
        src_ip: host(),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        src_port: 51234,
        dst_port: 8443,
        protocol: siem_correlation::Protocol::Tcp,
    }
}

fn alert() -> siem_core::Alert {
    siem_core::Alert {
        id: 1,
        timestamp_ms: 0,
        rule_id: "correlation".to_string(),
        title: "Correlated multi-lane evidence".to_string(),
        severity: siem_core::Severity::Critical,
        mitre_technique: None,
        source_events: vec![],
        context: HashMap::new(),
    }
}

fn gated() -> ReviewGatedResponse {
    ReviewGatedResponse::new(
        TriggerConfig::default(),
        SlaPolicy::FailSafe,
        ResponsePolicy::new(siem_core::Severity::Medium, Default::default()),
    )
    .unwrap()
}

#[tokio::test]
async fn multi_lane_corroboration_still_requires_human_review_then_executes() {
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(8);
    let (engine, xdp, clamav, _spectral, _metrics) = CorrelationEngine::new(CorrelationConfig::default(), out_tx);
    tokio::spawn(engine.run());

    // Two independent lanes corroborate the same host: an unconfirmed
    // fast-path (XDP-style) hit and a quarantine action.
    xdp.submit(host(), flow(), "beacon pattern", false);
    clamav.submit(host(), "invoice.exe", "Win.Trojan.Generic", true);

    let verdict = tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
        .await
        .expect("verdict should arrive")
        .expect("channel open");
    assert_eq!(verdict.sources.len(), 2);

    let flow_prediction = verdict_to_flow_prediction(&verdict, "corr-e2e-1");
    assert_eq!(flow_prediction.predicted_label, "MultiLaneCorroboration");
    // mean_confidence of an unapproved XDP hit (0.6) and a ClamAV match
    // (1.0) is 0.8 -- below TriggerConfig::default()'s 0.90 floor, so this
    // must still be queued even though two lanes already agree. Defense in
    // depth: the correlation engine's own emission bar is not treated as
    // sufficient on its own.
    assert!((flow_prediction.confidence - 0.8).abs() < 1e-6);

    let mut gr = gated();
    let mut action = LogOnly;
    let disposition = gr
        .handle_flow_prediction(flow_prediction, alert(), "198.51.100.77", &mut action)
        .unwrap();
    assert_eq!(disposition, Disposition::QueuedForReview(TriggerReason::LowConfidenceAttack));

    // A human reviews it and confirms -- now containment executes.
    let disposition = gr
        .resolve_and_execute(
            "corr-e2e-1",
            "analyst_priya",
            Verdict::ExecuteContainment,
            "confirmed: same host flagged by both fast-path and quarantine",
            alert(),
            "198.51.100.77",
            &mut action,
        )
        .unwrap();
    assert_eq!(disposition, Disposition::Executed);
}

#[tokio::test]
async fn single_lane_critical_from_correlation_gets_extra_scrutiny() {
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(8);
    let (engine, xdp, _clamav, _spectral, _metrics) = CorrelationEngine::new(CorrelationConfig::default(), out_tx);
    tokio::spawn(engine.run());

    // human_approved: true -> Critical severity, confidence 1.0, on its own.
    xdp.submit(host(), flow(), "confirmed C2 beacon", true);

    let verdict = tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
        .await
        .expect("verdict should arrive")
        .expect("channel open");
    assert_eq!(verdict.sources, vec![siem_correlation::LaneSource::Xdp]);

    let flow_prediction = verdict_to_flow_prediction(&verdict, "corr-e2e-2");
    assert_eq!(flow_prediction.predicted_label, "SingleLaneCritical");
    assert!((flow_prediction.confidence - 1.0).abs() < 1e-6);
    // Even at full confidence, a single-lane verdict is deliberately routed
    // through the force-review path -- see verdict_to_flow_prediction's
    // docs on why weaker corroboration still needs a human.
    assert!(flow_prediction.is_out_of_distribution);

    let mut gr = gated();
    let mut action = LogOnly;
    let disposition = gr
        .handle_flow_prediction(flow_prediction, alert(), "198.51.100.77", &mut action)
        .unwrap();
    assert_eq!(disposition, Disposition::QueuedForReview(TriggerReason::NovelPattern));
}
