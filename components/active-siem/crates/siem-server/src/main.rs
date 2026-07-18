//! ActiveSIEM orchestrator - demo wiring of the full pipeline:
//!
//!   collector -> rule engine (noisy/known attacks) -> ML scorer (quiet infiltration)
//!            -> alert stream -> response policy (guarded active response)
//!
//! This binary simulates an SSH brute-force (caught by siem-rules) and a
//! slow-beacon infiltration flow (caught by siem-ml, invisible to signatures)
//! to demonstrate why both detection layers are necessary.

use burn::backend::{Autodiff, NdArray};
use burn::module::AutodiffModule;
use review_queue::prelude::{now, FlowPrediction, ReviewQueue, SlaPolicy, TriggerConfig, Verdict};
use siem_collector::synthetic_flow;
use siem_core::EventKind;
use siem_ml::classifier::{Category, Prediction};
use siem_ml::{score, train, AutoencoderConfig, FlowFeatures};
use siem_response::{LogOnly, ResponsePolicy};
use siem_review::ReviewGatedResponse;
use siem_rules::RuleEngine;
use siem_store::Store;
use std::collections::HashSet;

type TrainBackend = Autodiff<NdArray<f32>>;
type InferBackend = NdArray<f32>;

/// Fires an outbound webhook notification iff `disposition` is
/// `QueuedForReview` and notifications are configured -- see `siem-notify`'s
/// crate docs on why this is called explicitly at each site (3a/3b/4a/4b
/// below) rather than baked into `siem-review`/`review-queue` themselves.
fn maybe_notify_queued(
    webhook_url: &Option<String>,
    disposition: &siem_review::Disposition,
    flow_id: &str,
    predicted_label: &str,
    confidence: f64,
) {
    let Some(url) = webhook_url else { return };
    if let siem_review::Disposition::QueuedForReview(reason) = disposition {
        let notifier = siem_notify::WebhookNotifier::new(url.clone());
        siem_notify::notify_queued_for_review(
            &notifier,
            flow_id,
            predicted_label,
            confidence,
            &reason.to_string(),
            now(),
        );
    }
}

fn main() {
    println!("=== ActiveSIEM demo ===\n");

    // --- 0. Persistence: connect to Postgres for the event/alert data model. ---
    //
    // Previously there was no persistence layer at all -- every Event/Alert
    // lived only in this process's memory for the duration of one run.
    // `siem-store` adds a real PostgreSQL-backed store (see its crate docs
    // for why Postgres specifically). Connection failure degrades to
    // in-memory-only rather than aborting the whole demo: a SIEM's
    // detection/response pipeline should keep running even if its
    // persistence backend is briefly unreachable (that's the same
    // fail-open-on-infra-but-fail-safe-on-decisions posture
    // `review_queue`'s SLA policy already takes) -- a real deployment would
    // additionally alert loudly on this, which is out of scope for a demo
    // binary but the same `tracing`-based alerting pattern `review_queue`
    // established would be the way to do it.
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "host=127.0.0.1 user=siem password=siem dbname=active_siem".to_string());
    let mut store = match Store::connect(&database_url) {
        Ok(mut s) => match s.migrate() {
            Ok(()) => {
                println!("-- Connected to PostgreSQL, events/alerts will be persisted --");
                Some(s)
            }
            Err(e) => {
                println!("-- WARNING: connected to PostgreSQL but migration failed ({e}); continuing without persistence --");
                None
            }
        },
        Err(e) => {
            println!(
                "-- WARNING: could not connect to PostgreSQL at '{database_url}' ({e}); \
                 continuing without persistence. Set DATABASE_URL to point at a reachable \
                 instance to enable it. --"
            );
            None
        }
    };

    // Opt-in outbound webhook notifications (n8n-compatible -- see
    // siem-notify's crate docs for exactly what this is and, just as
    // importantly, isn't used for: outbound "tell a human" notifications
    // only, never anywhere in the detection/correlation/containment
    // decision path). Unlike Postgres, not configuring this is the normal
    // case, not a degraded one -- no scary warning, just a note either way.
    let webhook_url = std::env::var("N8N_WEBHOOK_URL").ok();
    match &webhook_url {
        Some(url) => println!("-- Outbound notifications enabled: {url} --"),
        None => println!("-- Outbound notifications disabled (set N8N_WEBHOOK_URL to enable) --"),
    }
    let sla_alert_sink: Box<dyn review_queue::alert::SlaBreachAlertSink> = match &webhook_url {
        Some(url) => Box::new(siem_notify::WebhookAlertSink(siem_notify::WebhookNotifier::new(url.clone()))),
        None => Box::new(review_queue::alert::LoggingAlertSink),
    };

    // --- 1. Rule engine: catches the noisy precursor (brute force) ---
    let rules = RuleEngine::load_yaml(siem_rules::builtin_rules_yaml()).unwrap();
    let mut engine = RuleEngine::new(rules);
    let mut next_id = 1u64;

    let mut bruteforce_alerts: Vec<siem_core::Alert> = Vec::new();
    println!("\n-- Simulating SSH brute force from 10.0.0.5 --");
    for i in 0..5 {
        let mut ev = siem_collector::parse_sshd_line(
            "web01",
            "agent-01",
            "Jul 13 10:00:01 web01 sshd[123]: Failed password for root from 10.0.0.5 port 51000 ssh2",
        )
        .unwrap();
        ev.id = next_id;
        ev.timestamp_ms = i * 1000;
        next_id += 1;
        if let Some(s) = store.as_mut() {
            if let Err(e) = s.insert_event(&ev) {
                println!("  (failed to persist event {}: {e})", ev.id);
            }
        }
        for alert in engine.process(&ev) {
            println!(
                "  ALERT [{}] {} (severity {:?}, mitre {:?})",
                alert.rule_id, alert.title, alert.severity, alert.mitre_technique
            );
            if let Some(s) = store.as_mut() {
                if let Err(e) = s.insert_alert(&alert) {
                    println!("  (failed to persist alert {}: {e})", alert.id);
                }
            }
            bruteforce_alerts.push(alert);
        }
    }

    // --- 2. ML scorer: catches the quiet infiltration flow rules would miss ---
    println!("\n-- Training autoencoder on benign traffic shape --");
    let device = Default::default();
    let benign: Vec<FlowFeatures> = (0..200)
        .map(|i| {
            let ev = synthetic_flow(
                "web01",
                "agent-01",
                "10.0.0.20",
                "203.0.113.10",
                40000 + (i % 1000),
                443,
                (2_000 + (i % 500) * 10) as u64, // a couple seconds, variable
                (1500 + (i % 300) * 20) as u64,  // normal browsing-sized upload
                (40_000 + (i % 2000) * 5) as u64, // much larger download than upload
                (20 + (i % 10)) as u64,
            );
            let EventKind::Flow { .. } = &ev.kind else {
                unreachable!()
            };
            FlowFeatures::from_event(&ev.kind).unwrap()
        })
        .collect();

    let config = AutoencoderConfig::default();
    let model = train::<TrainBackend>(&device, &config, &benign, 300, 1e-2);
    let infer_model = model.valid(); // drop autodiff graph for inference

    // Calibrate a threshold from benign reconstruction error (e.g. 99th percentile-ish: max + margin)
    let device_infer: <InferBackend as burn::tensor::backend::Backend>::Device = Default::default();
    let benign_scores: Vec<f32> = benign
        .iter()
        .map(|f| score::<InferBackend>(&infer_model, &device_infer, *f))
        .collect();
    let max_benign = benign_scores.iter().cloned().fold(0f32, f32::max);
    let threshold = max_benign * 1.5 + 0.001;
    println!("  calibrated anomaly threshold: {threshold:.5}");

    println!("\n-- Scoring a suspected infiltration beacon (long, tiny, periodic, upload-heavy) --");
    let mut beacon = synthetic_flow(
        "web01",
        "agent-01",
        "10.0.0.20",
        "198.51.100.77", // unfamiliar low-reputation-looking destination
        51234,
        8443,
        9 * 60_000, // 9 minutes - unusually long for a "normal" web hit
        1_800,      // small, steady upload (exfil-shaped)
        900,        // barely any response - not a normal request/response pattern
        14,
    );
    beacon.id = next_id; // synthetic_flow() defaults id to 0; give it a real, unique id
    let f = FlowFeatures::from_event(&beacon.kind).unwrap();
    let s = score::<InferBackend>(&infer_model, &device_infer, f);
    println!("  reconstruction error: {s:.5} (threshold {threshold:.5})");
    let is_infiltration = s > threshold;
    println!("  flagged as anomalous/infiltration-like: {is_infiltration}");
    if let Some(store) = store.as_mut() {
        if let Err(e) = store.insert_event(&beacon) {
            println!("  (failed to persist event {}: {e})", beacon.id);
        }
    }

    // --- 3. Guarded, review-gated active response ---
    //
    // Previously this called `ResponsePolicy::handle` directly off the
    // autoencoder's boolean anomaly flag: any flow clearing the
    // severity/allowlist/rate-limit guards executed immediately, and
    // "escalate to human review" was just an `Err(&str)` this binary
    // printed and discarded -- there was nothing durable a human could
    // actually act on.
    //
    // `siem_review::ReviewGatedResponse` puts `review_queue::ReviewQueue`
    // in front of `ResponsePolicy`: a prediction must be confidently and
    // unambiguously classified (or explicitly approved by a human) before
    // `ResponsePolicy`'s guards -- and therefore any response action --
    // are ever reached. `ResponsePolicy` itself is untouched.
    //
    // The queue's state now persists across runs via `review_queue::store`
    // -- previously this built a fresh in-memory `ReviewQueue` on every
    // invocation, so anything queued for review vanished the moment the
    // demo exited. `ReviewGatedResponse`'s `queue`/`policy` fields are
    // public specifically so a caller can load/save the underlying
    // `ReviewQueue` itself, rather than needing a bespoke persistence API
    // duplicated in this crate.
    println!("\n-- Guarded, review-gated active response --");

    let review_state_path =
        std::env::var("REVIEW_QUEUE_STATE_PATH").unwrap_or_else(|_| "review_queue_state.json".to_string());
    let queue: ReviewQueue = review_queue::store::load_or_new(&review_state_path, TriggerConfig::default(), SlaPolicy::FailSafe)
        .expect("failed to load or initialize review queue state");
    println!("  review queue state: {review_state_path} ({} existing item(s))", queue.stats().total);

    let mut allowlist = HashSet::new();
    allowlist.insert("10.0.0.99".to_string()); // never auto-block our own host (e.g. a management/jump box)
    let response_policy = ResponsePolicy::new(siem_core::Severity::Medium, allowlist);
    let mut gated = ReviewGatedResponse { queue, policy: response_policy };
    let mut action = LogOnly;

    // The queue's duplicate-flow-id rejection (a deliberate safety property
    // -- see review_queue::queue::ReviewQueue::ingest) means re-submitting
    // the same flow id across runs now that state persists would error, so
    // each run gets a fresh id rather than the same literal every time.
    let run_stamp = siem_core::Event::now_ms();
    let flow_flood_id = format!("flow-flood-{run_stamp}");
    let flow_beacon_id = format!("flow-beacon-{run_stamp}");

    // 3a. A confident, unambiguous classification clears the review gate
    // automatically and reaches `ResponsePolicy` immediately -- same
    // end-to-end behavior as before, just now with a recorded, queryable
    // audit decision backing it instead of nothing.
    println!("\n  3a. Confident classification (DenialOfService, 1.000):");
    let confident_flood = Prediction {
        category: Category::DenialOfService,
        confidence: 1.0,
        runner_up_category: None,
        runner_up_confidence: None,
    };
    let flood_alert = siem_core::Alert {
        id: 1001,
        timestamp_ms: siem_core::Event::now_ms(),
        rule_id: "ml-classifier".to_string(),
        title: "Classifier: DenialOfService".to_string(),
        severity: siem_core::Severity::High,
        mitre_technique: Some("T1498".to_string()),
        source_events: vec![],
        context: Default::default(),
    };
    match gated.handle(
        &flow_flood_id,
        &confident_flood,
        false,
        flood_alert.clone(),
        "203.0.113.44",
        &mut action,
    ) {
        Ok(disposition) => println!("      disposition: {disposition:?}"),
        Err(e) => println!("      error: {e}"),
    }
    if let Some(s) = store.as_mut() {
        if let Err(e) = s.insert_alert(&flood_alert) {
            println!("      (failed to persist alert {}: {e})", flood_alert.id);
        }
    }

    // 3b. The same 0.856-confidence Benign-predicted-as-Infiltration case
    // `siem-ml/tests/categorical_isolation.rs` measures as this project's
    // one classifier error, applied to the beacon flow from part 2 above.
    // This is exactly the case that must NOT auto-block: a real deployment
    // running the old code path would have blocked 198.51.100.77 on a
    // call the classifier itself is calibrated to get wrong sometimes.
    println!(
        "\n  3b. Borderline classification (Infiltration, 0.856 -- the exact confidence \
         siem-ml/tests/categorical_isolation.rs measures as this classifier's one error):"
    );
    let borderline_beacon = Prediction {
        category: Category::Infiltration,
        confidence: 0.856,
        runner_up_category: None,
        runner_up_confidence: None,
    };
    let beacon_alert = siem_core::Alert {
        id: 1002,
        timestamp_ms: siem_core::Event::now_ms(),
        rule_id: "ml-classifier".to_string(),
        title: "Classifier: Infiltration".to_string(),
        severity: siem_core::Severity::High,
        mitre_technique: Some("T1071".to_string()),
        source_events: vec![beacon.id],
        context: Default::default(),
    };
    let disposition_3b = gated.handle(
        &flow_beacon_id,
        &borderline_beacon,
        is_infiltration, // fold in the autoencoder's independent anomaly verdict from part 2
        beacon_alert.clone(),
        "198.51.100.77",
        &mut action,
    );
    match &disposition_3b {
        Ok(disposition) => {
            println!("      disposition: {disposition:?}  (no action taken)");
            maybe_notify_queued(&webhook_url, disposition, &flow_beacon_id, "Infiltration", 0.856);
        }
        Err(e) => println!("      error: {e}"),
    }
    if let Some(s) = store.as_mut() {
        if let Err(e) = s.insert_alert(&beacon_alert) {
            println!("      (failed to persist alert {}: {e})", beacon_alert.id);
        }
    }
    println!(
        "      containment check before review: {}",
        gated.queue.containment_decision(&flow_beacon_id)
    );

    // A human reviews it (e.g. via `review_queue`'s CLI: `review_queue
    // review --flow-id flow-beacon-01 --reviewer analyst_priya --verdict
    // contain --rationale "..."`) and confirms it's real -- only then does
    // containment execute.
    println!("      -- analyst_priya reviews {flow_beacon_id}, confirms via pcap --");
    match gated.resolve_and_execute(
        &flow_beacon_id,
        "analyst_priya",
        Verdict::ExecuteContainment,
        "confirmed lateral movement pattern via pcap; not the classifier's usual false positive shape",
        beacon_alert,
        "198.51.100.77",
        &mut action,
    ) {
        Ok(disposition) => println!("      disposition after review: {disposition:?}"),
        Err(e) => println!("      error: {e}"),
    }
    println!(
        "      containment check after review:  {}",
        gated.queue.containment_decision(&flow_beacon_id)
    );
    println!(
        "      full audit trail for {flow_beacon_id}: {} decision(s) on the ontology graph",
        gated.queue.decisions_for_flow(&flow_beacon_id).len()
    );

    // --- 4. Correlation engine: fuses evidence across lanes, not just ---
    // ---    single-source predictions like parts 3a/3b above.        ---
    //
    // `siem-correlation` (see its crate docs) is a fan-in engine: three
    // typed, non-blocking lane senders -- XDP enforcement, ClamAV
    // quarantine, spectral/anomaly scoring -- feed a single consumer that
    // joins evidence per host within a rolling window and emits a
    // `CorrelationVerdict` the moment either two distinct lanes corroborate
    // the same host, or one lane reports something already Critical.
    // `siem-correlation-bridge` adapts `active-siem`'s two real detectors
    // (the rule engine, the ML classifier/autoencoder) onto this engine's
    // lanes, and adapts its verdicts back into the same review gate parts
    // 3a/3b already used -- correlation output is not trusted more than a
    // single classifier call just because two lanes agree; see the
    // bridge's `verdict_to_flow_prediction` docs for why.
    println!("\n-- Correlation engine (fan-in across detection lanes) --");
    let runtime = tokio::runtime::Runtime::new().expect("failed to start tokio runtime for the correlation engine");
    let correlation_alert: siem_core::Alert = runtime.block_on(async {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(64);
        let (engine, xdp, clamav, spectral, metrics) =
            siem_correlation::CorrelationEngine::new(siem_correlation::CorrelationConfig::default(), out_tx);
        tokio::spawn(engine.run());

        // 4a. SingleLaneCritical: the *same real bruteforce alert* from
        // part 1 above, submitted through the XDP lane. Five confirmed
        // failed SSH logins from one source is already a strong,
        // deterministic signal (`human_approved: true` -- this isn't
        // "maybe", it's a rule that already fired on hard thresholds), so
        // the correlation engine emits a Critical verdict off this one
        // lane alone. `siem-rules` operates on log events, not flow
        // telemetry, so there's no real `FlowKey` behind this alert --
        // the one below is illustrative (attacker -> web01, port 22),
        // constructed for the lane's sake rather than sourced from a
        // captured flow.
        if let Some(bf_alert) = bruteforce_alerts.first() {
            let attacker: std::net::IpAddr = "10.0.0.5".parse().unwrap();
            let ssh_flow = siem_correlation::FlowKey {
                src_ip: attacker,
                dst_ip: "10.0.0.20".parse().unwrap(),
                src_port: 51000,
                dst_port: 22,
                protocol: siem_correlation::Protocol::Tcp,
            };
            siem_correlation_bridge::rule_alert_to_xdp(&xdp, attacker, ssh_flow, bf_alert, true);

            let verdict = tokio::time::timeout(std::time::Duration::from_millis(200), out_rx.recv())
                .await
                .expect("SingleLaneCritical verdict should arrive quickly")
                .expect("channel open");
            println!(
                "  4a. {attacker} -- verdict: {:?}, confidence {:.2}, reason {:?}",
                verdict.severity, verdict.confidence, verdict.reason
            );
            if let Some(url) = &webhook_url {
                let notifier = siem_notify::WebhookNotifier::new(url.clone());
                let sources: Vec<String> = verdict.sources.iter().map(|s| format!("{s:?}")).collect();
                siem_notify::notify_correlation_verdict(
                    &notifier,
                    &attacker.to_string(),
                    &format!("{:?}", verdict.reason),
                    verdict.confidence,
                    &sources,
                    now(),
                );
            }
            let flow_id = format!("corr-{attacker}-{}", siem_core::Event::now_ms());
            let flow_prediction = siem_correlation_bridge::verdict_to_flow_prediction(&verdict, &flow_id);
            match gated.handle_flow_prediction(flow_prediction, bf_alert.clone(), &attacker.to_string(), &mut action) {
                Ok(disposition) => {
                    println!("      disposition: {disposition:?}");
                    maybe_notify_queued(&webhook_url, &disposition, &flow_id, "SingleLaneCritical", verdict.confidence as f64);
                }
                Err(e) => println!("      error: {e}"),
            }
            println!("      -- analyst_priya reviews {flow_id}, confirms the rule engine wasn't a false positive --");
            match gated.resolve_and_execute(
                &flow_id,
                "analyst_priya",
                Verdict::ExecuteContainment,
                "five confirmed failed logins from one source; not a false positive",
                bf_alert.clone(),
                &attacker.to_string(),
                &mut action,
            ) {
                Ok(disposition) => println!("      disposition after review: {disposition:?}"),
                Err(e) => println!("      error: {e}"),
            }
        }

        // 4b. MultiLaneCorroboration: the *same beacon flow's real ML
        // anomaly score* from part 2 above (Spectral lane), corroborated
        // by a **simulated** ClamAV quarantine hit on the same internal
        // host (10.0.0.20). There is no real file-scanning/AV component
        // in this codebase -- this event is clearly synthetic, standing
        // in for what a real ClamAV integration would submit, not a
        // fabricated detection presented as genuine.
        let internal_host: std::net::IpAddr = "10.0.0.20".parse().unwrap();
        if let Some(beacon_flow) = siem_correlation_bridge::flow_key_from_event(&beacon) {
            // Deliberately capped below SpectralSender's own Critical band
            // (>= 0.9) rather than passed through raw: the beacon's real
            // reconstruction error is ~6000x its calibrated threshold
            // (see part 2), which would make this single event Critical on
            // its own and fire immediately -- demonstrating the
            // SingleLaneCritical path again, not what this section is for.
            // Capping at 0.85 keeps it in the High band so the engine
            // waits for the ClamAV corroboration below within the window,
            // which is the actual point of this scenario. A real
            // deployment would calibrate the raw-error-to-[0,1] mapping
            // properly rather than picking a cap to fit a demo narrative.
            let normalized_anomaly = (s / threshold / 50.0).clamp(0.0, 0.85) as f64;
            siem_correlation_bridge::ml_score_to_spectral(&spectral, internal_host, beacon_flow, normalized_anomaly);
        }
        clamav.submit(
            internal_host,
            "svc_update.exe",
            "SIMULATED.Win.Dropper.Generic (no real AV integration in this codebase)",
            true,
        );

        let verdict = tokio::time::timeout(std::time::Duration::from_millis(200), out_rx.recv())
            .await
            .expect("MultiLaneCorroboration verdict should arrive quickly")
            .expect("channel open");
        println!(
            "  4b. {internal_host} -- verdict: {:?}, confidence {:.2}, reason {:?}, sources {:?}",
            verdict.severity, verdict.confidence, verdict.reason, verdict.sources
        );
        if let Some(url) = &webhook_url {
            let notifier = siem_notify::WebhookNotifier::new(url.clone());
            let sources: Vec<String> = verdict.sources.iter().map(|s| format!("{s:?}")).collect();
            siem_notify::notify_correlation_verdict(
                &notifier,
                &internal_host.to_string(),
                &format!("{:?}", verdict.reason),
                verdict.confidence,
                &sources,
                now(),
            );
        }
        let flow_id = format!("corr-{internal_host}-{}", siem_core::Event::now_ms());
        let flow_prediction = siem_correlation_bridge::verdict_to_flow_prediction(&verdict, &flow_id);
        let internal_alert = siem_core::Alert {
            id: 1003,
            timestamp_ms: siem_core::Event::now_ms(),
            rule_id: "correlation-engine".to_string(),
            title: "Multi-lane corroborated: anomalous beacon + AV hit on same host".to_string(),
            severity: siem_core::Severity::Critical,
            mitre_technique: Some("T1071".to_string()),
            source_events: vec![beacon.id],
            context: Default::default(),
        };
        // NOTE: `siem_store::Store` wraps the blocking `postgres` crate,
        // which drives its connection with its own internal tokio runtime
        // -- calling it from inside this `block_on`'d async block would
        // panic ("Cannot start a runtime from within a runtime"). Persist
        // this alert after `block_on` returns instead (see below); nothing
        // about that ordering changes what gets persisted, since the alert
        // itself doesn't depend on anything computed later in this block.
        match gated.handle_flow_prediction(flow_prediction, internal_alert.clone(), &internal_host.to_string(), &mut action) {
            Ok(disposition) => {
                println!("      disposition: {disposition:?}");
                // Two corroborating lanes can be enough to clear the
                // review floor on their own (confidence is the mean of
                // both lanes' confidence) -- in that case there's nothing
                // pending for a human to resolve, unlike 4a/3b above where
                // a single weaker signal always queues. Handle both
                // outcomes rather than assuming which one occurs, since
                // the exact confidence depends on the autoencoder's
                // training run (see part 2) and can drift slightly.
                if matches!(disposition, siem_review::Disposition::QueuedForReview(_)) {
                    maybe_notify_queued(&webhook_url, &disposition, &flow_id, "MultiLaneCorroboration", verdict.confidence as f64);
                    println!(
                        "      -- analyst_priya reviews {flow_id}, confirms both lanes point at the same compromise --"
                    );
                    match gated.resolve_and_execute(
                        &flow_id,
                        "analyst_priya",
                        Verdict::ExecuteContainment,
                        "anomalous beacon and AV hit corroborate on the same host",
                        internal_alert.clone(),
                        &internal_host.to_string(),
                        &mut action,
                    ) {
                        Ok(disposition) => println!("      disposition after review: {disposition:?}"),
                        Err(e) => println!("      error: {e}"),
                    }
                } else {
                    println!(
                        "      (two corroborating lanes already cleared the confidence floor -- no human review needed here)"
                    );
                }
            }
            Err(e) => println!("      error: {e}"),
        }

        let snap = metrics.snapshot();
        println!(
            "  correlation metrics: events_received={} verdicts_emitted={} verdicts_dropped={}",
            snap.events_received, snap.verdicts_emitted, snap.verdicts_dropped
        );

        internal_alert
    });
    if let Some(s) = store.as_mut() {
        if let Err(e) = s.insert_alert(&correlation_alert) {
            println!("  (failed to persist alert {}: {e})", correlation_alert.id);
        }
    }

    // --- 5. SLA sweep: exercises the alert-sink path live. ---
    //
    // Every flow above got a human decision in the same run, so nothing
    // is actually pending by the time execution reaches here. Ingest one
    // deliberately-unreviewed flow and sweep it immediately
    // (`sla_seconds=0`) to show the fail-safe timeout -> alert-sink path
    // end to end, not just in siem-review/review-queue's own test suites.
    println!("\n-- SLA sweep (fail-safe timeout path) --");
    let sla_flow_id = format!("flow-unreviewed-{}", siem_core::Event::now_ms());
    gated
        .queue
        .ingest(FlowPrediction {
            flow_id: sla_flow_id.clone(),
            predicted_label: "Infiltration".to_string(),
            confidence: 0.70, // deliberately below the review floor, so it queues instead of auto-resolving
            runner_up_label: None,
            runner_up_confidence: None,
            is_out_of_distribution: false,
            observed_at: now(),
        })
        .expect("fresh flow id should ingest cleanly");
    let sla_resolutions = gated
        .queue
        .sweep_expired_with_sink(0, sla_alert_sink.as_ref())
        .expect("sweep should not fail");
    for r in &sla_resolutions {
        println!(
            "  '{}' resolved via SLA fallback: verdict={} (never auto-contains under fail-safe)",
            r.prediction.flow_id, r.decision.verdict
        );
    }
    println!(
        "  ({} of these alerts went to {})",
        sla_resolutions.len(),
        if webhook_url.is_some() { "the configured webhook" } else { "tracing logs only -- set N8N_WEBHOOK_URL to route them out" }
    );

    review_queue::store::save(&gated.queue, &review_state_path)
        .expect("failed to persist review queue state");
    println!("\n  review queue state saved to {review_state_path} (persists across runs)");

    if let Some(mut s) = store {
        match (s.count_events(), s.count_alerts()) {
            (Ok(events), Ok(alerts)) => {
                println!("  PostgreSQL now holds {events} event(s) and {alerts} alert(s) (persists across runs)");
            }
            _ => println!("  (could not read back final PostgreSQL counts)"),
        }
    }
}
