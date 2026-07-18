//! Closes two gaps `active-siem`'s own README documents under "Honest gaps":
//!
//! 1. *"No confidence-threshold/fallback wiring yet between the classifier
//!    and the autoencoder (low-confidence classifier predictions should
//!    fall back to the open-set anomaly score...)"* -- [`to_flow_prediction`]
//!    takes the autoencoder's anomaly verdict as an input and folds it into
//!    `review_queue`'s `is_out_of_distribution` signal, so a low-confidence
//!    or novel-shaped classifier call is exactly what routes to a human.
//!
//! 2. `siem_response::ResponsePolicy::handle` currently *always* executes
//!    once its guards (severity/allowlist/rate-limit) pass -- "escalate to
//!    human review" is just an `Err(&'static str)` that the demo binary
//!    prints and drops. There is no queue, no audit trail, and nothing a
//!    human can actually act on. [`ReviewGatedResponse`] puts
//!    `review_queue::ReviewQueue` in front of `ResponsePolicy`: a
//!    classifier prediction must clear the review trigger (confident,
//!    unambiguous, in-distribution) *or* be explicitly approved by a human
//!    before `ResponsePolicy::handle` -- and therefore any real containment
//!    action -- is ever called.
//!
//! `ResponsePolicy` itself is untouched: its guards are an orthogonal,
//! already-tested safety layer (never touch an allowlisted host, never
//! exceed the rate limit) that still applies *after* the review gate
//! clears. This crate composes the two rather than replacing either.

use review_queue::prelude::*;
use siem_core::Alert;
use siem_ml::classifier::Prediction;
use siem_response::{ResponseAction, ResponsePolicy};

/// Turns a classifier `Prediction` into the `FlowPrediction` `review_queue`
/// gates on. `is_anomalous_by_autoencoder` should come from
/// `siem_ml::is_anomalous` scored on the same flow -- passed in rather than
/// computed here because scoring needs a concrete `burn` `Backend`
/// parameter this crate deliberately stays generic over (see the module
/// docs' point 1: this is the fallback-wiring the README flags as missing).
pub fn to_flow_prediction(
    flow_id: impl Into<String>,
    prediction: &Prediction,
    is_anomalous_by_autoencoder: bool,
    observed_at: Timestamp,
) -> FlowPrediction {
    FlowPrediction {
        flow_id: flow_id.into(),
        predicted_label: prediction.category.name().to_string(),
        confidence: prediction.confidence as f64,
        runner_up_label: prediction.runner_up_category.map(|c| c.name().to_string()),
        runner_up_confidence: prediction.runner_up_confidence.map(|c| c as f64),
        is_out_of_distribution: is_anomalous_by_autoencoder,
        observed_at,
    }
}

/// What happened to one alert after passing through the review gate and
/// (if cleared) `ResponsePolicy`'s own guards.
#[derive(Debug, Clone, PartialEq)]
pub enum Disposition {
    /// Cleared the review gate (auto or human-approved) and every
    /// `ResponsePolicy` guard; the action executed.
    Executed,
    /// Cleared the review gate, but `ResponsePolicy` itself withheld it
    /// (allowlisted target, rate limit, below severity floor, duplicate).
    /// This is a *second*, independent reason to withhold -- distinct from
    /// not clearing review at all.
    WithheldByPolicy(&'static str),
    /// Did not clear the review gate; queued for a human, no action taken.
    /// Call [`ReviewGatedResponse::resolve_and_execute`] once a verdict is
    /// recorded.
    QueuedForReview(TriggerReason),
    /// Review gate resolved this as benign (auto or human); no action was
    /// ever attempted.
    Dismissed,
    /// A human reviewed this and asked for further escalation rather than
    /// a contain/dismiss call. No action was attempted.
    Escalated,
}

/// Composes `review_queue::ReviewQueue` (the human-review gate) with
/// `siem_response::ResponsePolicy` (the rate-limit/allowlist/severity
/// guards). A classifier prediction must clear both before any
/// `ResponseAction` executes.
pub struct ReviewGatedResponse {
    pub queue: ReviewQueue,
    pub policy: ResponsePolicy,
}

impl ReviewGatedResponse {
    pub fn new(
        trigger_cfg: TriggerConfig,
        sla_policy: SlaPolicy,
        policy: ResponsePolicy,
    ) -> review_queue::error::Result<Self> {
        Ok(Self {
            queue: ReviewQueue::new(trigger_cfg, sla_policy)?,
            policy,
        })
    }

    /// Feed one classifier prediction through the review gate, and -- if it
    /// clears (auto-resolved to `ExecuteContainment`) -- through
    /// `ResponsePolicy`'s guards and `action`.
    ///
    /// `flow_id` must be unique per flow scored; re-scoring the same flow
    /// is a caller bug (`ReviewQueue::ingest` rejects duplicates) since it
    /// would let a flow be "re-submitted" past an earlier flag.
    pub fn handle(
        &mut self,
        flow_id: &str,
        prediction: &Prediction,
        is_anomalous_by_autoencoder: bool,
        alert: Alert,
        target_ip: &str,
        action: &mut dyn ResponseAction,
    ) -> review_queue::error::Result<Disposition> {
        let flow_prediction = to_flow_prediction(flow_id, prediction, is_anomalous_by_autoencoder, now());
        self.handle_flow_prediction(flow_prediction, alert, target_ip, action)
    }

    /// The evidence-source-agnostic core of `handle`: given any already-
    /// constructed `FlowPrediction`, gate it through the review queue and
    /// (if cleared) `ResponsePolicy`. `handle` is a thin wrapper over this
    /// for the classifier's own `Prediction` type; other evidence sources
    /// -- e.g. `siem-correlation-bridge`, which builds a `FlowPrediction`
    /// from a `CorrelationVerdict` fusing multiple detection lanes rather
    /// than from a single classifier call -- use this directly instead of
    /// duplicating the gating logic.
    pub fn handle_flow_prediction(
        &mut self,
        flow_prediction: FlowPrediction,
        alert: Alert,
        target_ip: &str,
        action: &mut dyn ResponseAction,
    ) -> review_queue::error::Result<Disposition> {
        let flow_id = flow_prediction.flow_id.clone();
        let predicted_label = flow_prediction.predicted_label.clone();
        let confidence = flow_prediction.confidence;
        let outcome = self.queue.ingest(flow_prediction)?;

        match outcome {
            IngestOutcome::AutoResolved {
                verdict: Verdict::ExecuteContainment,
                ..
            } => Ok(self.run_policy(&alert, target_ip, action)),
            IngestOutcome::AutoResolved { verdict: Verdict::Dismiss, .. } => Ok(Disposition::Dismissed),
            IngestOutcome::AutoResolved {
                verdict: Verdict::EscalateFurther,
                ..
            } => Ok(Disposition::Escalated), // not produced by ingest today; handled for completeness
            IngestOutcome::QueuedForReview { reason } => {
                tracing::info!(
                    flow_id,
                    predicted_label,
                    confidence,
                    reason = %reason,
                    "flow queued for human review; no response action taken"
                );
                Ok(Disposition::QueuedForReview(reason))
            }
        }
    }

    /// Record a human's verdict on a previously-queued flow, and -- if they
    /// approved containment -- run it through `ResponsePolicy` and
    /// `action`, same as an auto-resolved approval would.
    pub fn resolve_and_execute(
        &mut self,
        flow_id: &str,
        reviewer: &str,
        verdict: Verdict,
        rationale: &str,
        alert: Alert,
        target_ip: &str,
        action: &mut dyn ResponseAction,
    ) -> review_queue::error::Result<Disposition> {
        let decision = self.queue.record_decision(flow_id, reviewer, verdict, rationale)?;
        Ok(match decision.verdict {
            Verdict::ExecuteContainment => self.run_policy(&alert, target_ip, action),
            Verdict::Dismiss => Disposition::Dismissed,
            Verdict::EscalateFurther => Disposition::Escalated,
        })
    }

    /// Sweep SLA-expired pending items. Delegates to `ReviewQueue`'s default
    /// `LoggingAlertSink`, so an unreviewed attack call that times out under
    /// a fail-safe policy is logged loudly (`ERROR`), not silently
    /// dismissed -- see `review_queue::alert`.
    pub fn sweep_expired(&mut self, sla_seconds: i64) -> review_queue::error::Result<Vec<SlaResolution>> {
        self.queue.sweep_expired(sla_seconds)
    }

    fn run_policy(&mut self, alert: &Alert, target_ip: &str, action: &mut dyn ResponseAction) -> Disposition {
        match self.policy.handle(action, alert, target_ip) {
            Ok(()) => Disposition::Executed,
            Err(reason) => {
                tracing::warn!(
                    target_ip,
                    reason,
                    "review gate approved containment but ResponsePolicy withheld it"
                );
                Disposition::WithheldByPolicy(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_core::{Alert, Severity};
    use siem_response::LogOnly;
    use std::collections::{HashMap, HashSet};

    fn alert(severity: Severity) -> Alert {
        Alert {
            id: 1,
            timestamp_ms: 0,
            rule_id: "ml-classifier".into(),
            title: "test alert".into(),
            severity,
            mitre_technique: None,
            source_events: vec![],
            context: HashMap::new(),
        }
    }

    fn prediction(label: &str, confidence: f32) -> Prediction {
        prediction_with_runner_up(label, confidence, None, None)
    }

    fn prediction_with_runner_up(
        label: &str,
        confidence: f32,
        runner_up_label: Option<&str>,
        runner_up_confidence: Option<f32>,
    ) -> Prediction {
        let category_of = |l: &str| match l {
            "Benign" => siem_ml::classifier::Category::Benign,
            "Infiltration" => siem_ml::classifier::Category::Infiltration,
            "BruteForce" => siem_ml::classifier::Category::BruteForce,
            "CommandAndControl" => siem_ml::classifier::Category::CommandAndControl,
            "DenialOfService" => siem_ml::classifier::Category::DenialOfService,
            _ => siem_ml::classifier::Category::Reconnaissance,
        };
        Prediction {
            category: category_of(label),
            confidence,
            runner_up_category: runner_up_label.map(category_of),
            runner_up_confidence,
        }
    }

    fn gated() -> ReviewGatedResponse {
        ReviewGatedResponse::new(
            TriggerConfig::default(),
            SlaPolicy::FailSafe,
            ResponsePolicy::new(Severity::Medium, HashSet::new()),
        )
        .unwrap()
    }

    #[test]
    fn confident_attack_prediction_clears_review_and_executes() {
        let mut gr = gated();
        let mut action = LogOnly;
        let outcome = gr
            .handle(
                "flow-dos",
                &prediction("DenialOfService", 1.0),
                false,
                alert(Severity::High),
                "203.0.113.5",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::Executed);
    }

    #[test]
    fn the_0_856_infiltration_case_is_queued_not_executed() {
        // Mirrors the exact misclassification from
        // siem-ml/tests/categorical_isolation.rs: true=Benign,
        // predicted=Infiltration, confidence=0.856. This must never reach
        // ResponsePolicy, let alone execute a block.
        let mut gr = gated();
        let mut action = LogOnly;
        let outcome = gr
            .handle(
                "flow-suspect",
                &prediction("Infiltration", 0.856),
                false,
                alert(Severity::High),
                "198.51.100.77",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::QueuedForReview(TriggerReason::LowConfidenceAttack));
        assert_eq!(
            gr.queue.containment_decision("flow-suspect"),
            ContainmentDecision::NotApproved
        );
    }

    #[test]
    fn autoencoder_anomaly_flag_forces_review_even_at_high_confidence() {
        // Closes the README's documented gap: a confident classifier call
        // that the autoencoder independently flags as out-of-distribution
        // must still go to a human, not auto-execute.
        let mut gr = gated();
        let mut action = LogOnly;
        let outcome = gr
            .handle(
                "flow-novel",
                &prediction("DenialOfService", 0.999),
                true, // autoencoder says this doesn't look like anything trained on
                alert(Severity::High),
                "203.0.113.9",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::QueuedForReview(TriggerReason::NovelPattern));
    }

    #[test]
    fn human_approval_of_queued_flow_executes_containment() {
        let mut gr = gated();
        let mut action = LogOnly;
        gr.handle(
            "flow-suspect",
            &prediction("Infiltration", 0.856),
            false,
            alert(Severity::High),
            "198.51.100.77",
            &mut action,
        )
        .unwrap();

        let outcome = gr
            .resolve_and_execute(
                "flow-suspect",
                "analyst_priya",
                Verdict::ExecuteContainment,
                "confirmed lateral movement via pcap",
                alert(Severity::High),
                "198.51.100.77",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::Executed);
    }

    #[test]
    fn review_approval_still_subject_to_allowlist_guard() {
        // The review gate and ResponsePolicy are independent layers: even
        // an explicit human "contain" verdict must not block an
        // allowlisted host. This is exactly the kind of self-inflicted
        // outage ResponsePolicy's allowlist guard exists to prevent.
        let mut allowlist = HashSet::new();
        allowlist.insert("10.0.0.20".to_string());
        let mut gr = ReviewGatedResponse::new(
            TriggerConfig::default(),
            SlaPolicy::FailSafe,
            ResponsePolicy::new(Severity::Medium, allowlist),
        )
        .unwrap();
        let mut action = LogOnly;

        let outcome = gr
            .handle(
                "flow-self",
                &prediction("Infiltration", 0.856),
                false,
                alert(Severity::High),
                "10.0.0.20",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::QueuedForReview(TriggerReason::LowConfidenceAttack));

        let outcome = gr
            .resolve_and_execute(
                "flow-self",
                "analyst_priya",
                Verdict::ExecuteContainment,
                "reviewed, but this is our own allowlisted host -- should still be blocked at the policy layer",
                alert(Severity::High),
                "10.0.0.20",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::WithheldByPolicy("target is allowlisted; escalate to human review"));
    }

    #[test]
    fn narrow_runner_up_margin_forces_review_even_at_high_top1_confidence() {
        // Closes the other half of the previously-flagged gap: predict()
        // now returns a runner-up, and to_flow_prediction actually threads
        // it through, so ReviewTrigger's narrow-margin check -- previously
        // dead code from this crate's perspective, since runner_up was
        // always None -- is reachable.
        let mut gr = gated();
        let mut action = LogOnly;
        let outcome = gr
            .handle(
                "flow-close-call",
                &prediction_with_runner_up("DenialOfService", 0.95, Some("BruteForce"), Some(0.88)), // margin 0.07
                false,
                alert(Severity::High),
                "203.0.113.10",
                &mut action,
            )
            .unwrap();
        assert_eq!(outcome, Disposition::QueuedForReview(TriggerReason::NarrowMargin));
    }

    #[test]
    fn sla_timeout_dismisses_never_executes() {
        let mut gr = gated();
        let mut action = LogOnly;
        gr.handle(
            "flow-suspect",
            &prediction("Infiltration", 0.856),
            false,
            alert(Severity::High),
            "198.51.100.77",
            &mut action,
        )
        .unwrap();

        let resolutions = gr.sweep_expired(0).unwrap();
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].decision.verdict, Verdict::Dismiss);
        assert_eq!(
            gr.queue.containment_decision("flow-suspect"),
            ContainmentDecision::NotApproved
        );
    }
}
