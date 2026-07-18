//! Best-effort outbound webhook notifications.
//!
//! # Where this fits, and where it deliberately doesn't
//!
//! This crate is scoped narrowly on purpose: it is the *outbound
//! notification/ops-integration* layer only -- "tell a human, or an
//! external system, that something happened." It is never on the
//! detection, correlation, or containment-authorization path.
//!
//! - `review_queue::alert::LoggingAlertSink` already documents this gap
//!   directly: it "guarantees something lands in logs; it does not page
//!   anyone. Production deployments should wrap or replace this with a
//!   sink that actually reaches an on-call human." [`WebhookAlertSink`]
//!   is that sink.
//! - A tool like n8n is a genuinely good fit *here* specifically: fanning
//!   one event out to Slack, email, PagerDuty, Jira, a SIEM's own ticket
//!   queue, etc. is exactly the kind of low-code integration glue n8n is
//!   built for, and doing it in n8n means not hand-writing and
//!   maintaining a bespoke Rust HTTP client for every downstream service
//!   this project might ever want to notify.
//! - It would be a **bad** fit for the actual detection/correlation/
//!   containment-decision pipeline. That logic needs to stay fast,
//!   deterministic, and covered by the kind of property/invariant tests
//!   this workspace already has throughout (`sla_fail_safe_never_auto_contains_property`,
//!   the containment-audit-graph invariants, etc.) -- routing flow/event
//!   data through an external low-code workflow engine before a
//!   containment decision would add latency, a new failure mode, and a
//!   security surface (SIEM telemetry now flows to a third-party-ish
//!   workflow runner) with none of that rigor behind it. Nothing in this
//!   crate is called from `siem-correlation`'s emission logic or
//!   `review_queue`'s `ingest`/`record_decision`/containment-authorization
//!   path; it only ever fires *after* a decision (or a lack of one, in the
//!   SLA-timeout case) has already been made and recorded on the audit
//!   graph.
//! - n8n itself is also new attack surface -- a real server to run, patch,
//!   and secure, whose compromise would only leak notifications (never
//!   containment authority, since it has none), which is the right
//!   blast-radius tradeoff for what it's used for here.
//!
//! # What's actually implemented
//!
//! [`WebhookNotifier`] POSTs a small JSON payload to a configured URL --
//! deliberately generic, not n8n-specific wire format, since n8n's
//! "Webhook" trigger node accepts an arbitrary JSON body and that's the
//! only contract this needs to satisfy. [`WebhookAlertSink`] adapts it to
//! `review_queue::alert::SlaBreachAlertSink`, so it can be dropped directly
//! into `ReviewQueue::sweep_expired_with_sink`. `notify_queued_for_review`
//! and `notify_correlation_verdict` are free functions for the other two
//! points a real deployment would want a human paged: the moment
//! something is queued (not just once its SLA has already expired), and a
//! correlation-engine verdict landing.
//!
//! Uses `ureq` (a blocking client) rather than an async HTTP stack,
//! matching the rest of this workspace's synchronous style (same
//! reasoning as `siem-store`'s choice of blocking `postgres` over async
//! `sqlx`/`tokio-postgres` directly).

use serde::Serialize;
use std::time::Duration;

/// Generic notification payload. Deliberately not n8n-specific: any
/// webhook-style receiver (n8n, a generic Slack incoming-webhook adapter,
/// a test harness) can consume this shape.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    pub event: NotificationEvent,
    /// "info" | "warning" | "critical" -- kept as a plain string rather
    /// than reusing `siem_core::Severity` so this crate has no dependency
    /// on `siem-core` at all; see the module docs on why this stays
    /// generic/standalone.
    pub severity: String,
    pub title: String,
    pub details: serde_json::Value,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// A flow/verdict was queued and needs a human decision.
    QueuedForReview,
    /// A pending review timed out and was resolved by the SLA fallback
    /// policy without a human ever looking at it.
    SlaBreach,
    /// The correlation engine fused evidence across lanes into a verdict.
    CorrelationVerdict,
}

#[derive(Debug)]
pub enum NotifyError {
    Transport(Box<ureq::Error>),
    Io(std::io::Error),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::Transport(e) => write!(f, "webhook request failed: {e}"),
            NotifyError::Io(e) => write!(f, "webhook request I/O error: {e}"),
        }
    }
}
impl std::error::Error for NotifyError {}

/// POSTs [`Notification`]s to a fixed webhook URL. `timeout` bounds worst-
/// case latency of a single send -- this matters more than it might look:
/// see [`WebhookAlertSink`]'s docs for why a slow/unreachable webhook must
/// never be allowed to stall the review queue.
pub struct WebhookNotifier {
    url: String,
    timeout: Duration,
}

impl WebhookNotifier {
    /// `timeout` defaults to 3 seconds if not overridden via
    /// [`WebhookNotifier::with_timeout`] -- short enough to bound the
    /// worst case, generous enough for a same-network n8n instance.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), timeout: Duration::from_secs(3) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn send(&self, notification: &Notification) -> Result<(), NotifyError> {
        ureq::post(&self.url)
            .timeout(self.timeout)
            .send_json(notification)
            .map(|_response| ())
            .map_err(|e| NotifyError::Transport(Box::new(e)))
    }

    /// Same as [`send`](Self::send), but never returns an error -- logs
    /// via `tracing::warn!` and moves on. This is the method every call
    /// site in this crate actually uses: a failed *notification* must
    /// never become a failed *detection/response pipeline*, so nothing
    /// upstream of a notify call should have to handle a delivery failure
    /// as anything more than "log it and continue."
    pub fn send_best_effort(&self, notification: &Notification) {
        if let Err(e) = self.send(notification) {
            tracing::warn!(
                url = %self.url,
                event = ?notification.event,
                error = %e,
                "webhook notification failed to send (continuing -- this must never block the pipeline)"
            );
        }
    }
}

/// Adapts [`WebhookNotifier`] to `review_queue::alert::SlaBreachAlertSink`,
/// so it can be handed straight to `ReviewQueue::sweep_expired_with_sink`
/// (or `sweep_expired`, once wired as the default -- see `siem-server`'s
/// demo for how).
///
/// # Why this is safe to call synchronously from `sweep_expired`
///
/// `sweep_expired_with_sink` was refactored (see the comment at its call
/// site in `queue.rs`) to release its internal lock *before* calling into
/// any `SlaBreachAlertSink`, precisely because this sink exists: the
/// original implementation called `alert_sink.notify()` while still
/// holding `ReviewQueue`'s lock, which was harmless when the only sink was
/// `tracing`-based logging, but would have meant a slow or unreachable
/// webhook could stall every other `ReviewQueue` operation (`ingest`,
/// `record_decision`, ...) for up to `WebhookNotifier`'s timeout, once per
/// breach in the sweep. This sink's own `timeout` (default 3s) still
/// bounds *its own* worst case, but the lock-release fix is what stops
/// that worst case from propagating to the rest of the system.
pub struct WebhookAlertSink(pub WebhookNotifier);

impl review_queue::alert::SlaBreachAlertSink for WebhookAlertSink {
    fn notify(&self, breach: &review_queue::alert::SlaBreach) {
        let severity = if breach.is_unreviewed_attack_dismissal() { "critical" } else { "warning" };
        let notification = Notification {
            event: NotificationEvent::SlaBreach,
            severity: severity.to_string(),
            title: format!(
                "SLA breach: flow '{}' resolved unreviewed ({})",
                breach.prediction.flow_id, breach.decision.verdict
            ),
            details: serde_json::json!({
                "flow_id": breach.prediction.flow_id,
                "predicted_label": breach.prediction.predicted_label,
                "confidence": breach.prediction.confidence,
                "verdict": breach.decision.verdict.to_string(),
                "rationale": breach.decision.rationale,
                "decision_id": breach.decision.decision_id,
            }),
            timestamp: breach.decision.decided_at,
        };
        self.0.send_best_effort(&notification);
    }
}

/// Notify that a flow/verdict was just queued for human review -- the
/// moment a human would actually want to be paged at, since it's the
/// earliest point action can still be taken quickly, unlike an SLA-breach
/// notification which by definition means the window already closed.
/// Not baked into `review_queue`/`siem-review`'s core (those stay
/// dependency-light and this crate's send failures must never be able to
/// affect them); called explicitly at the point of use instead -- see
/// `siem-server`'s demo.
pub fn notify_queued_for_review(
    notifier: &WebhookNotifier,
    flow_id: &str,
    predicted_label: &str,
    confidence: f64,
    reason: &str,
    now: i64,
) {
    let notification = Notification {
        event: NotificationEvent::QueuedForReview,
        severity: "warning".to_string(),
        title: format!("Review needed: '{flow_id}' ({predicted_label}, {confidence:.3} confidence)"),
        details: serde_json::json!({
            "flow_id": flow_id,
            "predicted_label": predicted_label,
            "confidence": confidence,
            "trigger_reason": reason,
        }),
        timestamp: now,
    };
    notifier.send_best_effort(&notification);
}

/// Notify that the correlation engine emitted a verdict. Fired regardless
/// of whether the verdict goes on to clear the review floor automatically
/// or gets queued -- an ops channel may still want visibility into every
/// multi-lane corroboration, not just the ones that ended up needing a
/// human.
pub fn notify_correlation_verdict(
    notifier: &WebhookNotifier,
    host: &str,
    reason: &str,
    confidence: f32,
    sources: &[String],
    now: i64,
) {
    let notification = Notification {
        event: NotificationEvent::CorrelationVerdict,
        severity: if sources.len() > 1 { "critical".to_string() } else { "warning".to_string() },
        title: format!("Correlation verdict on {host}: {reason} ({confidence:.2} confidence)"),
        details: serde_json::json!({
            "host": host,
            "reason": reason,
            "confidence": confidence,
            "sources": sources,
        }),
        timestamp: now,
    };
    notifier.send_best_effort(&notification);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A minimal, dependency-free HTTP/1.1 server: reads one request,
    /// captures its JSON body, responds `200 OK`. Enough to verify
    /// `WebhookNotifier` actually performs a real POST with a well-formed
    /// JSON body over a real socket -- this is the same wire contract
    /// n8n's "Webhook" trigger node expects (POST, JSON body), so this
    /// validates the integration mechanism honestly even without a real
    /// n8n instance running in this environment.
    fn spawn_capturing_server() -> (String, mpsc::Receiver<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            tx.send(json).unwrap();

            let mut stream = stream;
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        });

        (format!("http://{addr}"), rx)
    }

    #[test]
    fn webhook_notifier_sends_well_formed_json_post() {
        let (url, rx) = spawn_capturing_server();
        let notifier = WebhookNotifier::new(url);
        let notification = Notification {
            event: NotificationEvent::QueuedForReview,
            severity: "warning".to_string(),
            title: "test notification".to_string(),
            details: serde_json::json!({ "flow_id": "flow-1" }),
            timestamp: 1_700_000_000,
        };

        notifier.send(&notification).expect("send should succeed against a real listening server");

        let received = rx.recv_timeout(std::time::Duration::from_secs(2)).expect("server should have received a request");
        assert_eq!(received["event"], "queued_for_review");
        assert_eq!(received["severity"], "warning");
        assert_eq!(received["title"], "test notification");
        assert_eq!(received["details"]["flow_id"], "flow-1");
        assert_eq!(received["timestamp"], 1_700_000_000);
    }

    #[test]
    fn send_best_effort_never_panics_on_unreachable_url() {
        // Port 1 is reserved/unlikely to have a listener; connection
        // should fail fast (or time out), and send_best_effort must
        // absorb that rather than propagate a panic.
        let notifier = WebhookNotifier::new("http://127.0.0.1:1").with_timeout(Duration::from_millis(200));
        let notification = Notification {
            event: NotificationEvent::SlaBreach,
            severity: "critical".to_string(),
            title: "unreachable test".to_string(),
            details: serde_json::json!({}),
            timestamp: 0,
        };
        notifier.send_best_effort(&notification); // must not panic
    }

    #[test]
    fn alert_sink_maps_unreviewed_attack_dismissal_to_critical() {
        let (url, rx) = spawn_capturing_server();
        let sink = WebhookAlertSink(WebhookNotifier::new(url));

        let prediction = review_queue::types::FlowPrediction {
            flow_id: "flow-9".to_string(),
            predicted_label: "Infiltration".to_string(),
            confidence: 0.856,
            runner_up_label: None,
            runner_up_confidence: None,
            is_out_of_distribution: false,
            observed_at: 0,
        };
        let decision = review_queue::types::AuditDecision {
            decision_id: "dec-1".to_string(),
            flow_id: "flow-9".to_string(),
            reviewer: review_queue::types::Reviewer::SystemSlaTimeout,
            verdict: review_queue::types::Verdict::Dismiss,
            rationale: "SLA breach".to_string(),
            decided_at: 0,
        };
        let breach = review_queue::alert::SlaBreach { prediction, decision };
        assert!(breach.is_unreviewed_attack_dismissal());

        use review_queue::alert::SlaBreachAlertSink;
        sink.notify(&breach);

        let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(received["event"], "sla_breach");
        assert_eq!(received["severity"], "critical");
        assert_eq!(received["details"]["flow_id"], "flow-9");
    }
}
