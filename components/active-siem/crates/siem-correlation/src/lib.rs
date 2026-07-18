//! Correlation fan-in.
//!
//! Connects the three post-analysis lanes — XDP enforcement, ClamAV
//! quarantine, and spectral anomaly scoring — to the correlation
//! engine (SIEM). Each lane gets its own typed, non-blocking sender;
//! the engine is the single consumer that fuses events per host into
//! a windowed correlation record and emits a `CorrelationVerdict`
//! downstream to containment.
//!
//! This crate is deliberately standalone: no dependency on `siem-core`
//! or any other `active-siem` crate, and `FlowKey`/`Protocol` below are
//! its own minimal types rather than reuses of `siem_core::EventKind`'s
//! `Flow` variant. That's intentional, not an oversight -- a fan-in
//! correlation engine is a reusable piece of infrastructure independent
//! of any one SIEM's event schema; see `siem-correlation-bridge` for the
//! glue that adapts `active-siem`'s actual detectors (the rule engine,
//! the ML classifier/autoencoder) onto this crate's lane senders, and
//! adapts `CorrelationVerdict` into `review_queue`'s human-review gate.
//!
//! # Design
//!
//! - **Fan-in, not fan-out.** Unlike ingestion (one producer, many
//!   consumers), this is three producers, one consumer — a natural
//!   fit for `tokio::sync::mpsc`, which supports multiple cloned
//!   senders into a single receiver. No custom fan-in plumbing needed.
//! - **Lane sends never block.** Each typed sender uses `try_send`.
//!   If the correlation engine is overloaded and its inbound buffer
//!   is full, the event is dropped and counted — XDP, ClamAV, and the
//!   spectral engine must never stall waiting on the SIEM.
//! - **Correlation key is the host**, not the flow. XDP reasons about
//!   a flow, ClamAV about a file/host, spectral about a flow — the
//!   common denominator, and what containment ultimately isolates, is
//!   the host IP. Events carry their flow-level detail for audit, but
//!   are joined on `host: IpAddr`.
//! - **Emission rule:** a verdict is emitted the moment two distinct
//!   lanes corroborate the same host within the correlation window,
//!   or immediately for a single `Critical` event (e.g. an XDP block
//!   that already required human approval). A host with only one
//!   sub-critical lane by the time its window expires is logged, not
//!   escalated to containment — insufficient evidence.
//! - **Bounded memory under adversarial load.** Per-host evidence is
//!   capped; total tracked hosts is capped, with oldest-first
//!   eviction — an attacker fanning out across many source IPs can't
//!   grow the correlation state without bound.
//!
//! # Cargo.toml
//! ```toml
//! tokio = { version = "1", features = ["rt-multi-thread", "sync", "time", "macros"] }
//! tracing = "0.1"
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

// ---------------------------------------------------------------------
// Shared flow identity
//
// In the real crate this is `crate::ingestion::FlowKey` — redefined
// here, minimally, so this module compiles and tests standalone.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

// ---------------------------------------------------------------------
// Severity, ordered Low < Medium < High < Critical
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------
// Lane-specific event detail
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneSource {
    Xdp,
    ClamAv,
    Spectral,
}

#[derive(Debug, Clone)]
pub enum LaneDetail {
    Xdp {
        flow: FlowKey,
        reason: String,
        human_approved: bool,
    },
    ClamAv {
        file_name: String,
        signature: String,
        quarantined: bool,
    },
    Spectral {
        flow: FlowKey,
        anomaly_score: f64,
        fiedler_shift: f64,
    },
}

/// A single fused-in event, produced by one of the three lanes.
#[derive(Debug, Clone)]
pub struct CorrelationEvent {
    pub host: IpAddr,
    pub source: LaneSource,
    pub severity: Severity,
    /// 0.0-1.0. Reflects the producing lane's own confidence — e.g.
    /// spectral anomaly score normalized, ClamAV signature match is
    /// always 1.0, XDP is 1.0 once human-approved and 0.6 while
    /// pending.
    pub confidence: f32,
    pub observed_at: Instant,
    pub detail: LaneDetail,
}

// ---------------------------------------------------------------------
// Correlated output, handed to containment
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationReason {
    MultiLaneCorroboration,
    SingleLaneCritical,
}

#[derive(Debug, Clone)]
pub struct CorrelationVerdict {
    pub host: IpAddr,
    pub severity: Severity,
    pub confidence: f32,
    pub sources: Vec<LaneSource>,
    pub evidence: Vec<CorrelationEvent>,
    pub reason: CorrelationReason,
    /// When the first piece of evidence for this host arrived -- lets a
    /// consumer measure correlation latency (`decided_at - first_seen`),
    /// e.g. to tune `CorrelationConfig::window`.
    pub first_seen: Instant,
    pub decided_at: Instant,
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct CorrelationMetrics {
    pub events_received: AtomicU64,
    pub verdicts_emitted: AtomicU64,
    pub verdicts_dropped: AtomicU64,
    pub hosts_evicted_ttl: AtomicU64,
    pub hosts_evicted_capacity: AtomicU64,
    pub xdp_dropped: AtomicU64,
    pub clamav_dropped: AtomicU64,
    pub spectral_dropped: AtomicU64,
}

#[derive(Clone)]
pub struct CorrelationMetricsHandle(Arc<CorrelationMetrics>);

impl CorrelationMetricsHandle {
    pub fn snapshot(&self) -> CorrelationMetricsSnapshot {
        let m = &self.0;
        CorrelationMetricsSnapshot {
            events_received: m.events_received.load(Ordering::Relaxed),
            verdicts_emitted: m.verdicts_emitted.load(Ordering::Relaxed),
            verdicts_dropped: m.verdicts_dropped.load(Ordering::Relaxed),
            hosts_evicted_ttl: m.hosts_evicted_ttl.load(Ordering::Relaxed),
            hosts_evicted_capacity: m.hosts_evicted_capacity.load(Ordering::Relaxed),
            xdp_dropped: m.xdp_dropped.load(Ordering::Relaxed),
            clamav_dropped: m.clamav_dropped.load(Ordering::Relaxed),
            spectral_dropped: m.spectral_dropped.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CorrelationMetricsSnapshot {
    pub events_received: u64,
    pub verdicts_emitted: u64,
    pub verdicts_dropped: u64,
    pub hosts_evicted_ttl: u64,
    pub hosts_evicted_capacity: u64,
    pub xdp_dropped: u64,
    pub clamav_dropped: u64,
    pub spectral_dropped: u64,
}

// ---------------------------------------------------------------------
// Typed, non-blocking lane senders
// ---------------------------------------------------------------------

/// Sender handed to the XDP enforcement lane. Only it can submit
/// `LaneSource::Xdp` events — callers can't accidentally mislabel a
/// lane's evidence.
#[derive(Clone)]
pub struct XdpSender {
    tx: mpsc::Sender<CorrelationEvent>,
    metrics: Arc<CorrelationMetrics>,
}

impl XdpSender {
    pub fn submit(
        &self,
        host: IpAddr,
        flow: FlowKey,
        reason: impl Into<String>,
        human_approved: bool,
    ) {
        let severity = if human_approved {
            Severity::Critical
        } else {
            Severity::High
        };
        let event = CorrelationEvent {
            host,
            source: LaneSource::Xdp,
            severity,
            confidence: if human_approved { 1.0 } else { 0.6 },
            observed_at: Instant::now(),
            detail: LaneDetail::Xdp {
                flow,
                reason: reason.into(),
                human_approved,
            },
        };
        if self.tx.try_send(event).is_err() {
            self.metrics.xdp_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("correlation engine backpressured: dropped XDP event");
        }
    }
}

/// Sender handed to the ClamAV quarantine lane.
#[derive(Clone)]
pub struct ClamAvSender {
    tx: mpsc::Sender<CorrelationEvent>,
    metrics: Arc<CorrelationMetrics>,
}

impl ClamAvSender {
    pub fn submit(
        &self,
        host: IpAddr,
        file_name: impl Into<String>,
        signature: impl Into<String>,
        quarantined: bool,
    ) {
        let event = CorrelationEvent {
            host,
            source: LaneSource::ClamAv,
            severity: if quarantined {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: 1.0, // signature match is deterministic
            observed_at: Instant::now(),
            detail: LaneDetail::ClamAv {
                file_name: file_name.into(),
                signature: signature.into(),
                quarantined,
            },
        };
        if self.tx.try_send(event).is_err() {
            self.metrics.clamav_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("correlation engine backpressured: dropped ClamAV event");
        }
    }
}

/// Sender handed to the spectral anomaly scoring lane.
#[derive(Clone)]
pub struct SpectralSender {
    tx: mpsc::Sender<CorrelationEvent>,
    metrics: Arc<CorrelationMetrics>,
}

impl SpectralSender {
    pub fn submit(&self, host: IpAddr, flow: FlowKey, anomaly_score: f64, fiedler_shift: f64) {
        let severity = if anomaly_score >= 0.9 {
            Severity::Critical
        } else if anomaly_score >= 0.7 {
            Severity::High
        } else if anomaly_score >= 0.4 {
            Severity::Medium
        } else {
            Severity::Low
        };
        let event = CorrelationEvent {
            host,
            source: LaneSource::Spectral,
            severity,
            confidence: anomaly_score.clamp(0.0, 1.0) as f32,
            observed_at: Instant::now(),
            detail: LaneDetail::Spectral {
                flow,
                anomaly_score,
                fiedler_shift,
            },
        };
        if self.tx.try_send(event).is_err() {
            self.metrics.spectral_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("correlation engine backpressured: dropped spectral event");
        }
    }
}

// ---------------------------------------------------------------------
// Per-host correlation state
// ---------------------------------------------------------------------

struct HostRecord {
    evidence: Vec<CorrelationEvent>,
    first_seen: Instant,
    last_seen: Instant,
    finalized: bool,
}

impl HostRecord {
    fn new(event: CorrelationEvent) -> Self {
        let now = event.observed_at;
        Self {
            evidence: vec![event],
            first_seen: now,
            last_seen: now,
            finalized: false,
        }
    }

    fn push(&mut self, event: CorrelationEvent, max_evidence: usize) {
        self.last_seen = event.observed_at;
        if self.evidence.len() >= max_evidence {
            self.evidence.remove(0); // drop oldest; bounded per-host memory
        }
        self.evidence.push(event);
    }

    fn distinct_sources(&self) -> Vec<LaneSource> {
        let mut sources = Vec::new();
        for e in &self.evidence {
            if !sources.contains(&e.source) {
                sources.push(e.source);
            }
        }
        sources
    }

    fn max_severity(&self) -> Severity {
        self.evidence
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(Severity::Low)
    }

    fn mean_confidence(&self) -> f32 {
        if self.evidence.is_empty() {
            return 0.0;
        }
        self.evidence.iter().map(|e| e.confidence).sum::<f32>() / self.evidence.len() as f32
    }
}

// ---------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// How long evidence for a host stays eligible to corroborate
    /// with newly arriving lane events.
    pub window: Duration,
    /// How often the sweep task checks for expired host state.
    pub sweep_interval: Duration,
    /// Inbound buffer depth shared by all three lanes (`try_send`
    /// fails past this — see module docs on backpressure).
    pub channel_capacity: usize,
    /// Cap on evidence retained per host, oldest dropped first.
    pub max_evidence_per_host: usize,
    /// Cap on total hosts tracked concurrently; oldest `last_seen`
    /// evicted first once exceeded. Bounds memory against an
    /// attacker fanning out across many source IPs.
    pub max_tracked_hosts: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(5),
            channel_capacity: 4096,
            max_evidence_per_host: 16,
            max_tracked_hosts: 100_000,
        }
    }
}

// ---------------------------------------------------------------------
// The correlation engine
// ---------------------------------------------------------------------

pub struct CorrelationEngine {
    rx: mpsc::Receiver<CorrelationEvent>,
    out_tx: mpsc::Sender<CorrelationVerdict>,
    state: HashMap<IpAddr, HostRecord>,
    config: CorrelationConfig,
    metrics: Arc<CorrelationMetrics>,
}

impl CorrelationEngine {
    /// Builds the engine plus the three typed senders lanes should
    /// hold onto. `out_tx` is supplied by the caller — typically the
    /// containment playbook's own inbound channel.
    pub fn new(
        config: CorrelationConfig,
        out_tx: mpsc::Sender<CorrelationVerdict>,
    ) -> (Self, XdpSender, ClamAvSender, SpectralSender, CorrelationMetricsHandle) {
        let (tx, rx) = mpsc::channel(config.channel_capacity);
        let metrics = Arc::new(CorrelationMetrics::default());

        let xdp = XdpSender {
            tx: tx.clone(),
            metrics: metrics.clone(),
        };
        let clamav = ClamAvSender {
            tx: tx.clone(),
            metrics: metrics.clone(),
        };
        let spectral = SpectralSender {
            tx,
            metrics: metrics.clone(),
        };

        let engine = Self {
            rx,
            out_tx,
            state: HashMap::new(),
            config,
            metrics: metrics.clone(),
        };

        (engine, xdp, clamav, spectral, CorrelationMetricsHandle(metrics))
    }

    pub async fn run(mut self) {
        let mut sweep = tokio::time::interval(self.config.sweep_interval);
        loop {
            tokio::select! {
                biased;
                _ = sweep.tick() => {
                    self.sweep_expired();
                }
                maybe_event = self.rx.recv() => {
                    match maybe_event {
                        Some(event) => self.handle_event(event),
                        None => {
                            tracing::info!("correlation engine: all lane senders dropped, shutting down");
                            return;
                        }
                    }
                }
            }
        }
    }

    fn handle_event(&mut self, event: CorrelationEvent) {
        use std::collections::hash_map::Entry;

        self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
        let host = event.host;
        let max_evidence = self.config.max_evidence_per_host;

        let already_finalized = match self.state.entry(host) {
            Entry::Vacant(v) => {
                v.insert(HostRecord::new(event));
                false
            }
            Entry::Occupied(mut o) => {
                let was_finalized = o.get().finalized;
                o.get_mut().push(event, max_evidence);
                was_finalized
            }
        };

        if !already_finalized {
            self.maybe_emit(host);
        }

        self.enforce_capacity();
    }

    fn maybe_emit(&mut self, host: IpAddr) {
        let Some(record) = self.state.get_mut(&host) else {
            return;
        };

        let sources = record.distinct_sources();
        let severity = record.max_severity();

        let reason = if sources.len() >= 2 {
            Some(CorrelationReason::MultiLaneCorroboration)
        } else if severity == Severity::Critical {
            Some(CorrelationReason::SingleLaneCritical)
        } else {
            None
        };

        let Some(reason) = reason else { return };

        let verdict = CorrelationVerdict {
            host,
            severity,
            confidence: record.mean_confidence(),
            sources,
            evidence: record.evidence.clone(),
            reason,
            first_seen: record.first_seen,
            decided_at: Instant::now(),
        };

        record.finalized = true;

        match self.out_tx.try_send(verdict) {
            Ok(()) => {
                self.metrics.verdicts_emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics.verdicts_dropped.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    %host,
                    "containment channel backpressured or closed: verdict dropped"
                );
            }
        }
    }

    fn sweep_expired(&mut self) {
        let now = Instant::now();
        let window = self.config.window;
        let before = self.state.len();
        self.state
            .retain(|_, record| now.duration_since(record.last_seen) < window);
        let evicted = before - self.state.len();
        if evicted > 0 {
            self.metrics
                .hosts_evicted_ttl
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
    }

    fn enforce_capacity(&mut self) {
        if self.state.len() <= self.config.max_tracked_hosts {
            return;
        }
        // Over cap: evict the single oldest-by-last_seen host. Called
        // only once state has already exceeded the cap, so the O(n)
        // scan is bounded by how far a burst overshoots the limit,
        // not by steady-state traffic.
        if let Some(oldest_host) = self
            .state
            .iter()
            .min_by_key(|(_, r)| r.last_seen)
            .map(|(host, _)| *host)
        {
            self.state.remove(&oldest_host);
            self.metrics
                .hosts_evicted_capacity
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
    }

    fn flow() -> FlowKey {
        FlowKey {
            src_ip: host(),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 5555,
            dst_port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[tokio::test]
    async fn single_sub_critical_lane_does_not_emit() {
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (engine, _xdp, _clamav, spectral, _metrics) =
            CorrelationEngine::new(CorrelationConfig::default(), out_tx);
        tokio::spawn(engine.run());

        spectral.submit(host(), flow(), 0.5, 0.1); // Medium severity, single lane

        let got = tokio::time::timeout(Duration::from_millis(100), out_rx.recv()).await;
        assert!(got.is_err(), "expected no verdict yet, insufficient evidence");
    }

    #[tokio::test]
    async fn two_lanes_corroborate_and_emit() {
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (engine, xdp, clamav, _spectral, metrics) =
            CorrelationEngine::new(CorrelationConfig::default(), out_tx);
        tokio::spawn(engine.run());

        xdp.submit(host(), flow(), "syn flood", false);
        clamav.submit(host(), "invoice.exe", "Win.Trojan.Generic", true);

        let verdict = tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .expect("verdict should arrive")
            .expect("channel open");

        assert_eq!(verdict.host, host());
        assert_eq!(verdict.reason, CorrelationReason::MultiLaneCorroboration);
        assert_eq!(verdict.sources.len(), 2);
        assert!(verdict.sources.contains(&LaneSource::Xdp));
        assert!(verdict.sources.contains(&LaneSource::ClamAv));

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(metrics.snapshot().verdicts_emitted, 1);
    }

    #[tokio::test]
    async fn single_critical_lane_emits_immediately() {
        let (out_tx, mut out_rx) = mpsc::channel(8);
        let (engine, xdp, _clamav, _spectral, _metrics) =
            CorrelationEngine::new(CorrelationConfig::default(), out_tx);
        tokio::spawn(engine.run());

        // human_approved: true -> Critical severity on its own.
        xdp.submit(host(), flow(), "confirmed C2 beacon", true);

        let verdict = tokio::time::timeout(Duration::from_millis(200), out_rx.recv())
            .await
            .expect("verdict should arrive")
            .expect("channel open");

        assert_eq!(verdict.reason, CorrelationReason::SingleLaneCritical);
        assert_eq!(verdict.severity, Severity::Critical);
        assert_eq!(verdict.sources, vec![LaneSource::Xdp]);
    }

    #[tokio::test]
    async fn stale_host_state_is_swept_on_ttl() {
        let (out_tx, _out_rx) = mpsc::channel(8);
        let config = CorrelationConfig {
            window: Duration::from_millis(50),
            sweep_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let (engine, _xdp, clamav, _spectral, metrics) = CorrelationEngine::new(config, out_tx);
        tokio::spawn(engine.run());

        clamav.submit(host(), "doc.pdf", "Heuristic.Suspicious", false);
        tokio::time::sleep(Duration::from_millis(150)).await;

        let snap = metrics.snapshot();
        assert!(snap.hosts_evicted_ttl >= 1, "expected TTL eviction to have run");
    }

    #[tokio::test]
    async fn capacity_eviction_bounds_tracked_hosts() {
        let (out_tx, _out_rx) = mpsc::channel(1024);
        let config = CorrelationConfig {
            max_tracked_hosts: 3,
            window: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let (engine, _xdp, clamav, _spectral, metrics) = CorrelationEngine::new(config, out_tx);
        tokio::spawn(engine.run());

        for i in 0..10u8 {
            let h = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            clamav.submit(h, "f", "sig", false);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let snap = metrics.snapshot();
        assert!(
            snap.hosts_evicted_capacity >= 6,
            "expected capacity eviction to keep tracked hosts near the cap, got {snap:?}"
        );
    }
}
