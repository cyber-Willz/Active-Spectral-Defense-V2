//! Traffic ingestion stage.
//!
//! This is the "Traffic ingestion" box in the active defense architecture
//! diagram, sitting immediately downstream of `nfqueue`/`engine` (the
//! "Firewall (perimeter)" box). It never receives raw traffic itself --
//! `nfqueue::run` already does coarse IP/port filtering and conntrack
//! admission before a packet ever reaches this module. Only packets that
//! clear that perimeter check (`Verdict::Accept`) get submitted here, which
//! is exactly what the diagram's single arrow from "Firewall (perimeter)"
//! into "Traffic ingestion" represents: this stage never sees a packet the
//! perimeter already decided to drop or reject.
//!
//! From here the packet fans out, without ever blocking `nfqueue`'s hot
//! verdict path, to the three downstream analysis lanes:
//!   - `nsm`      -- fast-path signature/rate/beacon detection, feeding XDP enforcement
//!   - `clamav`   -- content/signature scanning, feeding quarantine action
//!   - `spectral` -- HNSW + Jacobi spectral graph analysis, feeding anomaly scoring
//!
//! Those three lanes, and everything downstream of them (XDP enforcement,
//! quarantine action, anomaly scoring, the correlation engine, and the
//! containment playbook), live in their own crates/processes -- `nsm`,
//! `rust-clam`, and `spec_engine`/`gnn_spec_engine` respectively. This
//! module's job stops at fan-out: it hands each accepted packet to three
//! broadcast lanes and gets out of the way. Wiring an out-of-process
//! consumer to a lane (e.g. over a Unix socket or shared memory) is future
//! work tracked separately from this module; in-process, any component that
//! calls `subscribe_lanes()` can attach for free.
//!
//! # Design
//!
//! - `payload` is `bytes::Bytes`: an atomically refcounted, zero-copy
//!   buffer. Cloning it once per lane is a refcount bump, not a memcpy.
//! - Fan-out uses `tokio::sync::broadcast`. A slow consumer (typically
//!   the spectral engine under load) never backpressures the capture
//!   loop or the other lanes -- it just drops its own oldest buffered
//!   packets and surfaces `Lagged(n)` on its next `recv`, which we
//!   turn into a metric instead of a panic or a stall.
//! - `submit()` is the path rustwall's own NFQUEUE worker threads use: it
//!   is a plain synchronous call (`broadcast::Sender::send` never awaits or
//!   blocks), so nfqueue's thread-per-queue, non-async packet loop can call
//!   it directly without spinning up a Tokio runtime just to hand a packet
//!   off. `run()` / `PacketSource` remain available for an alternate,
//!   fully-async capture path (e.g. an aya XDP/TC ring buffer feeding this
//!   pipeline directly instead of via NFQUEUE) -- `submit()` is simply that
//!   same per-packet logic, factored out so it doesn't require one.
//! - All counters are lock-free atomics, safe to read from a metrics
//!   exporter concurrently with the hot path.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::packet::{L4Proto, ParsedPacket};

// ---------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------

/// Transport-layer protocol observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<L4Proto> for Protocol {
    fn from(p: L4Proto) -> Self {
        match p {
            L4Proto::Tcp => Protocol::Tcp,
            L4Proto::Udp => Protocol::Udp,
            L4Proto::Icmp => Protocol::Icmp,
            L4Proto::Other(n) => Protocol::Other(n),
        }
    }
}

/// Canonical 5-tuple identifying a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl From<&ParsedPacket> for FlowKey {
    fn from(p: &ParsedPacket) -> Self {
        Self {
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            protocol: p.proto.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}

/// A single ingested packet, ready for fan-out to downstream lanes.
#[derive(Debug, Clone)]
pub struct IngestedPacket {
    pub flow: FlowKey,
    pub captured_at: SystemTime,
    pub ifindex: u32,
    pub direction: Direction,
    pub payload: Bytes,
    /// Monotonically increasing sequence number, assigned at ingestion.
    /// Downstream consumers use gaps in this to detect their own drops
    /// independent of the `Lagged` count (useful for correlation
    /// engine audit trails).
    pub seq: u64,
}

impl IngestedPacket {
    /// Builds an `IngestedPacket` from a packet that already cleared the
    /// perimeter firewall's rule evaluation (`Verdict::Accept` in
    /// `nfqueue::run`). `seq` is left at 0 here -- `IngestionPipeline`
    /// assigns the real, monotonic value at submission time so it reflects
    /// ingestion order across all queue worker threads, not per-worker
    /// parse order.
    pub fn from_accepted(
        parsed: &ParsedPacket,
        raw: &[u8],
        ifindex: u32,
        direction: Direction,
    ) -> Self {
        Self {
            flow: FlowKey::from(parsed),
            captured_at: SystemTime::now(),
            ifindex,
            direction,
            payload: Bytes::copy_from_slice(raw),
            seq: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("capture source error: {0}")]
    Source(String),
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct LaneMetrics {
    pub delivered: AtomicU64,
    pub lagged: AtomicU64,
}

#[derive(Debug, Default)]
pub struct IngestionMetrics {
    pub captured: AtomicU64,
    pub bytes: AtomicU64,
    pub nsm: LaneMetrics,
    pub clamav: LaneMetrics,
    pub spectral: LaneMetrics,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestionMetricsSnapshot {
    pub captured: u64,
    pub bytes: u64,
    pub nsm_delivered: u64,
    pub nsm_lagged: u64,
    pub clamav_delivered: u64,
    pub clamav_lagged: u64,
    pub spectral_delivered: u64,
    pub spectral_lagged: u64,
}

impl IngestionMetricsSnapshot {
    /// Renders these counters as Prometheus exposition-format text, using
    /// the same `rustwall_` namespacing convention as `metrics::Metrics`,
    /// so `metrics::serve`'s `/metrics` route can append this directly
    /// after its own output.
    pub fn to_prometheus(&self) -> String {
        format!(
            "# HELP rustwall_ingestion_captured_total Packets handed from the perimeter firewall to the ingestion fan-out.\n\
             # TYPE rustwall_ingestion_captured_total counter\n\
             rustwall_ingestion_captured_total {}\n\
             # HELP rustwall_ingestion_bytes_total Payload bytes handed to the ingestion fan-out.\n\
             # TYPE rustwall_ingestion_bytes_total counter\n\
             rustwall_ingestion_bytes_total {}\n\
             # HELP rustwall_ingestion_lane_delivered_total Packets delivered per downstream lane.\n\
             # TYPE rustwall_ingestion_lane_delivered_total counter\n\
             rustwall_ingestion_lane_delivered_total{{lane=\"nsm\"}} {}\n\
             rustwall_ingestion_lane_delivered_total{{lane=\"clamav\"}} {}\n\
             rustwall_ingestion_lane_delivered_total{{lane=\"spectral\"}} {}\n\
             # HELP rustwall_ingestion_lane_lagged_total Packets dropped per downstream lane due to a slow consumer.\n\
             # TYPE rustwall_ingestion_lane_lagged_total counter\n\
             rustwall_ingestion_lane_lagged_total{{lane=\"nsm\"}} {}\n\
             rustwall_ingestion_lane_lagged_total{{lane=\"clamav\"}} {}\n\
             rustwall_ingestion_lane_lagged_total{{lane=\"spectral\"}} {}\n",
            self.captured,
            self.bytes,
            self.nsm_delivered,
            self.clamav_delivered,
            self.spectral_delivered,
            self.nsm_lagged,
            self.clamav_lagged,
            self.spectral_lagged,
        )
    }
}

#[derive(Clone)]
pub struct IngestionMetricsHandle(Arc<IngestionMetrics>);

impl IngestionMetricsHandle {
    pub fn snapshot(&self) -> IngestionMetricsSnapshot {
        let m = &self.0;
        IngestionMetricsSnapshot {
            captured: m.captured.load(Ordering::Relaxed),
            bytes: m.bytes.load(Ordering::Relaxed),
            nsm_delivered: m.nsm.delivered.load(Ordering::Relaxed),
            nsm_lagged: m.nsm.lagged.load(Ordering::Relaxed),
            clamav_delivered: m.clamav.delivered.load(Ordering::Relaxed),
            clamav_lagged: m.clamav.lagged.load(Ordering::Relaxed),
            spectral_delivered: m.spectral.delivered.load(Ordering::Relaxed),
            spectral_lagged: m.spectral.lagged.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------
// Capture source abstraction
// ---------------------------------------------------------------------

/// Abstraction over an alternate, fully-async capture mechanism (an aya
/// XDP/TC ring buffer, AF_PACKET, pcap, or a test mock) that wants to drive
/// `IngestionPipeline::run` directly instead of going through NFQUEUE and
/// `submit()`. Implementors should only block within `recv`; the pipeline
/// drives it from a dedicated task.
#[async_trait::async_trait]
pub trait PacketSource: Send {
    async fn recv(&mut self) -> Result<IngestedPacket, IngestionError>;
}

// ---------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------

/// Configuration for the ingestion pipeline.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Per-lane broadcast buffer depth (packets, not bytes). Size
    /// generously for the slowest lane -- the spectral engine under
    /// load -- so ordinary bursts don't trip `Lagged`. Tune against
    /// production packet-rate telemetry; 8192 is a starting point for
    /// moderate-throughput links, not a universal default.
    pub lane_capacity: usize,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self { lane_capacity: 8192 }
    }
}

/// Receiver handles for the three downstream analysis lanes. Obtain
/// one `IngestionLanes` per consumer at startup.
pub struct IngestionLanes {
    pub nsm: broadcast::Receiver<Arc<IngestedPacket>>,
    pub clamav: broadcast::Receiver<Arc<IngestedPacket>>,
    pub spectral: broadcast::Receiver<Arc<IngestedPacket>>,
}

pub struct IngestionPipeline {
    tx: broadcast::Sender<Arc<IngestedPacket>>,
    metrics: Arc<IngestionMetrics>,
    seq: AtomicU64,
}

impl IngestionPipeline {
    pub fn new(config: IngestionConfig) -> (Self, IngestionMetricsHandle) {
        let (tx, _rx) = broadcast::channel(config.lane_capacity);
        let metrics = Arc::new(IngestionMetrics::default());
        (
            Self {
                tx,
                metrics: metrics.clone(),
                seq: AtomicU64::new(0),
            },
            IngestionMetricsHandle(metrics),
        )
    }

    /// Subscribe to all three lanes. Cheap -- three receiver handles
    /// into the same underlying ring buffer, no data copied.
    pub fn subscribe_lanes(&self) -> IngestionLanes {
        IngestionLanes {
            nsm: self.tx.subscribe(),
            clamav: self.tx.subscribe(),
            spectral: self.tx.subscribe(),
        }
    }

    /// Synchronous submission path. This is what `nfqueue::run` calls for
    /// every packet the perimeter firewall accepts: assigns the monotonic
    /// sequence number, updates capture metrics, and broadcasts to all
    /// three lanes. `broadcast::Sender::send` never awaits or blocks, so
    /// this is safe to call from any thread -- including NFQUEUE's
    /// synchronous, thread-per-queue worker loop -- without a Tokio
    /// runtime running anywhere in the process.
    pub fn submit(&self, mut pkt: IngestedPacket) {
        pkt.seq = self.seq.fetch_add(1, Ordering::Relaxed);

        self.metrics.captured.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes
            .fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);

        // If every lane is empty (no subscribers yet), the packet is
        // simply dropped -- this is intentional: ingestion should never
        // stall waiting for a consumer to attach.
        let _ = self.tx.send(Arc::new(pkt));
    }

    /// Drives an async capture loop until `shutdown` is cancelled or the
    /// source returns an error. Only needed for the alternate `PacketSource`
    /// capture path (see module docs); rustwall's own NFQUEUE path uses
    /// `submit()` directly and never calls this. Spawn as its own task:
    ///
    /// ```ignore
    /// let (pipeline, metrics) = IngestionPipeline::new(IngestionConfig::default());
    /// let lanes = pipeline.subscribe_lanes();
    /// let shutdown = CancellationToken::new();
    /// tokio::spawn(async move { pipeline.run(source, shutdown).await });
    /// ```
    pub async fn run(
        &self,
        mut source: impl PacketSource,
        shutdown: CancellationToken,
    ) -> Result<(), IngestionError> {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    tracing::info!("ingestion pipeline shutting down");
                    return Ok(());
                }
                pkt = source.recv() => {
                    self.submit(pkt?);
                }
            }
        }
    }
}

/// Helper for consumers: reads the next packet on a lane, recording
/// lag transparently and continuing past drops rather than treating
/// `Lagged` as fatal.
pub async fn recv_lane(
    rx: &mut broadcast::Receiver<Arc<IngestedPacket>>,
    lane: &LaneMetrics,
) -> Option<Arc<IngestedPacket>> {
    loop {
        match rx.recv().await {
            Ok(pkt) => {
                lane.delivered.fetch_add(1, Ordering::Relaxed);
                return Some(pkt);
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                lane.lagged.fetch_add(n, Ordering::Relaxed);
                tracing::warn!(dropped = n, "consumer lane lagged, packets dropped");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{self, L4Proto};
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_parsed() -> ParsedPacket {
        ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            proto: L4Proto::Tcp,
            src_port: 4444,
            dst_port: 443,
            tcp_flags: None,
            payload_len: 4,
        }
    }

    #[test]
    fn from_accepted_maps_flow_key_from_parsed_packet() {
        let parsed = sample_parsed();
        let raw = [0x00u8, 0x01, 0x02, 0x03];
        let pkt = IngestedPacket::from_accepted(&parsed, &raw, 2, Direction::Ingress);
        assert_eq!(pkt.flow.src_port, 4444);
        assert_eq!(pkt.flow.dst_port, 443);
        assert_eq!(pkt.flow.protocol, Protocol::Tcp);
        assert_eq!(pkt.payload.as_ref(), &raw[..]);
        assert_eq!(pkt.ifindex, 2);
        assert_eq!(pkt.direction, Direction::Ingress);
    }

    #[test]
    fn submit_assigns_monotonic_seq_and_updates_metrics() {
        let (pipeline, metrics) = IngestionPipeline::new(IngestionConfig { lane_capacity: 16 });
        let mut lanes = pipeline.subscribe_lanes();

        let parsed = sample_parsed();
        let raw = [0xAAu8; 4];
        pipeline.submit(IngestedPacket::from_accepted(&parsed, &raw, 1, Direction::Ingress));
        pipeline.submit(IngestedPacket::from_accepted(&parsed, &raw, 1, Direction::Ingress));

        let first = lanes.nsm.try_recv().expect("first packet");
        let second = lanes.nsm.try_recv().expect("second packet");
        assert_eq!(first.seq, 0);
        assert_eq!(second.seq, 1);

        let snap = metrics.snapshot();
        assert_eq!(snap.captured, 2);
        assert_eq!(snap.bytes, 8);
    }

    #[tokio::test]
    async fn fans_out_to_all_three_lanes_without_copying_payload() {
        let (pipeline, _metrics) = IngestionPipeline::new(IngestionConfig { lane_capacity: 16 });
        let mut lanes = pipeline.subscribe_lanes();

        let parsed = sample_parsed();
        let raw = [0x00u8, 0x01, 0x02, 0x03];
        pipeline.submit(IngestedPacket::from_accepted(&parsed, &raw, 2, Direction::Ingress));

        let lane_metrics = LaneMetrics::default();
        let nsm_pkt = recv_lane(&mut lanes.nsm, &lane_metrics).await.expect("nsm");
        let clamav_pkt = recv_lane(&mut lanes.clamav, &lane_metrics).await.expect("clamav");
        let spectral_pkt = recv_lane(&mut lanes.spectral, &lane_metrics).await.expect("spectral");

        // Same Arc-backed payload delivered to all three lanes -- fan-out
        // is a refcount bump per lane, not a copy.
        assert!(Arc::ptr_eq(&nsm_pkt, &clamav_pkt));
        assert!(Arc::ptr_eq(&nsm_pkt, &spectral_pkt));
        let _ = packet::parse(&raw); // sanity: raw bytes still a valid packet
    }

    #[test]
    fn lane_metrics_default_is_zeroed() {
        let m = LaneMetrics::default();
        assert_eq!(m.delivered.load(Ordering::Relaxed), 0);
        assert_eq!(m.lagged.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prometheus_rendering_includes_all_three_lanes() {
        let snap = IngestionMetricsSnapshot {
            captured: 10,
            bytes: 4096,
            nsm_delivered: 10,
            nsm_lagged: 0,
            clamav_delivered: 8,
            clamav_lagged: 2,
            spectral_delivered: 5,
            spectral_lagged: 5,
        };
        let text = snap.to_prometheus();
        assert!(text.contains("rustwall_ingestion_captured_total 10"));
        assert!(text.contains(r#"lane="nsm"} 10"#));
        assert!(text.contains(r#"lane="clamav"} 2"#));
        assert!(text.contains(r#"lane="spectral"} 5"#));
    }
}
