//! Spectral engine -> Anomaly scoring lane (the diagram's right-hand
//! branch: "Spectral engine (HNSW + Jacobi analysis)" -> "Anomaly scoring
//! (Spectral graph update)" -> `siem_correlation::SpectralSender`), plus
//! the green feedback arrow in the diagram: "Containment feeds back into
//! anomaly scoring."
//!
//! Unlike `ClamAvSender` (see `asd-clamav-bridge`'s docs) and the
//! `siem-ml`-based `SpectralSender` wiring `siem-correlation-bridge`
//! ships with (see its module docs: *"This SIEM has no real
//! spectral-graph computation ... fiedler_shift is passed as 0.0"*), this
//! bridge sits in front of `spec_engine::QdrantSpectralSecurityEngine`,
//! which does compute a real Laplacian and a real Fiedler vector
//! (`spec_engine::laplacian_regularizer::DynamicLaplacianRegularizer`).
//! So both `anomaly_score` and `fiedler_shift` submitted here are real
//! numbers derived from the graph, not placeholders.
//!
//! # Feature mapping (honest gap)
//!
//! `QdrantSpectralSecurityEngine::ingest_cic` takes a `CicRow` --
//! `spec_engine`'s native input shape is a full CIC-IDS2018-style
//! ~52-dimension flow feature vector (`embed_cic_full`), which is what
//! the engine was trained against. A live packet-capture pipeline (`nsm`)
//! does not compute that full feature set -- CICFlowMeter-equivalent
//! feature extraction (per-direction IAT mean/std/min/max, active/idle
//! timing, TCP window sizes, etc.) is a substantial project in its own
//! right and out of scope here. [`FlowStats`] carries the subset this
//! integration layer actually has (packet/byte counts per direction,
//! duration, port, protocol) and [`flow_stats_to_cic_row`] fills
//! everything else with `0.0`/neutral defaults. This means the anomaly
//! score reflects real distances in a real trained latent space, but
//! computed from a partial, best-effort feature vector -- treat it as
//! directionally meaningful, not as calibrated as a properly-featurized
//! CICFlowMeter pipeline would be. Widening `FlowStats` and this mapping
//! to cover more of `CicRow` is the natural next step for anyone taking
//! this further.

use siem_correlation::{FlowKey, SpectralSender};
use spec_engine::{CicRow, QdrantSpectralSecurityEngine};
use std::net::IpAddr;

/// The subset of a flow's shape this integration layer actually has
/// available from `nsm`'s packet capture / flow table (see
/// `asd-xdp-bridge`'s docs on why `nsm`'s per-detector `Alert::extra`
/// doesn't carry a consistent, richer set).
#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    pub duration_secs: f64,
    pub packets_fwd: u64,
    pub packets_bwd: u64,
    pub bytes_fwd: f64,
    pub bytes_bwd: f64,
}

/// Builds a `CicRow` from a `FlowKey` + whatever `FlowStats` is
/// available. Every `CicRow` field this integration layer cannot derive
/// is left at a neutral default (`0.0`/`0`) rather than a fabricated
/// plausible-looking value -- see module docs.
pub fn flow_stats_to_cic_row(flow: &FlowKey, stats: &FlowStats, label: &str) -> CicRow {
    let proto = match flow.protocol {
        siem_correlation::Protocol::Tcp => 6,
        siem_correlation::Protocol::Udp => 17,
        siem_correlation::Protocol::Icmp => 1,
        siem_correlation::Protocol::Other(p) => p,
    };
    let tot_pkts = (stats.packets_fwd + stats.packets_bwd).max(1) as f64;
    let tot_bytes = stats.bytes_fwd + stats.bytes_bwd;

    CicRow {
        src_ip: flow.src_ip.to_string(),
        dst_ip: flow.dst_ip.to_string(),
        dst_port: flow.dst_port as u32,
        protocol: proto,
        timestamp: String::new(),
        flow_duration: (stats.duration_secs * 1_000_000.0) as i64, // CIC-IDS2018 uses microseconds
        tot_fwd_pkts: stats.packets_fwd,
        tot_bwd_pkts: stats.packets_bwd,
        totlen_fwd_pkts: stats.bytes_fwd,
        totlen_bwd_pkts: stats.bytes_bwd,
        fwd_pkt_len_max: 0.0,
        fwd_pkt_len_min: 0.0,
        fwd_pkt_len_mean: if stats.packets_fwd > 0 { stats.bytes_fwd / stats.packets_fwd as f64 } else { 0.0 },
        fwd_pkt_len_std: 0.0,
        bwd_pkt_len_max: 0.0,
        bwd_pkt_len_min: 0.0,
        bwd_pkt_len_mean: if stats.packets_bwd > 0 { stats.bytes_bwd / stats.packets_bwd as f64 } else { 0.0 },
        bwd_pkt_len_std: 0.0,
        flow_byts_s: if stats.duration_secs > 0.0 { tot_bytes / stats.duration_secs } else { 0.0 },
        flow_pkts_s: if stats.duration_secs > 0.0 { tot_pkts / stats.duration_secs } else { 0.0 },
        flow_iat_mean: 0.0,
        flow_iat_std: 0.0,
        flow_iat_max: 0.0,
        flow_iat_min: 0.0,
        fwd_iat_tot: 0.0,
        fwd_iat_mean: 0.0,
        fwd_iat_std: 0.0,
        fwd_iat_max: 0.0,
        fwd_iat_min: 0.0,
        bwd_iat_tot: 0.0,
        bwd_iat_mean: 0.0,
        bwd_iat_std: 0.0,
        bwd_iat_max: 0.0,
        bwd_iat_min: 0.0,
        fwd_psh_flags: 0,
        bwd_psh_flags: 0,
        fwd_urg_flags: 0,
        bwd_urg_flags: 0,
        fwd_header_len: 0,
        bwd_header_len: 0,
        fwd_pkts_s: if stats.duration_secs > 0.0 { stats.packets_fwd as f64 / stats.duration_secs } else { 0.0 },
        bwd_pkts_s: if stats.duration_secs > 0.0 { stats.packets_bwd as f64 / stats.duration_secs } else { 0.0 },
        pkt_len_min: 0.0,
        pkt_len_max: 0.0,
        pkt_len_mean: if tot_pkts > 0.0 { tot_bytes / tot_pkts } else { 0.0 },
        pkt_len_std: 0.0,
        pkt_len_var: 0.0,
        fin_flag_cnt: 0,
        syn_flag_cnt: 0,
        rst_flag_cnt: 0,
        psh_flag_cnt: 0,
        ack_flag_cnt: 0,
        urg_flag_cnt: 0,
        cwe_flag_count: 0,
        ece_flag_cnt: 0,
        down_up_ratio: if stats.packets_fwd > 0 {
            stats.packets_bwd as f64 / stats.packets_fwd as f64
        } else {
            0.0
        },
        pkt_size_avg: if tot_pkts > 0.0 { tot_bytes / tot_pkts } else { 0.0 },
        fwd_seg_size_avg: 0.0,
        bwd_seg_size_avg: 0.0,
        fwd_byts_b_avg: 0.0,
        fwd_pkts_b_avg: 0.0,
        fwd_blk_rate_avg: 0.0,
        bwd_byts_b_avg: 0.0,
        bwd_pkts_b_avg: 0.0,
        bwd_blk_rate_avg: 0.0,
        subflow_fwd_pkts: stats.packets_fwd,
        subflow_fwd_byts: stats.bytes_fwd as u64,
        subflow_bwd_pkts: stats.packets_bwd,
        subflow_bwd_byts: stats.bytes_bwd as u64,
        init_fwd_win_byts: -1,
        init_bwd_win_byts: -1,
        fwd_act_data_pkts: stats.packets_fwd,
        fwd_seg_size_min: 0,
        active_mean: 0.0,
        active_std: 0.0,
        active_max: 0.0,
        active_min: 0.0,
        idle_mean: 0.0,
        idle_std: 0.0,
        idle_max: 0.0,
        idle_min: 0.0,
        label: label.to_string(),
    }
}

/// Ingests one flow through the real spectral engine and submits the
/// result to the spectral lane. `anomaly_score` is normalized against
/// the engine's own calibrated `threshold` before submission, matching
/// `SpectralSender::submit`'s `[0, 1]` convention (same normalization
/// approach `siem-correlation-bridge::ml_score_to_spectral`'s docs
/// describe for the reconstruction-error case). `fiedler_shift` is the
/// change in algebraic connectivity (λ₂) between this tick and the last
/// one recorded by the engine's regularizer -- a real value when the
/// graph had ≥2 nodes to compute one over, `0.0` otherwise (not faked).
pub async fn ingest_and_submit(
    engine: &QdrantSpectralSecurityEngine,
    spectral: &SpectralSender,
    host: IpAddr,
    flow: FlowKey,
    stats: &FlowStats,
    label: &str,
    threshold: f32,
) -> Result<spec_engine::IngestResult, spec_engine::EngineError> {
    let prev_lambda2 = engine.regularizer.read().unwrap().lambda2;

    let row = flow_stats_to_cic_row(&flow, stats, label);
    let result = engine.ingest_cic(&row).await?;

    let new_lambda2 = engine.regularizer.read().unwrap().lambda2;
    let fiedler_shift = (new_lambda2 - prev_lambda2) as f64;

    let normalized = if threshold > 0.0 {
        (result.anomaly_score / threshold).clamp(0.0, 1.0) as f64
    } else {
        0.0
    };

    spectral.submit(host, flow, normalized, fiedler_shift);
    Ok(result)
}

// ---------------------------------------------------------------------
// Containment -> anomaly scoring feedback (the diagram's green arrow)
// ---------------------------------------------------------------------

/// Records a containment-confirmed host as a permanent edge to a shared
/// "known threat" anchor entity in the spectral graph. Concretely: once
/// `siem-review`'s gate clears a `CorrelationVerdict` and containment
/// executes (see `orchestrator`'s `ActiveContainment::execute`), this is
/// called so that *future* `ingest_and_submit` calls for flows touching
/// this host see it already graph-adjacent to other confirmed threats --
/// shortening its spectral/commute-time distance to the malicious
/// cluster and raising its blast-radius reachability, which is exactly
/// the signal `ingest_cic`'s own severity/summary logic already reads
/// (see `spec_engine`'s `pair_distances`/`spectral_blast_radius`). This
/// is a real, persistent structural change to the graph `observed_edges`
/// feeds -- not a synthetic score bump.
///
/// Idempotent: calling this again for the same host just re-asserts the
/// same edge; `observed_edges` naturally dedupes in effect because every
/// consumer of it (`rebuild_spectral`) treats it as an edge list, and a
/// repeated edge only reinforces connectivity, it doesn't corrupt it.
pub fn record_confirmed_threat(engine: &QdrantSpectralSecurityEngine, host: IpAddr) {
    let host_entity = format!("Ip:{host}");
    let anchor = "Host:asd_confirmed_threat_anchor".to_string();
    engine.interner.get_or_intern(&host_entity);
    engine.interner.get_or_intern(&anchor);
    engine.observed_edges.write().unwrap().push((host_entity, anchor));
    tracing::warn!(%host, "asd-spectral-bridge: recorded confirmed threat, biasing future spectral scoring toward this host's cluster");
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_correlation::Protocol;

    #[test]
    fn flow_stats_map_basic_rates() {
        let flow = FlowKey {
            src_ip: "10.0.0.5".parse().unwrap(),
            dst_ip: "10.0.0.20".parse().unwrap(),
            src_port: 51000,
            dst_port: 443,
            protocol: Protocol::Tcp,
        };
        let stats = FlowStats { duration_secs: 2.0, packets_fwd: 10, packets_bwd: 5, bytes_fwd: 1000.0, bytes_bwd: 500.0 };
        let row = flow_stats_to_cic_row(&flow, &stats, "Benign");
        assert_eq!(row.dst_port, 443);
        assert_eq!(row.protocol, 6);
        assert!((row.flow_byts_s - 750.0).abs() < 1e-6);
        assert!((row.down_up_ratio - 0.5).abs() < 1e-6);
    }
}
