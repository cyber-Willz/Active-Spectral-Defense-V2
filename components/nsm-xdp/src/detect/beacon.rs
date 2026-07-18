//! C2 beacon detector.
//!
//! Malware call-home traffic tends to reconnect to the same
//! destination at a near-constant interval (jitter added by the
//! implant is usually small relative to the base interval). We track
//! inter-arrival times of new connections per (src, dst) pair and flag
//! low coefficient-of-variation patterns once enough samples exist.

use crate::alert::{Alert, Severity};
use crate::packet::{is_syn_only, PacketMeta};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

const MIN_SAMPLES: usize = 6;
const MAX_HISTORY: usize = 20;
/// Coefficient of variation (stddev / mean) below this is "too regular
/// to be human/browser-driven traffic".
const CV_THRESHOLD: f64 = 0.15;

struct History {
    last_conn: Option<Instant>,
    intervals: Vec<f64>, // seconds
}

pub struct BeaconDetector {
    per_pair: DashMap<(IpAddr, IpAddr, u16), History>,
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self { per_pair: DashMap::new() }
    }

    pub fn observe(&self, pkt: &PacketMeta) -> Option<Alert> {
        // Only count new outbound connection attempts (SYNs) as "beacons".
        if !is_syn_only(pkt.tcp_flags) {
            return None;
        }
        let key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port);
        let now = Instant::now();
        let mut h = self.per_pair.entry(key).or_insert_with(|| History { last_conn: None, intervals: Vec::new() });

        if let Some(last) = h.last_conn {
            let dt = now.duration_since(last).as_secs_f64();
            if dt > 0.5 {
                // ignore retransmit-ish SYNs
                h.intervals.push(dt);
                if h.intervals.len() > MAX_HISTORY {
                    h.intervals.remove(0);
                }
            }
        }
        h.last_conn = Some(now);

        if h.intervals.len() < MIN_SAMPLES {
            return None;
        }

        let mean: f64 = h.intervals.iter().sum::<f64>() / h.intervals.len() as f64;
        if mean < 0.3 {
            return None; // too fast to be a periodic beacon, likely a real burst
        }
        let variance: f64 =
            h.intervals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / h.intervals.len() as f64;
        let cv = variance.sqrt() / mean;
        let sample_count = h.intervals.len();
        drop(h);

        if cv <= CV_THRESHOLD {
            return Some(Alert::new(
                Severity::Medium,
                "beacon",
                format!(
                    "{} -> {}:{} reconnects every ~{:.1}s with low jitter (cv={:.3}) across {} samples: possible C2 beacon",
                    pkt.src_ip, pkt.dst_ip, pkt.dst_port, mean, cv, sample_count
                ),
                Some(pkt.src_ip),
                Some(pkt.dst_ip),
                serde_json::json!({ "mean_interval_s": mean, "cv": cv, "samples": sample_count }),
            ));
        }
        None
    }
}
