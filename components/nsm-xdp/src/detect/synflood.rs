//! Detects SYN floods by counting SYN-only segments aimed at a single
//! destination IP:port within a sliding window and comparing against
//! the rate of completed (SYN+ACK observed indirectly via flow table)
//! handshakes. Kept simple: pure SYN-rate thresholding per destination.

use crate::alert::{Alert, Severity};
use crate::packet::{is_syn_only, PacketMeta};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct Counter {
    started: Instant,
    syns: u32,
    sources: std::collections::HashSet<IpAddr>,
}

pub struct SynFloodDetector {
    per_dst: DashMap<(IpAddr, u16), Counter>,
    window: Duration,
    syn_threshold: u32,
}

impl SynFloodDetector {
    pub fn new(window: Duration, syn_threshold: u32) -> Self {
        Self { per_dst: DashMap::new(), window, syn_threshold }
    }

    pub fn observe(&self, pkt: &PacketMeta) -> Option<Alert> {
        if !is_syn_only(pkt.tcp_flags) {
            return None;
        }
        let key = (pkt.dst_ip, pkt.dst_port);
        let now = Instant::now();
        let mut c = self.per_dst.entry(key).or_insert_with(|| Counter {
            started: now,
            syns: 0,
            sources: std::collections::HashSet::new(),
        });

        if now.duration_since(c.started) > self.window {
            c.started = now;
            c.syns = 0;
            c.sources.clear();
        }
        c.syns += 1;
        c.sources.insert(pkt.src_ip);
        let (syns, n_src) = (c.syns, c.sources.len());
        drop(c);

        if syns >= self.syn_threshold {
            let severity = if n_src > 20 { Severity::Critical } else { Severity::High };
            return Some(Alert::new(
                severity,
                "synflood",
                format!(
                    "{}:{} received {} SYNs from {} sources within {:?}",
                    pkt.dst_ip, pkt.dst_port, syns, n_src, self.window
                ),
                None,
                Some(pkt.dst_ip),
                serde_json::json!({ "syn_count": syns, "distinct_sources": n_src }),
            ));
        }
        None
    }
}
