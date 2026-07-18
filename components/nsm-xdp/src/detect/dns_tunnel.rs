//! Heuristic DNS-tunneling / DNS-exfiltration detector.
//!
//! Real DNS tunneling tools (iodine, dnscat2, DNSExfiltrator, ...) tend
//! to produce queries that are (a) unusually long, (b) high in Shannon
//! entropy because they encode binary payloads in base32/base64-ish
//! alphabets, and (c) issued at a much higher rate per source than
//! normal resolver traffic. None of these alone is conclusive, so we
//! score and combine them.

use crate::alert::{Alert, Severity};
use crate::packet::{L4Proto, PacketMeta};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MIN_LABEL_LEN_FOR_ENTROPY: usize = 20;
const HIGH_ENTROPY_BITS_PER_BYTE: f64 = 4.0; // ~random base32/64 sits well above this

struct RateWindow {
    started: Instant,
    queries: u32,
    suspicious_labels: u32,
}

pub struct DnsTunnelDetector {
    per_src: DashMap<IpAddr, RateWindow>,
    window: Duration,
    query_rate_threshold: u32,
}

impl DnsTunnelDetector {
    pub fn new(window: Duration, query_rate_threshold: u32) -> Self {
        Self { per_src: DashMap::new(), window, query_rate_threshold }
    }

    /// Very small, dependency-free heuristic parse: looks for the
    /// question-name label(s) inside a UDP/53 payload without needing a
    /// full DNS message parser. Good enough to flag long encoded labels.
    fn longest_label_len(payload: &[u8]) -> usize {
        // Skip the 12-byte DNS header if present, then walk length-prefixed
        // labels defensively (bounds-checked, bails out on malformed input).
        if payload.len() < 13 {
            return 0;
        }
        let mut i = 12usize;
        let mut longest = 0usize;
        while i < payload.len() {
            let len = payload[i] as usize;
            if len == 0 || len & 0xC0 != 0 {
                break; // end of name or compression pointer
            }
            if i + 1 + len > payload.len() {
                break;
            }
            longest = longest.max(len);
            i += 1 + len;
        }
        longest
    }

    fn shannon_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let len = bytes.len() as f64;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn observe(&self, pkt: &PacketMeta) -> Option<Alert> {
        if pkt.proto != L4Proto::Udp || (pkt.dst_port != 53 && pkt.src_port != 53) {
            return None;
        }
        let label_len = Self::longest_label_len(&pkt.payload_head);
        let is_long = label_len >= MIN_LABEL_LEN_FOR_ENTROPY;
        let entropy = Self::shannon_entropy(&pkt.payload_head);
        let is_high_entropy = entropy >= HIGH_ENTROPY_BITS_PER_BYTE;

        let now = Instant::now();
        let mut w = self.per_src.entry(pkt.src_ip).or_insert_with(|| RateWindow {
            started: now,
            queries: 0,
            suspicious_labels: 0,
        });
        if now.duration_since(w.started) > self.window {
            w.started = now;
            w.queries = 0;
            w.suspicious_labels = 0;
        }
        w.queries += 1;
        if is_long && is_high_entropy {
            w.suspicious_labels += 1;
        }
        let (queries, suspicious) = (w.queries, w.suspicious_labels);
        drop(w);

        if suspicious >= 5 {
            return Some(Alert::new(
                Severity::High,
                "dns_tunnel",
                format!(
                    "{} sent {} high-entropy/long DNS labels within {:?} (possible tunneling)",
                    pkt.src_ip, suspicious, self.window
                ),
                Some(pkt.src_ip),
                Some(pkt.dst_ip),
                serde_json::json!({ "suspicious_labels": suspicious, "max_label_len": label_len, "entropy": entropy }),
            ));
        }
        if queries >= self.query_rate_threshold {
            return Some(Alert::new(
                Severity::Medium,
                "dns_tunnel",
                format!(
                    "{} issued {} DNS queries within {:?} (abnormal query rate)",
                    pkt.src_ip, queries, self.window
                ),
                Some(pkt.src_ip),
                Some(pkt.dst_ip),
                serde_json::json!({ "query_count": queries }),
            ));
        }
        None
    }
}
