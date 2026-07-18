//! Detects vertical/horizontal port scans: a source touching an
//! unusual number of distinct destination ports (or hosts) within a
//! short window. This mirrors the classic Snort/Suricata `sfPortscan`
//! heuristic, with two important refinements over a naive version:
//!
//! 1. Only TCP SYN-only segments count as a "touch". A raw packet
//!    counter is dominated by ordinary return traffic -- a single
//!    QUIC/HTTP3 CDN server alone can touch 30+ of your local UDP
//!    ports in a few seconds, and that has nothing to do with
//!    scanning. Counting only new-connection attempts (SYN, no ACK)
//!    is what every real port-scan tool (nmap, masscan, etc.)
//!    actually looks like on the wire.
//! 2. Direction matters. Someone else's SYNs arriving at *your* IP
//!    are a very different signal from *your own machine* opening a
//!    burst of outbound connections (which is just... browsing --
//!    one webpage can touch 15+ distinct CDN/ad/tracker hosts in
//!    under a second). We classify by comparing against the set of
//!    local interface addresses and apply separate, much looser
//!    thresholds to the outbound case.

use crate::alert::{Alert, Severity};
use crate::packet::{is_syn_only, L4Proto, PacketMeta};
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Window {
    started: Instant,
    ports: HashSet<u16>,
    hosts: HashSet<IpAddr>,
}

pub struct Thresholds {
    pub port_threshold: usize,
    pub host_threshold: usize,
}

pub struct PortScanDetector {
    local_ips: Arc<HashSet<IpAddr>>,
    per_src: DashMap<IpAddr, Window>,
    window: Duration,
    inbound: Thresholds,
    outbound: Thresholds,
}

impl PortScanDetector {
    pub fn new(local_ips: Arc<HashSet<IpAddr>>, window: Duration, inbound: Thresholds, outbound: Thresholds) -> Self {
        Self { local_ips, per_src: DashMap::new(), window, inbound, outbound }
    }

    pub fn observe(&self, pkt: &PacketMeta) -> Option<Alert> {
        // Only new-connection attempts are scan signal; established
        // traffic (ACKs, data, SYN-ACK replies) is not.
        if pkt.proto != L4Proto::Tcp || !is_syn_only(pkt.tcp_flags) || pkt.dst_port == 0 {
            return None;
        }

        let dst_is_local = self.local_ips.contains(&pkt.dst_ip);
        let src_is_local = self.local_ips.contains(&pkt.src_ip);
        // Neither end is us (e.g. sniffing other hosts' traffic on a
        // shared segment) -- not enough context to say who's scanning whom.
        if !dst_is_local && !src_is_local {
            return None;
        }

        // Inbound: a remote host is sending us SYNs -- track by the
        // remote (attacker) address. Outbound: we're the one sending
        // SYNs out -- track by our own local address so all of our
        // outbound activity accumulates in one window regardless of
        // which local IP a given interface used.
        let (tracking_key, thresholds, direction) = if dst_is_local {
            (pkt.src_ip, &self.inbound, "inbound")
        } else {
            (pkt.src_ip, &self.outbound, "outbound") // src_ip == our own address here
        };

        let now = Instant::now();
        let mut entry = self.per_src.entry(tracking_key).or_insert_with(|| Window {
            started: now,
            ports: HashSet::new(),
            hosts: HashSet::new(),
        });

        if now.duration_since(entry.started) > self.window {
            entry.started = now;
            entry.ports.clear();
            entry.hosts.clear();
        }

        entry.ports.insert(pkt.dst_port);
        entry.hosts.insert(pkt.dst_ip);
        let (n_ports, n_hosts) = (entry.ports.len(), entry.hosts.len());
        drop(entry);

        if n_ports >= thresholds.port_threshold {
            // Critical (not just High) once a single source is
            // *dramatically* past the normal alerting threshold --
            // this is what --xdp-auto-block keys off. 5x is a
            // judgment call (20 ports -> High at the default
            // threshold, 100+ -> Critical); tune if that's too
            // aggressive/lax for your traffic. Before this, portscan
            // never escalated past High, and synflood's Critical
            // alerts never carry a single attributable src_ip (it's
            // a many-sources detector) -- so auto-block had no
            // detector that could ever satisfy it. See
            // scripts/test-xdp-integration.py.
            let severity = if n_ports >= thresholds.port_threshold.saturating_mul(5) {
                Severity::Critical
            } else {
                Severity::High
            };
            return Some(Alert::new(
                severity,
                "portscan",
                format!(
                    "{} touched {} distinct ports within {:?} ({direction} vertical scan)",
                    tracking_key, n_ports, self.window
                ),
                Some(pkt.src_ip),
                if dst_is_local { Some(pkt.dst_ip) } else { None },
                serde_json::json!({ "distinct_ports": n_ports, "direction": direction }),
            ));
        }
        if n_hosts >= thresholds.host_threshold {
            let severity = if direction == "inbound" { Severity::Medium } else { Severity::Low };
            return Some(Alert::new(
                severity,
                "portscan",
                format!(
                    "{} touched {} distinct hosts within {:?} ({direction} horizontal scan)",
                    tracking_key, n_hosts, self.window
                ),
                Some(pkt.src_ip),
                None,
                serde_json::json!({ "distinct_hosts": n_hosts, "direction": direction }),
            ));
        }
        None
    }
}
