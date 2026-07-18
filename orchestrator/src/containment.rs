//! The containment playbook (diagram box: "Containment playbook --
//! Isolate host, block IP"). Implements `siem_response::ResponseAction`,
//! so it's what actually runs once a `CorrelationVerdict` clears
//! `siem-review`'s human-review gate and `ResponsePolicy`'s own guards
//! (severity floor / allowlist / rate limit) -- see
//! `ReviewGatedResponse::handle_flow_prediction` in
//! `components/active-siem/crates/siem-review`.
//!
//! Fires three things per confirmed host, matching the diagram exactly:
//!
//! 1. **XDP enforcement, confirmed.** Issues `BLOCK` over `nsm`'s control
//!    socket (`asd_xdp_bridge::NsmControlClient`) -- the "human-approved
//!    block" the diagram's XDP enforcement box describes; a corroborated,
//!    review-gate-cleared verdict *is* that approval.
//! 2. **Rule sync feedback loop** (blue dashed arrow, XDP enforcement ->
//!    firewall). Pushes the full confirmed-host set to rustwall's
//!    perimeter policy via `asd_firewall_sync::sync_confirmed_hosts`.
//! 3. **Containment -> anomaly-scoring feedback loop** (green dashed
//!    arrow). Records the confirmed host into the spectral graph via
//!    `asd_spectral_bridge::record_confirmed_threat`, if a spectral
//!    engine handle was configured.

use asd_firewall_sync::FirewallSyncTarget;
use asd_xdp_bridge::NsmControlClient;
use siem_core::Alert;
use siem_response::ResponseAction;
use spec_engine::QdrantSpectralSecurityEngine;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct ActiveContainment {
    pub nsm_control: NsmControlClient,
    pub xdp_block_ttl_secs: u64,
    pub firewall_target: FirewallSyncTarget,
    pub spectral_engine: Option<Arc<QdrantSpectralSecurityEngine>>,
    confirmed_hosts: Mutex<HashSet<IpAddr>>,
}

impl ActiveContainment {
    pub fn new(
        nsm_control: NsmControlClient,
        xdp_block_ttl_secs: u64,
        firewall_target: FirewallSyncTarget,
        spectral_engine: Option<Arc<QdrantSpectralSecurityEngine>>,
    ) -> Self {
        Self {
            nsm_control,
            xdp_block_ttl_secs,
            firewall_target,
            spectral_engine,
            confirmed_hosts: Mutex::new(HashSet::new()),
        }
    }
}

impl ResponseAction for ActiveContainment {
    fn execute(&mut self, alert: &Alert, target_ip: &str) -> bool {
        let host: IpAddr = match target_ip.parse() {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(target_ip, error = %e, "containment: target is not a valid IP, cannot act");
                return false;
            }
        };

        // 1. XDP enforcement -- confirmed block.
        let xdp_ok = match self.nsm_control.block(host, self.xdp_block_ttl_secs) {
            Ok(response) => {
                tracing::warn!(%host, %response, "containment: nsm BLOCK issued (confirmed)");
                true
            }
            Err(e) => {
                tracing::error!(%host, error = %e, "containment: nsm BLOCK failed (is nsm running with --xdp-control-socket?)");
                false
            }
        };

        // 2. Rule sync feedback loop -> perimeter firewall.
        let host_list: Vec<IpAddr> = {
            let mut hosts = self.confirmed_hosts.lock().expect("confirmed_hosts mutex poisoned");
            hosts.insert(host);
            hosts.iter().copied().collect()
        };
        let fw_ok = match asd_firewall_sync::sync_confirmed_hosts(&self.firewall_target, &host_list) {
            Ok(()) => {
                tracing::warn!(%host, "containment: rustwall coarse upstream rule synced");
                true
            }
            Err(e) => {
                tracing::error!(%host, error = %e, "containment: rustwall rule sync failed");
                false
            }
        };

        // 3. Containment -> anomaly-scoring feedback loop.
        if let Some(engine) = &self.spectral_engine {
            asd_spectral_bridge::record_confirmed_threat(engine, host);
        }

        tracing::warn!(%host, alert = %alert.title, severity = ?alert.severity, "containment executed: host isolated");
        xdp_ok || fw_ok
    }

    fn name(&self) -> &str {
        "active-spectral-defense/containment"
    }
}
