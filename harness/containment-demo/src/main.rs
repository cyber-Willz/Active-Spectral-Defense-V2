// One-off harness proving the real containment -> firewall-sync leg
// against the actually-running rustwall process (PID read from argv),
// exactly what orchestrator::containment::ActiveContainment does once a
// verdict clears the review gate. Not part of the shipped integration
// layer -- just exercises asd-firewall-sync's real code path live.
use asd_firewall_sync::FirewallSyncTarget;
use std::net::IpAddr;

fn main() -> anyhow::Result<()> {
    let pid: u32 = std::env::args().nth(1).expect("pid arg").parse()?;
    let target = FirewallSyncTarget {
        config_path: "/etc/rustwall/asd-managed.toml".into(),
        pid,
    };
    let confirmed: Vec<IpAddr> = vec!["198.51.100.7".parse()?];
    asd_firewall_sync::sync_confirmed_hosts(&target, &confirmed)?;
    println!("synced confirmed host(s) {:?} into rustwall config, SIGHUP sent to pid {pid}", confirmed);
    println!("current confirmed hosts: {:?}", asd_firewall_sync::current_confirmed_hosts(&target.config_path)?);
    Ok(())
}
