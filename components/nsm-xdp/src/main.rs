mod alert;
mod capture;
mod detect;
mod flow;
mod packet;
mod sim;
#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp;

use anyhow::Result;
use clap::Parser;
use detect::DetectionEngine;
use flow::FlowTable;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// nsm -- a lightweight Network Security Monitor.
#[derive(Parser, Debug)]
#[command(name = "nsm", version, about = "Lightweight Network Security Monitor")]
struct Cli {
    /// Network interface to capture on: name (Linux/macOS, e.g. eth0),
    /// numeric index, or a substring of the description (useful on
    /// Windows where device names are opaque GUIDs). Requires
    /// root/CAP_NET_RAW on Unix or an elevated terminal + Npcap on Windows.
    #[arg(short, long)]
    interface: Option<String>,

    /// List available network interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,

    /// Run with synthetic traffic instead of a live capture -- no root needed.
    #[arg(long)]
    simulate: bool,

    /// Idle flow eviction timeout in seconds.
    #[arg(long, default_value_t = 300)]
    flow_idle_secs: u64,

    /// Capture via the XDP fast path instead of pnet/AF_PACKET.
    /// Linux only; requires root/CAP_BPF+CAP_NET_ADMIN and a compiled
    /// nsm-ebpf object (see `scripts/build-ebpf.sh` / README).
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long)]
    xdp: bool,

    /// Path to the compiled nsm-ebpf object. Defaults to the path
    /// `scripts/build-ebpf.sh` produces.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, default_value = "xdp/nsm-ebpf/target/bpfel-unknown-none/release/nsm-ebpf")]
    xdp_obj: std::path::PathBuf,

    /// XDP attach mode. `native` is fastest but needs driver support;
    /// fall back to `skb` if attaching fails.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, value_enum, default_value = "native")]
    xdp_mode: xdp::XdpMode,

    /// When set, source IPv4 addresses behind a Critical alert (see
    /// `portscan.rs`'s Critical tier) are considered for the kernel's
    /// XDP blocklist. By itself this only LOGS candidates ("AUTO-BLOCK
    /// CANDIDATE") -- pass --xdp-auto-block-enforce too to actually
    /// drop traffic. This split exists so you can validate against
    /// real traffic before turning on real enforcement.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long)]
    xdp_auto_block: bool,

    /// Actually insert auto-block candidates into the kernel blocklist
    /// (XDP_DROP them) instead of only logging what would happen.
    /// Requires --xdp-auto-block. Off by default deliberately -- this
    /// is real, autonomous firewalling with no human in the loop
    /// beyond whatever detector thresholds you've configured.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, requires = "xdp_auto_block")]
    xdp_auto_block_enforce: bool,

    /// How long an auto- or manually-blocked entry stays in the kernel
    /// blocklist before expiring on its own.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, default_value_t = 300)]
    xdp_block_secs: u64,

    /// CIDR prefix length new auto-blocks are inserted at (1-32). 32
    /// (default) blocks only the exact offending host. A narrower
    /// value (e.g. 24) blocks that whole subnet -- harder for a
    /// scanner to defeat by rotating source addresses, at the cost of
    /// a wider false-positive blast radius. Does nothing against
    /// genuinely spoofed source addresses.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u8).range(1..=32))]
    xdp_block_prefix_len: u8,

    /// Address or CIDR range that must never be auto-blocked,
    /// regardless of what any detector says. Repeatable. The
    /// monitored interface's own local IPs are always protected
    /// automatically on top of whatever you list here.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long = "xdp-allowlist")]
    xdp_allowlist: Vec<String>,

    /// Max new auto-blocks allowed within --xdp-auto-block-rate-window-secs.
    /// Beyond this, further blocks are skipped (loudly logged, not
    /// silently dropped) rather than risking a false-positive storm
    /// firewalling large swaths of traffic.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, default_value_t = 20)]
    xdp_auto_block_rate_limit: u32,

    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long, default_value_t = 60)]
    xdp_auto_block_rate_window_secs: u64,

    /// Path to a Unix domain socket serving BLOCK/UNBLOCK/LIST/STATUS
    /// commands (see src/xdp/mod.rs's run_control_socket doc comment
    /// for the protocol). This is the recovery path if an auto-block
    /// false-positives on something important -- without it, the only
    /// way to undo a block is killing the process. Not created unless
    /// this is passed.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long)]
    xdp_control_socket: Option<std::path::PathBuf>,

    /// Path to persist the blocklist to. Rewritten on every block/
    /// unblock and reloaded from on startup, so a process restart --
    /// crash, deliberate, or an attacker-triggered one -- doesn't wipe
    /// active blocks. Strongly recommended alongside
    /// --xdp-auto-block-enforce; without it, a restart is a free pass
    /// for anyone currently blocked.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long)]
    xdp_blocklist_persist: Option<std::path::PathBuf>,

    /// If attaching fails with "Device or resource busy" (an XDP
    /// program from a previous run -- most often one that got stuck/
    /// suspended rather than cleanly exited, since a clean exit or
    /// even SIGKILL auto-detaches via the kernel's bpf_link lifetime,
    /// but a stopped-not-exited process's file descriptors stay open
    /// -- is still attached), shell out to `ip link set dev <iface>
    /// xdpgeneric/xdpdrv off` to clear it, then retry the attach once.
    /// Uses the same recovery commands you'd otherwise run by hand.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    #[arg(long)]
    xdp_force_detach: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("nsm=info".parse()?))
        .with_writer(std::io::stderr) // keep stdout clean for NDJSON alerts
        .init();

    let cli = Cli::parse();

    if cli.list_interfaces {
        capture::print_interfaces();
        return Ok(());
    }

    let flow_table = Arc::new(FlowTable::new());
    let (tx, rx) = mpsc::channel(4096);

    // The port-scan detector needs to know which addresses are "us"
    // to tell inbound scans apart from ordinary outbound browsing.
    let mut local_ips: HashSet<IpAddr> = HashSet::new();
    local_ips.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    local_ips.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    if cli.simulate {
        local_ips.insert(sim::DEMO_LOCAL_IP);
        let engine = Arc::new(DetectionEngine::new(local_ips));
        tokio::spawn(sim::run(tx));
        #[cfg(all(target_os = "linux", feature = "xdp"))]
        {
            run_event_loop(flow_table, engine, rx, cli.flow_idle_secs, None, false, cli.xdp_block_secs).await
        }
        #[cfg(not(all(target_os = "linux", feature = "xdp")))]
        {
            run_event_loop(flow_table, engine, rx, cli.flow_idle_secs).await
        }
    } else {
        let iface_name = cli
            .interface
            .ok_or_else(|| anyhow::anyhow!("--interface is required (or pass --simulate / --list-interfaces)"))?;
        let iface = capture::find_interface(&iface_name)?;
        for net in &iface.ips {
            local_ips.insert(net.ip());
        }
        // Also fold in every other interface's addresses (e.g. Wi-Fi +
        // Hyper-V + Ethernet all resolve to "us" for routing purposes).
        for other in capture::list_interfaces() {
            for net in &other.ips {
                local_ips.insert(net.ip());
            }
        }
        tracing::info!("capturing on {} ({})", iface.name, iface.description);

        #[cfg(all(target_os = "linux", feature = "xdp"))]
        let xdp_handle = if cli.xdp {
            tracing::info!("using XDP fast-path capture (--xdp-mode {:?})", cli.xdp_mode);

            let mut allowlist = Vec::new();
            for entry in &cli.xdp_allowlist {
                let cidr = if entry.contains('/') { entry.clone() } else { format!("{entry}/32") };
                match cidr.parse::<ipnetwork::Ipv4Network>() {
                    Ok(net) => allowlist.push(net),
                    Err(e) => tracing::warn!("xdp: ignoring invalid --xdp-allowlist entry '{entry}': {e}"),
                }
            }
            // Automatic, zero-config safety net: the interface's own
            // local IPs (and everything else discovered above) can
            // never be auto-blocked, regardless of --xdp-allowlist.
            // A detector misattributing traffic to your own gateway
            // shouldn't be able to firewall it.
            let mut auto_protected = 0usize;
            for ip in &local_ips {
                if let IpAddr::V4(v4) = ip {
                    if let Ok(net) = ipnetwork::Ipv4Network::new(*v4, 32) {
                        allowlist.push(net);
                        auto_protected += 1;
                    }
                }
            }
            tracing::info!(
                "xdp: allowlist has {} entr{} ({} from --xdp-allowlist, {} local addresses auto-protected)",
                allowlist.len(),
                if allowlist.len() == 1 { "y" } else { "ies" },
                cli.xdp_allowlist.len(),
                auto_protected
            );

            let config = xdp::AutoBlockConfig {
                allowlist,
                enforce: cli.xdp_auto_block_enforce,
                prefix_len: cli.xdp_block_prefix_len,
                rate_limit: cli.xdp_auto_block_rate_limit,
                rate_window: Duration::from_secs(cli.xdp_auto_block_rate_window_secs),
            };
            let handle = xdp::start(&cli.xdp_obj, &iface.name, cli.xdp_mode, tx, config, cli.xdp_control_socket, cli.xdp_blocklist_persist, cli.xdp_force_detach).await?;
            Some(handle)
        } else {
            #[cfg(unix)]
            tracing::info!("if this fails, re-run as root or grant CAP_NET_RAW");
            capture::spawn_capture_thread(iface, tx)?;
            None
        };
        #[cfg(not(all(target_os = "linux", feature = "xdp")))]
        {
            #[cfg(unix)]
            tracing::info!("if this fails, re-run as root or grant CAP_NET_RAW");
            #[cfg(windows)]
            tracing::info!("if this fails, re-run from an elevated (Administrator) terminal with Npcap installed");
            capture::spawn_capture_thread(iface, tx)?;
        }

        let engine = Arc::new(DetectionEngine::new(local_ips));
        #[cfg(all(target_os = "linux", feature = "xdp"))]
        {
            run_event_loop(flow_table, engine, rx, cli.flow_idle_secs, xdp_handle, cli.xdp_auto_block, cli.xdp_block_secs).await
        }
        #[cfg(not(all(target_os = "linux", feature = "xdp")))]
        {
            run_event_loop(flow_table, engine, rx, cli.flow_idle_secs).await
        }
    }
}

/// Minimal sd_notify client: writes a datagram to `$NOTIFY_SOCKET` if
/// systemd set it (i.e. nsm is running as a `Type=notify` unit).
/// Silently does nothing otherwise -- safe to call unconditionally
/// regardless of how nsm was launched (systemd, plain shell, etc.).
/// No new dependency: sd_notify's wire protocol is just "send this
/// text to a named Unix datagram socket," small enough to not be
/// worth a crate for.
#[cfg(unix)]
fn sd_notify(state: &str) {
    use std::os::unix::net::UnixDatagram;
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let _ = sock.send_to(state.as_bytes(), &path);
}
#[cfg(not(unix))]
fn sd_notify(_state: &str) {}

/// Answers "did the event loop's `tokio::select!` get scheduled and
/// run within the last `stale_after`" -- bumped by a ticker branch
/// inside `run_event_loop`'s `select!` itself (see both variants
/// below), not by a separate, independent task. That distinction
/// matters: an independent heartbeat task would keep ticking even if
/// the specific `select!` loop that actually does the work is
/// deadlocked on something (e.g. a poisoned/held lock) while other
/// tokio tasks on other worker threads remain schedulable -- it would
/// only catch a *fully* wedged runtime, not a localized hang in this
/// one loop. Bumping from inside the loop itself means the watchdog
/// reflects this loop's actual liveness, not just "is the process
/// alive at all."
///
/// This is still not a universal liveness guarantee -- it only proves
/// the `select!` got polled, not that `flow_table.update()` or
/// `engine.analyze()` didn't themselves hang on a given iteration
/// before looping back around. It's the best signal available without
/// instrumenting every downstream call, and it's exactly the class of
/// problem (a process that's alive but stuck) this project hit
/// firsthand with a suspended XDP run earlier.
struct Watchdog {
    last_alive_unix_secs: AtomicI64,
}

impl Watchdog {
    fn new() -> Arc<Self> {
        Arc::new(Self { last_alive_unix_secs: AtomicI64::new(now_unix()) })
    }

    fn bump(&self) {
        self.last_alive_unix_secs.store(now_unix(), Ordering::Relaxed);
    }

    /// Spawns the periodic checker. `interval` should be well under
    /// half of the systemd unit's `WatchdogSec=` (see
    /// `scripts/nsm.service`) -- systemd's own recommendation is
    /// roughly a 1:2 to 1:3 ping-to-timeout ratio, so `WatchdogSec=30`
    /// pairs with an `interval` around 10s.
    fn spawn_checker(self: Arc<Self>, interval: Duration, stale_after: Duration) {
        tokio::spawn(async move {
            sd_notify("READY=1");
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let age = now_unix() - self.last_alive_unix_secs.load(Ordering::Relaxed);
                if age <= stale_after.as_secs() as i64 {
                    sd_notify("WATCHDOG=1");
                } else {
                    // Deliberately skip the heartbeat rather than
                    // sending it anyway -- the entire point is to let
                    // systemd's own WatchdogSec timeout notice and
                    // restart us. Sending WATCHDOG=1 here would defeat
                    // that; logging is the only thing to do locally.
                    tracing::error!(
                        "watchdog: event loop hasn't ticked in {age}s (stale_after={}s) -- \
                         skipping systemd heartbeat, expecting a restart if WatchdogSec is set",
                        stale_after.as_secs()
                    );
                }
            }
        });
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(not(all(target_os = "linux", feature = "xdp")))]
async fn run_event_loop(
    flow_table: Arc<FlowTable>,
    engine: Arc<DetectionEngine>,
    mut rx: mpsc::Receiver<packet::PacketMeta>,
    flow_idle_secs: u64,
) -> Result<()> {
    spawn_flow_reaper(flow_table.clone(), flow_idle_secs);

    let watchdog = Watchdog::new();
    watchdog.clone().spawn_checker(Duration::from_secs(10), Duration::from_secs(30));
    let mut liveness_tick = tokio::time::interval(Duration::from_secs(5));

    tracing::info!("nsm running, alerts stream as NDJSON on stdout (Ctrl+C to stop)");
    loop {
        tokio::select! {
            maybe_meta = rx.recv() => {
                watchdog.bump();
                match maybe_meta {
                    Some(meta) => {
                        flow_table.update(&meta);
                        for a in engine.analyze(&meta) {
                            a.emit();
                        }
                    }
                    None => break, // capture side hung up
                }
            }
            _ = liveness_tick.tick() => {
                // Exists purely so the loop is provably still being
                // scheduled even during a quiet period with no
                // traffic -- without this, an idle interface would
                // look identical to a genuinely hung loop from the
                // watchdog's point of view.
                watchdog.bump();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down ({} active flows)", flow_table.active_count());
                sd_notify("STOPPING=1");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    flow_table: Arc<FlowTable>,
    engine: Arc<DetectionEngine>,
    mut rx: mpsc::Receiver<packet::PacketMeta>,
    flow_idle_secs: u64,
    xdp_handle: Option<Arc<xdp::XdpCapture>>,
    xdp_auto_block: bool,
    xdp_block_secs: u64,
) -> Result<()> {
    spawn_flow_reaper(flow_table.clone(), flow_idle_secs);

    let watchdog = Watchdog::new();
    watchdog.clone().spawn_checker(Duration::from_secs(10), Duration::from_secs(30));
    let mut liveness_tick = tokio::time::interval(Duration::from_secs(5));

    let block_ttl = Duration::from_secs(xdp_block_secs);

    tracing::info!("nsm running, alerts stream as NDJSON on stdout (Ctrl+C to stop)");
    loop {
        tokio::select! {
            maybe_meta = rx.recv() => {
                watchdog.bump();
                match maybe_meta {
                    Some(meta) => {
                        flow_table.update(&meta);
                        for a in engine.analyze(&meta) {
                            // Kernel-level enforcement: a Critical
                            // alert against a known source IPv4 is
                            // considered for BLOCKLIST_V4 -- subject
                            // to the allowlist, the observe/enforce
                            // gate, and the rate limiter, all inside
                            // block_ipv4 itself (which also logs
                            // whichever of those applied, so there's
                            // nothing more to do here on Ok).
                            if xdp_auto_block {
                                if let (Some(handle), Some(IpAddr::V4(src))) = (&xdp_handle, a.src_ip) {
                                    if a.severity == alert::Severity::Critical {
                                        if let Err(e) = handle.block_ipv4(src, block_ttl, None) {
                                            tracing::warn!("xdp: failed to auto-block {src}: {e}");
                                        }
                                    }
                                }
                            }
                            a.emit();
                        }
                    }
                    None => break, // capture side hung up
                }
            }
            _ = liveness_tick.tick() => {
                watchdog.bump();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down ({} active flows)", flow_table.active_count());
                sd_notify("STOPPING=1");
                break;
            }
        }
    }

    Ok(())
}

fn spawn_flow_reaper(flow_table: Arc<FlowTable>, flow_idle_secs: u64) {
    let idle = Duration::from_secs(flow_idle_secs);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let reaped = flow_table.reap_idle(idle);
            if reaped > 0 {
                tracing::debug!("reaped {reaped} idle flows, {} active", flow_table.active_count());
            }
        }
    });
}
