//! Userspace half of the XDP bypass path (Linux only).
//!
//! This module is a second *producer* for the same
//! `mpsc::Sender<PacketMeta>` that `capture::spawn_capture_thread`
//! (pnet/AF_PACKET) already feeds -- `flow.rs`, `detect::DetectionEngine`,
//! and everything downstream of `main::run_event_loop` are completely
//! unaware of which capture backend is in use. Enabling `--xdp` simply
//! swaps which thing calls `tx.send(meta)`.
//!
//! What it adds beyond capture:
//! - Loads and attaches the compiled `nsm-ebpf` XDP program.
//! - Reads `PacketEvent`s off its `RingBuf` asynchronously and
//!   converts them back into `PacketMeta`.
//! - Exposes `block_ipv4` / `unblock_ipv4`, used by `main.rs` to push
//!   confirmed-bad source IPs/ranges into the kernel's `BLOCKLIST_V4`
//!   map (a CIDR-aware `LpmTrie`, not exact-match) when a detector
//!   escalates to `Critical` -- gated by an allowlist, a rate limit,
//!   and an observe/enforce split (see `AutoBlockConfig`).
//! - Runs a small Unix-socket control interface (`BLOCK`/`UNBLOCK`/
//!   `LIST`/`STATUS`) so a false-positive block can be reversed
//!   without killing the process.
//! - Periodically logs `Stats` (passed/dropped/truncated/parse_errors)
//!   from the program's `PerCpuArray`.

use crate::packet::{L4Proto, PacketMeta};
use anyhow::{anyhow, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie as AyaLpmTrie};
use aya::maps::{MapData, PerCpuArray as AyaPerCpuArray, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use ipnetwork::Ipv4Network;
use nsm_common::{PacketEvent, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;

/// Matches the `xdp_action` values `nsm-ebpf` can be attached with.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum XdpMode {
    /// Driver-native XDP -- fastest, requires NIC driver support.
    Native,
    /// Generic/SKB mode -- works on any NIC, runs later in the stack
    /// (after `sk_buff` allocation), so less of a "bypass" but a safe
    /// fallback when native mode isn't supported.
    Skb,
    /// Offloaded entirely onto NIC hardware. Rare; only a handful of
    /// SmartNICs support it.
    Hw,
}

impl From<XdpMode> for XdpFlags {
    fn from(m: XdpMode) -> Self {
        match m {
            XdpMode::Native => XdpFlags::DRV_MODE,
            XdpMode::Skb => XdpFlags::SKB_MODE,
            XdpMode::Hw => XdpFlags::HW_MODE,
        }
    }
}

/// Everything that governs whether/how a `Critical` alert actually
/// results in kernel-level enforcement. Every field here exists
/// because of a specific gap: an earlier version of `--xdp-auto-block`
/// had none of these, meaning a single detector's verdict could
/// autonomously firewall a source with no confirmation, no allowlist,
/// and no rate limit -- and no way to undo it short of killing the
/// process.
#[derive(Clone)]
pub struct AutoBlockConfig {
    /// Addresses/ranges that must NEVER be blocked, regardless of what
    /// any detector says. `main.rs` populates this with `--xdp-allowlist`
    /// entries plus the monitored interface's own local IPs -- the
    /// latter automatically, as a zero-config safety net (a detector
    /// misattributing traffic to your own gateway shouldn't be able to
    /// firewall it).
    pub allowlist: Vec<Ipv4Network>,
    /// `false` (the default): `block_ipv4` logs what it WOULD block
    /// ("AUTO-BLOCK CANDIDATE") but never touches the kernel map. This
    /// is the practical human-in-the-loop gate for a headless daemon
    /// -- there's no sensible place for an interactive confirmation
    /// prompt, so the safe default is "observe first," with real
    /// enforcement an explicit, deliberate opt-in via
    /// `--xdp-auto-block-enforce`.
    pub enforce: bool,
    /// CIDR prefix length new blocks are inserted at (1-32). 32 (the
    /// default) blocks exactly the offending host, identical to the
    /// old exact-match behavior. A narrower prefix (e.g. 24) blocks
    /// the whole /24 the offender is in -- meaningfully harder for a
    /// scanner to defeat by rotating source addresses within that
    /// range, at the real cost of a wider false-positive blast radius
    /// (innocent hosts sharing that range, e.g. behind the same
    /// CGNAT/ISP block, get blocked too). Does nothing against
    /// genuinely spoofed source addresses -- no source-IP-based
    /// blocking scheme can.
    pub prefix_len: u8,
    /// Max new blocks allowed within `rate_window`. Once hit, further
    /// auto-block attempts are logged loudly and skipped (fail open --
    /// we'd rather risk under-blocking during a false-positive storm
    /// than risk firewalling half the internet) until the window
    /// rolls forward.
    pub rate_limit: u32,
    pub rate_window: Duration,
}

impl Default for AutoBlockConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            enforce: false,
            prefix_len: 32,
            rate_limit: 20,
            rate_window: Duration::from_secs(60),
        }
    }
}

/// Fixed-capacity sliding window over recent block timestamps.
struct RateLimiter {
    events: VecDeque<Instant>,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(limit: u32, window: Duration) -> Self {
        Self { events: VecDeque::new(), limit, window }
    }

    /// Records a block attempt and returns whether it's allowed under
    /// the current rate limit. Called only for blocks that already
    /// passed the allowlist and enforce-mode checks -- this is the
    /// last gate before anything actually touches the kernel map.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        while let Some(&front) = self.events.front() {
            if now.duration_since(front) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
        if self.events.len() as u32 >= self.limit {
            return false;
        }
        self.events.push_back(now);
        true
    }
}

/// Owns the loaded eBPF object for as long as the program should stay
/// attached; dropping it detaches XDP from the interface and tears
/// down its maps.
pub struct XdpCapture {
    // Keeps the underlying `Ebpf` (and therefore the attached `Xdp`
    // link + all maps) alive for the process lifetime.
    _ebpf: Arc<Mutex<Ebpf>>,
    blocklist: Arc<Mutex<AyaLpmTrie<MapData, [u8; 4], u64>>>,
    iface: String,
    config: AutoBlockConfig,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    /// If set, the blocklist is rewritten to this path on every
    /// block/unblock and reloaded from it on startup (see `start()`
    /// and `persist_blocklist()`). Without this, a process restart --
    /// including one an attacker deliberately triggers -- silently
    /// wipes every active block, handing them a free pass. The flow
    /// table is deliberately NOT persisted the same way: it's
    /// detection-heuristic state that rebuilds itself within a
    /// sliding window of seconds, not a security control whose loss
    /// has real consequences.
    persist_path: Option<PathBuf>,
}

/// Loads `nsm-ebpf` from `obj_path`, attaches it to `iface` in `mode`,
/// and spawns the tasks that stream events into `tx`, periodically log
/// stats, sweep expired blocklist entries, and (if `control_socket` is
/// `Some`) serve the `BLOCK`/`UNBLOCK`/`LIST`/`STATUS` control
/// interface. Returns once the program is attached and the reader
/// task is running.
pub async fn start(
    obj_path: &Path,
    iface: &str,
    mode: XdpMode,
    tx: Sender<PacketMeta>,
    config: AutoBlockConfig,
    control_socket: Option<PathBuf>,
    persist_path: Option<PathBuf>,
    force_detach: bool,
) -> Result<Arc<XdpCapture>> {
    let bytes = std::fs::read(obj_path)
        .with_context(|| format!("reading eBPF object at {}", obj_path.display()))?;
    let mut ebpf = Ebpf::load(&bytes).context("loading nsm-ebpf object")?;

    let program: &mut Xdp = ebpf
        .program_mut("nsm_xdp")
        .ok_or_else(|| anyhow!("nsm-ebpf object has no 'nsm_xdp' program"))?
        .try_into()
        .context("nsm_xdp is not an XDP program")?;
    program.load().context("loading nsm_xdp into the kernel")?;

    if let Err(e) = program.attach(iface, mode.into()) {
        let busy = e.to_string().to_lowercase().contains("busy");
        if force_detach && busy {
            tracing::warn!(
                "xdp: attach to {iface} failed (device or resource busy) -- an XDP program from a \
                 previous run is likely still attached (this happens when a previous process got \
                 stuck/suspended rather than exiting cleanly -- a clean exit, or even SIGKILL, \
                 auto-detaches via the kernel's bpf_link lifetime, but a stopped-not-exited \
                 process's file descriptors stay open). --xdp-force-detach is set, clearing it \
                 and retrying once."
            );
            force_clear_xdp(iface);
            program
                .attach(iface, mode.into())
                .with_context(|| format!("attaching nsm_xdp to '{iface}' (retry after --xdp-force-detach)"))?;
        } else if busy {
            return Err(e).with_context(|| {
                format!(
                    "attaching nsm_xdp to interface '{iface}': device or resource busy. This usually \
                     means an XDP program from a previous run is still attached (most often a stuck/\
                     suspended process -- Ctrl+Z rather than Ctrl+C -- whose file descriptors never \
                     closed). Recover manually with:\n  \
                     sudo ip link set dev {iface} xdpgeneric off\n  \
                     sudo ip link set dev {iface} xdpdrv off\n\
                     or pass --xdp-force-detach to have nsm do this automatically."
                )
            });
        } else {
            return Err(e).with_context(|| {
                format!("attaching nsm_xdp to interface '{iface}' (try --xdp-mode skb if native mode is unsupported by this NIC's driver)")
            });
        }
    }

    let ringbuf_map = ebpf.take_map("EVENTS").ok_or_else(|| anyhow!("nsm-ebpf object has no 'EVENTS' map"))?;
    let ring = RingBuf::try_from(ringbuf_map).context("EVENTS is not a ring buffer map")?;

    // take_map (not map()+clone()) is required here: `map()` returns a
    // borrowed `&Map`, and `&Map` is trivially `Clone` regardless of
    // whether `Map` itself is -- so `.clone()` on it silently produces
    // another borrow, not an owned value. That yields
    // `LpmTrie<&MapData, ..>`/`PerCpuArray<&MapData, ..>` instead of
    // the `MapData`-owning versions our structs/functions expect, and
    // fails to type-check. take_map() removes the entry from `ebpf`'s
    // internal map table and hands back an owned `Map`, which is what
    // we actually want since these outlive this function.
    let blocklist_map = ebpf
        .take_map("BLOCKLIST_V4")
        .ok_or_else(|| anyhow!("nsm-ebpf object has no 'BLOCKLIST_V4' map"))?;
    let mut blocklist: AyaLpmTrie<_, [u8; 4], u64> =
        AyaLpmTrie::try_from(blocklist_map).context("BLOCKLIST_V4 is not an LpmTrie")?;

    if let Some(path) = &persist_path {
        match load_persisted_blocklist(path) {
            Ok(entries) => {
                let now = now_ns();
                let mut restored = 0u32;
                let mut expired_skipped = 0u32;
                for (ip, prefix_len, expiry_ns) in entries {
                    if expiry_ns <= now {
                        expired_skipped += 1;
                        continue; // no point restoring an already-expired block
                    }
                    let key = Key::new(prefix_len as u32, ip.octets());
                    if let Err(e) = blocklist.insert(&key, expiry_ns, 0) {
                        tracing::warn!("xdp: failed to restore persisted block {ip}/{prefix_len}: {e}");
                    } else {
                        restored += 1;
                    }
                }
                tracing::info!(
                    "xdp: restored {restored} block(s) from {} ({expired_skipped} already expired, skipped)",
                    path.display()
                );
            }
            Err(e) => tracing::warn!("xdp: couldn't load persisted blocklist from {}: {e} (starting with an empty blocklist)", path.display()),
        }
    }

    let stats_map = ebpf
        .take_map("STATS")
        .ok_or_else(|| anyhow!("nsm-ebpf object has no 'STATS' map"))?;
    let stats: AyaPerCpuArray<_, StatsRaw> =
        AyaPerCpuArray::try_from(stats_map).context("STATS is not a PerCpuArray")?;

    tokio::spawn(read_events(ring, tx));
    tokio::spawn(log_stats(stats));

    let blocklist = Arc::new(Mutex::new(blocklist));
    tokio::spawn(sweep_expired_blocklist(blocklist.clone()));

    tracing::info!("XDP program attached to {iface} ({mode:?} mode)");
    if !config.enforce {
        tracing::warn!(
            "xdp: auto-block is in OBSERVE mode -- Critical alerts will be logged as block candidates \
             but nothing will actually be dropped. Pass --xdp-auto-block-enforce once you've validated \
             this against real traffic."
        );
    }
    if !config.allowlist.is_empty() {
        tracing::info!("xdp: {} allowlist entr{} loaded (never auto-blocked)",
            config.allowlist.len(), if config.allowlist.len() == 1 { "y" } else { "ies" });
    }
    if persist_path.is_none() {
        tracing::warn!(
            "xdp: no --xdp-blocklist-persist path set -- the blocklist will be wiped on the next \
             restart (deliberate or not). Set one if losing active blocks on crash/restart is a concern."
        );
    }

    // Everything above needed full privileges (BPF_MAP_CREATE,
    // BPF_PROG_LOAD, bpf_link_create for the XDP attach). Nothing
    // below does -- ongoing map element operations are the only thing
    // left, which is why CAP_BPF is specifically retained rather than
    // dropped entirely. See drop_privileges()'s doc comment for the
    // honest uncertainty about whether even that's still needed.
    drop_privileges();

    let capture = Arc::new(XdpCapture {
        _ebpf: Arc::new(Mutex::new(ebpf)),
        blocklist,
        iface: iface.to_string(),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(config.rate_limit, config.rate_window))),
        config,
        persist_path,
    });

    if let Some(path) = control_socket {
        tokio::spawn(run_control_socket(capture.clone(), path));
    }

    Ok(capture)
}

impl XdpCapture {
    /// Called from `main.rs` when a detector escalates an alert to
    /// `Critical` with an attributable source IPv4. Respects the
    /// observe/enforce gate (see `AutoBlockConfig::enforce`) -- this
    /// is the automatic path, not a manually-typed command, so it
    /// never bypasses "are we actually supposed to be enforcing yet."
    pub fn block_ipv4(&self, ip: Ipv4Addr, ttl: Duration, prefix_len: Option<u8>) -> Result<BlockOutcome> {
        self.block_ipv4_inner(ip, ttl, prefix_len, /* bypass_enforce_gate */ false)
    }

    /// Same as `block_ipv4`, but skips the observe/enforce gate.
    /// Reserved for the control socket's manual `BLOCK` command: an
    /// operator explicitly typing `BLOCK` *is* the human confirmation
    /// the enforce gate exists to require, so re-requiring
    /// `--xdp-auto-block-enforce` on top of that would just be
    /// friction, not safety. Still goes through the allowlist and
    /// rate limiter -- an operator fat-fingering a loop of `BLOCK`
    /// commands doesn't get an exemption from those.
    pub fn force_block_ipv4(&self, ip: Ipv4Addr, ttl: Duration, prefix_len: Option<u8>) -> Result<BlockOutcome> {
        self.block_ipv4_inner(ip, ttl, prefix_len, /* bypass_enforce_gate */ true)
    }

    fn block_ipv4_inner(&self, ip: Ipv4Addr, ttl: Duration, prefix_len: Option<u8>, bypass_enforce_gate: bool) -> Result<BlockOutcome> {
        if self.config.allowlist.iter().any(|net| net.contains(ip)) {
            tracing::debug!("xdp: {ip} is allowlisted, not blocking");
            return Ok(BlockOutcome::Allowlisted);
        }

        if !self.config.enforce && !bypass_enforce_gate {
            tracing::warn!(
                "xdp: AUTO-BLOCK CANDIDATE {ip} (observe mode -- not enforced; pass --xdp-auto-block-enforce to actually drop this)"
            );
            return Ok(BlockOutcome::ObserveOnly);
        }

        if !self.rate_limiter.lock().unwrap().allow() {
            tracing::warn!(
                "xdp: auto-block RATE LIMIT hit ({} per {:?}) -- skipping block of {ip}. \
                 This usually means either a false-positive storm (check what's triggering \
                 Critical alerts) or a real, large-scale attack outpacing single-IP blocking \
                 (which auto-block can't fully mitigate anyway). Not blocking further sources \
                 until the window rolls forward.",
                self.config.rate_limit, self.config.rate_window
            );
            return Ok(BlockOutcome::RateLimited);
        }

        let prefix_len = prefix_len.unwrap_or(self.config.prefix_len).clamp(1, 32);
        let expiry_ns = now_ns() + ttl.as_nanos() as u64;
        let key = Key::new(prefix_len as u32, ip.octets());
        self.blocklist
            .lock()
            .unwrap()
            .insert(&key, expiry_ns, 0)
            .with_context(|| format!("inserting {ip}/{prefix_len} into BLOCKLIST_V4"))?;
        tracing::warn!("xdp: blocking {ip}/{prefix_len} on {} for {:?}", self.iface, ttl);
        self.persist_blocklist();
        Ok(BlockOutcome::Blocked)
    }

    /// Removes `ip`/`prefix_len` from the blocklist immediately, ahead
    /// of its TTL. `prefix_len` defaults to 32 (undo a single-host
    /// block) if not specified. This is the release valve
    /// `block_ipv4` needs to not be a footgun -- reachable today via
    /// the control socket's `UNBLOCK` command (see `run_control_socket`).
    pub fn unblock_ipv4(&self, ip: Ipv4Addr, prefix_len: Option<u8>) -> Result<()> {
        let prefix_len = prefix_len.unwrap_or(32).clamp(1, 32);
        let key = Key::new(prefix_len as u32, ip.octets());
        // May not contain the key (already expired/never inserted);
        // that's not an error condition worth surfacing.
        let _ = self.blocklist.lock().unwrap().remove(&key);
        tracing::info!("xdp: unblocked {ip}/{prefix_len} on {}", self.iface);
        self.persist_blocklist();
        Ok(())
    }

    /// Rewrites the persistence file (if `--xdp-blocklist-persist` is
    /// set) from the current live blocklist contents. Called after
    /// every successful block/unblock so the file is never more than
    /// one mutation stale -- if the process dies between a block and
    /// the next one, at worst that single most-recent block is lost,
    /// not the whole history. Failures are logged, not propagated:
    /// losing the ability to persist shouldn't take down the actual
    /// enforcement path.
    fn persist_blocklist(&self) {
        let Some(path) = &self.persist_path else { return };
        if let Err(e) = write_persisted_blocklist(path, &self.list_blocked_raw()) {
            tracing::warn!("xdp: failed to persist blocklist to {}: {e}", path.display());
        }
    }

    /// Current blocklist contents as `(ip, prefix_len, absolute_expiry_ns)`
    /// -- used only for persistence, where the raw timestamp is what
    /// you want (re-deriving "seconds remaining" at load time avoids
    /// the small extra drift double-converting through a
    /// seconds-remaining figure would introduce).
    fn list_blocked_raw(&self) -> Vec<(Ipv4Addr, u8, u64)> {
        let map = self.blocklist.lock().unwrap();
        map.iter()
            .filter_map(|entry| entry.ok())
            // Same UNVERIFIED .data()/.prefix_len() accessor guess as
            // list_blocked() below.
            .map(|(key, expiry)| (Ipv4Addr::from(key.data()), key.prefix_len() as u8, expiry))
            .collect()
    }

    /// Current blocklist contents as `(ip, prefix_len, seconds_remaining)`,
    /// for the control socket's `LIST` command. Entries whose TTL has
    /// already passed (but haven't been swept yet -- see
    /// `sweep_expired_blocklist`) are filtered out rather than shown
    /// with a confusing negative remaining time.
    fn list_blocked(&self) -> Vec<(Ipv4Addr, u8, u64)> {
        let now = now_ns();
        let map = self.blocklist.lock().unwrap();
        map.iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|(key, expiry)| {
                if expiry <= now {
                    return None;
                }
                let remaining_secs = (expiry - now) / 1_000_000_000;
                // UNVERIFIED: assumes Key<[u8;4]> exposes `.data()`
                // and `.prefix_len()` accessor methods. If this fails
                // to compile, the likely fix is field access instead
                // (`key.data`/`key.prefix_len`) -- aya's Key<K> wrapper
                // API for this isn't something either of us has seen
                // real compiler output for yet.
                Some((Ipv4Addr::from(key.data()), key.prefix_len() as u8, remaining_secs))
            })
            .collect()
    }
}

/// What `block_ipv4` actually did, so callers (auto-block in
/// `main.rs`, or the control socket's manual `BLOCK` command) can
/// report/log the right thing instead of assuming every call resulted
/// in an actual kernel-level block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    Blocked,
    Allowlisted,
    ObserveOnly,
    RateLimited,
}

/// `BLOCKLIST_V4` entries are only *checked* for expiry on lookup
/// (see `nsm-ebpf`'s `try_nsm_xdp`) -- an expired entry just stops
/// matching, it doesn't disappear. Without this, a long-running
/// auto-block deployment would slowly fill the map's fixed
/// `BLOCKLIST_MAX_ENTRIES` capacity with dead entries until inserts
/// start failing. Runs independently of `unblock_ipv4` (that's for
/// deliberate/manual overrides; this is routine garbage collection).
async fn sweep_expired_blocklist(blocklist: Arc<Mutex<AyaLpmTrie<MapData, [u8; 4], u64>>>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = now_ns();

        // Key<[u8;4]> is Copy (aya::Pod: Copy + 'static, and we've
        // seen real compiler output confirming Key<K> implements
        // aya::Pod), so the expired keys can just be collected
        // directly -- no need to reconstruct them via .data()/
        // .prefix_len() the way list_blocked() has to for display.
        let expired: Vec<Key<[u8; 4]>> = {
            let map = blocklist.lock().unwrap();
            map.iter()
                .filter_map(|entry| entry.ok())
                .filter(|(_, expiry)| *expiry <= now)
                .map(|(key, _)| key)
                .collect()
        };
        if expired.is_empty() {
            continue;
        }

        let mut map = blocklist.lock().unwrap();
        let n = expired.len();
        for key in &expired {
            let _ = map.remove(key);
        }
        tracing::debug!("xdp: swept {n} expired blocklist entries");
    }
}

/// Serves `BLOCK`/`UNBLOCK`/`LIST`/`STATUS` over a Unix domain socket
/// at `path`, one line in, one line back, one connection at a time
/// (each accepted connection gets its own task, but there's no
/// shared-state contention beyond what `XdpCapture`'s own `Mutex`es
/// already handle). This exists specifically so a false-positive
/// block has a way to be undone without killing the process --
/// `unblock_ipv4` existed as an API already, this is what actually
/// makes it reachable.
///
/// Protocol (plain text, one command per line, case-insensitive verb):
///   BLOCK <ip>[/prefix] [ttl_secs]   -- default prefix 32, default ttl 300
///   UNBLOCK <ip>[/prefix]            -- default prefix 32
///   LIST                             -- one "ip/prefix ttl_remaining_secs" per line
///   STATUS                           -- interface, enforce mode, allowlist/rate-limit config
/// Any parse/lookup failure gets a one-line "ERROR: ..." response;
/// nothing here is authenticated beyond filesystem permissions on the
/// socket itself, which is why those are set explicitly below (mode
/// 0600) rather than left to whatever the process's ambient umask
/// happens to produce -- an unauthenticated socket that can issue
/// BLOCK/UNBLOCK commands is exactly the kind of thing that shouldn't
/// be world-connectable by accident. Since `nsm` runs as root (or
/// with CAP_BPF/CAP_NET_ADMIN), 0600 means only root can connect by
/// default; if you want a non-root operator account to use the
/// control socket without `sudo`, chgrp the path to a dedicated group
/// after startup and loosen to 0660 -- deliberately not automated
/// here, since choosing that group is a real security decision this
/// code shouldn't make silently on your behalf.
async fn run_control_socket(capture: Arc<XdpCapture>, path: PathBuf) {
    let _ = std::fs::remove_file(&path); // clear a stale socket from a previous unclean exit
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("xdp: failed to bind control socket at {}: {e}", path.display());
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(
            "xdp: couldn't set {} to mode 0600 ({e}) -- it may be more permissive than intended, \
             check its actual permissions before relying on it",
            path.display()
        );
    }
    tracing::info!("xdp: control socket listening at {} (mode 0600, root-only by default)", path.display());

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("xdp: control socket accept error: {e}");
                continue;
            }
        };
        let capture = capture.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let response = handle_control_command(&capture, line.trim());
                let _ = write_half.write_all(response.as_bytes()).await;
                let _ = write_half.write_all(b"\n").await;
            }
        });
    }
}

fn handle_control_command(capture: &XdpCapture, line: &str) -> String {
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_ascii_uppercase();

    let parse_ip_prefix = |s: &str| -> Result<(Ipv4Addr, Option<u8>), String> {
        match s.split_once('/') {
            Some((ip, prefix)) => {
                let ip = ip.parse().map_err(|e| format!("bad IP '{ip}': {e}"))?;
                let prefix: u8 = prefix.parse().map_err(|e| format!("bad prefix '{prefix}': {e}"))?;
                Ok((ip, Some(prefix)))
            }
            None => {
                let ip = s.parse().map_err(|e| format!("bad IP '{s}': {e}"))?;
                Ok((ip, None))
            }
        }
    };

    match verb.as_str() {
        "BLOCK" => {
            let Some(target) = parts.next() else { return "ERROR: usage: BLOCK <ip>[/prefix] [ttl_secs]".into() };
            let (ip, prefix) = match parse_ip_prefix(target) {
                Ok(v) => v,
                Err(e) => return format!("ERROR: {e}"),
            };
            let ttl_secs: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(300);
            // Manual blocks still respect the allowlist (defense in
            // depth) but bypass observe-mode -- an operator explicitly
            // typing BLOCK is already the human confirmation that gate
            // exists for. Rate limiting still applies: this is still
            // capable of firewalling real traffic, an operator fat-
            // fingering a loop of BLOCK commands shouldn't get an
            // exemption from the same safety net.
            match capture.force_block_ipv4(ip, Duration::from_secs(ttl_secs), prefix) {
                Ok(outcome) => format!("OK: {outcome:?} {ip}/{}", prefix.unwrap_or(capture.config.prefix_len)),
                Err(e) => format!("ERROR: {e}"),
            }
        }
        "UNBLOCK" => {
            let Some(target) = parts.next() else { return "ERROR: usage: UNBLOCK <ip>[/prefix]".into() };
            let (ip, prefix) = match parse_ip_prefix(target) {
                Ok(v) => v,
                Err(e) => return format!("ERROR: {e}"),
            };
            match capture.unblock_ipv4(ip, prefix) {
                Ok(()) => format!("OK: unblocked {ip}/{}", prefix.unwrap_or(32)),
                Err(e) => format!("ERROR: {e}"),
            }
        }
        "LIST" => {
            let entries = capture.list_blocked();
            if entries.is_empty() {
                "OK: (blocklist empty)".to_string()
            } else {
                entries
                    .into_iter()
                    .map(|(ip, prefix, secs)| format!("{ip}/{prefix} {secs}s"))
                    .collect::<Vec<_>>()
                    .join("; ")
            }
        }
        "STATUS" => format!(
            "OK: iface={} enforce={} prefix_len={} rate_limit={}/{:?} allowlist_entries={}",
            capture.iface,
            capture.config.enforce,
            capture.config.prefix_len,
            capture.config.rate_limit,
            capture.config.rate_window,
            capture.config.allowlist.len()
        ),
        "" => String::new(),
        other => format!("ERROR: unknown command '{other}' (try BLOCK, UNBLOCK, LIST, STATUS)"),
    }
}

/// Shells out to `ip link set dev <iface> xdpgeneric/xdpdrv off` to
/// clear any XDP program currently attached to `iface`, regardless of
/// which process (or no process at all, if it was orphaned) attached
/// it. These are the exact commands used to manually recover from a
/// stuck-process attachment earlier in this project's development --
/// see the README's "What happens if nsm crashes or is killed"
/// section. Deliberately implemented via `ip` (universally available
/// wherever this can run at all, since attaching XDP already implies
/// a working iproute2) rather than through aya/netlink APIs directly
/// -- this is exactly the well-tested recovery path already known to
/// work, not a new one.
fn force_clear_xdp(iface: &str) {
    for mode_flag in ["xdpgeneric", "xdpdrv"] {
        let result = std::process::Command::new("ip")
            .args(["link", "set", "dev", iface, mode_flag, "off"])
            .output();
        match result {
            Ok(out) if out.status.success() => {
                tracing::debug!("xdp: `ip link set dev {iface} {mode_flag} off` succeeded");
            }
            Ok(out) => {
                // Not fatal -- if there was nothing in that mode to
                // clear, `ip` may report a non-zero exit; we try both
                // modes unconditionally rather than trying to
                // pre-determine which one is actually attached.
                tracing::debug!(
                    "xdp: `ip link set dev {iface} {mode_flag} off` exited non-zero: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!("xdp: couldn't run `ip` to clear a stale XDP attachment: {e} (is iproute2 installed?)");
            }
        }
    }
}

/// Drops from whatever capabilities the process started with (root,
/// or specific `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_NET_RAW` grants) down to
/// just `{CAP_BPF, CAP_NET_ADMIN}` -- the two capabilities ongoing map
/// operations (block/unblock/list, from the control socket or
/// auto-block) and any future re-attach could plausibly still need.
///
/// Deliberately does NOT drop to zero: whether
/// `BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` on an already-open map
/// fd requires `CAP_BPF` to still be held (as opposed to only being
/// checked once, at `BPF_MAP_CREATE` time) isn't something either of
/// us has confirmed against a real kernel. Dropping too aggressively
/// risks turning "block a confirmed attacker" into a silent (well --
/// logged, but easy to miss) permission failure, which is a worse
/// failure mode than "process holds slightly more privilege than the
/// theoretical minimum." If you confirm on your kernel that ongoing
/// map ops work with `CAP_BPF` also dropped, tighten this further.
///
/// Does NOT drop the process's UID/GID -- it keeps running as
/// whatever user launched it (root, if via `sudo`). A full UID drop
/// is a bigger change (control socket and persistence file ownership
/// both need to follow the new UID) and is left as future work; this
/// only shrinks the *capability* set, not the user identity.
///
/// Failures here are logged, not fatal -- e.g. running inside a
/// container without `CAP_SETPCAP` would make this a no-op rather
/// than a crash. Best-effort hardening, not a security boundary you
/// should rely on being airtight.
fn drop_privileges() {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    let keep: HashSet<Capability> = [Capability::CAP_BPF, Capability::CAP_NET_ADMIN].into_iter().collect();

    let current = match caps::read(None, CapSet::Permitted) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("xdp: couldn't read current capabilities, skipping privilege drop: {e}");
            return;
        }
    };

    // The bounding set can only shrink one capability at a time --
    // there's no bulk "set the bounding set to exactly X" syscall,
    // only prctl(PR_CAPBSET_DROP, cap), which is inherently
    // per-capability. Effective/Permitted (below) do have a bulk set
    // API.
    let mut dropped = 0u32;
    let mut failed = 0u32;
    for cap in &current {
        if keep.contains(cap) {
            continue;
        }
        match caps::drop(None, CapSet::Bounding, *cap) {
            Ok(()) => dropped += 1,
            Err(_) => failed += 1,
        }
    }

    if let Err(e) = caps::set(None, CapSet::Effective, &keep) {
        tracing::warn!("xdp: failed to shrink effective capability set: {e}");
    }
    if let Err(e) = caps::set(None, CapSet::Permitted, &keep) {
        tracing::warn!("xdp: failed to shrink permitted capability set: {e}");
    }

    if failed > 0 {
        tracing::warn!("xdp: {failed} capabilities couldn't be dropped from the bounding set (non-fatal)");
    }
    tracing::info!(
        "xdp: dropped {dropped} capabilities after attach, retained {{CAP_BPF, CAP_NET_ADMIN}} for ongoing map operations"
    );
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
    // Note: this is wall-clock epoch time, not CLOCK_BOOTTIME like
    // bpf_ktime_get_ns(). We only ever compare *durations* we compute
    // ourselves against a single agreed-upon clock -- see the caveat
    // in the README ("Clock caveat") for why this is fine for TTL
    // purposes but shouldn't be read as an absolute boot-time value.
}

/// Plain-text persistence format: one `ip/prefix expiry_ns` entry per
/// line. Deliberately simple (not JSON/bincode) so it's trivially
/// human-inspectable and hand-editable with a text editor if you ever
/// need to manually fix up a stuck entry outside the control socket.
fn write_persisted_blocklist(path: &Path, entries: &[(Ipv4Addr, u8, u64)]) -> Result<()> {
    use std::io::Write;
    let mut buf = String::new();
    for (ip, prefix_len, expiry_ns) in entries {
        buf.push_str(&format!("{ip}/{prefix_len} {expiry_ns}\n"));
    }

    // Atomic write: write to a sibling temp file, then rename over the
    // real path. rename() on the same filesystem is atomic, so a
    // crash mid-write can never leave a half-written, corrupt
    // blocklist file behind -- worst case, the temp file is left over
    // and the previous good file is untouched.
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        f.write_all(buf.as_bytes())
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        f.sync_all().with_context(|| format!("fsyncing {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn load_persisted_blocklist(path: &Path) -> Result<Vec<(Ipv4Addr, u8, u64)>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()), // first run, nothing to restore
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    let mut entries = Vec::new();
    for (lineno, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((ip_prefix, expiry_str)) = line.split_once(' ') else {
            tracing::warn!("xdp: skipping malformed line {} in {}: {line:?}", lineno + 1, path.display());
            continue;
        };
        let Some((ip_str, prefix_str)) = ip_prefix.split_once('/') else {
            tracing::warn!("xdp: skipping malformed line {} in {}: {line:?}", lineno + 1, path.display());
            continue;
        };
        let (Ok(ip), Ok(prefix_len), Ok(expiry_ns)) =
            (ip_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>(), expiry_str.parse::<u64>())
        else {
            tracing::warn!("xdp: skipping malformed line {} in {}: {line:?}", lineno + 1, path.display());
            continue;
        };
        entries.push((ip, prefix_len, expiry_ns));
    }
    Ok(entries)
}

/// Converts an eBPF-side `PacketEvent` back into the same `PacketMeta`
/// the pnet capture path produces, so downstream code never needs to
/// know which backend captured a given packet.
fn event_to_meta(ev: &PacketEvent) -> Option<PacketMeta> {
    let (src_ip, dst_ip) = match ev.ip_ver {
        4 => (
            IpAddr::V4(Ipv4Addr::new(ev.src_addr[0], ev.src_addr[1], ev.src_addr[2], ev.src_addr[3])),
            IpAddr::V4(Ipv4Addr::new(ev.dst_addr[0], ev.dst_addr[1], ev.dst_addr[2], ev.dst_addr[3])),
        ),
        6 => (
            IpAddr::V6(Ipv6Addr::from(ev.src_addr)),
            IpAddr::V6(Ipv6Addr::from(ev.dst_addr)),
        ),
        _ => return None,
    };

    let proto = match ev.proto {
        p if p == PROTO_TCP => L4Proto::Tcp,
        p if p == PROTO_UDP => L4Proto::Udp,
        p if p == PROTO_ICMP => L4Proto::Icmp,
        other => L4Proto::Other(other),
    };

    Some(PacketMeta {
        // ev.ts_ns is CLOCK_BOOTTIME-relative (bpf_ktime_get_ns), not
        // wall-clock -- we don't have a cheap way to convert it
        // in-kernel without an extra helper call, and none of the
        // detectors need absolute time, only deltas. Stamp with
        // capture-time wall clock instead; see README "Clock caveat".
        ts: SystemTime::now(),
        src_ip,
        dst_ip,
        src_port: ev.src_port,
        dst_port: ev.dst_port,
        proto,
        tcp_flags: ev.tcp_flags,
        length: ev.length as usize,
        // The XDP fast path intentionally doesn't capture payload
        // bytes (see nsm-common::PacketEvent docs), so signature.rs's
        // content matching won't fire on XDP-sourced packets. Run
        // without --xdp, or extend PacketEvent with a fixed-size
        // payload window, if you need both.
        payload_head: Vec::new(),
    })
}

async fn read_events(ring: RingBuf<MapData>, tx: Sender<PacketMeta>) {
    let mut poll = match AsyncFd::new(ring) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("xdp: failed to register ring buffer fd: {e}");
            return;
        }
    };

    loop {
        let mut guard = match poll.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("xdp: ring buffer poll error: {e}");
                return;
            }
        };

        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            if item.len() != std::mem::size_of::<PacketEvent>() {
                tracing::warn!(
                    "xdp: ring buffer event size mismatch (got {}, expected {}) -- nsm-ebpf and nsm-common are out of sync, rebuild both",
                    item.len(),
                    std::mem::size_of::<PacketEvent>()
                );
                continue;
            }
            let ev: PacketEvent = *bytemuck::from_bytes(&item);
            // Drop the ring buffer item (and the borrow of `ring` it
            // holds) before the `.await` below -- holding a borrow of
            // the mmap'd ring buffer across an await point isn't
            // needed here (we've already copied everything we need
            // into the owned `ev`/`meta`) and risks making this
            // task's future non-Send, which tokio::spawn requires.
            drop(item);
            if let Some(meta) = event_to_meta(&ev) {
                // NOT blocking_send(): this closure runs inside the
                // tokio runtime (spawned via tokio::spawn), and
                // blocking_send() is for synchronous/non-async
                // callers only -- calling it here blocks a runtime
                // worker thread and panics ("Cannot block the current
                // thread from within a runtime").
                if tx.send(meta).await.is_err() {
                    tracing::warn!("xdp: analysis channel closed, stopping event reader");
                    return;
                }
            }
        }
        guard.clear_ready();
    }
}

// Must match nsm-ebpf's `Stats` struct field-for-field (repr(C), same
// order) -- there's no shared crate for it since it's an
// implementation detail of nsm-ebpf, not part of the public
// kernel/userspace wire contract in nsm-common.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct StatsRaw {
    passed: u64,
    dropped: u64,
    truncated: u64,
    parse_errors: u64,
}

// aya::maps::PerCpuArray<_, V> requires `V: aya::Pod` -- aya's own
// unsafe marker trait (an `unsafe trait Pod: Copy + 'static {}`
// asserting "safe to reinterpret as raw bytes / zero-initialize"),
// separate from `bytemuck::Pod` used in nsm-common. `StatsRaw` is
// `#[repr(C)]`, made entirely of `u64` fields (no padding, no
// pointers, no niches), and `Copy`, so this is sound.
unsafe impl aya::Pod for StatsRaw {}

async fn log_stats(stats: AyaPerCpuArray<MapData, StatsRaw>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        let Ok(per_cpu) = stats.get(&0, 0) else { continue };
        let mut total = StatsRaw::default();
        for v in per_cpu.iter() {
            total.passed += v.passed;
            total.dropped += v.dropped;
            total.truncated += v.truncated;
            total.parse_errors += v.parse_errors;
        }
        tracing::info!(
            "xdp stats: passed={} dropped={} truncated={} parse_errors={}",
            total.passed,
            total.dropped,
            total.truncated,
            total.parse_errors
        );
    }
}

// Runs with `cargo test --features xdp` on Linux (this whole module
// is gated the same way in main.rs). No root, no attached interface,
// no kernel involvement needed -- event_to_meta() is a pure function
// over a PacketEvent value, so these test the userspace half of the
// kernel/userspace boundary directly. They do NOT test whether
// nsm-ebpf itself produces well-formed PacketEvents from malformed
// wire bytes -- that's a property of the compiled, verifier-checked
// program and can only be tested by actually attaching it and sending
// real frames; see scripts/test-xdp-integration.py /
// scripts/test-xdp-integration.sh for that half.
#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> PacketEvent {
        let mut ev = PacketEvent::zeroed();
        ev.ts_ns = 123;
        ev.ifindex = 2;
        ev.length = 60;
        ev
    }

    #[test]
    fn ipv4_tcp_converts_correctly() {
        let mut ev = base_event();
        ev.ip_ver = 4;
        ev.src_addr[..4].copy_from_slice(&[10, 0, 0, 66]);
        ev.dst_addr[..4].copy_from_slice(&[10, 0, 0, 10]);
        ev.proto = PROTO_TCP;
        ev.src_port = 51234;
        ev.dst_port = 443;
        ev.tcp_flags = 0b0000_0010; // SYN
        ev.action = nsm_common::ACTION_PASSED;

        let meta = event_to_meta(&ev).expect("valid v4/TCP event should convert");
        assert_eq!(meta.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66)));
        assert_eq!(meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
        assert_eq!(meta.src_port, 51234);
        assert_eq!(meta.dst_port, 443);
        assert!(matches!(meta.proto, L4Proto::Tcp));
        assert_eq!(meta.tcp_flags, 0b0000_0010);
        assert_eq!(meta.length, 60);
        assert!(meta.payload_head.is_empty(), "XDP path never captures payload -- see nsm-common::PacketEvent docs");
    }

    #[test]
    fn ipv6_udp_converts_correctly() {
        let mut ev = base_event();
        ev.ip_ver = 6;
        ev.src_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        ev.dst_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        ev.proto = PROTO_UDP;
        ev.src_port = 53;
        ev.dst_port = 12345;
        ev.action = nsm_common::ACTION_PASSED;

        let meta = event_to_meta(&ev).expect("valid v6/UDP event should convert");
        assert_eq!(meta.src_ip, IpAddr::V6(Ipv6Addr::from(ev.src_addr)));
        assert_eq!(meta.dst_ip, IpAddr::V6(Ipv6Addr::from(ev.dst_addr)));
        assert!(matches!(meta.proto, L4Proto::Udp));
    }

    #[test]
    fn icmp_and_unrecognized_proto_are_preserved_not_dropped() {
        let mut ev = base_event();
        ev.ip_ver = 4;
        ev.proto = PROTO_ICMP;
        assert!(matches!(event_to_meta(&ev).unwrap().proto, L4Proto::Icmp));

        let mut ev = base_event();
        ev.ip_ver = 4;
        ev.proto = 47; // GRE -- deliberately not TCP/UDP/ICMP
        assert!(matches!(event_to_meta(&ev).unwrap().proto, L4Proto::Other(47)));
    }

    #[test]
    fn unknown_ip_version_is_rejected_not_guessed() {
        // A corrupted/malformed PacketEvent (ip_ver neither 4 nor 6)
        // must be dropped outright, not silently defaulted to v4 --
        // guessing here would misattribute traffic to the wrong
        // protocol family. This is the userspace half of "fail safe
        // on malformed input"; nsm-ebpf itself never emits ip_ver
        // outside {4, 6} today (see try_nsm_xdp), so in practice this
        // guards against a future kernel-side bug or nsm-ebpf/nsm
        // version skew, not a currently-reachable path.
        let mut ev = base_event();
        ev.ip_ver = 0;
        assert!(event_to_meta(&ev).is_none());

        let mut ev = base_event();
        ev.ip_ver = 7;
        assert!(event_to_meta(&ev).is_none());
    }

    #[test]
    fn dropped_action_events_still_convert() {
        // ACTION_DROPPED events (nsm-ebpf's enforcement path) carry no
        // L4 fields -- the drop decision happens before TCP/UDP
        // parsing -- but must still convert so run_event_loop can
        // log/count them rather than silently losing drop visibility.
        let mut ev = base_event();
        ev.ip_ver = 4;
        ev.action = nsm_common::ACTION_DROPPED;
        ev.src_addr[..4].copy_from_slice(&[198, 51, 100, 23]);

        let meta = event_to_meta(&ev).expect("dropped events must still convert");
        assert_eq!(meta.src_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23)));
        assert_eq!(meta.src_port, 0);
        assert_eq!(meta.dst_port, 0);
    }
}
