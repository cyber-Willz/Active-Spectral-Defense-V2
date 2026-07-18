# nsm — a concise, cross-platform Network Security Monitor in Rust

A single-binary NSM: live packet capture → 5-tuple flow tracking →
five parallel detectors → NDJSON alerts on stdout. Runs on **Linux and
Windows** from the same source tree — `pnet`'s datalink layer abstracts
raw `AF_PACKET` sockets on Linux and Npcap/WinPcap on Windows behind
one API, so `packet.rs`, `flow.rs`, and every detector are 100%
platform-agnostic. Only interface naming and privilege elevation
differ, both handled in `capture.rs` via `cfg(unix)` / `cfg(windows)`.

## Build — Linux

```bash
cargo build --release
sudo ./target/release/nsm --list-interfaces
sudo ./target/release/nsm --interface eth0
```

No extra setup needed: raw-socket capture works out of the box with
root or `CAP_NET_RAW` (see below).

## Build — Windows

Three one-time setup steps (this is `pnet`'s requirement, not this
project's):

1. **Install Npcap** — https://npcap.com/#download — during install,
   check **"Install Npcap in WinPcap API-compatible Mode."**
2. **Get the Npcap SDK** — https://npcap.com/#download (separate "SDK"
   download) — unzip it somewhere, e.g. `C:\npcap-sdk`.
3. **Point the linker at it** before building, in PowerShell:
   ```powershell
   $env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
   cargo build --release
   ```
   You must use the **MSVC** Rust toolchain (`rustup default
   stable-x86_64-pc-windows-msvc`), not the GNU one — Npcap's
   `Packet.lib` only links against MSVC.

Then, from an **elevated (Administrator)** terminal:

```powershell
.\target\release\nsm.exe --list-interfaces
.\target\release\nsm.exe --interface 2
```

Windows device names are opaque (`\Device\NPF_{9B2E1B4E-...}`), so
`--list-interfaces` prints a numeric index and description — pass
either the index (`--interface 2`) or a substring of the description
(`--interface "Ethernet"`) instead of the raw name.

## Build — XDP fast path (Linux only, optional)

By default `nsm` captures via `pnet`/`AF_PACKET`, same as always. On
Linux you can opt into an XDP-based capture + enforcement path instead:
packets are parsed in-kernel at the earliest RX hook, mirrored to
userspace over a lock-free ring buffer instead of a per-packet
`AF_PACKET` copy, and confirmed attackers can be `XDP_DROP`ped by the
kernel before they reach the network stack at all.

This is two separate builds:

1. **The eBPF program** (`xdp/nsm-ebpf`) — a freestanding, `no_std`
   binary that gets loaded into the kernel. Needs its own toolchain:

   ```bash
   rustup toolchain install nightly --component rust-src
   cargo install bpf-linker   # needs LLVM: apt install llvm-dev libclang-dev clang
   ./scripts/build-ebpf.sh
   ```

   This produces `xdp/nsm-ebpf/target/bpfel-unknown-none/release/nsm-ebpf`.

2. **`nsm` itself, with the `xdp` feature**:

   ```bash
   cargo build --release --features xdp
   sudo ./target/release/nsm --interface eth0 --xdp
   # native XDP unsupported by this NIC's driver? fall back to SKB mode:
   sudo ./target/release/nsm --interface eth0 --xdp --xdp-mode skb
   # observe what auto-block WOULD do, without dropping anything yet:
   sudo ./target/release/nsm --interface eth0 --xdp --xdp-auto-block
   # once you've validated that against real traffic, actually enforce it:
   sudo ./target/release/nsm --interface eth0 --xdp \
       --xdp-auto-block --xdp-auto-block-enforce \
       --xdp-allowlist 10.0.0.1 --xdp-allowlist 192.168.1.0/24 \
       --xdp-control-socket /run/nsm/control.sock
   ```

   Without `--features xdp` (the default), `nsm` builds exactly as
   before — the `xdp` module, its `aya` dependency, and the `--xdp*`
   flags don't exist in the binary at all.

Requires Linux 5.8+ (ring buffer maps), root or
`CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`, and — for `--xdp-mode native`
(the default) — a NIC driver with native XDP support; `--xdp-mode skb`
works on any NIC as a slower fallback.

### Auto-block safety controls

`--xdp-auto-block` alone only **observes** — it logs what it would
block (`AUTO-BLOCK CANDIDATE ...`) without touching the kernel map.
Real enforcement is a separate, deliberate opt-in:

| Flag | What it does |
|---|---|
| `--xdp-auto-block` | Consider Critical alerts for blocking; observe-only by itself. |
| `--xdp-auto-block-enforce` | Actually insert candidates into `BLOCKLIST_V4` (requires `--xdp-auto-block`). |
| `--xdp-allowlist <ip-or-cidr>` | Never block this address/range, no matter what (repeatable). |
| `--xdp-block-prefix-len <1-32>` | CIDR width for new blocks; 32 (default) = exact host only. |
| `--xdp-auto-block-rate-limit <N>` / `--xdp-auto-block-rate-window-secs <S>` | Cap new blocks to N per S-second window (default 20/60s); beyond that, further blocks are skipped and logged loudly rather than risking a false-positive storm. |
| `--xdp-control-socket <path>` | Unix socket serving `BLOCK`/`UNBLOCK`/`LIST`/`STATUS` — the recovery path if something important gets blocked by mistake. |

The interface's own local IPs are **always** protected from auto-block
automatically, on top of whatever `--xdp-allowlist` you configure — a
detector misattributing traffic to your own gateway shouldn't be able
to firewall it.

Talking to the control socket is just plain text, one command per
line:

```bash
echo "STATUS" | socat - UNIX-CONNECT:/run/nsm/control.sock
echo "LIST" | socat - UNIX-CONNECT:/run/nsm/control.sock
echo "UNBLOCK 203.0.113.9" | socat - UNIX-CONNECT:/run/nsm/control.sock
echo "BLOCK 203.0.113.9/24 600" | socat - UNIX-CONNECT:/run/nsm/control.sock
# no socat? nc -U also works, or anything that can write a line to a Unix socket
```

**On CIDR-width blocking (`--xdp-block-prefix-len`)**: widening past
32 helps against a scanner rotating source addresses within a real,
contiguous range — it does **nothing** against genuinely spoofed
source addresses (no source-IP-based scheme can defend against that),
and it widens the false-positive blast radius to everyone else sharing
that range (e.g. behind the same CGNAT block). Treat it as a
deliberate trade-off, not a default to reach for casually.

**Highest-risk change in this codebase, flagged explicitly**:
`BLOCKLIST_V4` moved from a plain `HashMap` (exact `/32` match only)
to an `LpmTrie` (CIDR-aware longest-prefix match) to make
`--xdp-block-prefix-len` possible at all. This is real kernel-side
surgery — a new map type, a new key-construction path in both
`nsm-ebpf` and `src/xdp/mod.rs` — that needs to pass the verifier
again and has not been run anywhere; see "Notes / limitations" below
for the specific API surface (`Key<K>`'s accessor methods, in
particular) that's an educated guess rather than something confirmed
against real compiler output.

### Operational hardening

Four gaps worth being explicit about, and what's done about each:

**Privilege drop after attach.** `nsm` needs full root/`CAP_BPF`+
`CAP_NET_ADMIN`+`CAP_NET_RAW` to load and attach the XDP program, but
not for anything after that. Once attach succeeds,
`src/xdp/mod.rs::drop_privileges()` shrinks the bounding, effective,
and permitted capability sets down to just `{CAP_BPF, CAP_NET_ADMIN}`
— everything else (including `CAP_NET_RAW`, `CAP_SYS_ADMIN` if
present, etc.) is dropped. It deliberately does *not* drop to zero:
whether ongoing map element operations (block/unblock/list) actually
still require `CAP_BPF` on an already-open map fd, versus that only
being checked once at map-creation time, isn't confirmed against a
real kernel — dropping too far risks turning "block a confirmed
attacker" into a logged-but-easy-to-miss permission failure, which is
worse than retaining slightly more privilege than the theoretical
minimum. It also doesn't drop the process's UID — still runs as
whatever user launched it. Full UID drop is a larger change (control
socket and persistence file ownership both need to follow) and isn't
attempted here.

**Blocklist persistence.** `--xdp-blocklist-persist <path>` rewrites
the blocklist to a plain-text file on every block/unblock and reloads
it on startup (skipping any entries that already expired while the
process was down). Without this flag, a process restart — crash,
deliberate, or one an attacker manages to trigger — silently wipes
every active block. The flow table is deliberately *not* persisted
the same way: it's detection-heuristic state that rebuilds itself
within a sliding window of seconds, not a security control whose loss
has real consequences, so the added complexity wasn't worth it there.

**What actually happens if `nsm` crashes or is killed**, since this
turned out to be more specific than "any crash is bad": XDP attachment
in `aya` is a `bpf_link` — a file-descriptor-backed kernel object whose
lifetime is tied to that fd. The kernel closes *all* of a process's
file descriptors on exit, for any reason, including `SIGKILL` — so a
genuinely crashed or killed process auto-detaches cleanly with no
manual intervention needed. The actual failure mode, and the one this
project hit firsthand mid-session, is a process that's **suspended,
not exited** (`Ctrl+Z` / job-control stop) — its file descriptors stay
open because the process itself still exists, so the XDP program stays
attached with nothing managing it. Two mitigations:
- `--xdp-force-detach`: if attaching fails with "device or resource
  busy" (an existing attachment), shell out to
  `ip link set dev <iface> xdpgeneric/xdpdrv off` — the exact commands
  used to manually recover from this earlier — and retry once, instead
  of just failing.
- A systemd watchdog (`scripts/nsm.service`): the event loop bumps a
  liveness timestamp on every `select!` iteration (including a 5s
  idle-tick so a quiet interface doesn't look indistinguishable from a
  genuinely hung loop); a checker task sends `WATCHDOG=1` to systemd
  only while that timestamp is fresh. A stuck-but-alive process stops
  heartbeating, and systemd's own `WatchdogSec=` kills and restarts it
  — this is the actual fix for the suspended-process case, since a
  stuck process can't reliably alarm on itself. Copy
  `scripts/nsm.service` to `/etc/systemd/system/`, edit the
  `ExecStart` line for your interface/flags, `systemctl enable --now
  nsm`.

**Ring buffer contention under multi-queue NIC throughput.**
`BPF_MAP_TYPE_RINGBUF` is a single buffer shared across all CPUs, with
reservation serialized through a spinlock — a real, kernel-documented
contention point once multiple cores submit concurrently at high
packet rates. The real fix is N per-CPU ring buffers (one per RSS
queue, selected via `bpf_get_smp_processor_id()`); that's a genuine
kernel-side redesign — new map layout, new lookup logic in
`nsm-ebpf`, a fresh trip through the verifier — and wasn't attempted
here, deliberately: stacking another unverified kernel change on top
of the `LpmTrie` migration (which hasn't even been compile-checked
yet as of this writing) isn't a responsible order of operations. What
*is* done: `RINGBUF_BYTE_SIZE` was bumped from 1 MiB to 4 MiB
(~65k in-flight events instead of ~16k), which raises the bar before
`STATS.truncated` starts climbing under a burst, without touching
contention itself or any already-verified code. If `truncated` shows
up under real load, that constant (in `xdp/nsm-common/src/lib.rs`) is
the first knob to try; per-CPU ring buffers remain the real fix,
scoped as future work.

## Run without any of the above (either OS)

```bash
# No root/Administrator, no NIC, no Npcap needed --
# exercises every detector with synthetic traffic:
./target/release/nsm --simulate
```

Alerts stream as newline-delimited JSON on stdout (pipe into `jq`,
Filebeat, Vector, or a SIEM); operational logs go to stderr so the two
never mix. Ctrl+C shuts down cleanly on both platforms.

```bash
./target/release/nsm --simulate | jq 'select(.severity == "High" or .severity == "Critical")'
```

## Architecture

```
capture.rs   pnet datalink capture (raw sockets on Linux, Npcap on Windows) -> blocking thread -> mpsc channel
             cross-platform interface resolution (name / index / description substring)
             OS-specific privilege-error hints (root+CAP_NET_RAW vs elevated Administrator+Npcap)
src/xdp/     (Linux, --features xdp) userspace loader: attaches xdp/nsm-ebpf,
mod.rs       streams ring-buffer events -> the SAME mpsc channel as capture.rs,
             exposes block_ipv4()/unblock_ipv4() (allowlist + rate-limit +
             observe/enforce gated) plus a Unix-socket control interface
xdp/nsm-ebpf in-kernel XDP program (separate no_std build, see below): parses
  src/       headers, XDP_DROPs blocklisted sources/ranges via a CIDR-aware
             LpmTrie, mirrors PacketEvents to a ring buffer
xdp/nsm-common  #[repr(C)] PacketEvent struct shared by both sides of that boundary
packet.rs    Ethernet/IPv4/IPv6/TCP/UDP/ICMP parsing -> PacketMeta (fully platform-agnostic)
flow.rs      DashMap-backed bidirectional 5-tuple flow table (conn.log-style), idle reaping
detect/
  portscan.rs    distinct dest-port / dest-host count per source in a sliding window
  synflood.rs    SYN rate per destination, weighted by number of distinct sources
  dns_tunnel.rs  DNS label length + Shannon entropy + query-rate heuristics
  beacon.rs      coefficient-of-variation on connection inter-arrival times (C2 check-ins)
  signature.rs   Suricata-style byte-pattern content matching
alert.rs     severity-tagged Alert struct, JSON emission
sim.rs       synthetic traffic generator for --simulate (works identically on both OSes)
```

Each detector maintains its own bounded, self-expiring state
(`DashMap` + sliding windows), so the engine is a single
`analyze(&PacketMeta) -> Vec<Alert>` call per packet with no shared
locks across detectors, and no platform-specific code outside
`capture.rs` (pnet) / `src/xdp/` (XDP).

### eBPF/XDP fast path

`src/xdp/mod.rs` is a second *producer* for the exact same
`mpsc::Sender<PacketMeta>` that `capture::spawn_capture_thread` already
feeds — every detector, `flow.rs`, and `run_event_loop` are completely
unaware of which backend captured a given packet. `--xdp` just changes
who calls `tx.send(meta)`:

- **Capture**: `xdp/nsm-ebpf` parses Ethernet/IPv4/IPv6/TCP/UDP headers
  directly out of the packet buffer at the XDP hook (in the NIC driver
  in native mode) and pushes a fixed-size `PacketEvent` into a `RingBuf`
  map. Userspace reads it asynchronously (`tokio::io::unix::AsyncFd`
  over the ring buffer's fd) and converts each event back into the
  same `PacketMeta` the pnet path produces.
- **Enforcement**: `BLOCKLIST_V4` is a `BPF_MAP_TYPE_LPM_TRIE` (source
  IPv4 prefix -> expiry timestamp), checked before any header parsing
  happens. With `--xdp-auto-block --xdp-auto-block-enforce`,
  `run_event_loop` pushes the source IP of any `Critical` alert into
  that map (subject to the allowlist and rate limiter -- see "Auto-block
  safety controls" above); the *next* packet from a blocked source or
  range is `XDP_DROP`ped in the driver, before `sk_buff` allocation or
  the network stack — actual bypass, not just faster logging.

Trade-off: the XDP fast path doesn't capture payload bytes (see
`nsm-common::PacketEvent`'s docs), so `signature.rs`'s content matching
never fires on XDP-sourced packets. Everything else (port scan, SYN
flood, DNS tunneling, beaconing) works identically either way, since
they only ever looked at `PacketMeta`'s header fields to begin with.

## Detectors, briefly

- **Port scan** — flags a source touching ≥20 distinct ports on one
  host (vertical) or ≥15 distinct hosts (horizontal) within 10s.
  Escalates to Critical at 5× the port threshold (≥100 distinct ports
  by default) — this tier exists specifically so `--xdp-auto-block`
  has a single-source, high-confidence signal to act on; tune the
  multiplier in `portscan.rs` if it's too aggressive/lax for your
  traffic.
- **SYN flood** — flags ≥100 SYNs at one destination within 5s;
  escalates to Critical once more than 20 distinct sources are
  involved. Note: because a flood is by nature multi-source, these
  Critical alerts never carry a single attributable `src_ip` — so
  `--xdp-auto-block` (which blocks by source IP) can never fire on a
  synflood alert, only on portscan's. Blocking one of many flood
  sources wouldn't meaningfully mitigate a distributed flood anyway.
- **DNS tunneling** — combines label length, Shannon entropy of the
  query name, and per-source query rate; five-plus high-entropy/long
  labels in 30s raises a High alert.
- **Beaconing** — tracks inter-arrival time between new connections to
  the same (src, dst, port); a coefficient of variation ≤0.15 over 6+
  samples looks like scheduled malware check-in traffic rather than
  human-driven use.
- **Signatures** — a small default ruleset (cleartext basic-auth,
  UNION SELECT, `${jndi:`, EICAR string, etc.) as a byte-substring
  content-match engine; trivial to extend with your own `Rule` entries.

## Extending

Add a new detector by implementing `observe(&PacketMeta) -> Option<Alert>`
(or `Vec<Alert>`) with your own state struct, then wire it into
`DetectionEngine::new()` / `analyze()` in `detect/mod.rs`. Every
detector owns its state independently, so new ones can't affect
existing detection paths, and none of them need to know which OS
they're running on.

## Testing

Two tiers, because some properties genuinely can't be verified without
a real kernel:

**Unit tests** — `cargo test` (add `--features xdp` on Linux to also
cover the XDP-specific modules). No root, no privileges, no attached
interface, nothing environment-dependent:
- `nsm-common`: `PacketEvent`'s layout (the 64-byte/no-padding
  assertion), zeroing, and byte round-tripping through `bytemuck` --
  exactly what crosses the kernel/userspace ring buffer boundary.
- `src/xdp/mod.rs`: `event_to_meta()` — every `PacketEvent` →
  `PacketMeta` conversion path (v4/v6, TCP/UDP/ICMP/unknown proto,
  `ACTION_DROPPED` events, and that a malformed `ip_ver` is rejected
  rather than silently guessed).
- `xdp/nsm-ebpf`: `tcp_flags_byte()`, the one pure/leaf function in
  the kernel program with no pointer arithmetic or map access, tested
  against raw-byte-derived `TcpHdr`s covering every flag combination.
  (Deliberately does *not* extend to `try_nsm_xdp`'s pointer-chasing
  bounds-checking code — that already passed the real kernel verifier
  once and refactoring it to be more "testable" without the ability
  to re-verify here would risk breaking it for a theoretical benefit.)

What unit tests structurally *cannot* cover: whether the actual
compiled, verifier-approved `nsm-ebpf` binary fails safe against
malformed wire bytes, whether `--xdp-auto-block` really drops traffic
once a source lands in `BLOCKLIST_V4`, and how the ring buffer behaves
under real load. Those are properties of the loaded, attached program,
not of any Rust function in isolation.

**Privileged integration test** — `sudo ./scripts/test-xdp-integration.sh`
(Linux, root, `python3`, `nc`; needs `nsm` already built with
`--features xdp` and `xdp/nsm-ebpf` already built via
`scripts/build-ebpf.sh`). Creates an isolated veth pair, attaches the
real XDP program to one end, and from the other end:
1. sends a well-formed SYN as a sanity check;
2. sends four deliberately malformed frames (too short to contain an
   Ethernet header, an Ethernet header with no IP payload behind it,
   an IPv4 header with an invalid IHL, and a truncated TCP header) and
   checks `STATS.parse_errors`/`STATS.passed` move the way the code's
   actual fail-safe behavior predicts, *and* that nsm is still alive
   afterward;
3. runs an extreme single-source port scan to trigger portscan's
   Critical tier, watches for `--xdp-auto-block` to push that source
   into `BLOCKLIST_V4`, then confirms a follow-up packet from it gets
   `XDP_DROP`ped (`STATS.dropped` increments) instead of passed;
4. bursts several thousand frames from a Python raw socket as a
   best-effort load test, reporting whether `STATS.truncated` ever
   moved — informational either way, since whether a single-threaded
   Python sender can out-pace the async ring buffer reader depends on
   the host, not on correctness;
5. (shell script only, not the Python half) blocks an address via the
   control socket, confirms the persistence file was written
   immediately (no polling/sleep needed — `persist_blocklist()` runs
   synchronously inside the same call that answers `BLOCK`), stops
   `nsm` with a real `SIGTERM`, restarts it pointed at the same
   `--xdp-blocklist-persist` path, and confirms both the startup log
   (`restored 1 block(s)...`) and a fresh `LIST` over the control
   socket show the block survived.

**Status**: phases 1-4 have been run for real against a live kernel
and passed, including everything from the `LpmTrie` migration,
capability drop, and control socket — `BLOCK`/`LIST`/`UNBLOCK` were
each independently confirmed working by hand before phase 5 (which
exercises the same commands, just scripted) was written. Phase 5 itself
is new and has not been run anywhere; treat it with the same "expect a
debug round" posture as everything else the first time through.

## Notes / limitations

- IPv4/IPv6 + TCP/UDP/ICMP only; no VLAN tag or tunnel (GRE/VXLAN)
  unwrapping yet.
- The DNS parser is intentionally minimal (label-walk only, no full
  RR parsing) — sufficient for the tunneling heuristic, not a general
  DNS decoder.
- Thresholds are tuned for illustration; in production, calibrate them
  against your own baseline traffic to control false-positive rate.
- This is a monitoring/detection tool only in its default (pnet)
  configuration — it does not block or drop traffic unless you opt
  into `--xdp --xdp-auto-block --xdp-auto-block-enforce` (see below).
- The Windows build steps above (Npcap + SDK + MSVC + `$env:LIB`) come
  from `pnet_datalink` itself; this project's code doesn't add any
  extra Windows-specific dependencies.
- **XDP fast path (`--xdp`) is still a monitoring/enforcement tool,
  not a full IPS**: `BLOCKLIST_V4` is IPv4-only (no IPv6) and, even
  with CIDR-width blocking (`--xdp-block-prefix-len`), it's still
  source-IP-based — genuinely spoofed source addresses can't be
  meaningfully blocked by any scheme that keys off the source address,
  full stop. Pair auto-block with your own judgment about which
  detectors you trust to drive it, and see "Auto-block safety
  controls" above for the allowlist/rate-limit/observe-enforce
  machinery that exists specifically to bound the damage a bad
  detector verdict can do.
- **Clock caveat**: `PacketEvent::ts_ns` is `bpf_ktime_get_ns()`
  (`CLOCK_BOOTTIME`-relative), not wall-clock. `src/xdp/mod.rs`
  currently stamps converted `PacketMeta`s with capture-time wall
  clock rather than converting it, since none of the detectors need
  absolute time, only deltas between consecutive packets. If you add
  a detector that cares about true packet arrival time under load,
  revisit this.
- `xdp/nsm-ebpf` and `src/xdp/mod.rs` were written against `aya 0.13`
  /`network-types 0.0.8` from training knowledge, in a sandbox with no
  Rust toolchain available to compile-check them — `aya`'s API has
  shifted across versions before. Run `cargo check` (userspace) and
  `scripts/build-ebpf.sh` (kernel side) first and expect to fix minor
  method-name drift, especially in `network_types::tcp::TcpHdr`'s
  bitfield accessors and `aya::maps::RingBuf`'s async read loop.
- **Highest-risk unverified piece: `LpmTrie`'s `Key<K>` accessor API.**
  `src/xdp/mod.rs`'s `list_blocked()` and `sweep_expired_blocklist()`
  call `.data()`/`.prefix_len()` on values of type `Key<[u8; 4]>`
  yielded by iterating the map — these method names are an educated
  guess, not something either of us has seen real compiler output
  for. If `cargo check --features xdp` fails there, the likely fix is
  field access instead (`key.data`/`key.prefix_len`) rather than
  method calls; both are explicitly flagged in the code comments at
  each call site. `Key::new(prefix_len, data)`'s constructor shape
  (used everywhere blocks are inserted, in both `nsm-ebpf` and
  userspace) is a similarly unverified guess, though a lower-risk one
  since it's a single, consistent pattern used the same way in both
  places rather than several different accessor guesses.
- **Second unverified piece, lower risk: the `caps` crate's exact
  API** (`caps::read`/`caps::set`/`caps::drop`, the `CapSet`/
  `Capability` enum variant names) in `drop_privileges()`. `caps` is a
  small, long-stable crate, so this is a milder guess than the `aya`
  API surface above, but still unconfirmed against real compiler
  output. Failures here are caught and logged rather than propagated
  (see the function's doc comment), so worst case if something's
  wrong is a compile error to fix, not a runtime surprise.
- **No in-kernel `debug!()` logging.** An earlier version used
  `aya-log-ebpf`'s `debug!()` macro for one log line on the blocklist
  drop path. That macro backs itself with its own ring buffer map
  (`AYA_LOGS`), and userspace's `EbpfLogger::init()` call discarded
  its returned handle without keeping it alive — which closed that
  map's fd immediately, so the *next* syscall (`BPF_PROG_LOAD`) failed
  with `fd N is not pointing to valid bpf_map`, confirmed via
  `strace -f -e trace=bpf`. Fixing that properly means getting
  `EbpfLogger`'s async read-loop lifetime right; instead, the logger
  integration was removed entirely, since drop visibility already
  exists via `STATS.dropped` and an `ACTION_DROPPED` event on the
  (unrelated, unaffected) `EVENTS` map. If you reintroduce
  `aya-log-ebpf`, keep the `EbpfLogger` alive for the process
  lifetime (spawn a task that polls and flushes it) rather than
  discarding it.

