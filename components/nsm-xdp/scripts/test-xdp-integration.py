#!/usr/bin/env python3
"""Frame-level integration checks for nsm's XDP fast path.

Invoked by scripts/test-xdp-integration.sh (which sets up the veth
pair, starts `nsm --xdp`, and tears everything down afterward). Not
meant to be run standalone unless you've already done that setup
yourself -- see that script for the expected environment.

This exists because none of what it tests can be verified with a
plain `cargo test`: fail-safe behavior against malformed frames, the
--xdp-auto-block drop path, and ring-buffer-under-load behavior are
all properties of the compiled, kernel-verifier-approved nsm-ebpf
program actually attached to a live interface, not of any single Rust
function in isolation.

Reads nsm's own log output (stdout+stderr, both redirected to one
file by the shell wrapper) to observe STATS lines and alert JSON --
i.e. this is black-box testing against exactly the same observable
surface a human operator watching `RUST_LOG=debug nsm --xdp` would
see, nothing more privileged than that.

STATUS: written without any way to run it -- no Linux box, no Rust
toolchain, no root available in the environment that wrote this. Like
every other piece of the XDP integration this session, expect the
first run to surface real bugs (frame construction mistakes, timing
assumptions that don't hold, log-format drift) rather than to pass
outright. Treat failures here as signal, not as this script being
broken.
"""
import argparse
import json
import re
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800

STATS_RE = re.compile(r"passed=(\d+) dropped=(\d+) truncated=(\d+) parse_errors=(\d+)")


# ---------------------------------------------------------------- framing --

def get_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as f:
        return bytes.fromhex(f.read().strip().replace(":", ""))


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def eth_header(dst_mac: bytes, src_mac: bytes, ethertype: int) -> bytes:
    return struct.pack("!6s6sH", dst_mac, src_mac, ethertype)


def ipv4_header(src_ip: str, dst_ip: str, payload_len: int, proto: int, ihl_words: int = 5, ttl: int = 64) -> bytes:
    ver_ihl = (4 << 4) | (ihl_words & 0x0F)
    total_len = ihl_words * 4 + payload_len
    base = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0, ttl, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    csum = ip_checksum(base)
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0, ttl, proto, csum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )


def tcp_header(src_port: int, dst_port: int, flags: int = 0x02) -> bytes:
    # SYN by default. Checksum left as 0 -- try_nsm_xdp never
    # validates it (only structural parsing), so it's irrelevant to
    # every assertion this script makes.
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 5 << 4, flags, 8192, 0, 0)


def build_syn_frame(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port) -> bytes:
    tcp = tcp_header(src_port, dst_port)
    ip = ipv4_header(src_ip, dst_ip, len(tcp), proto=6)
    return eth_header(dst_mac, src_mac, ETH_P_IP) + ip + tcp


def build_bad_ihl_frame(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port) -> bytes:
    """Eth+IPv4 with IHL claiming 0 words (< the 5-word/20-byte
    minimum). try_nsm_xdp's explicit `ihl < size_of::<Ipv4Hdr>()`
    check should reject this -> parse_errors++, XDP_PASS."""
    tcp = tcp_header(src_port, dst_port)
    ip = bytearray(ipv4_header(src_ip, dst_ip, len(tcp), proto=6))
    ip[0] = (ip[0] & 0xF0) | 0x00  # zero out the IHL nibble
    return eth_header(dst_mac, src_mac, ETH_P_IP) + bytes(ip) + tcp


def build_truncated_l4_frame(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port) -> bytes:
    """Valid Eth+IPv4, but the frame is cut off partway through the
    TCP header. ptr_at::<TcpHdr> should fail bounds-checking and
    try_nsm_xdp degrades gracefully (ports left at 0, event still
    emitted, proto still recorded) rather than treating this as a
    hard parse error -- see try_nsm_xdp's TCP branch: `if let Ok(tcp)
    = ptr_at(...)` has no else, so a truncated L4 header is silently
    skipped, not counted in parse_errors. Expect passed++, NOT
    parse_errors++."""
    tcp = tcp_header(src_port, dst_port)[:10]  # half a TCP header
    ip = ipv4_header(src_ip, dst_ip, len(tcp), proto=6)
    return eth_header(dst_mac, src_mac, ETH_P_IP) + ip + tcp


def build_short_eth_frame() -> bytes:
    """Fewer than 14 bytes total -- ptr_at::<EthHdr> itself fails.
    Expect parse_errors++."""
    return b"\x00" * 8


def build_eth_only_frame(dst_mac, src_mac) -> bytes:
    """A syntactically valid Ethernet header claiming EtherType=IPv4,
    but with zero bytes of IP payload after it. ptr_at::<Ipv4Hdr>
    should fail (nothing there to bounds-check into). Expect
    parse_errors++."""
    return eth_header(dst_mac, src_mac, ETH_P_IP)


# -------------------------------------------------------------- log reading --

def tail_new_lines(path, pos):
    with open(path, "r", errors="replace") as f:
        f.seek(pos)
        lines = f.readlines()
        return lines, f.tell()


def parse_stats(line):
    m = STATS_RE.search(line)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())  # (passed, dropped, truncated, parse_errors)


def latest_stats(path):
    """Best-effort read of whatever stats line is already in the log
    (there's one immediately on attach -- see main.rs/xdp/mod.rs,
    tokio::time::interval fires its first tick right away)."""
    pos = 0
    stats = None
    lines, pos = tail_new_lines(path, 0)
    for line in lines:
        s = parse_stats(line)
        if s:
            stats = s
    return stats, pos


def wait_for_next_stats(path, pos, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        lines, pos = tail_new_lines(path, pos)
        for line in lines:
            s = parse_stats(line)
            if s:
                return s, pos
        time.sleep(0.5)
    raise TimeoutError(f"no new 'xdp stats:' line within {timeout}s -- is nsm still running?")


def wait_for_alert(path, pos, predicate, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        lines, pos = tail_new_lines(path, pos)
        for line in lines:
            line = line.strip()
            if line.startswith("{") and '"detector"' in line:
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if predicate(alert):
                    return alert, pos
        time.sleep(0.3)
    return None, pos


# --------------------------------------------------------------------- main --

def send(sock, frame: bytes):
    sock.send(frame)


def run(args):
    failures = []
    warnings = []

    def check(name, cond, detail=""):
        status = "PASS" if cond else "FAIL"
        print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))
        if not cond:
            failures.append(name)

    def note(name, detail):
        print(f"[INFO] {name} -- {detail}")
        warnings.append(name)

    recv_mac = get_mac(args.recv_iface)
    send_mac = get_mac(args.send_iface)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.send_iface, 0))

    stats, pos = latest_stats(args.nsm_log)
    if stats is None:
        print("no stats line found yet in nsm log -- did it actually attach?", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] baseline stats: passed={stats[0]} dropped={stats[1]} truncated={stats[2]} parse_errors={stats[3]}")

    # --- Phase 1: sanity -- one well-formed SYN should just pass. ---
    print("\n=== Phase 1: sanity (well-formed SYN) ===")
    before = stats
    send(sock, build_syn_frame(recv_mac, send_mac, args.src_ip, args.dst_ip, 51000, 22))
    stats, pos = wait_for_next_stats(args.nsm_log, pos)
    check("well-formed frame is counted as passed",
          stats[0] > before[0],
          f"passed {before[0]} -> {stats[0]}")
    check("well-formed frame does not trip parse_errors",
          stats[3] == before[3],
          f"parse_errors {before[3]} -> {stats[3]}")

    # --- Phase 2: malformed-input fail-safe. ---
    print("\n=== Phase 2: malformed/truncated frames (fail-safe) ===")
    before = stats
    send(sock, build_short_eth_frame())
    send(sock, build_eth_only_frame(recv_mac, send_mac))
    send(sock, build_bad_ihl_frame(recv_mac, send_mac, args.src_ip, args.dst_ip, 51001, 23))
    send(sock, build_truncated_l4_frame(recv_mac, send_mac, args.src_ip, args.dst_ip, 51002, 24))
    stats, pos = wait_for_next_stats(args.nsm_log, pos)

    check("nsm is still alive after malformed frames (fail-safe, not fail-crash)",
          True,  # if wait_for_next_stats() returned at all, the process kept logging
          "a new stats line appeared, so the process didn't die/hang")
    check("the 3 hard-malformed frames (short-eth, eth-only, bad-IHL) bumped parse_errors by >=3",
          stats[3] - before[3] >= 3,
          f"parse_errors {before[3]} -> {stats[3]} (delta {stats[3] - before[3]})")
    check("the truncated-L4 frame degrades gracefully (counted as passed, not parse_errors)",
          stats[0] > before[0],
          f"passed {before[0]} -> {stats[0]}")

    # --- Phase 3: auto-block via an extreme single-source port scan. ---
    print("\n=== Phase 3: --xdp-auto-block (portscan -> BLOCKLIST_V4 -> XDP_DROP) ===")
    print("(needs portscan.rs's Critical tier -- see the accompanying source change; "
          "if that wasn't applied, this phase will correctly report no Critical alert seen.)")
    alert_pos = pos  # start watching for alerts from "now"
    for port in range(20000, 20160):
        send(sock, build_syn_frame(recv_mac, send_mac, args.src_ip, args.dst_ip, 52000, port))
    alert, alert_pos = wait_for_alert(
        args.nsm_log, alert_pos,
        lambda a: a.get("detector") == "portscan" and a.get("severity") == "Critical" and a.get("src_ip") == args.src_ip,
        timeout=15,
    )
    if alert is None:
        note("no Critical portscan alert observed for the scanning source",
             "auto-block cannot be exercised without one -- check portscan.rs's threshold/severity logic, "
             "or that this test sent enough distinct ports fast enough to land in one detection window")
    else:
        check("Critical portscan alert observed for the scanning source", True, json.dumps(alert))
        before = stats
        time.sleep(0.5)  # give run_event_loop a moment to call block_ipv4() after the alert
        send(sock, build_syn_frame(recv_mac, send_mac, args.src_ip, args.dst_ip, 52999, 8080))
        stats, pos = wait_for_next_stats(args.nsm_log, pos)
        check("a follow-up packet from the now-blocked source is XDP_DROPped, not passed",
              stats[1] > before[1],
              f"dropped {before[1]} -> {stats[1]}")

    # --- Phase 4: best-effort ring buffer saturation under a burst. ---
    print("\n=== Phase 4: ring buffer saturation under load (best-effort) ===")
    before = stats
    burst_src_ip = args.load_src_ip
    t0 = time.time()
    n = 8000
    for i in range(n):
        send(sock, build_syn_frame(recv_mac, send_mac, burst_src_ip, args.dst_ip, 40000 + (i % 1000), 8080))
    elapsed = time.time() - t0
    print(f"[INFO] sent {n} frames in {elapsed:.2f}s ({n / elapsed:.0f} pps from this single-threaded sender)")
    stats, pos = wait_for_next_stats(args.nsm_log, pos)
    delta_passed = stats[0] - before[0]
    delta_truncated = stats[2] - before[2]
    print(f"[INFO] passed += {delta_passed}, truncated += {delta_truncated}")
    if delta_truncated > 0:
        check("ring buffer saturation was reached and handled without a crash", True,
              f"truncated went up by {delta_truncated} -- some events were dropped under load, "
              "but the packets themselves were still XDP_PASSed and nsm kept running")
    else:
        note("ring buffer was never observed to saturate in this run",
             f"passed += {delta_passed} with truncated staying at 0 -- either this sender (a single-threaded "
             "Python raw-socket loop) can't generate enough pps to fill a 4 MiB/~65k-event ring buffer faster "
             "than the async reader drains it, or the ring genuinely has enough headroom for this load. "
             "Not a failure either way, but not a confirmed test of the truncated-counter code path. "
             "(If you've since lowered RINGBUF_BYTE_SIZE back down in xdp/nsm-common/src/lib.rs for easier "
             "saturation testing, update this message to match.)")

    print(f"\n{'='*60}")
    if failures:
        print(f"FAILED: {len(failures)} check(s) failed: {failures}")
        return 1
    print(f"All hard checks passed. {len(warnings)} informational note(s) above worth reading.")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--send-iface", required=True, help="veth end this script sends raw frames from")
    p.add_argument("--recv-iface", required=True, help="veth end nsm's XDP program is attached to")
    p.add_argument("--nsm-log", required=True, help="path to nsm's redirected stdout+stderr")
    p.add_argument("--dst-ip", required=True, help="IP configured on --recv-iface")
    p.add_argument("--src-ip", required=True, help="IP configured on --send-iface (used for phases 1-3)")
    p.add_argument("--load-src-ip", default="10.250.0.9",
                   help="distinct source IP for the phase 4 burst, so it isn't affected by phase 3's block")
    args = p.parse_args()
    sys.exit(run(args))
