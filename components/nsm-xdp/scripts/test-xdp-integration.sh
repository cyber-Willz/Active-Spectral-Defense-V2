#!/usr/bin/env bash
# Privileged, Linux-only integration test for the XDP fast path.
#
# Exercises things unit tests structurally cannot, because they're
# properties of the COMPILED, KERNEL-VERIFIER-APPROVED nsm-ebpf
# program actually attached to a live interface (and, for Phase 5, of
# a real process restart), not of any Rust function in isolation:
#   1. fail-safe behavior against malformed/truncated frames
#   2. the --xdp-auto-block / BLOCKLIST_V4 drop path
#   3. best-effort ring buffer saturation under a traffic burst
#   4. blocklist persistence surviving a real process restart
#
# Needs: root, Linux, `cargo build --release --features xdp`,
# `./scripts/build-ebpf.sh` already run, python3, nc (netcat, for the
# control-socket persistence check -- the same command-line tool used
# to manually validate BLOCK/UNBLOCK/LIST earlier in this project).
#
# Creates a veth pair (nsm-test-a / nsm-test-b) in the default network
# namespace and attaches XDP to nsm-test-a. Doesn't touch any other
# interface. Cleans up on exit -- including on failure, via the trap
# below. If this is ever killed with SIGKILL instead of a normal
# exit/SIGTERM, the veth pair and/or XDP attachment may be left
# behind; rerunning this script cleans up a stale nsm-test-a from a
# previous run automatically, or see the `cleanup` function below for
# the manual commands.
#
# STATUS: Phases 1-4 (via test-xdp-integration.py) have been run for
# real against a live kernel and passed, including the LpmTrie/
# capability-drop/control-socket work from later rounds -- see the
# project history for the actual transcript. Phase 5 (persistence
# across a restart) below is new and has NOT been run anywhere yet;
# treat it with the same "expect a debug round" posture as everything
# else the first time through.
set -euo pipefail

VETH_A=nsm-test-a
VETH_B=nsm-test-b
NSM_BIN=./target/release/nsm
EBPF_OBJ=xdp/nsm-ebpf/target/bpfel-unknown-none/release/nsm-ebpf
PERSIST_FILE="$(mktemp /tmp/nsm-xdp-test-blocklist.XXXXXX)"
CTRL_SOCK="$(mktemp -u /tmp/nsm-xdp-test-ctrl.XXXXXX.sock)"
NSM_PID=""
LOG_FILE="$(mktemp /tmp/nsm-xdp-test.XXXXXX.log)"
LOG_FILE_2="$(mktemp /tmp/nsm-xdp-test-restart.XXXXXX.log)"

cleanup() {
    echo "--- cleanup ---"
    if [[ -n "$NSM_PID" ]] && kill -0 "$NSM_PID" 2>/dev/null; then
        kill -TERM "$NSM_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$NSM_PID" 2>/dev/null || true
    fi
    ip link set dev "$VETH_A" xdpgeneric off 2>/dev/null || true
    ip link set dev "$VETH_A" xdpdrv off 2>/dev/null || true
    ip link del "$VETH_A" 2>/dev/null || true
    rm -f "$PERSIST_FILE" "$CTRL_SOCK"
    echo "logs preserved at: $LOG_FILE and $LOG_FILE_2"
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (needs CAP_BPF/CAP_NET_ADMIN to attach XDP)" >&2
    exit 1
fi
if [[ ! -x "$NSM_BIN" ]]; then
    echo "missing $NSM_BIN -- run: cargo build --release --features xdp" >&2
    exit 1
fi
if [[ ! -f "$EBPF_OBJ" ]]; then
    echo "missing $EBPF_OBJ -- run: ./scripts/build-ebpf.sh" >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    echo "python3 is required (used to craft raw frames byte-exactly)" >&2
    exit 1
fi
if ! command -v nc >/dev/null; then
    echo "nc (netcat) is required for the Phase 5 control-socket check" >&2
    exit 1
fi

echo "--- setting up veth pair $VETH_A <-> $VETH_B ---"
ip link del "$VETH_A" 2>/dev/null || true   # in case a previous run left it behind
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip addr add 10.250.0.1/30 dev "$VETH_A"
ip addr add 10.250.0.2/30 dev "$VETH_B"
ip link set "$VETH_A" up
ip link set "$VETH_B" up

# Launches nsm with the flags all phases share, writing to $1 (log
# file), and waits (up to ~10s) for it to report a successful attach.
# Sets NSM_PID as a side effect. Exits the whole script on failure --
# a failed attach at any point (initial launch or the Phase 5 restart)
# means there's nothing further worth testing.
launch_and_wait_for_attach() {
    local log_file="$1"
    RUST_LOG=nsm=debug,aya=info "$NSM_BIN" --interface "$VETH_A" --xdp --xdp-mode skb \
        --xdp-auto-block --xdp-auto-block-enforce --xdp-block-secs 10 \
        --xdp-blocklist-persist "$PERSIST_FILE" \
        --xdp-control-socket "$CTRL_SOCK" \
        >"$log_file" 2>&1 &
    NSM_PID=$!

    local attached=0
    for _ in $(seq 1 20); do
        if grep -q "XDP program attached" "$log_file" 2>/dev/null; then
            attached=1
            break
        fi
        if ! kill -0 "$NSM_PID" 2>/dev/null; then
            echo "nsm exited before attaching -- full log ($log_file):" >&2
            cat "$log_file" >&2
            exit 1
        fi
        sleep 0.5
    done
    if [[ "$attached" -ne 1 ]]; then
        echo "nsm did not report attach within 10s -- full log ($log_file):" >&2
        cat "$log_file" >&2
        exit 1
    fi
}

echo "--- starting nsm (--xdp --xdp-mode skb --xdp-auto-block --xdp-auto-block-enforce, persist+control-socket enabled) ---"
echo "    log: $LOG_FILE"
launch_and_wait_for_attach "$LOG_FILE"
echo "attached."

echo "--- running frame-level checks (phases 1-4) ---"
set +e
python3 "$(dirname "$0")/test-xdp-integration.py" \
    --send-iface "$VETH_B" \
    --recv-iface "$VETH_A" \
    --nsm-log "$LOG_FILE" \
    --dst-ip 10.250.0.1 \
    --src-ip 10.250.0.2
RESULT=$?
set -e

echo ""
echo "=== Phase 5: blocklist persistence across a real restart ==="
PHASE5_FAIL=0

echo "--- blocking a test address via the control socket ---"
BLOCK_RESP="$(echo "BLOCK 198.51.100.42/32 3600" | nc -U -w2 "$CTRL_SOCK")"
echo "  BLOCK response: $BLOCK_RESP"
if [[ "$BLOCK_RESP" != OK:* ]]; then
    echo "  [FAIL] BLOCK command did not return OK -- can't test persistence of something that was never blocked"
    PHASE5_FAIL=1
else
    # persist_blocklist() runs synchronously inside block_ipv4_inner
    # (see src/xdp/mod.rs), so by the time BLOCK's response comes
    # back over the socket, the write to $PERSIST_FILE has already
    # happened -- no arbitrary sleep needed here to "wait for the
    # write," unlike the detector-timing waits used in phases 1-4.
    if [[ -s "$PERSIST_FILE" ]]; then
        echo "  [PASS] $PERSIST_FILE is non-empty after BLOCK: $(cat "$PERSIST_FILE")"
    else
        echo "  [FAIL] $PERSIST_FILE is still empty after a successful BLOCK -- persist_blocklist() didn't write"
        PHASE5_FAIL=1
    fi

    echo "--- stopping nsm cleanly (SIGTERM, same as Ctrl+C) ---"
    kill -TERM "$NSM_PID"
    for _ in $(seq 1 20); do
        kill -0 "$NSM_PID" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$NSM_PID" 2>/dev/null; then
        echo "  [FAIL] nsm didn't exit within 10s of SIGTERM -- killing it and failing this phase"
        kill -KILL "$NSM_PID" 2>/dev/null || true
        PHASE5_FAIL=1
    else
        echo "  exited cleanly."
    fi

    echo "--- restarting nsm with the same --xdp-blocklist-persist path ---"
    echo "    log: $LOG_FILE_2"
    launch_and_wait_for_attach "$LOG_FILE_2"
    echo "  re-attached."

    if grep -q "restored 1 block(s)" "$LOG_FILE_2"; then
        echo "  [PASS] startup log confirms 1 block restored from $PERSIST_FILE"
    else
        echo "  [FAIL] no 'restored 1 block(s)' line in the restart log -- see $LOG_FILE_2"
        PHASE5_FAIL=1
    fi

    LIST_RESP="$(echo "LIST" | nc -U -w2 "$CTRL_SOCK")"
    echo "  LIST response after restart: $LIST_RESP"
    if [[ "$LIST_RESP" == *"198.51.100.42/32"* ]]; then
        echo "  [PASS] the blocked address survived the restart"
    else
        echo "  [FAIL] 198.51.100.42/32 is not in the post-restart blocklist"
        PHASE5_FAIL=1
    fi
fi

if [[ "$PHASE5_FAIL" -ne 0 ]]; then
    RESULT=1
fi

echo ""
echo "--- full nsm log (first run) ---"
cat "$LOG_FILE"
echo ""
echo "--- full nsm log (after restart) ---"
cat "$LOG_FILE_2"

exit "$RESULT"
