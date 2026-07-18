//! Types shared between the `nsm-ebpf` kernel program and `nsm`'s
//! userspace XDP loader (`src/xdp/`).
//!
//! Everything here has to be `no_std`, `#[repr(C)]`, and free of
//! pointers/padding: it's the wire format that crosses the
//! kernel/userspace boundary through a BPF ring buffer, so the layout
//! must be identical (and alignment-stable) on both sides.

#![cfg_attr(not(test), no_std)]

use bytemuck::{Pod, Zeroable};

/// Max simultaneous auto-blocked source IPv4 addresses. Sized well
/// above what any of the userspace detectors would plausibly flag at
/// once; raise if you run `--xdp-auto-block` against a very noisy
/// network.
pub const BLOCKLIST_MAX_ENTRIES: u32 = 65_536;

/// Ring buffer capacity in bytes. Must be a power of two. At
/// `size_of::<PacketEvent>() == 64` bytes, 4 MiB holds ~65k in-flight
/// events -- generous headroom for the userspace consumer to fall
/// behind a burst without the kernel silently dropping events
/// (tracked in `Stats::truncated`, see `nsm-ebpf`). If you're seeing
/// `truncated` climb under real load, raising this is the first thing
/// to try; it's a compile-time constant, so bump it here and rebuild
/// both `nsm-ebpf` (`scripts/build-ebpf.sh`) and `nsm` itself.
///
/// This does NOT address the deeper limitation, which raising the
/// size can't fix: `BPF_MAP_TYPE_RINGBUF` is a single buffer shared
/// across all CPUs, with reservation (`bpf_ringbuf_reserve`)
/// serialized through a spinlock -- a real, kernel-documented
/// contention point once multiple cores are submitting concurrently
/// under high multi-queue NIC throughput. The actual fix for that is
/// N per-CPU ring buffers (one per RSS queue/CPU, selected via
/// `bpf_get_smp_processor_id()`), which is a genuine kernel-side
/// redesign -- new map layout, new lookup-which-buffer logic in
/// nsm-ebpf, a fresh trip through the verifier -- not something to
/// bolt on casually alongside other changes. Scoped as future work,
/// not attempted here; a bigger buffer is the safe, real mitigation
/// available today without touching already-verified kernel code.
pub const RINGBUF_BYTE_SIZE: u32 = 1 << 22; // 4 MiB

/// L4 protocol numbers, mirrors `crate::packet::L4Proto` on the
/// userspace side (kept as a plain u8 here since cross-boundary enums
/// with unknown discriminants aren't safely `Pod`).
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;

/// Why this event was pushed to the ring buffer.
pub const ACTION_PASSED: u8 = 0;
/// The packet matched `BLOCKLIST_V4` and was `XDP_DROP`ped -- this
/// event exists purely so userspace can log/count the drop; the
/// packet itself never continued past the NIC driver.
pub const ACTION_DROPPED: u8 = 1;

/// One packet's worth of metadata, pushed from the XDP program to
/// userspace via a `RingBuf`. Fixed size, no heap data -- the
/// equivalent of `nsm::packet::PacketMeta` but POD, and without the
/// `payload_head` capture (signature matching on the XDP fast path is
/// intentionally out of scope; see README's "Notes / limitations").
///
/// `src_addr`/`dst_addr` hold the address in network byte order:
/// IPv4 in the first 4 bytes (rest zeroed), IPv6 across all 16.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct PacketEvent {
    pub ts_ns: u64,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub ip_ver: u8,
    pub proto: u8,
    pub tcp_flags: u8,
    pub action: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u32,
    pub ifindex: u32,
    pub _reserved: [u8; 8],
}

// Compile-time layout sanity check -- if this ever fails, `Pod`'s
// derive would already refuse to compile, but the explicit assert
// gives a much clearer error message than a derive macro failure.
const _: () = assert!(core::mem::size_of::<PacketEvent>() == 64);

impl PacketEvent {
    pub const fn zeroed() -> Self {
        Self {
            ts_ns: 0,
            src_addr: [0; 16],
            dst_addr: [0; 16],
            ip_ver: 0,
            proto: 0,
            tcp_flags: 0,
            action: 0,
            src_port: 0,
            dst_port: 0,
            length: 0,
            ifindex: 0,
            _reserved: [0; 8],
        }
    }
}

// `cargo test -p nsm-common` runs these against the host target (the
// crate is only `no_std` when NOT compiling for test, via the
// `cfg_attr` above) -- no eBPF toolchain, no root, no kernel needed.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_event_is_64_bytes_with_no_hidden_padding() {
        // Belt-and-suspenders alongside the const-assert above: if
        // someone adds/reorders a field and accidentally introduces
        // padding, this (and the Pod derive itself) should catch it.
        assert_eq!(core::mem::size_of::<PacketEvent>(), 64);
    }

    #[test]
    fn zeroed_is_all_zero_bytes() {
        let ev = PacketEvent::zeroed();
        assert!(bytemuck::bytes_of(&ev).iter().all(|&b| b == 0));
    }

    #[test]
    fn bytemuck_roundtrip_preserves_every_field() {
        // Exercises exactly what crosses the kernel/userspace
        // boundary: nsm-ebpf writes a PacketEvent's bytes into the
        // ring buffer, src/xdp/mod.rs::read_events reads them back
        // via bytemuck::from_bytes. If any field's offset/size is
        // wrong, this is where it would show up.
        let mut ev = PacketEvent::zeroed();
        ev.ts_ns = 0x0102_0304_0506_0708;
        ev.src_addr = [1; 16];
        ev.dst_addr = [2; 16];
        ev.ip_ver = 4;
        ev.proto = PROTO_TCP;
        ev.tcp_flags = 0b0001_0010; // SYN+ACK in nsm's packed layout
        ev.action = ACTION_DROPPED;
        ev.src_port = 4444;
        ev.dst_port = 443;
        ev.length = 1500;
        ev.ifindex = 2;

        let bytes = bytemuck::bytes_of(&ev).to_vec();
        let back: PacketEvent = *bytemuck::from_bytes(&bytes[..]);

        assert_eq!(back.ts_ns, ev.ts_ns);
        assert_eq!(back.src_addr, ev.src_addr);
        assert_eq!(back.dst_addr, ev.dst_addr);
        assert_eq!(back.ip_ver, ev.ip_ver);
        assert_eq!(back.proto, ev.proto);
        assert_eq!(back.tcp_flags, ev.tcp_flags);
        assert_eq!(back.action, ev.action);
        assert_eq!(back.src_port, ev.src_port);
        assert_eq!(back.dst_port, ev.dst_port);
        assert_eq!(back.length, ev.length);
        assert_eq!(back.ifindex, ev.ifindex);
    }

    #[test]
    fn undersized_buffer_is_rejected_not_misread() {
        // Documents the invariant src/xdp/mod.rs::read_events relies
        // on: a ring buffer item that's the wrong size must never be
        // silently reinterpreted. (The production code checks
        // item.len() itself before calling bytemuck::from_bytes;
        // try_from_bytes here is bytemuck's own safe equivalent of
        // that same check, used to pin the invariant down as a test.)
        let too_short = [0u8; 32];
        assert!(bytemuck::try_from_bytes::<PacketEvent>(&too_short).is_err());
    }
}
