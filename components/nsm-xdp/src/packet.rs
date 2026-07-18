//! Parses raw Ethernet frames into a protocol-agnostic `PacketMeta`
//! struct used by every downstream detector.

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// Normalized view of a single captured packet. Only the fields the
/// detection engines actually need are kept; the raw payload is capped
/// so we never hold onto more memory than necessary.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub ts: SystemTime,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: L4Proto,
    pub tcp_flags: u8,
    pub length: usize,
    /// First N bytes of the L4 payload, for lightweight signature matching.
    pub payload_head: Vec<u8>,
}

const PAYLOAD_CAP: usize = 256;

pub fn parse_ethernet_frame(data: &[u8]) -> Option<PacketMeta> {
    let eth = EthernetPacket::new(data)?;
    let ts = SystemTime::now();
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            parse_ipv4(&ip, ts)
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            parse_ipv6(&ip, ts)
        }
        _ => None,
    }
}

fn parse_ipv4(ip: &Ipv4Packet, ts: SystemTime) -> Option<PacketMeta> {
    let src_ip = IpAddr::V4(ip.get_source());
    let dst_ip = IpAddr::V4(ip.get_destination());
    let length = ip.packet().len();
    match ip.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => build_tcp(ip.payload(), src_ip, dst_ip, ts, length),
        IpNextHeaderProtocols::Udp => build_udp(ip.payload(), src_ip, dst_ip, ts, length),
        IpNextHeaderProtocols::Icmp => build_icmp(ip.payload(), src_ip, dst_ip, ts, length),
        other => Some(PacketMeta {
            ts,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            proto: L4Proto::Other(other.0),
            tcp_flags: 0,
            length,
            payload_head: Vec::new(),
        }),
    }
}

fn parse_ipv6(ip: &Ipv6Packet, ts: SystemTime) -> Option<PacketMeta> {
    let src_ip = IpAddr::V6(ip.get_source());
    let dst_ip = IpAddr::V6(ip.get_destination());
    let length = ip.packet().len();
    match ip.get_next_header() {
        IpNextHeaderProtocols::Tcp => build_tcp(ip.payload(), src_ip, dst_ip, ts, length),
        IpNextHeaderProtocols::Udp => build_udp(ip.payload(), src_ip, dst_ip, ts, length),
        IpNextHeaderProtocols::Icmp => build_icmp(ip.payload(), src_ip, dst_ip, ts, length),
        other => Some(PacketMeta {
            ts,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            proto: L4Proto::Other(other.0),
            tcp_flags: 0,
            length,
            payload_head: Vec::new(),
        }),
    }
}

fn build_tcp(
    buf: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ts: SystemTime,
    length: usize,
) -> Option<PacketMeta> {
    let tcp = TcpPacket::new(buf)?;
    let payload = tcp.payload();
    Some(PacketMeta {
        ts,
        src_ip,
        dst_ip,
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        proto: L4Proto::Tcp,
        tcp_flags: tcp.get_flags(),
        length,
        payload_head: payload[..payload.len().min(PAYLOAD_CAP)].to_vec(),
    })
}

fn build_udp(
    buf: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ts: SystemTime,
    length: usize,
) -> Option<PacketMeta> {
    let udp = UdpPacket::new(buf)?;
    let payload = udp.payload();
    Some(PacketMeta {
        ts,
        src_ip,
        dst_ip,
        src_port: udp.get_source(),
        dst_port: udp.get_destination(),
        proto: L4Proto::Udp,
        tcp_flags: 0,
        length,
        payload_head: payload[..payload.len().min(PAYLOAD_CAP)].to_vec(),
    })
}

fn build_icmp(
    buf: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ts: SystemTime,
    length: usize,
) -> Option<PacketMeta> {
    let _icmp = IcmpPacket::new(buf)?;
    Some(PacketMeta {
        ts,
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        proto: L4Proto::Icmp,
        tcp_flags: 0,
        length,
        payload_head: Vec::new(),
    })
}

pub fn is_syn_only(flags: u8) -> bool {
    flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0
}
