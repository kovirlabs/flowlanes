//! Windows and the rest: no per-socket drop count is read.
//!
//! On Windows 11 (build 26300, 2026-11-23) 5,000 datagrams sent over
//! loopback to a socket that was not being read left `In Erroneous
//! Datagrams` of `netsh interface ipv4 show udpstats` unchanged while `In
//! Datagrams` rose by 5,000, so the system-wide MIB-II counters do not show
//! these drops either. Loss is still visible: the exporter's sequence
//! numbers leave a gap, which the decoder counts.

use super::SocketDrops;

/// Not available on this OS.
pub fn socket_drops(_port: u16) -> SocketDrops {
    SocketDrops::Unavailable(
        "this OS gives no count of datagrams dropped at a full socket buffer; \
         loss shows as sequence gaps",
    )
}
