//! Linux: the kernel keeps a per-socket drop count in `/proc/net/udp`.

use super::SocketDrops;
use super::procfs::drops_for_port;

/// Datagrams the kernel dropped at the UDP socket bound to `port`.
pub fn socket_drops(port: u16) -> SocketDrops {
    let mut total = None;
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(d) = drops_for_port(&text, port)
        {
            total = Some(total.unwrap_or(0) + d);
        }
    }
    match total {
        Some(d) => SocketDrops::Counted(d),
        None => SocketDrops::Unavailable("no socket on this port in /proc/net/udp"),
    }
}
