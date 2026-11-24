//! What differs by operating system: how many datagrams the kernel dropped
//! at this socket because its receive buffer was full.

mod procfs;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::socket_drops;

#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
pub use other::socket_drops;

/// Datagrams dropped at the socket, when the OS says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDrops {
    /// Dropped at this socket since it was bound.
    Counted(u64),
    /// The OS gives no such count; the reason.
    Unavailable(&'static str),
}
