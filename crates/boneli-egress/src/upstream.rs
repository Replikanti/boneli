//! The `Upstream` seam (ADR-006, D11): resolving an allowed name and
//! connecting to one checked address. Crate-local, not a `boneli-app`
//! port: no use case drives the egress, so it has no in-memory adapter or
//! contract suite; the tests replace it with a fake.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// A stream the relay moves bytes through: a second handle for the other
/// direction, half-close, and timeouts (ADR-006, D7).
pub trait RelayStream: Read + Write + Send {
    /// A second handle to the same socket.
    fn try_clone_box(&self) -> io::Result<Box<dyn RelayStream>>;
    /// Shuts down reading, writing or both, for every handle.
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    /// Sets the read timeout; `None` blocks without a limit.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Sets the write timeout; `None` blocks without a limit.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl RelayStream for TcpStream {
    fn try_clone_box(&self) -> io::Result<Box<dyn RelayStream>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

impl RelayStream for UnixStream {
    fn try_clone_box(&self) -> io::Result<Box<dyn RelayStream>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        UnixStream::shutdown(self, how)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

/// Where allowed connections go. The egress calls `resolve` only for a
/// name on the allowlist, after its `allowed` record (D3, D8), and
/// `connect` only for addresses that passed the address check (D4).
pub trait Upstream: Send + Sync {
    /// Every address of `host`, with `port`.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
    /// A connection to `addr`, or an error within about `timeout`; a
    /// timeout is `ErrorKind::TimedOut`.
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<Box<dyn RelayStream>>;
}

/// The real upstream: the system resolver through `ToSocketAddrs`
/// (`getaddrinfo`) and TCP with `TCP_NODELAY` (D5).
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpUpstream;

impl Upstream for TcpUpstream {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }

    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        // The relay forwards whole reads; Nagle with delayed ACKs would
        // hold back small server-sent events (D5).
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}
