//! The `Dial` seam (ADR-009, D10): one connection per request to an
//! allowlisted host. Crate-local, not a `boneli-app` port, modeled on
//! `boneli-egress`'s `Upstream` (ADR-006, D11): no use case drives it, so
//! it has no in-memory adapter or contract suite; the tests replace it
//! with a fake registry served over `UnixStream::pair`.
//!
//! Every request has a deadline. The client enforces it on whatever
//! stream a `Dial` returns ([`Timed`]), and [`TlsDial`] enforces it again
//! below TLS: a TLS read returns only once a whole record has arrived, so
//! a peer that sends a record one byte at a time, each byte within the
//! read timeout, would hold a read above TLS open far past the deadline.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use boneli_http::{IdleCheck, Transport};
use boneli_https::{ConnectOptions, Nonblocking, TlsConfig};

/// A stream the client can send a request over: timeouts and the idle
/// check of ADR-003, item 12.
pub trait Stream: Transport + IdleCheck {}

impl<T: Transport + IdleCheck> Stream for T {}

/// Where requests go.
pub trait Dial {
    /// A connection to `host:port`, for a request that must complete by
    /// `deadline`. The client calls it only for hosts on the registry's
    /// allowlist, one connection per request.
    fn dial(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Box<dyn Stream>>;
}

/// The real dial: TCP to each address of the host in turn, then a TLS
/// handshake with `boneli_https::connect_over`, certificates always
/// verified against the caller's `TlsConfig` (ADR-005), and the timeouts
/// of the caller's `ConnectOptions`. The deadline holds on the socket
/// under TLS for the handshake and every later read and write.
#[derive(Clone, Debug)]
pub struct TlsDial {
    config: TlsConfig,
    options: ConnectOptions,
}

impl TlsDial {
    /// A dial with these roots and timeouts.
    pub fn new(config: TlsConfig, options: ConnectOptions) -> TlsDial {
        TlsDial { config, options }
    }
}

impl Dial for TlsDial {
    fn dial(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Box<dyn Stream>> {
        let mut last = None;
        for addr in (host, port).to_socket_addrs()? {
            let left = time_left(deadline)?;
            match TcpStream::connect_timeout(&addr, left.min(self.options.connect_timeout())) {
                Ok(tcp) => {
                    let socket = DeadlineSocket {
                        tcp,
                        deadline,
                        read_cap: Cell::new(None),
                        write_cap: Cell::new(None),
                    };
                    return boneli_https::connect_over(socket, host, &self.config, &self.options)
                        .map(|tls| Box::new(tls) as Box<dyn Stream>)
                        .map_err(|e| match e {
                            boneli_https::Error::Io(e) => e,
                            other => io::Error::other(other.to_string()),
                        });
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
    }
}

/// What is left until `deadline`, or a `TimedOut` error once it passed.
fn time_left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the request deadline passed",
        ));
    }
    Ok(left)
}

/// The timeout for the next read or write: what is left of the deadline,
/// at most `cap`.
fn next_timeout(deadline: Instant, cap: Option<Duration>) -> io::Result<Duration> {
    let left = time_left(deadline)?;
    Ok(cap.map_or(left, |cap| cap.min(left)))
}

/// A TCP socket whose every read and write is bounded by a deadline and by
/// the timeout TLS sets (`ConnectOptions::io_timeout`).
struct DeadlineSocket {
    tcp: TcpStream,
    deadline: Instant,
    read_cap: Cell<Option<Duration>>,
    write_cap: Cell<Option<Duration>>,
}

impl Read for DeadlineSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = next_timeout(self.deadline, self.read_cap.get())?;
        self.tcp.set_read_timeout(Some(timeout))?;
        self.tcp.read(buf)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = next_timeout(self.deadline, self.write_cap.get())?;
        self.tcp.set_write_timeout(Some(timeout))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

impl Transport for DeadlineSocket {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_cap.set(timeout);
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_cap.set(timeout);
        Ok(())
    }
}

impl Nonblocking for DeadlineSocket {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.tcp.set_nonblocking(nonblocking)
    }
}

/// A dialed stream under the request's deadline: before each read and
/// write the stream's timeout is set to what is left of the deadline, at
/// most `io`, and once the deadline has passed every call fails with
/// `TimedOut`.
pub(crate) struct Timed {
    inner: Box<dyn Stream>,
    deadline: Instant,
    io: Duration,
}

impl Timed {
    pub(crate) fn new(inner: Box<dyn Stream>, deadline: Instant, io: Duration) -> Timed {
        Timed {
            inner,
            deadline,
            io,
        }
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = next_timeout(self.deadline, Some(self.io))?;
        self.inner.set_read_timeout(Some(timeout))?;
        self.inner.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = next_timeout(self.deadline, Some(self.io))?;
        self.inner.set_write_timeout(Some(timeout))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl IdleCheck for Timed {
    fn is_idle(&mut self) -> io::Result<Option<bool>> {
        self.inner.is_idle()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::Timed;

    /// A peer that never answers: the read fails at the deadline, not at
    /// the larger io timeout.
    #[test]
    fn read_stops_at_the_deadline() {
        let (near, _far) = UnixStream::pair().expect("pair");
        let start = Instant::now();
        let mut timed = Timed::new(
            Box::new(near),
            start + Duration::from_millis(200),
            Duration::from_secs(30),
        );
        let mut buf = [0u8; 1];
        assert!(timed.read(&mut buf).is_err());
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        let again = timed.read(&mut buf).expect_err("past the deadline");
        assert_eq!(again.kind(), std::io::ErrorKind::TimedOut);
    }
}
