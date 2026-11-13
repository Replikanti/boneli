//! Streams the server can put deadlines on, and the tunnel that a CONNECT
//! leaves behind.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// A byte stream with read and write timeouts. The server sets the read
/// timeout before every read to what is left of the current deadline, so a
/// total deadline holds without polling.
pub trait Transport: Read + Write {
    /// Sets the read timeout; `None` blocks without a limit.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Sets the write timeout; `None` blocks without a limit.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Transport for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

impl Transport for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// A stream after a successful CONNECT. Bytes that arrived together with
/// the head come first when reading; writes go to the stream.
#[derive(Debug)]
pub struct Tunnel<S> {
    early: Vec<u8>,
    pos: usize,
    stream: S,
}

impl<S> Tunnel<S> {
    pub(crate) fn new(early: Vec<u8>, stream: S) -> Tunnel<S> {
        Tunnel {
            early,
            pos: 0,
            stream,
        }
    }

    /// The bytes read past the head that have not been read from the tunnel
    /// yet.
    pub fn early(&self) -> &[u8] {
        &self.early[self.pos..]
    }

    /// The stream under the tunnel.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The stream under the tunnel. Reading from it directly skips the
    /// early bytes.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// The early bytes not read yet, and the stream.
    pub fn into_parts(mut self) -> (Vec<u8>, S) {
        self.early.drain(..self.pos);
        (self.early, self.stream)
    }
}

impl<S: Read> Read for Tunnel<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.early.len() {
            let n = buf.len().min(self.early.len() - self.pos);
            buf[..n].copy_from_slice(&self.early[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.stream.read(buf)
    }
}

impl<S: Write> Write for Tunnel<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
