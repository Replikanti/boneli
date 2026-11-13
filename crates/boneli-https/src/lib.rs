//! A TLS client for Boneli's adapters and brokers: rustls with the ring
//! provider, TLS 1.3 and 1.2, Mozilla's roots from `webpki-roots` plus
//! roots the caller supplies (ADR-005).
//!
//! It fails closed. Certificates are always verified and the API has no
//! switch and no hook to change that. `connect` and `connect_over` finish
//! the handshake before they return, so a certificate error surfaces there
//! and not on the first read. A TCP close without `close_notify` is an
//! `UnexpectedEof` error, never a clean end of the stream. No 0-RTT data
//! is sent, and no key log is written (`SSLKEYLOGFILE` is never read).
//!
//! The handshake has a total deadline, `ConnectOptions::handshake_timeout`,
//! on top of the timeout of each read and write, so a peer that sends a
//! byte now and then cannot hold `connect` open.
//!
//! `TlsStream` is a `boneli_http::Transport` when its stream is one, and an
//! `IdleCheck` that counts what rustls already holds: plaintext it has
//! decrypted, records that have arrived, and the part of a record that has
//! arrived. A response that arrives inside TLS while a connection is idle
//! therefore ends that connection, as on a plain socket (ADR-003, item 12).
#![doc(test(attr(forbid(unsafe_code))))]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_http::{IdleCheck, Transport, Tunnel};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Everything that can go wrong while configuring or opening a TLS
/// connection.
#[derive(Debug)]
pub enum Error {
    /// The underlying stream failed, including a timeout and the end of
    /// the stream during the handshake.
    Io(io::Error),
    /// TLS failed: the handshake, the certificate, or a certificate the
    /// caller added as a root.
    Tls(rustls::Error),
    /// Not a DNS name or IP address that a certificate can be checked
    /// against: empty, not ASCII, in brackets, or a numeric form that only
    /// `inet_aton` reads as an address (`127.1`). Nothing was read,
    /// written, resolved or dialed.
    InvalidServerName,
    /// No certificate in the input, or an empty trust store.
    NoCertificates,
    /// A corrupt PEM block.
    Pem(pem::Error),
    /// A zero timeout or port.
    InvalidInput(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::InvalidServerName => f.write_str("invalid server name"),
            Error::NoCertificates => f.write_str("no certificates"),
            Error::Pem(e) => write!(f, "corrupt PEM: {e}"),
            Error::InvalidInput(what) => write!(f, "invalid input: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Tls(e) => Some(e),
            Error::Pem(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    /// Unwraps the TLS error that rustls carries inside an `io::Error`.
    fn from(e: io::Error) -> Self {
        if e.get_ref().is_some_and(|inner| inner.is::<rustls::Error>()) {
            if let Some(inner) = e.into_inner() {
                if let Ok(tls) = inner.downcast::<rustls::Error>() {
                    return Error::Tls(*tls);
                }
            }
            return Error::InvalidInput("lost TLS error");
        }
        Error::Io(e)
    }
}

/// `Result` with this crate's `Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// The certificates a server's chain must end in.
#[derive(Clone, Debug)]
pub struct Roots {
    store: RootCertStore,
}

impl Roots {
    /// Mozilla's root program, as compiled into `webpki-roots`. The host's
    /// CA bundle is never read (ADR-005).
    pub fn mozilla() -> Roots {
        Roots {
            store: RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
        }
    }

    /// No roots, for a caller that supplies its own, such as a customer's
    /// internal CA.
    pub fn empty() -> Roots {
        Roots {
            store: RootCertStore::empty(),
        }
    }

    /// Adds every certificate in `pem` and returns how many. All or
    /// nothing: on any error the store is unchanged. Input without a
    /// certificate is an error, because an empty bundle is a configuration
    /// mistake; other PEM sections (a key, for example) are skipped.
    pub fn add_pem(&mut self, pem: &[u8]) -> Result<usize> {
        let certs = CertificateDer::pem_slice_iter(pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Pem)?;
        if certs.is_empty() {
            return Err(Error::NoCertificates);
        }
        let mut store = self.store.clone();
        for cert in &certs {
            store.add(cert.clone()).map_err(Error::Tls)?;
        }
        self.store = store;
        Ok(certs.len())
    }

    /// Adds one DER-encoded certificate.
    pub fn add_der(&mut self, der: &[u8]) -> Result<()> {
        self.store
            .add(CertificateDer::from(der.to_vec()))
            .map_err(Error::Tls)
    }

    /// The number of roots.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether there are no roots.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

/// A client configuration: the ring provider, TLS 1.3 and 1.2, ALPN
/// `http/1.1`, SNI on, no early data, no key log, and verification against
/// the given roots (ADR-005). Cheap to clone; share one per set of roots,
/// so that sessions can resume.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    client: Arc<ClientConfig>,
}

impl TlsConfig {
    /// A configuration that trusts `roots`. Empty roots are an error: they
    /// would refuse every server.
    pub fn new(roots: Roots) -> Result<TlsConfig> {
        if roots.is_empty() {
            return Err(Error::NoCertificates);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(Error::Tls)?
            .with_root_certificates(roots.store)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_sni = true;
        // A replayed request to a paid API would be charged twice.
        client.enable_early_data = false;
        // `key_log` stays rustls' `NoKeyLog`.
        Ok(TlsConfig {
            client: Arc::new(client),
        })
    }
}

/// Timeouts for `connect` and `connect_over`. No defaults: the right
/// values depend on the peer, as for `boneli_http::Limits` (ADR-003, item
/// 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectOptions {
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
}

impl ConnectOptions {
    /// `connect_timeout` bounds each TCP connection attempt of `connect`;
    /// `connect_over` gets a stream that is already connected and does not
    /// use it. `handshake_timeout` bounds the whole TLS handshake, however
    /// the peer spreads its bytes. `io_timeout` bounds each read and write,
    /// during the handshake and after it, when it becomes the stream's
    /// read and write timeout. A zero value is an error: std rejects a zero
    /// timeout.
    pub fn new(
        connect_timeout: Duration,
        handshake_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<ConnectOptions> {
        if connect_timeout.is_zero() || handshake_timeout.is_zero() || io_timeout.is_zero() {
            return Err(Error::InvalidInput("a timeout is zero"));
        }
        Ok(ConnectOptions {
            connect_timeout,
            handshake_timeout,
            io_timeout,
        })
    }

    /// The timeout of each TCP connection attempt.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The total time the TLS handshake may take.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// The read and write timeout of the socket.
    pub fn io_timeout(&self) -> Duration {
        self.io_timeout
    }
}

/// The name a certificate is checked against: an IP address, or a DNS
/// name that rustls accepts. rustls refuses names whose last label is a
/// number (the WHATWG rule ADR-003 applies to hosts), so `127.1` or
/// `0x7f000001` never reach `getaddrinfo`.
fn server_name(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_owned()).map_err(|_| Error::InvalidServerName)
}

/// Resolves `host` with std, connects to each address in turn with
/// `connect_timeout`, and completes the TLS handshake with `host` as the
/// server name within `handshake_timeout`; then `io_timeout` is the
/// socket's read and write timeout. A handshake failure is returned at
/// once, without trying further addresses.
pub fn connect(
    host: &str,
    port: u16,
    config: &TlsConfig,
    options: &ConnectOptions,
) -> Result<TlsStream<TcpStream>> {
    let name = server_name(host)?;
    if port == 0 {
        return Err(Error::InvalidInput("port is zero"));
    }
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, options.connect_timeout) {
            Ok(tcp) => return handshake(tcp, name, config, options),
            Err(e) => last = Some(e),
        }
    }
    Err(Error::Io(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "the host has no address")
    })))
}

/// Completes a TLS handshake over `transport`, for example a CONNECT
/// tunnel (`boneli_http::connect_tunnel`) through a proxy, within
/// `handshake_timeout`; then `io_timeout` is the transport's read and
/// write timeout. `connect_timeout` does not apply: the caller connected.
pub fn connect_over<S: Transport>(
    transport: S,
    name: &str,
    config: &TlsConfig,
    options: &ConnectOptions,
) -> Result<TlsStream<S>> {
    let name = server_name(name)?;
    handshake(transport, name, config, options)
}

fn handshake<S: Transport>(
    transport: S,
    name: ServerName<'static>,
    config: &TlsConfig,
    options: &ConnectOptions,
) -> Result<TlsStream<S>> {
    let mut conn = ClientConnection::new(Arc::clone(&config.client), name).map_err(Error::Tls)?;
    let deadline = Instant::now()
        .checked_add(options.handshake_timeout)
        .ok_or(Error::InvalidInput("the handshake timeout is too large"))?;
    let mut framed = Framed::new(transport);
    {
        let mut io = Deadline {
            stream: &mut framed,
            deadline,
            io_timeout: options.io_timeout,
        };
        while conn.is_handshaking() {
            let (read, written) = conn.complete_io(&mut io)?;
            if read == 0 && written == 0 && conn.is_handshaking() {
                return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }
    framed.inner.set_read_timeout(Some(options.io_timeout))?;
    framed.inner.set_write_timeout(Some(options.io_timeout))?;
    Ok(TlsStream {
        stream: StreamOwned::new(conn, framed),
    })
}

/// The stream during the handshake: before each read and write it sets
/// the stream's timeout to what is left of the handshake deadline, at most
/// `io_timeout`, so the deadline holds however the peer spreads its bytes
/// (as the server's deadlines of ADR-003, item 8). rustls' `complete_io`
/// reads more than once per call, so the deadline lives here and not in
/// the loop around it.
struct Deadline<'a, S> {
    stream: &'a mut Framed<S>,
    deadline: Instant,
    io_timeout: Duration,
}

impl<S: Transport> Deadline<'_, S> {
    /// The timeout for the next read or write, or a `TimedOut` error when
    /// the deadline has passed.
    fn timeout(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(handshake_timed_out());
        }
        Ok(left.min(self.io_timeout))
    }

    /// A read or write that timed out at the deadline is the deadline's
    /// error, whatever error kind the platform reports for a timeout.
    fn check(&self, e: io::Error) -> io::Error {
        let timed_out = matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        );
        if timed_out && Instant::now() >= self.deadline {
            return handshake_timed_out();
        }
        e
    }
}

fn handshake_timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the TLS handshake did not finish in time",
    )
}

impl<S: Transport> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.timeout()?;
        self.stream.inner.set_read_timeout(Some(timeout))?;
        self.stream.read(buf).map_err(|e| self.check(e))
    }
}

impl<S: Transport> Write for Deadline<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timeout = self.timeout()?;
        self.stream.inner.set_write_timeout(Some(timeout))?;
        self.stream.write(buf).map_err(|e| self.check(e))
    }

    fn flush(&mut self) -> io::Result<()> {
        let timeout = self.timeout()?;
        self.stream.inner.set_write_timeout(Some(timeout))?;
        self.stream.flush().map_err(|e| self.check(e))
    }
}

/// The stream under TLS, following the record framing of every byte read
/// from it. All of them go to rustls, so when a record is incomplete here,
/// rustls holds part of a record it cannot decrypt yet. Every record,
/// from the first byte the server sends, starts with a five-byte header
/// whose last two bytes are the length of the body.
struct Framed<S> {
    inner: S,
    /// The header bytes of the current record read so far.
    header: [u8; 5],
    header_len: usize,
    /// The body bytes of the current record not read yet.
    body_left: usize,
}

impl<S> Framed<S> {
    fn new(inner: S) -> Framed<S> {
        Framed {
            inner,
            header: [0; 5],
            header_len: 0,
            body_left: 0,
        }
    }

    fn track(&mut self, mut bytes: &[u8]) {
        while let Some((&first, rest)) = bytes.split_first() {
            if self.body_left > 0 {
                let take = self.body_left.min(bytes.len());
                self.body_left -= take;
                bytes = &bytes[take..];
                continue;
            }
            self.header[self.header_len] = first;
            self.header_len += 1;
            bytes = rest;
            if self.header_len == self.header.len() {
                self.body_left = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.header_len = 0;
            }
        }
    }

    /// Whether the bytes read so far end inside a record.
    fn mid_record(&self) -> bool {
        self.header_len > 0 || self.body_left > 0
    }
}

impl<S: Read> Read for Framed<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.track(&buf[..n]);
        Ok(n)
    }
}

impl<S: Write> Write for Framed<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A stream whose reads can be switched to non-blocking, so that the idle
/// check of `TlsStream` can take in the records that have arrived without
/// waiting for more.
pub trait Nonblocking {
    /// Switches non-blocking mode on or off.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
}

impl Nonblocking for TcpStream {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }
}

impl Nonblocking for UnixStream {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }
}

impl<S: Nonblocking> Nonblocking for Tunnel<S> {
    /// Switches the stream under the tunnel. Early bytes are read first
    /// either way.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
}

/// A client TLS connection over `S`, after its handshake.
pub struct TlsStream<S: Read + Write> {
    stream: StreamOwned<ClientConnection, Framed<S>>,
}

impl<S: Read + Write> TlsStream<S> {
    /// Sends `close_notify`, so that the peer can tell the end of the
    /// stream from a truncation. Nothing may be written afterwards.
    pub fn close(&mut self) -> io::Result<()> {
        self.stream.conn.send_close_notify();
        self.stream.flush()
    }

    /// The negotiated protocol version.
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.stream.conn.protocol_version()
    }

    /// The protocol the server chose by ALPN, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.stream.conn.alpn_protocol()
    }

    /// The stream under TLS, for example to set timeouts.
    pub fn get_ref(&self) -> &S {
        &self.stream.sock.inner
    }

    /// Whether rustls holds plaintext not read yet, or has seen
    /// `close_notify`.
    fn has_input(&mut self) -> io::Result<bool> {
        let state = self
            .stream
            .conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(state.plaintext_bytes_to_read() > 0 || state.peer_has_closed())
    }

    /// Takes in the records that have arrived on a non-blocking stream:
    /// `true` when the stream would block with no input and rustls holds
    /// no part of a record, `false` on plaintext, `close_notify`, the end
    /// of the stream or an incomplete record.
    fn take_arrived(&mut self) -> io::Result<bool> {
        loop {
            match self.stream.conn.read_tls(&mut self.stream.sock) {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    if self.has_input()? {
                        return Ok(false);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(!self.stream.sock.mid_record());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Read + Write> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("protocol_version", &self.protocol_version())
            .finish_non_exhaustive()
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    /// Reads plaintext. The end of the stream without `close_notify` is an
    /// `UnexpectedEof` error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S: Transport> Transport for TlsStream<S> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.sock.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.sock.inner.set_write_timeout(timeout)
    }
}

impl<S: Read + Write + Nonblocking> IdleCheck for TlsStream<S> {
    /// Input is what rustls already holds (decrypted plaintext not read
    /// yet, or `close_notify`) and what has arrived on the stream. Records
    /// that arrive are taken into rustls, not dropped, so complete
    /// post-handshake messages such as TLS 1.3 session tickets leave the
    /// stream idle, while application data or the end of the stream does
    /// not. Part of a record is input too: rustls cannot tell what it is
    /// until the rest arrives, and the rest could be a response. So a
    /// ticket that has partly arrived ends the connection, which costs a
    /// reconnect and fails closed. Asking only the stream under TLS would
    /// miss what rustls has buffered, and would count a session ticket as
    /// input.
    fn is_idle(&mut self) -> io::Result<Option<bool>> {
        if self.has_input()? {
            return Ok(Some(false));
        }
        self.stream.sock.inner.set_nonblocking(true)?;
        let idle = self.take_arrived();
        self.stream.sock.inner.set_nonblocking(false)?;
        idle.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_fails_closed() {
        let config = TlsConfig::new(Roots::mozilla()).expect("config");
        let client = &config.client;
        assert!(!client.enable_early_data, "no 0-RTT");
        assert!(client.enable_sni);
        assert_eq!(client.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(!client.key_log.will_log("CLIENT_RANDOM"), "no key log");
    }
}
