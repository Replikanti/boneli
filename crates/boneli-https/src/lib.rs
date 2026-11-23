//! A TLS client for Boneli's adapters and brokers: rustls with the ring
//! provider, TLS 1.3 and 1.2, Mozilla's roots from `webpki-roots` plus
//! roots the caller supplies (ADR-005).
//!
//! The key exchange offers the hybrid post-quantum group X25519MLKEM768
//! first (RFC 10024; ADR-016): ML-KEM-768 from the pure-Rust `ml-kem`
//! crate next to ring's X25519, so a recorded session stays as hard to
//! decrypt as X25519 alone even if ML-KEM falls, and as hard as ML-KEM
//! once X25519 falls to a quantum computer. X25519, P-256 and P-384 follow;
//! the ClientHello carries the hybrid and the X25519 key share, so a
//! server without the hybrid picks X25519 with no extra round trip.
//! [`TlsConfig::classical`] leaves the hybrid out, for a host whose
//! network path drops the larger ClientHello.
//!
//! It fails closed. Certificates are always verified and the API has no
//! switch and no hook to change that. `connect` and `connect_over` finish
//! the handshake before they return, so a certificate error surfaces there
//! and not on the first read. A TCP close without `close_notify` is an
//! `UnexpectedEof` error, never a clean end of the stream. No 0-RTT data
//! is sent, and no key log is written (`SSLKEYLOGFILE` is never read).
//!
//! Server certificates are checked for revocation by CRL (ADR-017). After
//! rustls has verified the chain, the CRL distribution points of the leaf
//! are fetched over plain HTTP (or HTTPS), cached per `TlsConfig` for at
//! most 24 hours and never past their `nextUpdate`, and the chain is
//! verified again with the list. A listed leaf fails the connection with
//! [`Error::Revoked`]; a leaf that names a point no list settles fails it
//! with [`Error::RevocationUnknown`]: an attacker on the path can drop a
//! plain-HTTP fetch, so the check fails closed and has no switch to turn
//! it off. A leaf that names no point but an OCSP responder is checked by
//! OCSP instead (ADR-020): one GET per responder over plain HTTP, the
//! answer verified against the leaf's issuer on the verified path (or a
//! responder that issuer authorized), cached by the same rules; a revoked
//! answer is [`Error::Revoked`], and every answer that does not settle the
//! leaf, an unreachable responder included, is
//! [`Error::RevocationUnknown`]. A leaf with neither passes unchecked, which
//! [`TlsStream::revocation`] reports. Before the leaf, each intermediate
//! on the path webpki verifies is checked against its issuer's CRL
//! (ADR-027), from the anchor side down, by the same fetch, cache and
//! fail-closed rules, with at most [`MAX_CA_CRL_FETCHES`] fetches of at
//! most [`MAX_CA_CRL_BYTES`] per connection; a listed intermediate is
//! [`Error::Revoked`], and one without a fetchable point passes
//! unchecked, which [`TlsStream::intermediate_revocation`] reports. The
//! anchor is configured trust and never checked. Resumed sessions are
//! checked again.
//!
//! The handshake has a total deadline, `ConnectOptions::handshake_timeout`,
//! on top of the timeout of each read and write, so a peer that sends a
//! byte now and then cannot hold `connect` open.
//!
//! Names are resolved by the crate's own stub [`Resolver`] (ADR-022), never
//! by `getaddrinfo`, which takes no timeout: `TlsDial`'s target and the
//! hosts of every CRL and OCSP fetch under the request's or the check's
//! deadline, `connect`'s host within `ConnectOptions::connect_timeout`.
//! It reads `/etc/hosts` and asks the name servers of `/etc/resolv.conf`
//! on the caller's thread, so no lookup outlives its call; names that only
//! another NSS source knows (mDNS, LDAP, split DNS behind uplink servers)
//! do not resolve. [`TlsConfig::with_resolver`] sets another resolver.
//!
//! `TlsStream` is a `boneli_http::Transport` when its stream is one, and an
//! `IdleCheck` that counts what rustls already holds: plaintext it has
//! decrypted, records that have arrived, and the part of a record that has
//! arrived. A response that arrives inside TLS while a connection is idle
//! therefore ends that connection, as on a plain socket (ADR-003, item 12).
//!
//! The crate also exports ring's SHA-256 as [`Sha256`], the one content
//! hash of the runner (ADR-009, D6): ring is linked here for TLS already,
//! so content addressing adds no crate and ring stays in this crate. For
//! the same reason it exports ring's RS256 signatures as [`RsaSha256Key`]
//! and the system's random source as [`fill_random`], for GitHub App
//! tokens and branch names (ADR-014, D4).
//!
//! [`Dial`] is the seam HTTPS clients connect through, one connection per
//! request under a deadline that holds below TLS; [`TlsDial`] is the real
//! one (ADR-009, D10; moved here from `boneli-oci` by ADR-014, D4).
#![doc(test(attr(forbid(unsafe_code))))]

mod dial;
mod pq;
mod random;
mod resolve;
mod revocation;
mod rsa;
mod sha256;

pub use dial::{Dial, Stream, Timed, TlsDial};
pub use random::{RandomFailed, fill_random};
pub use resolve::{
    DNS_DEFAULT_ATTEMPTS, DNS_DEFAULT_NDOTS, DNS_DEFAULT_TRY_TIMEOUT, DNS_MAX_ATTEMPTS,
    DNS_MAX_NAME_SERVERS, DNS_MAX_NDOTS, DNS_MAX_TRY_TIMEOUT, DNS_PORT, DNS_UDP_MESSAGE_BYTES,
    Resolver, ResolverConfig,
};
pub use revocation::{
    CA_CRL_CACHE_MAX_BYTES, CA_CRL_CHECK_DEADLINE, CRL_CACHE_MAX_BYTES, CRL_CHECK_DEADLINE,
    CRL_CONNECT_TIMEOUT, CRL_HANDSHAKE_TIMEOUT, CRL_IO_TIMEOUT, CRL_MAX_AGE_SECS,
    CRL_MAX_HEAD_BYTES, CRL_MAX_HEADERS, CRL_MIN_RATE, CRL_REFRESH_RETRY_SECS, CRL_SETUP_TIME,
    CrlFetchError, CrlScheme, CrlSource, CrlUrl, MAX_CA_CRL_BYTES, MAX_CA_CRL_FETCHES,
    MAX_CRL_BYTES, MAX_CRL_URL_BYTES, MAX_CRL_URLS, MAX_OCSP_RESPONSE_BYTES,
    MAX_OCSP_RESPONSE_CERTS, MAX_OCSP_URLS, OCSP_CACHE_MAX_ENTRIES, OCSP_CHECK_DEADLINE,
    OCSP_MAX_AGE_SECS, OCSP_REFRESH_RETRY_SECS, OcspSource, RevocationFailure,
    RevocationFailureKind, RevocationStatus,
};
pub use rsa::{KeyError, RsaSha256Key};
pub use sha256::Sha256;

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_http::{IdleCheck, Transport, Tunnel};
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::ring::kx_group;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use revocation::{HttpSource, Revocation};

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
    /// A certificate of the server's chain is revoked: the leaf or an
    /// intermediate listed in the CRL at `url` (ADR-017, ADR-027), or the
    /// leaf reported revoked by the OCSP responder at `url` (ADR-020).
    Revoked {
        /// The canonical URL of the list or the responder.
        url: String,
    },
    /// A certificate of the server's chain names CRL distribution points
    /// or OCSP responders and none of them settled whether it is revoked:
    /// each failure with its URL and cause (ADR-017, item 4; ADR-020); an
    /// intermediate's details start with `intermediate k of n` (ADR-027).
    /// The check fails closed.
    RevocationUnknown(Vec<RevocationFailure>),
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
            Error::Revoked { url } => write!(f, "the certificate is revoked ({url})"),
            Error::RevocationUnknown(failures) => {
                f.write_str("the certificate's revocation status is unknown")?;
                for (i, failure) in failures.iter().enumerate() {
                    f.write_str(if i == 0 { ": " } else { "; " })?;
                    write!(f, "{failure}")?;
                }
                Ok(())
            }
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
            if let Some(inner) = e.into_inner()
                && let Ok(tls) = inner.downcast::<rustls::Error>()
            {
                return Error::Tls(*tls);
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
/// the given roots (ADR-005). The key exchange groups are, in this order,
/// X25519MLKEM768 (TLS 1.3 only), X25519, P-256 and P-384 (ADR-016), or
/// the last three for [`TlsConfig::classical`]. Server certificates are
/// checked for revocation by CRL (ADR-017) or OCSP (ADR-020), and their
/// intermediates by CRL (ADR-027), with no switch to turn it off. Cheap
/// to clone; clones share the session store and the CRL, CA and OCSP
/// caches, so share one per set of roots.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    client: Arc<ClientConfig>,
    roots: Arc<RootCertStore>,
    revocation: Arc<Revocation>,
    resolver: Resolver,
}

impl TlsConfig {
    /// A configuration that trusts `roots` and offers the hybrid
    /// post-quantum key exchange X25519MLKEM768 first (ADR-016). Empty
    /// roots are an error: they would refuse every server.
    pub fn new(roots: Roots) -> Result<TlsConfig> {
        // Explicit, so that a rustls update that changes ring's default
        // groups cannot change what the runner offers.
        TlsConfig::with_groups(
            roots,
            vec![
                pq::X25519MLKEM768,
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ],
        )
    }

    /// The same configuration without the hybrid post-quantum group: it
    /// offers X25519, P-256 and P-384 and sends one X25519 key share
    /// (ADR-016, item 8). For one case only: a host behind a middlebox that
    /// drops a ClientHello spanning two TCP segments, which the hybrid's
    /// 1216-byte key share makes it. Certificates are verified exactly as
    /// with [`TlsConfig::new`]; what is given up, for that host only, is
    /// the protection of recorded traffic against a future quantum
    /// computer. Never a fallback after a failed handshake: retrying
    /// without the hybrid would hand an active attacker a downgrade.
    pub fn classical(roots: Roots) -> Result<TlsConfig> {
        TlsConfig::with_groups(
            roots,
            vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        )
    }

    /// The one builder of both constructors, so that they differ in the
    /// key exchange groups and nothing else.
    fn with_groups(roots: Roots, groups: Vec<&'static dyn SupportedKxGroup>) -> Result<TlsConfig> {
        if roots.is_empty() {
            return Err(Error::NoCertificates);
        }
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: groups,
            ..rustls::crypto::ring::default_provider()
        });
        // One store for the handshake and the revocation check, so a list
        // is verified against exactly the roots the chain was.
        let roots = Arc::new(roots.store);
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(Error::Tls)?
            .with_root_certificates(Arc::clone(&roots))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_sni = true;
        // A replayed request to a paid API would be charged twice.
        client.enable_early_data = false;
        // `key_log` stays rustls' `NoKeyLog`.
        let client = Arc::new(client);
        // `https` distribution points and OCSP responders are fetched over
        // the same client without a revocation check (`fetch_config`).
        let resolver = Resolver::system();
        let source = Arc::new(HttpSource::new(TlsConfig::fetch_config(
            &client, &roots, &resolver,
        )));
        Ok(TlsConfig {
            revocation: Arc::new(Revocation::on(
                Arc::clone(&roots),
                Arc::clone(client.crypto_provider()),
                Arc::clone(&source) as Arc<dyn CrlSource>,
                source,
            )),
            client,
            roots,
            resolver,
        })
    }

    /// What an `https` CRL or OCSP fetch connects with: the same client and
    /// roots without a revocation check, which keeps the fetch from
    /// recursing (ADR-017, item 6; ADR-020, item 8), and `resolver` for the
    /// hosts of every fetch (ADR-022).
    fn fetch_config(
        client: &Arc<ClientConfig>,
        roots: &Arc<RootCertStore>,
        resolver: &Resolver,
    ) -> TlsConfig {
        TlsConfig {
            client: Arc::clone(client),
            roots: Arc::clone(roots),
            revocation: Arc::new(Revocation::off()),
            resolver: resolver.clone(),
        }
    }

    /// The same configuration with names resolved by `resolver` (ADR-022,
    /// D7): `TlsDial`'s target, `connect`'s host and the hosts of every CRL
    /// and OCSP fetch. The default is [`Resolver::system`]. It installs
    /// fetch sources over the new resolver for both CRLs and OCSP, so it
    /// replaces a source set earlier by [`TlsConfig::with_crl_source`] or
    /// [`TlsConfig::with_ocsp_source`]: call those after it. Both caches
    /// start empty.
    pub fn with_resolver(&self, resolver: Resolver) -> TlsConfig {
        let source = Arc::new(HttpSource::new(TlsConfig::fetch_config(
            &self.client,
            &self.roots,
            &resolver,
        )));
        TlsConfig {
            client: Arc::clone(&self.client),
            roots: Arc::clone(&self.roots),
            revocation: Arc::new(self.revocation.with_sources(
                Some(Arc::clone(&source) as Arc<dyn CrlSource>),
                Some(source),
            )),
            resolver,
        }
    }

    /// The same configuration with CRLs from `source`, the OCSP source of
    /// this one, and both caches empty (ADR-017, item 10): for tests, and
    /// for a source that reaches CRLs another way. Whatever the source
    /// returns is verified against this configuration's roots and the
    /// system clock; a source can make connections fail, never pass a
    /// certificate a valid list revokes.
    pub fn with_crl_source(&self, source: Arc<dyn CrlSource>) -> TlsConfig {
        TlsConfig {
            client: Arc::clone(&self.client),
            roots: Arc::clone(&self.roots),
            revocation: Arc::new(self.revocation.with_sources(Some(source), None)),
            resolver: self.resolver.clone(),
        }
    }

    /// The same configuration with OCSP responses from `source`, the CRL
    /// source of this one, and both caches empty (ADR-020, item 11): for
    /// tests, and for a source that reaches responders another way.
    /// Whatever the source returns is verified against the leaf's issuer
    /// on the path these roots verify, the leaf's CertID and the system
    /// clock; a source can make connections fail, never pass a certificate
    /// the issuer reports revoked in an answer still valid.
    pub fn with_ocsp_source(&self, source: Arc<dyn OcspSource>) -> TlsConfig {
        TlsConfig {
            client: Arc::clone(&self.client),
            roots: Arc::clone(&self.roots),
            revocation: Arc::new(self.revocation.with_sources(None, Some(source))),
            resolver: self.resolver.clone(),
        }
    }

    /// The same configuration without a revocation check: what an `https`
    /// CRL or OCSP fetch connects with.
    #[cfg(test)]
    pub(crate) fn without_revocation(&self) -> TlsConfig {
        TlsConfig::fetch_config(&self.client, &self.roots, &self.resolver)
    }
}

/// Timeouts for `connect` and `connect_over`. No defaults: the right
/// values depend on the peer, as for `boneli_http::Limits` (ADR-003, item
/// 7).
///
/// The revocation check after the handshake has its own deadline,
/// [`CRL_CHECK_DEADLINE`], shared by all the leaf's CRL URLs, or
/// [`OCSP_CHECK_DEADLINE`] for a leaf checked by OCSP: on a cold cache, or
/// once a list or answer is due again, it adds at most that to `connect`
/// and `connect_over` (ADR-017, item 7; ADR-020, item 7), after the
/// intermediates' check with its own [`CA_CRL_CHECK_DEADLINE`] (ADR-027).
/// A warm cache adds no I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectOptions {
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
}

impl ConnectOptions {
    /// `connect_timeout` bounds the name lookup of `connect` (ADR-022) and
    /// each of its TCP connection attempts; `connect_over` gets a stream
    /// that is already connected and does not use it. `handshake_timeout`
    /// bounds the whole TLS handshake, however the peer spreads its bytes.
    /// `io_timeout` bounds each read and write, during the handshake and
    /// after it, when it becomes the stream's read and write timeout. A
    /// zero value is an error: std rejects a zero timeout.
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

    /// The timeout of `connect`'s name lookup and of each TCP connection
    /// attempt.
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

/// Resolves `host` with the `TlsConfig`'s resolver within
/// `connect_timeout` (ADR-022, D7), connects to each address in turn with
/// `connect_timeout`, and completes the TLS handshake with `host` as the
/// server name within `handshake_timeout`; then `io_timeout` is the
/// socket's read and write timeout. A handshake failure is returned at
/// once, without trying further addresses.
///
/// A host must be a server name ([`Error::InvalidServerName`] otherwise)
/// and, ASCII-lowercased, in ADR-003's grammar, as for [`TlsDial`]: a name
/// rustls accepts but the grammar does not (an underscore, a trailing dot)
/// is `Error::Io` of kind `InvalidInput`, before any query is sent.
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
    let lookup_deadline = saturating_deadline(Instant::now(), options.connect_timeout);
    let mut last = None;
    for addr in config.resolver.lookup(host, port, lookup_deadline)? {
        match TcpStream::connect_timeout(&addr, options.connect_timeout) {
            Ok(tcp) => return handshake(tcp, name, config, options, None),
            Err(e) => last = Some(e),
        }
    }
    Err(Error::Io(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "the host has no address")
    })))
}

/// `now + timeout`, or, when the clock cannot hold that sum (a timeout
/// such as `Duration::MAX`, "no bound of mine"), the latest instant within
/// a factor of two of it: the lookup is then bounded by the resolver's own
/// tries only, as the dial was before ADR-022.
fn saturating_deadline(now: Instant, timeout: Duration) -> Instant {
    let mut timeout = timeout;
    loop {
        // Halving ends: `now + 0` always fits.
        if let Some(deadline) = now.checked_add(timeout) {
            return deadline;
        }
        timeout /= 2;
    }
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
    connect_over_until(transport, name, config, options, None)
}

/// `connect_over` whose revocation check ends by `outer` at the latest:
/// `TlsDial` passes its request's deadline (ADR-017, item 7).
pub(crate) fn connect_over_until<S: Transport>(
    transport: S,
    name: &str,
    config: &TlsConfig,
    options: &ConnectOptions,
    outer: Option<Instant>,
) -> Result<TlsStream<S>> {
    let name = server_name(name)?;
    handshake(transport, name, config, options, outer)
}

fn handshake<S: Transport>(
    transport: S,
    name: ServerName<'static>,
    config: &TlsConfig,
    options: &ConnectOptions,
    outer: Option<Instant>,
) -> Result<TlsStream<S>> {
    let mut conn =
        ClientConnection::new(Arc::clone(&config.client), name.clone()).map_err(Error::Tls)?;
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
    // rustls has verified the chain; now its revocation (ADR-017, item 1;
    // ADR-027). Not inside the handshake: rustls skips the verifier when it
    // resumes a session, but restores the peer's chain from it, so a
    // resumed connection is checked here again. No application byte has
    // been sent.
    let status = match conn.peer_certificates() {
        Some(chain) => config.revocation.check(chain, &name, outer)?,
        None => {
            return Err(Error::RevocationUnknown(vec![RevocationFailure {
                url: None,
                kind: RevocationFailureKind::NotSettled,
                detail: "the server sent no certificate".into(),
            }]));
        }
    };
    framed.inner.set_read_timeout(Some(options.io_timeout))?;
    framed.inner.set_write_timeout(Some(options.io_timeout))?;
    Ok(TlsStream {
        stream: StreamOwned::new(conn, framed),
        revocation: status.leaf,
        intermediate_revocation: status.intermediates,
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

/// A client TLS connection over `S`, after its handshake and revocation
/// check.
pub struct TlsStream<S: Read + Write> {
    stream: StreamOwned<ClientConnection, Framed<S>>,
    revocation: RevocationStatus,
    intermediate_revocation: Vec<RevocationStatus>,
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

    /// The key exchange group of the handshake, such as
    /// `NamedGroup::X25519MLKEM768` (ADR-016), for tests and logs.
    pub fn key_exchange_group(&self) -> Option<rustls::NamedGroup> {
        self.stream
            .conn
            .negotiated_key_exchange_group()
            .map(|group| group.name())
    }

    /// What the revocation check found (ADR-017, ADR-020): checked against
    /// which list or responder, decided by a stale cached list or answer,
    /// or a certificate without either source that passed unchecked. For
    /// tests and logs.
    pub fn revocation(&self) -> &RevocationStatus {
        &self.revocation
    }

    /// What the check of each intermediate on the verified path found
    /// (ADR-027), the leaf's issuer first: checked against which list,
    /// decided by a stale cached list, or an intermediate without a
    /// fetchable point that passed unchecked. Empty when a root issued the
    /// leaf. For tests and logs.
    pub fn intermediate_revocation(&self) -> &[RevocationStatus] {
        &self.intermediate_revocation
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
            .field("revocation", &self.revocation)
            .field("intermediate_revocation", &self.intermediate_revocation)
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

    use rustls::NamedGroup;

    fn groups(config: &TlsConfig) -> Vec<NamedGroup> {
        let provider = config.client.crypto_provider();
        provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect()
    }

    fn assert_fails_closed(config: &TlsConfig) {
        let client = &config.client;
        assert!(!client.enable_early_data, "no 0-RTT");
        assert!(client.enable_sni);
        assert_eq!(client.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(!client.key_log.will_log("CLIENT_RANDOM"), "no key log");
    }

    #[test]
    fn config_offers_hybrid_first() {
        let config = TlsConfig::new(Roots::mozilla()).expect("config");
        assert_fails_closed(&config);
        assert_eq!(
            groups(&config),
            [
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]
        );
    }

    #[test]
    fn classical_config_has_no_hybrid() {
        let config = TlsConfig::classical(Roots::mozilla()).expect("config");
        assert_fails_closed(&config);
        assert_eq!(
            groups(&config),
            [
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]
        );
        assert!(matches!(
            TlsConfig::classical(Roots::empty()),
            Err(Error::NoCertificates)
        ));
    }
}
