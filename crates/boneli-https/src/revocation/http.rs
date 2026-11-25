//! The real `CrlSource` and `OcspSource` (ADR-017, items 6 and 7; ADR-020,
//! item 8): one HTTP/1.1 `GET` per fetch through `boneli-http`, directly
//! from this process, under the check's deadline, which bounds the host's
//! name lookup too (ADR-022). `Host` is the only field
//! sent: no `User-Agent`, credentials or cookies. 200 only, no redirect
//! followed, no `Content-Encoding`, the body read to its end under
//! `MAX_CRL_BYTES` for a leaf's list, `MAX_CA_CRL_BYTES` for an
//! intermediate's (ADR-027) and `MAX_OCSP_RESPONSE_BYTES` for an OCSP
//! response, whose request travels in the path (RFC 6960, A.1). An
//! `https` point or responder is fetched over this crate's TLS client with
//! the same roots and without a revocation check of its own, which keeps
//! the fetch from recursing: the list's or response's integrity comes from
//! its signature, not from the transport.
//!
//! With a proxy in the configuration every fetch goes through it (ADR-039,
//! D6): only the proxy's name is resolved; an `http` point or responder is
//! an absolute-form `GET http://host/path` to the proxy, first without
//! credentials: a proxy that does not authenticate a request itself may
//! pass `Proxy-Authorization` on to the server (Apache httpd's forward
//! proxy does), so the field goes out only on one retry, on a new
//! connection, after the proxy answered `407` with a `Basic`
//! `Proxy-Authenticate` challenge. Only the proxy's own `407` carries one:
//! a proxy does not pass a server's challenge on, so a `407` without it
//! came from behind the proxy and fails without a retry. An `https` one is
//! a `CONNECT` tunnel with `Proxy-Authorization` up front (the proxy reads a
//! `CONNECT` head and relays nothing of it) and then TLS as above, and the
//! request inside the tunnel carries `Host` only. A refused `CONNECT` and
//! a `407` to a `GET` are `CrlFetchError::Unreachable` naming the proxy and
//! the status; any other non-200 answer to a proxied `GET`, from the proxy
//! or the server behind it, is `CrlFetchError::Status`, as on a direct
//! fetch.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use boneli_http::{
    Connection, IdleCheck, Limits, Method, RequestBody, RequestHead, Target, Transport,
};

use super::ocsp::{MAX_OCSP_RESPONSE_BYTES, OcspSource};
use super::url::{CrlScheme, CrlUrl};
use super::{
    CRL_CONNECT_TIMEOUT, CRL_HANDSHAKE_TIMEOUT, CRL_IO_TIMEOUT, CRL_MAX_HEAD_BYTES,
    CRL_MAX_HEADERS, CrlFetchError, CrlSource, MAX_CRL_BYTES,
};
use crate::dial::{DeadlineSocket, time_left};
use crate::proxy::offers_basic;
use crate::{ConnectOptions, Nonblocking, Proxy, TlsConfig};

/// Fetches CRLs and OCSP responses over HTTP and HTTPS.
pub(crate) struct HttpSource {
    /// The handshake's roots and groups, without a revocation check, the
    /// resolver of every fetch's host, and the proxy every fetch goes
    /// through when one is set (ADR-039, D6).
    tls: TlsConfig,
    /// Each TCP connection attempt.
    pub(crate) connect_timeout: Duration,
    /// The TLS handshake of an `https` point or responder.
    pub(crate) handshake_timeout: Duration,
    /// Each read and write.
    pub(crate) io_timeout: Duration,
}

impl HttpSource {
    /// A source whose `https` fetches use `tls`, which must not check
    /// revocation itself.
    pub(crate) fn new(tls: TlsConfig) -> HttpSource {
        HttpSource {
            tls,
            connect_timeout: CRL_CONNECT_TIMEOUT,
            handshake_timeout: CRL_HANDSHAKE_TIMEOUT,
            io_timeout: CRL_IO_TIMEOUT,
        }
    }

    /// `GET path` at `url`'s host, the body at most `cap` bytes.
    fn fetch_path(
        &self,
        url: &CrlUrl,
        path: &str,
        cap: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let first = self.fetch_once(url, path, cap, deadline, false);
        let Some(proxy) = self.tls.proxy() else {
            return first;
        };
        // Only a proxied `GET` waits for `407` before it sends credentials
        // (ADR-039, D8); a `CONNECT` carried them already. `request`
        // returns `Status(407)` only for a 407 with a `Basic` challenge,
        // the proxy's own.
        if !matches!(url.scheme(), CrlScheme::Http) || first != Err(CrlFetchError::Status(407)) {
            return first;
        }
        if !proxy.has_credentials() {
            return Err(CrlFetchError::Unreachable(format!(
                "the proxy {} answered 407 to GET {url}: it asks for credentials and none are configured",
                proxy.authority()
            )));
        }
        // One retry, on a new connection, under the same deadline.
        match self.fetch_once(url, path, cap, deadline, true) {
            Err(CrlFetchError::Status(407)) => Err(CrlFetchError::Unreachable(format!(
                "the proxy {} answered 407 to GET {url} again: it refused the configured credentials; only Basic is sent",
                proxy.authority()
            ))),
            other => other,
        }
    }

    /// One fetch on one connection: to the point's host, or to the proxy,
    /// whose `Proxy-Authorization` a proxied `GET` carries only when
    /// `credentials` is set.
    fn fetch_once(
        &self,
        url: &CrlUrl,
        path: &str,
        cap: usize,
        deadline: Instant,
        credentials: bool,
    ) -> Result<Vec<u8>, CrlFetchError> {
        time_left(deadline).map_err(io_error)?;
        // With a proxy only the proxy's name is resolved (ADR-039, D6).
        let (host, port, what) = match self.tls.proxy() {
            Some(proxy) => (proxy.host(), proxy.port(), "the proxy"),
            None => (url.host(), url.port(), "the host"),
        };
        // The lookup counts inside the deadline (ADR-022); a lookup that
        // ran out of it is a timeout, like every later step.
        let addrs = self
            .tls
            .resolver
            .lookup(host, port, deadline)
            .map_err(|e| match e.kind() {
                io::ErrorKind::TimedOut => CrlFetchError::TimedOut,
                _ => CrlFetchError::Unreachable(format!("cannot resolve {what}: {e}")),
            })?;
        let mut last = None;
        for addr in addrs {
            let left = time_left(deadline).map_err(io_error)?;
            match TcpStream::connect_timeout(&addr, left.min(self.connect_timeout)) {
                Ok(tcp) => return self.get(tcp, url, path, cap, deadline, credentials),
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(
            || CrlFetchError::Unreachable(format!("{what} has no address")),
            io_error,
        ))
    }

    fn get(
        &self,
        tcp: TcpStream,
        url: &CrlUrl,
        path: &str,
        cap: usize,
        deadline: Instant,
        credentials: bool,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let socket = DeadlineSocket::new(tcp, deadline);
        socket
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| socket.set_write_timeout(Some(self.io_timeout)))
            .map_err(io_error)?;
        match (url.scheme(), self.tls.proxy()) {
            (CrlScheme::Http, None) => request(socket, url, path, cap, Route::Direct),
            (CrlScheme::Http, Some(proxy)) => {
                request(socket, url, path, cap, Route::Proxy { proxy, credentials })
            }
            (CrlScheme::Https, None) => self.https(socket, url, path, cap, deadline),
            (CrlScheme::Https, Some(proxy)) => {
                let tunnel = proxy
                    .tunnel(socket, url.host(), url.port())
                    .map_err(|e| tunnel_error(proxy, url, e))?;
                self.https(tunnel, url, path, cap, deadline)
            }
        }
    }

    /// TLS to `url`'s host over `stream`, then `GET path` inside it.
    fn https<S: Transport + Nonblocking>(
        &self,
        stream: S,
        url: &CrlUrl,
        path: &str,
        cap: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let options = ConnectOptions::new(
            self.connect_timeout,
            self.handshake_timeout,
            self.io_timeout,
        )
        .map_err(|e| CrlFetchError::Unreachable(e.to_string()))?;
        let tls =
            crate::connect_over_until(stream, url.host(), &self.tls, &options, Some(deadline))
                .map_err(|e| match e {
                    crate::Error::Io(e) => io_error(e),
                    other => CrlFetchError::Unreachable(format!("TLS: {other}")),
                })?;
        // Inside the tunnel the request is the server's: no proxy field.
        request(tls, url, path, cap, Route::Direct)
    }
}

/// A failed `CONNECT` to `url`'s host through `proxy`: a refusal is
/// `Unreachable` with the text of `Error::Proxy` (the proxy, the target
/// and the status); a timeout stays `TimedOut`; anything else names the
/// proxy. No text holds a field value.
fn tunnel_error(proxy: &Proxy, url: &CrlUrl, e: boneli_http::Error) -> CrlFetchError {
    use boneli_http::Error;
    match e {
        Error::Status(status) => {
            CrlFetchError::Unreachable(proxy.refused(url.host(), url.port(), status).to_string())
        }
        Error::Timeout => CrlFetchError::TimedOut,
        Error::Io(e)
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            CrlFetchError::TimedOut
        }
        other => CrlFetchError::Unreachable(format!(
            "CONNECT {}:{} through the proxy {}: {other}",
            url.host(),
            url.port(),
            proxy.authority()
        )),
    }
}

impl CrlSource for HttpSource {
    fn fetch(&self, url: &CrlUrl, deadline: Instant) -> Result<Vec<u8>, CrlFetchError> {
        self.fetch_path(url, url.path(), MAX_CRL_BYTES, deadline)
    }

    /// An intermediate's list under its own cap (ADR-027): a
    /// `Content-Length` above `cap` fails before the body is read.
    fn fetch_limited(
        &self,
        url: &CrlUrl,
        cap: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        self.fetch_path(url, url.path(), cap, deadline)
    }
}

impl OcspSource for HttpSource {
    fn fetch(
        &self,
        responder: &CrlUrl,
        request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let path = super::ocsp::get_path(responder, request);
        self.fetch_path(responder, &path, MAX_OCSP_RESPONSE_BYTES, deadline)
    }
}

/// Where a `GET` goes.
#[derive(Clone, Copy)]
enum Route<'a> {
    /// To the point's host, or inside a tunnel.
    Direct,
    /// To `proxy` in the absolute form, with its `Proxy-Authorization`
    /// only when `credentials` is set: on the retry after a `407`
    /// (ADR-039, D8).
    Proxy { proxy: &'a Proxy, credentials: bool },
}

/// `GET <path>` with `Host` only; 200, no content coding, the whole body
/// of at most `cap` bytes. Through a proxy, an `http` URL only: the
/// absolute form, plus `Proxy-Authorization` on the retry after a `407`.
fn request<S: Read + Write + IdleCheck>(
    stream: S,
    url: &CrlUrl,
    path: &str,
    cap: usize,
    route: Route<'_>,
) -> Result<Vec<u8>, CrlFetchError> {
    let limits =
        Limits::new(CRL_MAX_HEAD_BYTES, CRL_MAX_HEADERS, cap as u64).map_err(http_error)?;
    let mut head = RequestHead::new(
        Method::new("GET").map_err(http_error)?,
        Target::Origin(path.to_owned()),
    );
    let mut conn = match route {
        Route::Direct => Connection::new(stream, &url.authority(), limits),
        Route::Proxy { proxy, credentials } => {
            if credentials {
                head.headers = proxy.fields();
            }
            Connection::new_via_proxy(stream, &url.authority(), limits)
        }
    }
    .map_err(http_error)?;
    let mut response = conn.request(&head, RequestBody::None).map_err(http_error)?;
    let status = response.head.status;
    if status == 407
        && let Route::Proxy { proxy, .. } = route
        && !offers_basic(response.head.headers.get_all("proxy-authenticate"))
    {
        // Not the proxy's own challenge: a 407 from the server, or from
        // the plaintext leg behind the proxy, that a proxy which does not
        // authenticate passed on. Credentials sent now could reach the
        // server, so no retry (ADR-039, D8).
        return Err(CrlFetchError::Unreachable(format!(
            "the proxy {} returned 407 to GET {url} without a Basic Proxy-Authenticate \
challenge, so it is not the proxy's own; not retried with credentials",
            proxy.authority()
        )));
    }
    if status != 200 {
        return Err(CrlFetchError::Status(status));
    }
    // RFC 5280, 4.2.1.13 and RFC 6960, A.1: the server sends DER. A coding
    // would need a decoder and is never needed (none measured, ADR-017
    // item 6, ADR-020 item 8).
    let coded = response
        .head
        .headers
        .get_all("content-encoding")
        .any(|value| !value.trim_ascii().eq_ignore_ascii_case(b"identity"));
    if coded {
        return Err(CrlFetchError::Malformed(
            "the response has a content coding".into(),
        ));
    }
    let mut body = Vec::new();
    response
        .read_to_end(&mut body)
        .map_err(|e| http_error(e.into()))?;
    Ok(body)
}

fn io_error(e: io::Error) -> CrlFetchError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => CrlFetchError::TimedOut,
        _ => CrlFetchError::Unreachable(e.to_string()),
    }
}

fn http_error(e: boneli_http::Error) -> CrlFetchError {
    use boneli_http::Error;
    match e {
        Error::Timeout => CrlFetchError::TimedOut,
        Error::BodyTooLarge => CrlFetchError::TooLarge,
        Error::Status(status) => CrlFetchError::Status(status),
        Error::Io(e) => io_error(e),
        Error::UnexpectedEof => CrlFetchError::Unreachable("the connection closed early".into()),
        other => CrlFetchError::Malformed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    use crate::Roots;
    use crate::revocation::MAX_CA_CRL_BYTES;

    const GUARD: Duration = Duration::from_secs(10);

    fn crl_roots() -> Roots {
        let mut roots = Roots::empty();
        roots
            .add_pem(include_bytes!("../../tests/data/crl-ca.pem"))
            .expect("CRL test CA");
        roots
    }

    fn source() -> HttpSource {
        let tls = TlsConfig::new(crl_roots()).expect("config");
        HttpSource::new(tls.without_revocation())
    }

    fn crl(source: &HttpSource, url: &CrlUrl, deadline: Instant) -> Result<Vec<u8>, CrlFetchError> {
        CrlSource::fetch(source, url, deadline)
    }

    fn ocsp(
        source: &HttpSource,
        url: &CrlUrl,
        request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        OcspSource::fetch(source, url, request, deadline)
    }

    fn url(addr: SocketAddr, path: &str) -> CrlUrl {
        CrlUrl::parse(&format!("http://{addr}{path}")).expect("URL")
    }

    fn deadline() -> Instant {
        Instant::now() + GUARD
    }

    /// Reads a request head through its empty line.
    fn read_head(stream: &mut impl Read) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => break,
            }
        }
        head
    }

    /// Accepts one connection, reads its request head, runs `respond` on
    /// the stream and returns the head.
    fn server(
        respond: impl FnOnce(&mut TcpStream) + Send + 'static,
    ) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(GUARD)).expect("timeout");
            let head = read_head(&mut tcp);
            respond(&mut tcp);
            head
        });
        (addr, handle)
    }

    /// A server that answers with `response` and closes.
    fn answer(response: Vec<u8>) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        server(move |tcp| {
            let _ = tcp.write_all(&response);
        })
    }

    fn ok_with(body: &[u8]) -> Vec<u8> {
        let mut out =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn request_carries_host_only() {
        let (addr, server) = answer(ok_with(b"list"));
        let body = crl(&source(), &url(addr, "/ca.crl"), deadline()).expect("fetch");
        assert_eq!(body, b"list");
        let head = String::from_utf8(server.join().expect("server")).expect("ASCII");
        let mut lines = head.split("\r\n");
        assert_eq!(lines.next(), Some("GET /ca.crl HTTP/1.1"));
        let fields: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
        assert_eq!(fields, [format!("Host: 127.0.0.1:{}", addr.port())]);
        let lower = head.to_ascii_lowercase();
        for name in ["user-agent", "cookie", "authorization"] {
            assert!(!lower.contains(name), "{name} in {head:?}");
        }
    }

    #[test]
    fn redirect_is_not_followed() {
        let target = TcpListener::bind("127.0.0.1:0").expect("bind");
        target.set_nonblocking(true).expect("nonblocking");
        let location = format!("http://{}/ca.crl", target.local_addr().expect("addr"));
        let (addr, _server) = answer(
            format!("HTTP/1.1 301 Moved\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
        );
        let err = crl(&source(), &url(addr, "/ca.crl"), deadline());
        assert_eq!(err, Err(CrlFetchError::Status(301)));
        let accepted = target.accept().map(|_| ());
        assert_eq!(
            accepted.map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock),
            "the redirect target saw a connection"
        );
    }

    #[test]
    fn non_200_fails() {
        for status in [204, 404, 500] {
            let (addr, _server) =
                answer(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").into_bytes());
            assert_eq!(
                crl(&source(), &url(addr, "/ca.crl"), deadline()),
                Err(CrlFetchError::Status(status))
            );
        }
    }

    #[test]
    fn content_encoding_is_refused() {
        let (addr, _server) = answer(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nlist".to_vec(),
        );
        assert!(matches!(
            crl(&source(), &url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::Malformed(_))
        ));
        let (addr, _server) = answer(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 4\r\n\r\nlist"
                .to_vec(),
        );
        assert_eq!(
            crl(&source(), &url(addr, "/ca.crl"), deadline()),
            Ok(b"list".to_vec())
        );
    }

    /// A 200 head with a zero-length body and `fields` fields, padded with
    /// one `X-Pad` field to `total` bytes when `total` is given.
    fn head_with(fields: usize, total: Option<usize>) -> Vec<u8> {
        let mut head = String::from("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n");
        for i in 1..fields {
            head.push_str(&format!("X-F{i}: a\r\n"));
        }
        if let Some(total) = total {
            let pad = total - head.len() - "X-Pad: \r\n\r\n".len();
            head.push_str(&format!("X-Pad: {}\r\n", "a".repeat(pad)));
        }
        head.push_str("\r\n");
        if let Some(total) = total {
            assert_eq!(head.len(), total);
        }
        head.into_bytes()
    }

    #[test]
    fn oversized_head_is_refused() {
        let fetch = |head: Vec<u8>| {
            let (addr, _server) = answer(head);
            crl(&source(), &url(addr, "/ca.crl"), deadline())
        };
        assert_eq!(
            fetch(head_with(1, Some(CRL_MAX_HEAD_BYTES))),
            Ok(Vec::new())
        );
        assert!(matches!(
            fetch(head_with(1, Some(CRL_MAX_HEAD_BYTES + 1))),
            Err(CrlFetchError::Malformed(_))
        ));
        assert_eq!(fetch(head_with(CRL_MAX_HEADERS, None)), Ok(Vec::new()));
        assert!(matches!(
            fetch(head_with(CRL_MAX_HEADERS + 1, None)),
            Err(CrlFetchError::Malformed(_))
        ));
    }

    #[test]
    fn body_at_cap_passes_size_check() {
        // A `Content-Length` of exactly `MAX_CRL_BYTES` passes the size
        // check, so the client starts on the body; the server sends one
        // byte and closes. `TooLarge` here would mean `fetch` caps below
        // `MAX_CRL_BYTES`. No 32 MiB transfer, so no wall-clock margin to
        // keep (#131); the full body at a cap is read in
        // `chunked_body_at_cap_passes_size_check`.
        let (addr, server) = answer(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_CRL_BYTES}\r\n\r\n\0").into_bytes(),
        );
        assert_eq!(
            crl(&source(), &url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::Unreachable(
                "the connection closed early".into()
            ))
        );
        server.join().expect("server");
    }

    /// Chunk size of the chunked-body tests below; the cap is a multiple.
    const CHUNK: usize = 65_536;
    // Several whole chunks make up the cap, so no single chunk equals it.
    const _: () = assert!(MAX_CA_CRL_BYTES.is_multiple_of(CHUNK) && MAX_CA_CRL_BYTES / CHUNK > 1);

    /// A server that sends a chunked 200 head, `MAX_CA_CRL_BYTES` of body
    /// in chunks of `CHUNK` bytes, then `tail`. The chunk logic does not
    /// depend on the cap's value, so these tests use the 1 MiB CA cap
    /// through `fetch_limited` rather than moving 32 MiB (#131).
    fn chunked_at_cap(tail: &'static [u8]) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        server(move |tcp| {
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let size = format!("{CHUNK:x}\r\n");
            let chunk = vec![0u8; CHUNK];
            for _ in 0..MAX_CA_CRL_BYTES / CHUNK {
                let _ = tcp.write_all(size.as_bytes());
                let _ = tcp.write_all(&chunk);
                let _ = tcp.write_all(b"\r\n");
            }
            let _ = tcp.write_all(tail);
        })
    }

    #[test]
    fn chunked_body_at_cap_passes_size_check() {
        let (addr, _server) = chunked_at_cap(b"0\r\n\r\n");
        let body = source()
            .fetch_limited(&url(addr, "/ca.crl"), MAX_CA_CRL_BYTES, deadline())
            .expect("fetch");
        assert_eq!(body.len(), MAX_CA_CRL_BYTES);
    }

    #[test]
    fn body_one_over_cap_is_too_large() {
        // The chunks sum to the cap; one more 1-byte chunk is over it.
        let (addr, _server) = chunked_at_cap(b"1\r\n\0\r\n0\r\n\r\n");
        assert_eq!(
            source().fetch_limited(&url(addr, "/ca.crl"), MAX_CA_CRL_BYTES, deadline()),
            Err(CrlFetchError::TooLarge)
        );
    }

    #[test]
    fn chunk_header_over_cap_fails_before_data() {
        let (addr, server) = server(|tcp| {
            let _ = tcp.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    MAX_CA_CRL_BYTES + 1
                )
                .as_bytes(),
            );
            // No chunk data: a client that waited for it would end in
            // `TimedOut`, so the verdict alone shows it did not.
            let _ = read_head(tcp);
        });
        assert_eq!(
            source().fetch_limited(&url(addr, "/ca.crl"), MAX_CA_CRL_BYTES, deadline()),
            Err(CrlFetchError::TooLarge)
        );
        server.join().expect("server");
    }

    #[test]
    fn content_length_over_cap_fails_before_body() {
        let (addr, server) = server(|tcp| {
            let _ = tcp.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_CRL_BYTES + 1
                )
                .as_bytes(),
            );
            // No body byte: the client must not wait for one.
            let _ = read_head(tcp);
        });
        let start = Instant::now();
        assert_eq!(
            crl(&source(), &url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::TooLarge)
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        server.join().expect("server");
    }

    #[test]
    fn http_source_ca_cap_stops_before_body() {
        // An intermediate's list (ADR-027): a `Content-Length` one over
        // `MAX_CA_CRL_BYTES` fails before any body byte.
        let (addr, server) = server(|tcp| {
            let _ = tcp.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_CA_CRL_BYTES + 1
                )
                .as_bytes(),
            );
            let _ = read_head(tcp);
        });
        let start = Instant::now();
        assert_eq!(
            source().fetch_limited(&url(addr, "/root.crl"), MAX_CA_CRL_BYTES, deadline()),
            Err(CrlFetchError::TooLarge)
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        server.join().expect("server");
        // At the cap the body is read.
        let (addr, _server) = answer(ok_with(&vec![0u8; MAX_CA_CRL_BYTES]));
        let body = source()
            .fetch_limited(&url(addr, "/root.crl"), MAX_CA_CRL_BYTES, deadline())
            .expect("fetch");
        assert_eq!(body.len(), MAX_CA_CRL_BYTES);
    }

    #[test]
    fn stall_times_out() {
        let (addr, _server) = server(|tcp| {
            // Accept and never answer, until the client goes away.
            let _ = read_head(tcp);
        });
        let mut source = source();
        source.io_timeout = Duration::from_millis(200);
        let start = Instant::now();
        assert_eq!(
            crl(&source, &url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::TimedOut)
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn trickle_hits_deadline() {
        let (addr, _server) = server(|tcp| {
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\n");
            for _ in 0..200 {
                if tcp.write_all(b"X").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let start = Instant::now();
        assert_eq!(
            crl(
                &source(),
                &url(addr, "/ca.crl"),
                start + Duration::from_millis(300)
            ),
            Err(CrlFetchError::TimedOut)
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn deadline_already_passed_does_not_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        assert_eq!(
            crl(&source(), &url(addr, "/ca.crl"), Instant::now()),
            Err(CrlFetchError::TimedOut)
        );
        assert_eq!(
            listener.accept().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock)
        );
    }

    /// The lookup of a point's or responder's host counts inside the
    /// fetch's deadline (ADR-022): against a name server that never
    /// answers, both fetches end at the 300 ms deadline with `TimedOut`,
    /// never `Unreachable`, and not at the resolver's 10 s try timeout.
    #[test]
    fn stalled_resolver_times_out_at_the_deadline() {
        // Bound and never read: every query waits in its queue.
        let stalled = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let resolver = crate::Resolver::fixed(
            crate::ResolverConfig::new(
                vec![stalled.local_addr().expect("addr")],
                Duration::from_secs(10),
                2,
            )
            .expect("config"),
        );
        let tls = TlsConfig::new(crl_roots())
            .expect("config")
            .with_resolver(resolver);
        let source = HttpSource::new(tls.without_revocation());
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        let start = Instant::now();
        let result = crl(&source, &point, start + Duration::from_millis(300));
        let elapsed = start.elapsed();
        assert_eq!(result, Err(CrlFetchError::TimedOut));
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        let responder = CrlUrl::parse("http://ocsp.boneli.test/").expect("URL");
        let start = Instant::now();
        let result = ocsp(
            &source,
            &responder,
            b"request",
            start + Duration::from_millis(300),
        );
        let elapsed = start.elapsed();
        assert_eq!(result, Err(CrlFetchError::TimedOut));
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn https_point_fetches_without_recursion() {
        // The CRL server's own leaf names `http://crl.boneli.test/ca.crl`,
        // which does not resolve: with a revocation check on this
        // connection the fetch would fail there.
        let chain = CertificateDer::pem_slice_iter(include_bytes!("../../tests/data/crl-good.pem"))
            .collect::<Result<Vec<_>, _>>()
            .expect("cert");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/data/crl-leaf.key"))
            .expect("key");
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server cert"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(GUARD)).expect("timeout");
            let conn = ServerConnection::new(config).expect("server");
            let mut tls = StreamOwned::new(conn, tcp);
            let head = read_head(&mut tls);
            let _ = tls.write_all(&ok_with(b"over tls"));
            tls.conn.send_close_notify();
            let _ = tls.flush();
            head
        });
        let url = CrlUrl::parse(&format!("https://127.0.0.1:{}/ca.crl", addr.port())).expect("URL");
        assert_eq!(crl(&source(), &url, deadline()), Ok(b"over tls".to_vec()));
        let head = server.join().expect("server");
        assert!(head.starts_with(b"GET /ca.crl HTTP/1.1\r\n"));
    }

    // ------------------------------------------------------------- proxy

    /// A source whose fetches go through the proxy at `addr`, with
    /// credentials `user:pass`.
    fn proxied(addr: SocketAddr) -> HttpSource {
        let proxy = Proxy::new("127.0.0.1", addr.port())
            .expect("proxy")
            .with_credentials(crate::BasicCredentials::new("user", "pass").expect("valid"));
        let tls = TlsConfig::new(crl_roots())
            .expect("config")
            .with_proxy(proxy);
        HttpSource::new(tls.without_revocation())
    }

    /// An `http` point through the proxy: one absolute-form `GET` with
    /// `Host` only, to the proxy, never to the point's host
    /// (`crl.boneli.test` does not resolve). The credentials stay back
    /// until the proxy asks for them (ADR-039, D8).
    #[test]
    fn http_point_is_an_absolute_get_to_the_proxy() {
        let (addr, server) = answer(ok_with(b"list"));
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        assert_eq!(
            crl(&proxied(addr), &point, deadline()),
            Ok(b"list".to_vec())
        );
        let head = String::from_utf8(server.join().expect("server")).expect("ASCII");
        assert_eq!(
            head,
            "GET http://crl.boneli.test/ca.crl HTTP/1.1\r\nHost: crl.boneli.test\r\n\r\n"
        );
        // A non-200 from the proxy is a status, as on a direct fetch.
        let (addr, _server) =
            answer(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec());
        assert_eq!(
            crl(&proxied(addr), &point, deadline()),
            Err(CrlFetchError::Status(403))
        );
    }

    /// A proxy's `407` with a `Basic` challenge.
    const PROXY_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n";

    /// Accepts one connection per answer, in order, reads its request head
    /// and writes the answer. Returns the heads and the listener, so a
    /// test can check that no further connection came.
    fn sequence(
        answers: Vec<Vec<u8>>,
    ) -> (SocketAddr, thread::JoinHandle<(Vec<String>, TcpListener)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            let mut heads = Vec::new();
            for answer in answers {
                let (mut tcp, _) = listener.accept().expect("accept");
                tcp.set_read_timeout(Some(GUARD)).expect("timeout");
                heads.push(String::from_utf8(read_head(&mut tcp)).expect("ASCII"));
                let _ = tcp.write_all(&answer);
            }
            (heads, listener)
        });
        (addr, handle)
    }

    /// Whether a connection is waiting on `listener`.
    fn another_connection(listener: &TcpListener) -> bool {
        listener.set_nonblocking(true).expect("nonblocking");
        thread::sleep(Duration::from_millis(100));
        listener.accept().is_ok()
    }

    /// The proxy answers the plain `GET` with `407`: one retry on a new
    /// connection carries `Proxy-Authorization`, and its answer counts.
    #[test]
    fn proxied_get_sends_credentials_only_after_407() {
        let (addr, server) = sequence(vec![PROXY_407.to_vec(), ok_with(b"list")]);
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        assert_eq!(
            crl(&proxied(addr), &point, deadline()),
            Ok(b"list".to_vec())
        );
        let (heads, listener) = server.join().expect("server");
        assert_eq!(
            heads,
            [
                "GET http://crl.boneli.test/ca.crl HTTP/1.1\r\nHost: crl.boneli.test\r\n\r\n",
                "GET http://crl.boneli.test/ca.crl HTTP/1.1\r\nHost: crl.boneli.test\r\n\
Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            ]
        );
        assert!(!another_connection(&listener), "a third request");
        // The OCSP path goes through the same fetch.
        let (addr, server) = sequence(vec![PROXY_407.to_vec(), ok_with(b"answer")]);
        let responder = CrlUrl::parse("http://ocsp.boneli.test/").expect("URL");
        assert_eq!(
            ocsp(&proxied(addr), &responder, REQUEST, deadline()),
            Ok(b"answer".to_vec())
        );
        let (heads, _) = server.join().expect("server");
        assert!(!heads[0].contains("Proxy-Authorization"), "{heads:?}");
        assert!(
            heads[1].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "{heads:?}"
        );
    }

    /// A second `407` fails closed with an error that names the proxy and
    /// the refusal, never the credentials; there is no third try.
    #[test]
    fn second_407_fails_closed() {
        let (addr, server) = sequence(vec![PROXY_407.to_vec(), PROXY_407.to_vec()]);
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        let err = crl(&proxied(addr), &point, deadline()).expect_err("refused");
        assert_eq!(
            err,
            CrlFetchError::Unreachable(format!(
                "the proxy 127.0.0.1:{} answered 407 to GET http://crl.boneli.test/ca.crl again: \
it refused the configured credentials; only Basic is sent",
                addr.port()
            ))
        );
        let (heads, listener) = server.join().expect("server");
        assert_eq!(heads.len(), 2);
        assert!(!another_connection(&listener), "a third request");
    }

    /// A `407` with these `Proxy-Authenticate` fields.
    fn status_407(challenges: &[&str]) -> Vec<u8> {
        let mut head = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
        for challenge in challenges {
            head.push_str(&format!("Proxy-Authenticate: {challenge}\r\n"));
        }
        head.push_str("Content-Length: 0\r\n\r\n");
        head.into_bytes()
    }

    /// A `407` without a `Basic` challenge is not the proxy's own: a
    /// server's, passed on by a proxy that did not authenticate (Apache
    /// httpd with an IP rule strips the server's `Proxy-Authenticate`).
    /// No retry, so no credential goes out, and the error says why.
    #[test]
    fn relayed_407_without_basic_challenge_is_not_retried() {
        for challenges in [&[][..], &["Negotiate"], &["NTLM", "Negotiate abc=="]] {
            let (addr, server) = sequence(vec![status_407(challenges)]);
            let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
            let err = crl(&proxied(addr), &point, deadline()).expect_err("refused");
            let CrlFetchError::Unreachable(text) = &err else {
                panic!("{challenges:?}: {err:?}");
            };
            assert!(
                text.contains("without a Basic Proxy-Authenticate challenge"),
                "{text}"
            );
            assert!(!text.contains("dXNlcjpwYXNz"), "{text}");
            let (heads, listener) = server.join().expect("server");
            assert!(!heads[0].contains("Proxy-Authorization"), "{heads:?}");
            assert!(!another_connection(&listener), "{challenges:?}: retried");
        }
    }

    /// A `Basic` challenge among others, in one field or in several, in any
    /// case, is the proxy's own: one retry with credentials, as before.
    #[test]
    fn basic_among_challenges_is_retried_once() {
        for challenges in [
            &["Negotiate", "basic realm=\"proxy\""][..],
            &["Negotiate, BASIC realm=\"proxy\", NTLM"],
        ] {
            let (addr, server) = sequence(vec![status_407(challenges), ok_with(b"list")]);
            let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
            assert_eq!(
                crl(&proxied(addr), &point, deadline()),
                Ok(b"list".to_vec()),
                "{challenges:?}"
            );
            let (heads, listener) = server.join().expect("server");
            assert!(!heads[0].contains("Proxy-Authorization"), "{heads:?}");
            assert!(
                heads[1].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
                "{heads:?}"
            );
            assert!(!another_connection(&listener), "a third request");
        }
    }

    /// The proxy takes the credentials on the retry, and the server behind
    /// it answers `407`, passed on without a challenge: the fetch fails
    /// with that reason, with no third try.
    #[test]
    fn relayed_407_after_the_retry_is_final() {
        let (addr, server) = sequence(vec![PROXY_407.to_vec(), status_407(&[])]);
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        let err = crl(&proxied(addr), &point, deadline()).expect_err("refused");
        assert!(
            matches!(&err, CrlFetchError::Unreachable(t) if t.contains("without a Basic")),
            "{err:?}"
        );
        let (heads, listener) = server.join().expect("server");
        assert_eq!(heads.len(), 2);
        assert!(!another_connection(&listener), "a third request");
    }

    /// Without credentials a `407` is not retried and says that none are
    /// configured.
    #[test]
    fn proxied_407_without_credentials_is_not_retried() {
        let (addr, server) = sequence(vec![PROXY_407.to_vec()]);
        let proxy = Proxy::new("127.0.0.1", addr.port()).expect("proxy");
        let tls = TlsConfig::new(crl_roots())
            .expect("config")
            .with_proxy(proxy);
        let source = HttpSource::new(tls.without_revocation());
        let point = CrlUrl::parse("http://crl.boneli.test/ca.crl").expect("URL");
        let err = crl(&source, &point, deadline()).expect_err("refused");
        let CrlFetchError::Unreachable(text) = &err else {
            panic!("{err:?}");
        };
        assert!(text.contains("answered 407"), "{text}");
        assert!(text.contains("none are configured"), "{text}");
        let (_, listener) = server.join().expect("server");
        assert!(
            !another_connection(&listener),
            "a retry without credentials"
        );
    }

    /// `CONNECT` keeps its credentials up front, and its `407` is final:
    /// no retry.
    #[test]
    fn connect_carries_credentials_up_front_and_407_is_final() {
        let (addr, server) = sequence(vec![PROXY_407.to_vec()]);
        let point = CrlUrl::parse("https://crl.boneli.test/ca.crl").expect("URL");
        let err = crl(&proxied(addr), &point, deadline()).expect_err("refused");
        assert_eq!(
            err,
            CrlFetchError::Unreachable(format!(
                "the proxy 127.0.0.1:{} answered 407 to CONNECT crl.boneli.test:443: \
it asks for credentials; only Basic is sent",
                addr.port()
            ))
        );
        let (heads, listener) = server.join().expect("server");
        assert_eq!(
            heads,
            [
                "CONNECT crl.boneli.test:443 HTTP/1.1\r\nHost: crl.boneli.test:443\r\n\
Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
            ]
        );
        assert!(!another_connection(&listener), "CONNECT was retried");
    }

    /// An `https` point through the proxy: `CONNECT` with
    /// `Proxy-Authorization`, then TLS to the point inside the tunnel with
    /// a request that carries `Host` only. Here the proxy serves the
    /// point's TLS itself.
    #[test]
    fn https_point_tunnels_through_the_proxy() {
        let chain = CertificateDer::pem_slice_iter(include_bytes!("../../tests/data/crl-good.pem"))
            .collect::<Result<Vec<_>, _>>()
            .expect("cert");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/data/crl-leaf.key"))
            .expect("key");
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server cert"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let proxy = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(GUARD)).expect("timeout");
            let tunnel_head = read_head(&mut tcp);
            tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answer");
            let conn = ServerConnection::new(config).expect("server");
            let mut tls = StreamOwned::new(conn, tcp);
            let inner = read_head(&mut tls);
            let _ = tls.write_all(&ok_with(b"over tls"));
            tls.conn.send_close_notify();
            let _ = tls.flush();
            (tunnel_head, inner)
        });
        let point = CrlUrl::parse("https://localhost:8443/ca.crl").expect("URL");
        assert_eq!(
            crl(&proxied(addr), &point, deadline()),
            Ok(b"over tls".to_vec())
        );
        let (tunnel_head, inner) = proxy.join().expect("proxy");
        assert_eq!(
            String::from_utf8_lossy(&tunnel_head),
            "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\n\
Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        );
        assert_eq!(
            String::from_utf8_lossy(&inner),
            "GET /ca.crl HTTP/1.1\r\nHost: localhost:8443\r\n\r\n"
        );
    }

    /// A refused `CONNECT` for an `https` point is `Unreachable` naming the
    /// proxy, the target and the status, without the credentials.
    #[test]
    fn https_point_refused_by_the_proxy_names_it() {
        let (addr, _server) = answer(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec());
        let point = CrlUrl::parse("https://crl.boneli.test/ca.crl").expect("URL");
        let err = crl(&proxied(addr), &point, deadline()).expect_err("refused");
        assert_eq!(
            err,
            CrlFetchError::Unreachable(format!(
                "the proxy 127.0.0.1:{} answered 403 to CONNECT crl.boneli.test:443",
                addr.port()
            ))
        );
        assert!(!err.to_string().contains("dXNlcjpwYXNz"));
        // A deadline past the proxy dials nothing.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        assert_eq!(
            crl(&proxied(addr), &point, Instant::now()),
            Err(CrlFetchError::TimedOut)
        );
        assert_eq!(
            listener.accept().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock)
        );
    }

    // ------------------------------------------------------------- OCSP

    /// openssl's request for `ocsp-good.pem`.
    const REQUEST: &[u8] = include_bytes!("../../tests/data/ocsp-good.req");

    fn responder(addr: SocketAddr) -> CrlUrl {
        url(addr, "/")
    }

    #[test]
    fn ocsp_request_carries_host_only() {
        let (addr, server) = answer(ok_with(b"answer"));
        let body = ocsp(&source(), &responder(addr), REQUEST, deadline()).expect("fetch");
        assert_eq!(body, b"answer");
        let head = String::from_utf8(server.join().expect("server")).expect("ASCII");
        let mut lines = head.split("\r\n");
        let path = super::super::ocsp::get_path(&responder(addr), REQUEST);
        assert_eq!(lines.next(), Some(format!("GET {path} HTTP/1.1").as_str()));
        let fields: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
        assert_eq!(fields, [format!("Host: 127.0.0.1:{}", addr.port())]);
        let lower = head.to_ascii_lowercase();
        for name in ["user-agent", "accept", "cookie", "authorization"] {
            assert!(!lower.contains(name), "{name} in {head:?}");
        }
    }

    #[test]
    fn ocsp_non_200_and_redirect_fail() {
        for status in [301, 404, 500] {
            let (addr, _server) = answer(
                format!("HTTP/1.1 {status} X\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\n\r\n")
                    .into_bytes(),
            );
            assert_eq!(
                ocsp(&source(), &responder(addr), REQUEST, deadline()),
                Err(CrlFetchError::Status(status))
            );
        }
    }

    #[test]
    fn ocsp_content_encoding_is_refused() {
        let (addr, _server) = answer(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nresp".to_vec(),
        );
        assert!(matches!(
            ocsp(&source(), &responder(addr), REQUEST, deadline()),
            Err(CrlFetchError::Malformed(_))
        ));
    }

    #[test]
    fn ocsp_body_at_cap_passes_size_check() {
        let (addr, _server) = answer(ok_with(&vec![0u8; MAX_OCSP_RESPONSE_BYTES]));
        let body = ocsp(&source(), &responder(addr), REQUEST, deadline()).expect("fetch");
        assert_eq!(body.len(), MAX_OCSP_RESPONSE_BYTES);
    }

    #[test]
    fn ocsp_body_one_over_cap_is_too_large() {
        let (addr, _server) = server(|tcp| {
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let _ = tcp.write_all(b"10000\r\n");
            let _ = tcp.write_all(&vec![0u8; MAX_OCSP_RESPONSE_BYTES]);
            let _ = tcp.write_all(b"\r\n1\r\n\0\r\n0\r\n\r\n");
        });
        assert_eq!(
            ocsp(&source(), &responder(addr), REQUEST, deadline()),
            Err(CrlFetchError::TooLarge)
        );
    }

    #[test]
    fn ocsp_content_length_over_cap_fails_before_body() {
        let (addr, server) = server(|tcp| {
            let _ = tcp.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_OCSP_RESPONSE_BYTES + 1
                )
                .as_bytes(),
            );
            // No body byte: the client must not wait for one.
            let _ = read_head(tcp);
        });
        let start = Instant::now();
        assert_eq!(
            ocsp(&source(), &responder(addr), REQUEST, deadline()),
            Err(CrlFetchError::TooLarge)
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        server.join().expect("server");
    }

    #[test]
    fn https_responder_fetches_without_recursion() {
        // The server's leaf names `http://ocsp.boneli.test`, which does not
        // resolve: with a revocation check on this connection the fetch
        // would fail there.
        let chain =
            CertificateDer::pem_slice_iter(include_bytes!("../../tests/data/ocsp-good.pem"))
                .collect::<Result<Vec<_>, _>>()
                .expect("cert");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tests/data/crl-leaf.key"))
            .expect("key");
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server cert"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(GUARD)).expect("timeout");
            let conn = ServerConnection::new(config).expect("server");
            let mut tls = StreamOwned::new(conn, tcp);
            let head = read_head(&mut tls);
            let _ = tls.write_all(&ok_with(b"over tls"));
            tls.conn.send_close_notify();
            let _ = tls.flush();
            head
        });
        let mut roots = Roots::empty();
        roots
            .add_pem(include_bytes!("../../tests/data/ocsp-ca.pem"))
            .expect("OCSP test CA");
        let tls = TlsConfig::new(roots).expect("config");
        let source = HttpSource::new(tls.without_revocation());
        let url = CrlUrl::parse(&format!("https://127.0.0.1:{}/ocsp", addr.port())).expect("URL");
        assert_eq!(
            ocsp(&source, &url, REQUEST, deadline()),
            Ok(b"over tls".to_vec())
        );
        let head = server.join().expect("server");
        assert!(
            head.starts_with(b"GET /ocsp/MEIwQDA%2BMDwwOjAJBgUrDgMCGgUA"),
            "{:?}",
            String::from_utf8_lossy(&head)
        );
    }
}
