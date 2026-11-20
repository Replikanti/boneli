//! The real `CrlSource` (ADR-017, items 6 and 7): one HTTP/1.1 `GET` per
//! fetch through `boneli-http`, directly from this process, under the
//! check's deadline. `Host` is the only field sent: no `User-Agent`,
//! credentials or cookies. 200 only, no redirect followed, no
//! `Content-Encoding`, the body read to its end under `MAX_CRL_BYTES`.
//! An `https` point is fetched over this crate's TLS client with the same
//! roots and without a revocation check of its own, which keeps the fetch
//! from recursing: the list's integrity comes from its signature, not
//! from the transport.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use boneli_http::{
    Connection, IdleCheck, Limits, Method, RequestBody, RequestHead, Target, Transport,
};

use super::url::{CrlScheme, CrlUrl};
use super::{
    CRL_CONNECT_TIMEOUT, CRL_HANDSHAKE_TIMEOUT, CRL_IO_TIMEOUT, CRL_MAX_HEAD_BYTES,
    CRL_MAX_HEADERS, CrlFetchError, CrlSource, MAX_CRL_BYTES,
};
use crate::dial::{DeadlineSocket, time_left};
use crate::{ConnectOptions, TlsConfig};

/// Fetches CRLs over HTTP and HTTPS.
pub(crate) struct HttpCrlSource {
    /// The handshake's roots and groups, without a revocation check.
    tls: TlsConfig,
    /// Each TCP connection attempt.
    pub(crate) connect_timeout: Duration,
    /// The TLS handshake of an `https` point.
    pub(crate) handshake_timeout: Duration,
    /// Each read and write.
    pub(crate) io_timeout: Duration,
}

impl HttpCrlSource {
    /// A source whose `https` fetches use `tls`, which must not check
    /// revocation itself.
    pub(crate) fn new(tls: TlsConfig) -> HttpCrlSource {
        HttpCrlSource {
            tls,
            connect_timeout: CRL_CONNECT_TIMEOUT,
            handshake_timeout: CRL_HANDSHAKE_TIMEOUT,
            io_timeout: CRL_IO_TIMEOUT,
        }
    }

    fn get(
        &self,
        tcp: TcpStream,
        url: &CrlUrl,
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let socket = DeadlineSocket::new(tcp, deadline);
        socket
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| socket.set_write_timeout(Some(self.io_timeout)))
            .map_err(io_error)?;
        match url.scheme() {
            CrlScheme::Http => request(socket, url),
            CrlScheme::Https => {
                let options = ConnectOptions::new(
                    self.connect_timeout,
                    self.handshake_timeout,
                    self.io_timeout,
                )
                .map_err(|e| CrlFetchError::Unreachable(e.to_string()))?;
                let tls = crate::connect_over_until(
                    socket,
                    url.host(),
                    &self.tls,
                    &options,
                    Some(deadline),
                )
                .map_err(|e| match e {
                    crate::Error::Io(e) => io_error(e),
                    other => CrlFetchError::Unreachable(format!("TLS: {other}")),
                })?;
                request(tls, url)
            }
        }
    }
}

impl CrlSource for HttpCrlSource {
    fn fetch(&self, url: &CrlUrl, deadline: Instant) -> Result<Vec<u8>, CrlFetchError> {
        time_left(deadline).map_err(io_error)?;
        // std's resolver takes no timeout, so the lookup itself is not
        // bounded by the deadline, as for `TlsDial`'s own host (ADR-017,
        // known limits); everything after it is.
        let addrs = (url.host(), url.port())
            .to_socket_addrs()
            .map_err(|e| CrlFetchError::Unreachable(format!("cannot resolve the host: {e}")))?;
        let mut last = None;
        for addr in addrs {
            let left = time_left(deadline).map_err(io_error)?;
            match TcpStream::connect_timeout(&addr, left.min(self.connect_timeout)) {
                Ok(tcp) => return self.get(tcp, url, deadline),
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(
            || CrlFetchError::Unreachable("the host has no address".into()),
            io_error,
        ))
    }
}

/// `GET <path>` with `Host` only; 200, no content coding, the whole body.
fn request<S: Read + Write + IdleCheck>(stream: S, url: &CrlUrl) -> Result<Vec<u8>, CrlFetchError> {
    let limits = Limits::new(CRL_MAX_HEAD_BYTES, CRL_MAX_HEADERS, MAX_CRL_BYTES as u64)
        .map_err(http_error)?;
    let mut conn = Connection::new(stream, &url.authority(), limits).map_err(http_error)?;
    let head = RequestHead::new(
        Method::new("GET").map_err(http_error)?,
        Target::Origin(url.path().to_owned()),
    );
    let mut response = conn.request(&head, RequestBody::None).map_err(http_error)?;
    let status = response.head.status;
    if status != 200 {
        return Err(CrlFetchError::Status(status));
    }
    // RFC 5280, 4.2.1.13: the point serves DER. A coding would need a
    // decoder and is never needed (none measured, ADR-017 item 6).
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

    const GUARD: Duration = Duration::from_secs(10);

    fn crl_roots() -> Roots {
        let mut roots = Roots::empty();
        roots
            .add_pem(include_bytes!("../../tests/data/crl-ca.pem"))
            .expect("CRL test CA");
        roots
    }

    fn source() -> HttpCrlSource {
        let tls = TlsConfig::new(crl_roots()).expect("config");
        HttpCrlSource::new(tls.without_revocation())
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
        let body = source()
            .fetch(&url(addr, "/ca.crl"), deadline())
            .expect("fetch");
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
        let err = source().fetch(&url(addr, "/ca.crl"), deadline());
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
                source().fetch(&url(addr, "/ca.crl"), deadline()),
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
            source().fetch(&url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::Malformed(_))
        ));
        let (addr, _server) = answer(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 4\r\n\r\nlist"
                .to_vec(),
        );
        assert_eq!(
            source().fetch(&url(addr, "/ca.crl"), deadline()),
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
            source().fetch(&url(addr, "/ca.crl"), deadline())
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
        let (addr, _server) = answer(ok_with(&vec![0u8; MAX_CRL_BYTES]));
        let body = source()
            .fetch(&url(addr, "/ca.crl"), deadline())
            .expect("fetch");
        assert_eq!(body.len(), MAX_CRL_BYTES);
    }

    #[test]
    fn body_one_over_cap_is_too_large() {
        let (addr, _server) = server(|tcp| {
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let chunk = vec![0u8; 1_048_576];
            for _ in 0..32 {
                let _ = tcp.write_all(b"100000\r\n");
                let _ = tcp.write_all(&chunk);
                let _ = tcp.write_all(b"\r\n");
            }
            let _ = tcp.write_all(b"1\r\n\0\r\n0\r\n\r\n");
        });
        assert_eq!(
            source().fetch(&url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::TooLarge)
        );
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
            source().fetch(&url(addr, "/ca.crl"), deadline()),
            Err(CrlFetchError::TooLarge)
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        server.join().expect("server");
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
            source.fetch(&url(addr, "/ca.crl"), deadline()),
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
            source().fetch(&url(addr, "/ca.crl"), start + Duration::from_millis(300)),
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
            source().fetch(&url(addr, "/ca.crl"), Instant::now()),
            Err(CrlFetchError::TimedOut)
        );
        assert_eq!(
            listener.accept().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock)
        );
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
        assert_eq!(source().fetch(&url, deadline()), Ok(b"over tls".to_vec()));
        let head = server.join().expect("server");
        assert!(head.starts_with(b"GET /ca.crl HTTP/1.1\r\n"));
    }
}
