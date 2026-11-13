//! The client: one request at a time over any stream, responses framed per
//! RFC 9112 §6.3, and CONNECT tunnels (ADR-003).
//!
//! It follows no redirects, sends no `Accept-Encoding` and decodes nothing,
//! keeps no cookies and reads no proxy environment variables: the caller
//! decides each of these, for example whether credentials may follow a
//! redirect to another host.

use std::io::{self, Read, Write};

use crate::body::{BodyReader, BodyState, BodyWriter};
use crate::error::{Error, Result};
use crate::head::{
    Framing, RequestHead, ResponseHead, Target, authority_host, host_field, parse_response,
    response_framing,
};
use crate::limits::Limits;
use crate::transport::{IdleCheck, Tunnel};
use crate::wire::Wire;

/// Header fields the client writes itself. A caller that sets one gets an
/// error, so that a gateway cannot forward its peer's framing upstream.
const OWNED: [&str; 4] = ["host", "content-length", "transfer-encoding", "connection"];

/// The body of a request.
pub enum RequestBody<'a> {
    /// No body and no framing field.
    None,
    /// These bytes, sent with `Content-Length`.
    Bytes(&'a [u8]),
    /// Bytes from a reader: with `Content-Length` when `length` is known
    /// (the reader must yield exactly that many), chunked otherwise.
    Reader {
        /// The source of the body.
        reader: &'a mut dyn Read,
        /// The exact length, if known.
        length: Option<u64>,
    },
}

/// A client connection that sends one request at a time. It is reused only
/// while the peer stays quiet between responses: bytes beyond a response,
/// or bytes and the end of the stream that arrive before a request,
/// including the first, end it (ADR-003, item 12).
pub struct Connection<S> {
    wire: Wire<S>,
    body: BodyState,
    close: bool,
    /// A request has been sent before.
    used: bool,
    host: String,
    limits: Limits,
}

impl<S: Read + Write> Connection<S> {
    /// A connection over `stream` whose requests carry `Host: host`. The
    /// host is a name, an IPv4 address or a bracketed IPv6 address, with
    /// an optional port.
    pub fn new(stream: S, host: &str, limits: Limits) -> Result<Connection<S>> {
        Ok(Connection {
            wire: Wire::new(stream, None),
            body: BodyState::Done,
            close: false,
            used: false,
            host: host_field(host)?,
            limits,
        })
    }

    /// Whether another request may be sent: the last response body was read
    /// to its end, no byte beyond it has been read, and neither side asked
    /// to close. `request` also checks that nothing arrived since
    /// (`IdleCheck`).
    pub fn is_reusable(&self) -> bool {
        self.body == BodyState::Done && !self.close && self.wire.available().is_empty()
    }

    /// The stream, for example to set timeouts.
    pub fn get_ref(&self) -> &S {
        &self.wire.stream
    }
}

impl<S: Read + Write + IdleCheck> Connection<S> {
    /// Sends one request and reads the head of its response. The head must
    /// have an origin-form target and must not set `Host`,
    /// `Content-Length`, `Transfer-Encoding` or `Connection`; CONNECT goes
    /// through `connect_tunnel`. On an invalid head nothing is written.
    ///
    /// Before every request, the first included, the stream must not
    /// report input (`IdleCheck::is_idle`), and on a connection used before
    /// it must report that it is idle; otherwise nothing is written, the
    /// connection is no longer reusable, and the caller opens a new one.
    pub fn request(
        &mut self,
        head: &RequestHead,
        body: RequestBody<'_>,
    ) -> Result<Response<'_, S>> {
        if !self.is_reusable() {
            return Err(Error::InvalidInput("connection is not reusable"));
        }
        if !matches!(head.target, Target::Origin(_)) || head.method.is_connect() {
            return Err(Error::InvalidInput(
                "request() takes origin-form targets; use connect_tunnel",
            ));
        }
        if head.headers.has_any(&OWNED) {
            return Err(Error::InvalidInput(
                "the client writes Host and the framing fields",
            ));
        }
        let encoded = head.encode()?;
        // The request line, then our fields, then the caller's.
        let line_end = encoded
            .windows(2)
            .position(|w| w == b"\r\n")
            .map_or(0, |i| i + 2);
        let mut out = encoded[..line_end].to_vec();
        out.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());
        let framing = match &body {
            RequestBody::None => Framing::None,
            RequestBody::Bytes(bytes) => Framing::Length(bytes.len() as u64),
            RequestBody::Reader {
                length: Some(n), ..
            } => Framing::Length(*n),
            RequestBody::Reader { length: None, .. } => Framing::Chunked,
        };
        match framing {
            Framing::None => {}
            Framing::Length(n) => {
                out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes())
            }
            Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        }
        out.extend_from_slice(&encoded[line_end..]);

        // Bytes that arrived before the request answered no request; read
        // as the response they would answer this one. That holds for the
        // first request too: a tunnel's early bytes come from the proxy, not
        // from the origin. A stream that cannot tell serves one request.
        match self.wire.stream.is_idle() {
            Ok(Some(true)) => {}
            Ok(None) if !self.used => {}
            Ok(None) => {
                self.close = true;
                return Err(Error::InvalidInput(
                    "the stream cannot tell whether bytes arrived while it was idle",
                ));
            }
            Ok(Some(false)) => {
                self.close = true;
                return Err(Error::Malformed(
                    "bytes or the end of the stream arrived before the request",
                ));
            }
            Err(e) => {
                self.close = true;
                return Err(e.into());
            }
        }

        // From here on a failure leaves the stream in an unknown state.
        self.close = true;
        self.used = true;
        let stream = &mut self.wire.stream;
        match body {
            RequestBody::None => stream.write_all(&out)?,
            RequestBody::Bytes(bytes) => {
                out.extend_from_slice(bytes);
                stream.write_all(&out)?;
            }
            RequestBody::Reader { reader, length } => {
                stream.write_all(&out)?;
                let mut writer = match length {
                    Some(n) => BodyWriter::length(&mut *stream, n),
                    None => BodyWriter::chunked(&mut *stream),
                };
                io::copy(reader, &mut writer)?;
                writer.finish()?;
            }
        }
        stream.flush()?;

        let response = read_final_head(&mut self.wire, &self.limits)?;
        let framing = response_framing(&response.headers)?;
        let bodyless = head.method.is_head() || response.status == 204 || response.status == 304;
        self.body = match framing {
            _ if bodyless => BodyState::Done,
            Framing::None => BodyState::UntilClose { received: 0 },
            Framing::Length(n) if n > self.limits.max_body_bytes() => {
                return Err(Error::BodyTooLarge);
            }
            framing => BodyState::from_framing(framing),
        };
        self.close =
            response.headers.wants_close() || matches!(self.body, BodyState::UntilClose { .. });
        Ok(Response {
            head: response,
            body: BodyReader::new(&mut self.wire, &mut self.body, self.limits),
        })
    }
}

/// A response: its head, and its body to read.
pub struct Response<'a, S> {
    /// The final response head (interim 1xx heads are skipped).
    pub head: ResponseHead,
    body: BodyReader<'a, S>,
}

impl<'a, S: Read> Response<'a, S> {
    /// The body reader.
    pub fn body(&mut self) -> &mut BodyReader<'a, S> {
        &mut self.body
    }
}

impl<S: Read> Read for Response<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

/// Reads response heads until a final one. Interim 1xx heads are skipped
/// and count together with the final head against `max_head_bytes`, so an
/// endless 1xx stream fails; `101` is an error, because this client never
/// asks for a protocol switch.
fn read_final_head<S: Read>(wire: &mut Wire<S>, limits: &Limits) -> Result<ResponseHead> {
    let mut budget = limits.max_head_bytes();
    loop {
        let raw = wire.read_head(budget)?.ok_or(Error::UnexpectedEof)?;
        budget -= raw.bytes.len();
        let head = parse_response(&raw.bytes[raw.content..], limits)?;
        match head.status {
            101 => return Err(Error::Status(101)),
            100..=199 => continue,
            _ => return Ok(head),
        }
    }
}

/// Opens a tunnel with `CONNECT host:port`: sends the request, requires a
/// 2xx answer and keeps any bytes that arrived after its head. Any other
/// final status is `Error::Status`. `host` is a name, an IPv4 address or
/// an IPv6 address without brackets.
pub fn connect_tunnel<S: Read + Write>(
    mut stream: S,
    host: &str,
    port: u16,
    limits: &Limits,
) -> Result<Tunnel<S>> {
    if port == 0 {
        return Err(Error::InvalidInput("port is zero"));
    }
    let authority = format!("{}:{port}", authority_host(host)?);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes();
    stream.write_all(&request)?;
    stream.flush()?;
    let mut wire = Wire::new(stream, None);
    let head = read_final_head(&mut wire, limits)?;
    if !(200..300).contains(&head.status) {
        return Err(Error::Status(head.status));
    }
    let early = wire.take_buffered();
    Ok(Tunnel::new(early, wire.stream))
}
