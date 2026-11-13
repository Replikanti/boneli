//! The server: a Unix socket listener with one thread per connection and a
//! connection cap, and the per-connection loop with its deadlines,
//! rejections and keep-alive rules (ADR-003).

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Instant;

use crate::body::{BodyReader, BodyState, BodyWriter};
use crate::error::{Error, Result};
use crate::head::{
    Framing, Headers, RequestHead, encode_fields, encode_status_line, parse_request, reason_phrase,
};
use crate::limits::{Limits, ServerLimits};
use crate::transport::{Transport, Tunnel};
use crate::wire::Wire;

/// Header fields the server writes itself; a handler that sets one gets an
/// error and nothing is written.
const OWNED: [&str; 3] = ["content-length", "transfer-encoding", "connection"];

/// Serves `listener` until accepting fails, one thread per connection.
/// Blocks the calling thread. At `max_connections` it stops accepting, so
/// new clients wait in the kernel backlog; a slot is freed when its
/// connection ends, also when the handler panics. Per-connection errors end
/// only that connection.
///
/// One server serves one run: the socket path is the run's identity
/// (docs/ARCHITECTURE.md, "Isolation"), so a slow client holds only its own
/// run's slots.
pub fn serve<H>(listener: UnixListener, limits: ServerLimits, handler: H) -> io::Result<()>
where
    H: Fn(Exchange<'_, UnixStream>) -> Result<()> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let slots = Arc::new(Slots {
        used: Mutex::new(0),
        freed: Condvar::new(),
    });
    loop {
        {
            let mut used = slots.used.lock().unwrap_or_else(PoisonError::into_inner);
            while *used >= limits.max_connections() {
                used = slots
                    .freed
                    .wait(used)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            *used += 1;
        }
        let slot = Slot(Arc::clone(&slots));
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            // The client went away before it was accepted; the slot is
            // freed when `slot` drops.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let handler = Arc::clone(&handler);
        thread::Builder::new()
            .name("boneli-http".into())
            .spawn(move || {
                let _slot = slot;
                // The error ends this connection only; the handler has seen
                // what it needs, and logging is the caller's.
                let _ = serve_connection(stream, &limits, &*handler);
            })
            .map(drop)?;
    }
}

struct Slots {
    used: Mutex<usize>,
    freed: Condvar,
}

/// One connection's place under the cap; dropping it frees the place.
struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut used = self.0.used.lock().unwrap_or_else(PoisonError::into_inner);
        *used -= 1;
        self.0.freed.notify_one();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    /// Nothing sent yet.
    None,
    /// A complete response was sent.
    Done,
    /// A chunked response was started.
    Streaming,
    /// The stream was handed over by `accept_tunnel`.
    Tunnel,
    /// A response could not be sent; the connection closes without any
    /// further byte.
    Poisoned,
}

/// One connection's state between requests.
struct Conn<T> {
    wire: Wire<T>,
    limits: Limits,
    body: BodyState,
    close: bool,
    is_head: bool,
    is_connect: bool,
    reply: Reply,
    stream_finished: bool,
}

impl<T: Transport> Conn<T> {
    /// Answers a rejected request with the error's status and asks the
    /// client to close. Write errors are ignored: the connection closes
    /// either way.
    fn reject(&mut self, e: &Error) {
        if let Some(status) = e.status() {
            let reply = format!(
                "HTTP/1.1 {status} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                reason_phrase(status)
            );
            let _ = self.wire.stream.write_all(reply.as_bytes());
            let _ = self.wire.stream.flush();
        }
    }

    /// A response head with our framing and `Connection` fields. Checks the
    /// status and the handler's fields first.
    fn response_head(
        &mut self,
        status: u16,
        headers: &Headers,
        framing: Option<Framing>,
    ) -> Result<Vec<u8>> {
        if !(200..=999).contains(&status) {
            return Err(Error::InvalidInput(
                "handlers send final statuses from 200 to 999",
            ));
        }
        if self.is_connect && (200..300).contains(&status) {
            return Err(Error::InvalidInput(
                "a 2xx to CONNECT goes through accept_tunnel",
            ));
        }
        if headers.has_any(&OWNED) {
            return Err(Error::InvalidInput(
                "the server writes the framing fields and Connection",
            ));
        }
        let mut out = Vec::new();
        encode_status_line(&mut out, status, reason_phrase(status))?;
        encode_fields(&mut out, headers)?;
        match framing {
            Some(Framing::Length(n)) => {
                out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes())
            }
            Some(Framing::Chunked) => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
            Some(Framing::None) | None => {}
        }
        // A request body left unread is never drained: the connection
        // closes after this response. A CONNECT that is not tunnelled
        // closes too, because bytes after it are not a request.
        if self.close || self.body != BodyState::Done || self.is_connect {
            self.close = true;
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.wire.stream.write_all(bytes)?;
        self.wire.stream.flush()?;
        Ok(())
    }
}

/// One request and the means to answer it. The handler answers exactly
/// once, with `respond`, `respond_streaming` or (for CONNECT)
/// `accept_tunnel`; each consumes the exchange.
pub struct Exchange<'a, T> {
    conn: &'a mut Conn<T>,
    head: RequestHead,
}

impl<'a, T: Transport> Exchange<'a, T> {
    /// The request head.
    pub fn head(&self) -> &RequestHead {
        &self.head
    }

    /// The request body. Reads run under the request deadline; a timeout,
    /// a malformed chunk or a body over the limit is an error that the
    /// handler returns, and the server answers it with its status.
    pub fn body(&mut self) -> BodyReader<'_, T> {
        BodyReader::new(&mut self.conn.wire, &mut self.conn.body, self.conn.limits)
    }

    /// Closes the connection after this exchange.
    pub fn close_after(&mut self) {
        self.conn.close = true;
    }

    /// Sends a complete response with `Content-Length`. For a HEAD request
    /// the body bytes are left out; 204 and 304 carry no body. On an
    /// invalid status or field nothing is written and the connection
    /// closes.
    pub fn respond(self, status: u16, headers: &Headers, body: &[u8]) -> Result<()> {
        let conn = self.conn;
        conn.reply = Reply::Poisoned;
        let bodyless = status == 204 || status == 304;
        if bodyless && !body.is_empty() {
            return Err(Error::InvalidInput("204 and 304 carry no body"));
        }
        let framing = if bodyless {
            None
        } else {
            Some(Framing::Length(body.len() as u64))
        };
        let mut out = conn.response_head(status, headers, framing)?;
        if !conn.is_head {
            out.extend_from_slice(body);
        }
        conn.send(&out)?;
        conn.reply = Reply::Done;
        Ok(())
    }

    /// Starts a chunked response and returns its body writer. Call
    /// `BodyWriter::finish` at the end; without it the connection closes
    /// with the body unterminated. For a HEAD request the writer drops what
    /// it is given.
    pub fn respond_streaming(
        self,
        status: u16,
        headers: &Headers,
    ) -> Result<BodyWriter<'a, &'a mut T>> {
        let conn = self.conn;
        conn.reply = Reply::Poisoned;
        if status == 204 || status == 304 {
            return Err(Error::InvalidInput("204 and 304 carry no body"));
        }
        let out = conn.response_head(status, headers, Some(Framing::Chunked))?;
        conn.send(&out)?;
        conn.reply = Reply::Streaming;
        let Conn {
            wire,
            stream_finished,
            is_head,
            ..
        } = conn;
        Ok(BodyWriter::with_flag(
            &mut wire.stream,
            Framing::Chunked,
            *is_head,
            stream_finished,
        ))
    }

    /// Accepts a CONNECT: writes `200` and hands over the stream, with the
    /// bytes that arrived after the head first. The read timeout is
    /// cleared; the tunnel's own limits are the handler's. The connection
    /// closes when the handler returns.
    pub fn accept_tunnel(self) -> Result<Tunnel<&'a mut T>> {
        let conn = self.conn;
        conn.reply = Reply::Poisoned;
        if !conn.is_connect {
            return Err(Error::InvalidInput("accept_tunnel answers CONNECT only"));
        }
        conn.send(b"HTTP/1.1 200 OK\r\n\r\n")?;
        conn.wire.stream.set_read_timeout(None)?;
        conn.reply = Reply::Tunnel;
        let early = conn.wire.take_buffered();
        Ok(Tunnel::new(early, &mut conn.wire.stream))
    }
}

/// Serves one connection until either side closes it, a deadline passes or
/// a request is rejected. Public so that tests and TLS-wrapped streams can
/// use it.
///
/// - The first byte of each request must arrive within `idle_timeout`;
///   otherwise the connection closes quietly (`Ok`).
/// - From that byte, the head and the body must arrive within
///   `request_timeout`, or the answer is `408`.
/// - A request outside the accepted subset is answered with its status
///   (400, 413, 417, 431, 501 or 505) before the handler runs, and the
///   connection closes.
/// - `Expect: 100-continue` on a request with a body gets `100 Continue`
///   before the handler runs.
/// - A handler error before any response is answered with the error's
///   status, or closes without an answer when it has none; after a
///   response started it closes the connection. A handler that returns
///   without answering gets `500`.
///
/// Returns the error that ended the connection, if any.
pub fn serve_connection<T, H>(stream: T, limits: &ServerLimits, handler: &H) -> Result<()>
where
    T: Transport,
    H: Fn(Exchange<'_, T>) -> Result<()>,
{
    stream.set_write_timeout(Some(limits.write_timeout()))?;
    let mut conn = Conn {
        wire: Wire::new(stream, Some(<T as Transport>::set_read_timeout)),
        limits: *limits.http(),
        body: BodyState::Done,
        close: false,
        is_head: false,
        is_connect: false,
        reply: Reply::None,
        stream_finished: false,
    };
    loop {
        if conn.wire.available().is_empty() {
            conn.wire.deadline = Some(Instant::now() + limits.idle_timeout());
            match conn.wire.fill() {
                Ok(0) | Err(Error::Timeout) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        conn.wire.deadline = Some(Instant::now() + limits.request_timeout());
        let parsed = match conn.wire.read_head(conn.limits.max_head_bytes()) {
            Ok(None) => return Ok(()),
            Ok(Some(raw)) => parse_request(&raw.bytes[raw.content..], &conn.limits),
            Err(e) => Err(e),
        };
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(e) => {
                conn.reject(&e);
                return Err(e);
            }
        };
        conn.body = BodyState::from_framing(parsed.framing);
        conn.close = parsed.close;
        conn.is_head = parsed.head.method.is_head();
        conn.is_connect = parsed.head.method.is_connect();
        conn.reply = Reply::None;
        conn.stream_finished = false;
        if parsed.expect_continue && conn.body != BodyState::Done {
            conn.send(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        }

        let result = handler(Exchange {
            conn: &mut conn,
            head: parsed.head,
        });
        conn.wire.deadline = None;
        match (result, conn.reply) {
            (Err(e), Reply::None) => {
                conn.reject(&e);
                return Err(e);
            }
            (Err(e), _) => return Err(e),
            (Ok(()), Reply::None) => {
                let reply = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = conn.send(reply);
                return Ok(());
            }
            (Ok(()), Reply::Done) => {}
            (Ok(()), Reply::Streaming) if conn.stream_finished => {}
            (Ok(()), _) => return Ok(()),
        }
        if conn.close || conn.is_connect || conn.body != BodyState::Done {
            return Ok(());
        }
    }
}
