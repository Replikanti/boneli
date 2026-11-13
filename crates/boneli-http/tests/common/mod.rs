//! Helpers shared by the integration tests: in-memory streams that feed
//! input in fixed pieces, limit constructors, a recording server run and
//! unique Unix socket paths.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use boneli_http::{Error, Exchange, Headers, Limits, RequestHead, ServerLimits, Transport};

/// A reader that hands out its input in pieces of at most `size` bytes per
/// `read`, then reports end of file.
pub struct Pieces {
    chunks: VecDeque<Vec<u8>>,
}

/// Splits `data` into pieces of `size` bytes (the last one may be shorter).
pub fn pieces(data: &[u8], size: usize) -> Pieces {
    Pieces {
        chunks: data.chunks(size.max(1)).map(<[u8]>::to_vec).collect(),
    }
}

/// Splits `data` at the given offsets.
pub fn split_at(data: &[u8], offsets: &[usize]) -> Pieces {
    let mut chunks = VecDeque::new();
    let mut last = 0;
    for &at in offsets {
        chunks.push_back(data[last..at].to_vec());
        last = at;
    }
    chunks.push_back(data[last..].to_vec());
    Pieces { chunks }
}

impl Read for Pieces {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while let Some(front) = self.chunks.front_mut() {
            if front.is_empty() {
                self.chunks.pop_front();
                continue;
            }
            let n = front.len().min(buf.len());
            buf[..n].copy_from_slice(&front[..n]);
            front.drain(..n);
            return Ok(n);
        }
        Ok(0)
    }
}

/// An in-memory duplex stream: reads come from `input`, writes are
/// collected in a buffer the test keeps a handle to.
pub struct MemStream {
    input: Pieces,
    output: Rc<RefCell<Vec<u8>>>,
}

impl MemStream {
    /// A stream over `input` read in pieces of `piece` bytes, and the handle
    /// to everything written to it.
    pub fn new(input: &[u8], piece: usize) -> (MemStream, Rc<RefCell<Vec<u8>>>) {
        Self::from_pieces(pieces(input, piece))
    }

    /// A stream over prepared pieces.
    pub fn from_pieces(input: Pieces) -> (MemStream, Rc<RefCell<Vec<u8>>>) {
        let output = Rc::new(RefCell::new(Vec::new()));
        (
            MemStream {
                input,
                output: Rc::clone(&output),
            },
            output,
        )
    }
}

impl Read for MemStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for MemStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for MemStream {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

/// `Limits` that must be valid.
pub fn limits(head: usize, headers: usize, body: u64) -> Limits {
    Limits::new(head, headers, body).expect("valid limits")
}

/// Generous limits for tests that are not about limits.
pub fn wide() -> Limits {
    limits(16 * 1024, 64, 1024 * 1024)
}

/// Server limits with 5 s timeouts and room for four connections.
pub fn server_limits(http: Limits) -> ServerLimits {
    let five = Duration::from_secs(5);
    ServerLimits::new(http, 4, five, five, five).expect("valid server limits")
}

/// One request the handler saw, with the result of reading its body (the
/// error kind when reading failed).
pub type Seen = (RequestHead, Result<Vec<u8>, io::ErrorKind>);

/// What one server run over in-memory input saw.
pub struct Outcome {
    /// Everything the server wrote.
    pub output: Vec<u8>,
    /// Each request the handler saw.
    pub requests: Vec<Seen>,
    /// The result of `serve_connection`.
    pub result: Result<(), Error>,
}

impl Outcome {
    /// Status codes of the responses in `output`, in order.
    pub fn statuses(&self) -> Vec<u16> {
        statuses(&self.output)
    }

    /// The single status the server answered with; panics otherwise.
    pub fn status(&self) -> u16 {
        let all = self.statuses();
        assert_eq!(all.len(), 1, "expected one response, got {:?}", self.text());
        all[0]
    }

    /// The output as text, for assertion messages.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }

    /// The bodies the handler read completely.
    pub fn complete_bodies(&self) -> Vec<Vec<u8>> {
        self.requests
            .iter()
            .filter_map(|(_, body)| body.as_ref().ok().cloned())
            .collect()
    }
}

/// Status codes of every response head in `output` (a line that starts a
/// response is `HTTP/1.1 NNN`).
pub fn statuses(output: &[u8]) -> Vec<u16> {
    let text = String::from_utf8_lossy(output);
    let mut found = Vec::new();
    let mut rest: &str = &text;
    while let Some(at) = rest.find("HTTP/1.1 ") {
        let code = &rest[at + 9..];
        if code.len() >= 3 {
            if let Ok(n) = code[..3].parse() {
                found.push(n);
            }
        }
        rest = &rest[at + 9..];
    }
    found
}

/// Runs `serve_connection` over `input` fed in pieces of `piece` bytes. The
/// handler reads the whole body, answers `200` (`403` to a CONNECT) with an
/// empty body, and
/// returns a body error to the server, which maps it to a status.
pub fn run_server(input: &[u8], piece: usize, http: Limits) -> Outcome {
    let (stream, output) = MemStream::new(input, piece);
    run_server_on(stream, output, http)
}

/// `run_server` over a prepared stream.
pub fn run_server_on(stream: MemStream, output: Rc<RefCell<Vec<u8>>>, http: Limits) -> Outcome {
    let seen: RefCell<Vec<Seen>> = RefCell::new(Vec::new());
    let limits = server_limits(http);
    let result =
        boneli_http::serve_connection(stream, &limits, &|mut ex: Exchange<'_, MemStream>| {
            let head = ex.head().clone();
            let mut body = Vec::new();
            let read = ex.body().read_to_end(&mut body);
            match read {
                Ok(_) => {
                    // A CONNECT is refused: a 2xx would promise a tunnel.
                    let status = if head.method.is_connect() { 403 } else { 200 };
                    seen.borrow_mut().push((head, Ok(body)));
                    ex.respond(status, &Headers::new(), b"")
                }
                Err(e) => {
                    seen.borrow_mut().push((head, Err(e.kind())));
                    Err(Error::from(e))
                }
            }
        });
    let output = output.borrow().clone();
    Outcome {
        output,
        requests: seen.into_inner(),
        result,
    }
}

/// A Unix socket path under the temp directory, unique per process and
/// call. The caller removes it.
pub fn socket_path() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("boneli-http-{}-{}.sock", std::process::id(), n))
}

/// Removes the socket file when dropped.
pub struct SocketFile(pub PathBuf);

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
