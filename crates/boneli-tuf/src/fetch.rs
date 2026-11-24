//! One file from the repository (ADR-033, item 7): one `GET` on a new
//! connection through the caller's `Dial`, `Host` only, under a deadline
//! of `setup + size / min_rate`; `200` only, a `404` only where the caller
//! allows it; no content coding; a body of at most its cap, or of exactly
//! its listed length.

use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use boneli_http::{Connection, Method, RequestBody, RequestHead, ResponseHead, Target};
use boneli_https::{Dial, Timed};

use crate::repository::Repository;

/// The largest response head: 16,384 bytes, ADR-009 D12's value. The
/// repository's head of `timestamp.json` is 735 bytes, so 22 times that
/// (ADR-033, limits).
pub const MAX_HEAD_BYTES: usize = 16_384;

/// The most header fields in a response head: 64, ADR-009 D12's value.
/// The repository sends 20, so 3.2 times that (ADR-033, limits).
pub const MAX_HEADERS: usize = 64;

/// The time limits of the refresh's fetches (ADR-033, limits). The
/// connect and handshake timeouts belong to the caller's `Dial`
/// (`TlsDial`'s `ConnectOptions`: 10 s each, ADR-009 D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    io: Duration,
    setup: Duration,
    min_rate: u64,
}

/// Why [`Timeouts::new`] refused its values: the name of the one that is
/// zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTimeouts(pub &'static str);

impl fmt::Display for InvalidTimeouts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the timeout {} must not be zero", self.0)
    }
}

impl std::error::Error for InvalidTimeouts {}

impl Timeouts {
    /// - `io`: each read and write;
    /// - `setup` and `min_rate` (bytes per second): the deadline of a
    ///   fetch of `size` bytes is `setup + size / min_rate`, with `size`
    ///   the role's cap or the length the referring metadata lists.
    ///
    /// A zero value is refused.
    pub fn new(io: Duration, setup: Duration, min_rate: u64) -> Result<Timeouts, InvalidTimeouts> {
        if io.is_zero() {
            return Err(InvalidTimeouts("io"));
        }
        if setup.is_zero() {
            return Err(InvalidTimeouts("setup"));
        }
        if min_rate == 0 {
            return Err(InvalidTimeouts("min_rate"));
        }
        Ok(Timeouts {
            io,
            setup,
            min_rate,
        })
    }

    /// The deadline of a fetch of `size` bytes that starts now, `None`
    /// when it does not fit an `Instant`.
    fn deadline(&self, size: u64) -> Option<Instant> {
        let nanos = u128::from(size) * 1_000_000_000 / u128::from(self.min_rate);
        u64::try_from(nanos)
            .ok()
            .map(Duration::from_nanos)
            .and_then(|transfer| self.setup.checked_add(transfer))
            .and_then(|total| Instant::now().checked_add(total))
    }
}

impl Default for Timeouts {
    /// ADR-009 D12's values: `io` 30 s, `setup` 30 s, `min_rate` 1 MiB/s.
    /// `setup` is 63 times the slowest fetch measured from the repository
    /// (0.47 s) and leaves about 29.9 s for the leaf certificate's CRL
    /// inside the first request: about 29.9 MiB at `min_rate`, 93 times
    /// the measured 335,587 bytes (ADR-033, limits).
    fn default() -> Timeouts {
        Timeouts {
            io: Duration::from_secs(30),
            setup: Duration::from_secs(30),
            min_rate: 1_048_576,
        }
    }
}

/// How long the body may be.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Size {
    /// At most this many bytes.
    Cap(u64),
    /// Exactly this many bytes, as the referring metadata lists.
    Exact(u64),
}

impl Size {
    fn limit(self) -> u64 {
        match self {
            Size::Cap(n) | Size::Exact(n) => n,
        }
    }
}

/// What a fetch got.
pub(crate) enum Fetched {
    /// The body of a `200`.
    Body(Vec<u8>),
    /// A `404`: the end of the root chain for `N+1.root.json`, an error
    /// for every other file; the caller decides.
    NotFound,
}

/// Fetches `file` under the repository's prefix. A `404` is
/// [`Fetched::NotFound`]; every other status but `200` is an error, a
/// redirect included, which is never followed. The error is a fixed
/// sentence naming the URL, the status, sizes or the transport's error.
pub(crate) fn get(
    dial: &dyn Dial,
    repository: &Repository,
    timeouts: &Timeouts,
    file: &str,
    size: Size,
) -> Result<Fetched, String> {
    let url = format!("{repository}/{file}");
    let at = |e: &dyn fmt::Display| format!("GET {url}: {e}");
    let deadline = timeouts
        .deadline(size.limit())
        .ok_or_else(|| at(&format_args!("no deadline for {} bytes", size.limit())))?;
    let stream = dial
        .dial(repository.host(), repository.port(), deadline)
        .map_err(|e| at(&e))?;
    let timed = Timed::new(stream, deadline, timeouts.io);
    // Bodies are checked here against what this file may be.
    let limits =
        boneli_http::Limits::new(MAX_HEAD_BYTES, MAX_HEADERS, u64::MAX).map_err(|e| at(&e))?;
    let mut conn = Connection::new(timed, &repository.host_field(), limits).map_err(|e| at(&e))?;
    let method = Method::new("GET").map_err(|e| at(&e))?;
    let head = RequestHead::new(method, Target::Origin(repository.target(file)));
    let mut response = conn.request(&head, RequestBody::None).map_err(|e| at(&e))?;
    match response.head.status {
        200 => {}
        404 => return Ok(Fetched::NotFound),
        status => return Err(at(&format_args!("answered {status}"))),
    }
    check_head(&response.head, size).map_err(|e| at(&e))?;
    read_body(&mut response, size)
        .map(Fetched::Body)
        .map_err(|e| at(&e))
}

/// Refuses, before the body is read, a content coding other than
/// `identity` and a `Content-Length` over the cap or other than the
/// listed length.
fn check_head(head: &ResponseHead, size: Size) -> Result<(), String> {
    for coding in head.headers.get_all("content-encoding") {
        if !coding.eq_ignore_ascii_case(b"identity") {
            return Err("the response has a content coding other than identity".to_string());
        }
    }
    let Some(length) = head.headers.get("content-length") else {
        return Ok(());
    };
    // boneli-http accepted the field, so it is one decimal number.
    let length = std::str::from_utf8(length)
        .ok()
        .and_then(|l| l.parse::<u64>().ok())
        .ok_or_else(|| "the Content-Length is not a number".to_string())?;
    match size {
        Size::Cap(cap) if length > cap => Err(format!(
            "the response declares {length} bytes, above the limit of {cap}"
        )),
        Size::Exact(n) if length != n => Err(format!(
            "the response declares {length} bytes, not the listed {n}"
        )),
        _ => Ok(()),
    }
}

/// Reads at most the cap, or exactly the listed length: that many bytes,
/// then one more read must find the end.
fn read_body(body: &mut dyn Read, size: Size) -> Result<Vec<u8>, String> {
    let limit = size.limit();
    let mut bytes = Vec::new();
    body.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the body failed: {}", boneli_http::Error::from(e)))?;
    let len = bytes.len() as u64;
    match size {
        Size::Cap(cap) if len > cap => {
            Err(format!("the body is longer than the limit of {cap} bytes"))
        }
        Size::Exact(n) if len > n => Err(format!("the body is longer than the listed {n} bytes")),
        Size::Exact(n) if len < n => Err(format!("the body has {len} bytes, not the listed {n}")),
        _ => Ok(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_cap_inclusive() {
        let body = [b'x'; 8];
        assert_eq!(
            read_body(&mut &body[..], Size::Cap(8))
                .expect("at the cap")
                .len(),
            8
        );
        assert!(read_body(&mut &body[..], Size::Cap(7)).is_err());
    }

    #[test]
    fn body_exact_length() {
        let body = [b'x'; 8];
        assert_eq!(
            read_body(&mut &body[..], Size::Exact(8))
                .expect("exact")
                .len(),
            8
        );
        assert!(read_body(&mut &body[..], Size::Exact(7)).is_err());
        assert!(read_body(&mut &body[..], Size::Exact(9)).is_err());
    }

    #[test]
    fn head_length_and_coding() {
        let head = |fields: &[(&str, &str)]| {
            let mut head = ResponseHead::new(200);
            for (n, v) in fields {
                head.headers.append(*n, *v);
            }
            head
        };
        assert!(check_head(&head(&[("Content-Length", "8")]), Size::Cap(8)).is_ok());
        assert!(check_head(&head(&[("Content-Length", "9")]), Size::Cap(8)).is_err());
        assert!(check_head(&head(&[("Content-Length", "8")]), Size::Exact(8)).is_ok());
        assert!(check_head(&head(&[("Content-Length", "7")]), Size::Exact(8)).is_err());
        assert!(check_head(&head(&[]), Size::Exact(8)).is_ok());
        assert!(check_head(&head(&[("Content-Encoding", "IDENTITY")]), Size::Cap(8)).is_ok());
        for coding in ["gzip", "br", "identity, gzip", ""] {
            let fields = [("Content-Encoding", coding)];
            assert!(
                check_head(&head(&fields), Size::Cap(8)).is_err(),
                "{coding:?}"
            );
        }
    }

    #[test]
    fn deadline_is_setup_plus_size_over_rate() {
        let t = Timeouts::new(Duration::from_secs(1), Duration::from_secs(30), 1_048_576)
            .expect("timeouts");
        let before = Instant::now();
        let deadline = t.deadline(65_536).expect("deadline");
        let left = deadline - before;
        let expected = Duration::from_millis(30_062);
        assert!(
            left >= expected && left < expected + Duration::from_secs(1),
            "{left:?}"
        );
        // A size whose transfer time does not fit is no deadline, not a wrap.
        let slow = Timeouts::new(Duration::from_secs(1), Duration::from_secs(1), 1).expect("slow");
        assert!(slow.deadline(u64::MAX).is_none());
    }
}
