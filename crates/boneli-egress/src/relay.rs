//! The relay of an open tunnel (ADR-006, D7): bytes in both directions
//! without looking at them, half-close, a shared idle timeout, and byte
//! counts for the `close` record.
//!
//! The upload direction runs on the calling thread, the download direction
//! on one scoped thread; each owns one handle of each socket. A direction
//! that fails or idles out shuts both sockets down, so the other
//! direction's blocked read or write returns at once: no exit path leaves
//! a thread waiting for a peer, and every handle is dropped when `relay`
//! returns. A direction whose peer is gone (a broken pipe or a reset on
//! write) stops without that: the other direction reads from the same
//! peer and decides how the tunnel ended.

use std::io::{ErrorKind, Write};
use std::net::Shutdown;
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::log::End;
use crate::settings::Settings;
use crate::upstream::RelayStream;

/// How a tunnel ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Bytes from the sandbox to the upstream, the early bytes included.
    pub up: u64,
    /// Bytes from the upstream to the sandbox.
    pub down: u64,
    /// `Eof` when both directions reached the end of their stream, or one
    /// did and the peer it read from then closed its socket before taking
    /// the other direction's last bytes (a client that closes after its
    /// request while the origin still sends a TLS `close_notify`). `Idle`
    /// when the idle timeout ran out: no byte moved in either direction
    /// for it, or a peer took no byte for it. `Error` otherwise.
    pub end: End,
}

/// State the two directions share.
struct Shared {
    /// When a byte last arrived from either side.
    activity: Mutex<Instant>,
    /// The first end that was not `Eof`; it decides the outcome.
    abnormal: Mutex<Option<End>>,
    /// How many directions stopped because the peer they wrote to was gone.
    gone: Mutex<u8>,
    idle: Duration,
    buffer: usize,
}

impl Shared {
    fn touch(&self) {
        *self.activity.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    /// What is left of the idle window.
    fn remaining(&self) -> Duration {
        let last = *self.activity.lock().unwrap_or_else(PoisonError::into_inner);
        self.idle.saturating_sub(last.elapsed())
    }

    fn record(&self, end: End) {
        self.abnormal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(end);
    }

    fn abnormal(&self) -> Option<End> {
        *self.abnormal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn peer_gone(&self) {
        *self.gone.lock().unwrap_or_else(PoisonError::into_inner) += 1;
    }

    /// The outcome once both directions are done: the first abnormal end;
    /// `Error` when both peers were gone, since neither direction then saw
    /// the end of a stream; `Eof` otherwise.
    fn end(&self) -> End {
        let gone = *self.gone.lock().unwrap_or_else(PoisonError::into_inner);
        match self.abnormal() {
            Some(end) => end,
            None if gone >= 2 => End::Error,
            None => End::Eof,
        }
    }
}

/// Relays between `sandbox` and `upstream` until both directions are done.
/// `early` are the bytes that arrived with the CONNECT head; they go
/// upstream first and count as upload. Never panics on an I/O error: every
/// error, a failed clone and a failed thread spawn included, ends the
/// tunnel with `End::Error`.
pub fn relay(
    mut sandbox: Box<dyn RelayStream>,
    early: Vec<u8>,
    mut upstream: Box<dyn RelayStream>,
    settings: &Settings,
) -> RelayOutcome {
    let shared = Shared {
        activity: Mutex::new(Instant::now()),
        abnormal: Mutex::new(None),
        gone: Mutex::new(0),
        idle: settings.tunnel_idle(),
        buffer: settings.relay_buffer(),
    };
    let error = |sandbox: &dyn RelayStream, upstream: &dyn RelayStream, up: u64| {
        stop(sandbox, upstream);
        RelayOutcome {
            up,
            down: 0,
            end: End::Error,
        }
    };
    // The write timeouts stay at the idle timeout for the whole tunnel; the
    // read timeouts are set before every read to what is left of the
    // shared window.
    if sandbox.set_write_timeout(Some(shared.idle)).is_err()
        || upstream.set_write_timeout(Some(shared.idle)).is_err()
    {
        return error(&*sandbox, &*upstream, 0);
    }
    let mut up = 0u64;
    if !early.is_empty() {
        if upstream.write_all(&early).is_err() {
            return error(&*sandbox, &*upstream, 0);
        }
        up = early.len() as u64;
        shared.touch();
    }
    let (sandbox_w, upstream_r) = match (sandbox.try_clone_box(), upstream.try_clone_box()) {
        (Ok(sandbox_w), Ok(upstream_r)) => (sandbox_w, upstream_r),
        _ => return error(&*sandbox, &*upstream, up),
    };

    let shared = &shared;
    let down = thread::scope(|scope| {
        let spawned = thread::Builder::new()
            .name("boneli-egress-relay".into())
            .spawn_scoped(scope, move || {
                let (mut from, mut to) = (upstream_r, sandbox_w);
                direction(&mut *from, &mut *to, shared)
            });
        let handle = match spawned {
            Ok(handle) => handle,
            // The closure and its two handles are dropped with the error.
            Err(_) => {
                shared.record(End::Error);
                stop(&*sandbox, &*upstream);
                return 0;
            }
        };
        up += direction(&mut *sandbox, &mut *upstream, shared);
        handle.join().unwrap_or_else(|_| {
            shared.record(End::Error);
            0
        })
    });
    RelayOutcome {
        up,
        down,
        end: shared.end(),
    }
}

/// Shuts both sockets down in both directions. Errors are ignored: a
/// socket whose peer is gone may refuse, and it is ending either way.
fn stop(a: &dyn RelayStream, b: &dyn RelayStream) {
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}

/// Copies `from` to `to` until the end of `from`'s stream, an error, the
/// idle timeout, or a stop by the other direction. Returns the bytes
/// written to `to`. At the end of the stream `to` gets `shutdown(Write)`
/// and the other direction goes on (half-close); on an error or the idle
/// timeout both sockets are shut down, which ends the other direction too.
/// A write timeout is the idle timeout too: the write timeouts equal it.
/// When `to`'s peer is gone the direction stops without a stop of the
/// sockets and leaves the outcome to the other direction, which reads from
/// that peer: the end of its stream (the peer closed after its last
/// request) makes the tunnel `Eof`, an error or the idle timeout ends it
/// as that. No shutdown is needed for the other direction to return, since
/// its peer is gone; a peer that only stopped reading is still bounded by
/// the idle timeout.
fn direction(from: &mut dyn RelayStream, to: &mut dyn RelayStream, shared: &Shared) -> u64 {
    let mut buf = vec![0u8; shared.buffer];
    let mut moved = 0u64;
    let end = loop {
        let remaining = shared.remaining();
        if remaining.is_zero() {
            break End::Idle;
        }
        if from.set_read_timeout(Some(remaining)).is_err() {
            break End::Error;
        }
        match from.read(&mut buf) {
            Ok(0) => {
                // An error here means the socket is already shut or gone,
                // which ends that side anyway.
                let _ = to.shutdown(Shutdown::Write);
                return moved;
            }
            Ok(n) => {
                shared.touch();
                match to.write_all(&buf[..n]) {
                    Ok(()) => moved += n as u64,
                    Err(e) if gone(&e) => {
                        shared.peer_gone();
                        return moved;
                    }
                    Err(e) if timed_out(&e) => break End::Idle,
                    Err(_) => break End::Error,
                }
            }
            // The read waited for the rest of the window; the loop checks
            // whether the other direction moved bytes meanwhile.
            Err(e) if timed_out(&e) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break End::Error,
        }
    };
    shared.record(end);
    stop(from, to);
    moved
}

/// A socket timeout: `WouldBlock` is how std reports `EAGAIN` from a
/// socket with a timeout set, `TimedOut` covers platforms that differ.
fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// The peer of the socket written to is gone: it closed (a Unix socket
/// returns `EPIPE` on the first write after that) or reset the connection.
fn gone(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}
