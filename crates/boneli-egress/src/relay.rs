//! The relay of an open tunnel (ADR-006, D7): bytes in both directions
//! without looking at them, half-close, a shared idle timeout, and byte
//! counts for the `close` record.
//!
//! The upload direction runs on the calling thread, the download direction
//! on one scoped thread; each owns one handle of each socket. A direction
//! that fails or idles out shuts both sockets down, so the other
//! direction's blocked read or write returns at once: no exit path leaves
//! a thread waiting for a peer, and every handle is dropped when `relay`
//! returns.

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
    /// `Eof` when both directions reached the end of their stream, `Idle`
    /// when no byte moved in either direction for the idle timeout, `Error`
    /// otherwise.
    pub end: End,
}

/// State the two directions share.
struct Shared {
    /// When a byte last arrived from either side.
    activity: Mutex<Instant>,
    /// The first end that was not `Eof`; it decides the outcome.
    abnormal: Mutex<Option<End>>,
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
        end: shared.abnormal().unwrap_or(End::Eof),
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
                if to.write_all(&buf[..n]).is_err() {
                    break End::Error;
                }
                moved += n as u64;
            }
            // The read waited for the rest of the window; the loop checks
            // whether the other direction moved bytes meanwhile.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break End::Error,
        }
    };
    shared.record(end);
    stop(from, to);
    moved
}
