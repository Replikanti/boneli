//! The egress's adapter of the `Clock` port (ADR-006, D11).

use std::time::Instant;

use boneli_app::Clock;

/// Milliseconds since the clock was made, from `Instant`, which is
/// monotonic. Saturates at `u64::MAX`. The connection log's `t` comes from
/// it; the `start` record anchors it to wall time (ADR-006, D8).
#[derive(Clone, Copy, Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// A clock whose origin is now.
    pub fn new() -> MonotonicClock {
        MonotonicClock {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> MonotonicClock {
        MonotonicClock::new()
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
