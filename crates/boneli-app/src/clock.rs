//! The `Clock` port (ADR-004, D1).
//!
//! The domain has no clock (invariant 2). `DebugTicket` reads this port
//! before and after each measured job and reports the difference as the
//! job's duration (ADR-002, D3).

/// A monotonic millisecond counter.
pub trait Clock {
    /// Milliseconds since an origin the adapter chooses. A reading is never
    /// lower than an earlier one; the real adapter is built on a monotonic
    /// source, which its review checks, because no test can prove it.
    fn now_ms(&self) -> u64;
}
