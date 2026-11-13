//! [`StepClock`] and [`SequentialIds`]: deterministic `Clock` and `Ids`.

use std::sync::Mutex;

use boneli_app::{Clock, Ids};
use boneli_domain::RunId;

use crate::lock;

/// A `Clock` whose first reading is `start` and every later reading is
/// `step` milliseconds after the one before, saturating at `u64::MAX`.
/// With step 0 every reading is equal, which is legal.
#[derive(Debug)]
pub struct StepClock {
    next: Mutex<u64>,
    step: u64,
}

impl StepClock {
    /// A clock that starts at `start` and advances by `step` per reading.
    pub fn new(start: u64, step: u64) -> StepClock {
        StepClock {
            next: Mutex::new(start),
            step,
        }
    }
}

impl Clock for StepClock {
    fn now_ms(&self) -> u64 {
        let mut next = lock(&self.next);
        let now = *next;
        *next = now.saturating_add(self.step);
        now
    }
}

/// `Ids` that issues `run-1`, `run-2`, ... from a 64-bit counter.
#[derive(Debug)]
pub struct SequentialIds {
    next: Mutex<u64>,
}

impl Default for SequentialIds {
    fn default() -> SequentialIds {
        SequentialIds::new()
    }
}

impl SequentialIds {
    /// Ids starting at `run-1`.
    pub fn new() -> SequentialIds {
        SequentialIds {
            next: Mutex::new(1),
        }
    }
}

impl Ids for SequentialIds {
    fn run_id(&self) -> RunId {
        let mut next = lock(&self.next);
        let n = *next;
        *next = n.saturating_add(1);
        RunId::new(format!("run-{n}"))
    }
}
