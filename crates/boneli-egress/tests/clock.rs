//! The egress's `Clock` adapter (ADR-006, D11).

use std::thread;
use std::time::Duration;

use boneli_app::Clock;
use boneli_egress::MonotonicClock;

#[test]
fn monotonic_clock_passes_the_clock_contract() {
    let clock = MonotonicClock::new();
    boneli_app::contract::clock::run(&clock).expect("contract");
}

#[test]
fn monotonic_clock_counts_milliseconds_from_its_start() {
    let clock = MonotonicClock::new();
    let first = clock.now_ms();
    assert!(first < 1_000, "{first}");
    thread::sleep(Duration::from_millis(20));
    let later = clock.now_ms();
    assert!(later >= first + 20, "{first} then {later}");
}
