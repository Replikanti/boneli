//! Tests of `boneli-store-fs` (#4, ADR-012).
//!
//! One test target, so `ring` (through `boneli-https`) is linked once. The
//! modules follow the decisions of ADR-012: the contract suites, the root
//! rules and the lock (D1), the run log (D2 to D5), the evidence store (D2,
//! D4, D6) and the replay acceptance.

mod contract;
mod evidence;
mod log;
mod replay;
mod root;
mod support;
