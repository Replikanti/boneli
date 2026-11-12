//! Boneli domain.
//!
//! Types, run and case state machines, policies, gates and budget accounting.
//! Pure functions: no I/O, no wall clock, no threads, no async and no
//! external dependencies. The domain takes an event and returns a new state
//! and a list of commands; the application executes them through ports.
//!
//! Design: `docs/ARCHITECTURE.md`, sections "Code architecture" and
//! "Debugging line".
