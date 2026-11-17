//! A strict parser for a documented TOML 1.0 subset, for configuration and
//! Cargo manifests, without derive and with limits for untrusted input.
//!
//! - [`parse`] reads a document from bytes under [`Limits`] that have no
//!   defaults: input size and nesting depth (at most [`MAX_DEPTH`]). Every
//!   violation is an [`Error`], never a panic or an unbounded allocation.
//! - [`Table`] keeps its members in the order they were first created (no
//!   hash maps), and [`Value`] is a string, an `i64`, a boolean, an array
//!   or a table.
//!
//! The subset is TOML 1.0.0 without floats (`inf` and `nan` included), the
//! four date and time types and hexadecimal, octal and binary integers.
//! Everything else is in: bare, quoted and dotted keys, all four string
//! forms, decimal integers, booleans, arrays, inline tables, table headers
//! and arrays of tables. A value of an excluded type is
//! [`ErrorKind::Unsupported`] with the [`Feature`] it would have been,
//! never a misread prefix. Duplicate keys and redefined tables are errors,
//! as in TOML 1.0. Mapping to configuration types stays with the callers.
//! The reasons for each choice and the measurements behind every number
//! are in ADR-011 (`docs/adr/011-toml-subset.md`).
#![doc(test(attr(forbid(unsafe_code))))]

mod document;
mod error;
mod limits;
mod parse;
mod value;

pub use error::{Error, ErrorKind, Feature};
pub use limits::{Limits, MAX_DEPTH};
pub use parse::parse;
pub use value::{Table, Value};
