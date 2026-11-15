//! A strict RFC 8259 JSON parser and serializer without derive, for
//! untrusted input.
//!
//! - [`parse`] reads one value from bytes under [`Limits`] that have no
//!   defaults: input size, nesting depth (at most [`MAX_DEPTH`]) and value
//!   count. Every violation is an [`Error`], never a panic or an unbounded
//!   allocation.
//! - [`Value`] keeps object members in input order ([`Object`], no hash
//!   maps) and numbers as their lexemes ([`Number`]), so parsing and
//!   serializing again loses nothing.
//! - [`to_vec`] and [`to_string`] write compact, deterministic JSON.
//! - [`ndjson`] reads and writes one value per line.
//!
//! Accepted is RFC 8259 exactly: any value at the top level, whitespace SP,
//! HT, LF and CR only, UTF-8 only. Rejected are comments, trailing commas,
//! a leading BOM, duplicate keys and lone surrogate escapes; nothing is
//! repaired. Mapping to DTOs stays in the adapters. The reasons for each
//! choice and the measurements behind every number are in ADR-008
//! (`docs/adr/008-json-without-derive.md`).
#![doc(test(attr(forbid(unsafe_code))))]

mod error;
mod limits;
pub mod ndjson;
mod number;
mod parse;
mod serialize;
mod value;

pub use error::{Error, ErrorKind};
pub use limits::{Limits, MAX_DEPTH};
pub use number::Number;
pub use parse::parse;
pub use serialize::{to_string, to_vec};
pub use value::{IntoIter, Iter, Object, Value};
