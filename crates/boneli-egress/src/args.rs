//! The command line (ADR-006, D1): `--socket <path> --allow <host:port>
//! [--allow <host:port> ...] [--nat64-prefix <ipv6>/<len> ...]`, in the
//! `--flag value` form only.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use crate::address::Nat64Prefix;

/// The parsed command line. The allowlist entries are checked by
/// `Allowlist::parse` (D2); an empty list is refused there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// The socket path, as given: no `~` expansion, any bytes.
    pub socket: PathBuf,
    /// The `--allow` values, in the order given.
    pub allow: Vec<String>,
    /// The `--nat64-prefix` values (D4).
    pub nat64: BTreeSet<Nat64Prefix>,
}

/// A usage error (exit 2). Names the flag, never the value, which may come
/// from anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageError {
    /// No `--socket`.
    MissingSocket,
    /// `--socket` more than once.
    RepeatedSocket,
    /// A flag without its value.
    MissingValue {
        /// The flag.
        flag: &'static str,
    },
    /// The `--flag=value` form.
    EqualsForm,
    /// An argument that is not one of the flags.
    UnknownArgument,
    /// A value that is not UTF-8.
    NotUtf8 {
        /// The flag.
        flag: &'static str,
    },
    /// A `--nat64-prefix` value that is not exactly the text form of a
    /// NAT64 prefix (`Nat64Prefix::parse`).
    InvalidNat64Prefix,
    /// The same `--nat64-prefix` twice.
    RepeatedNat64Prefix,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::MissingSocket => f.write_str("--socket is required"),
            UsageError::RepeatedSocket => f.write_str("--socket is given more than once"),
            UsageError::MissingValue { flag } => write!(f, "{flag} needs a value"),
            UsageError::EqualsForm => f.write_str("use `--flag value`, not `--flag=value`"),
            UsageError::UnknownArgument => f.write_str("unknown argument"),
            UsageError::NotUtf8 { flag } => write!(f, "the value of {flag} is not UTF-8"),
            UsageError::InvalidNat64Prefix => {
                f.write_str("--nat64-prefix takes <ipv6>/<len> with len 32, 40, 48, 56, 64 or 96")
            }
            UsageError::RepeatedNat64Prefix => {
                f.write_str("the same --nat64-prefix is given twice")
            }
        }
    }
}

impl std::error::Error for UsageError {}

/// The usage line for stderr.
pub const USAGE: &str = "usage: boneli-egress --socket <path> --allow <host:port> \
     [--allow <host:port> ...] [--nat64-prefix <ipv6>/<len> ...]";

impl Args {
    /// Parses the arguments after the program name. The argument after a
    /// flag is its value, whatever it looks like.
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Args, UsageError> {
        let mut args = args.into_iter();
        let mut socket = None;
        let mut allow = Vec::new();
        let mut nat64 = BTreeSet::new();
        while let Some(arg) = args.next() {
            let flag = match arg.to_str() {
                Some(flag @ ("--socket" | "--allow" | "--nat64-prefix")) => flag,
                Some(other) if other.starts_with("--") && other.contains('=') => {
                    return Err(UsageError::EqualsForm);
                }
                _ => return Err(UsageError::UnknownArgument),
            };
            match flag {
                "--socket" => {
                    let value = args
                        .next()
                        .ok_or(UsageError::MissingValue { flag: "--socket" })?;
                    if socket.replace(PathBuf::from(value)).is_some() {
                        return Err(UsageError::RepeatedSocket);
                    }
                }
                "--allow" => {
                    let value = utf8(args.next(), "--allow")?;
                    allow.push(value);
                }
                _ => {
                    let value = utf8(args.next(), "--nat64-prefix")?;
                    let prefix =
                        Nat64Prefix::parse(&value).ok_or(UsageError::InvalidNat64Prefix)?;
                    if !nat64.insert(prefix) {
                        return Err(UsageError::RepeatedNat64Prefix);
                    }
                }
            }
        }
        Ok(Args {
            socket: socket.ok_or(UsageError::MissingSocket)?,
            allow,
            nat64,
        })
    }
}

fn utf8(value: Option<OsString>, flag: &'static str) -> Result<String, UsageError> {
    value
        .ok_or(UsageError::MissingValue { flag })?
        .into_string()
        .map_err(|_| UsageError::NotUtf8 { flag })
}
