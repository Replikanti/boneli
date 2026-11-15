//! The `LogSink` seam (ADR-006, D8, D11): where the connection log goes.

use std::io::{self, Write};

/// Appends one rendered record, a line that ends in `\n`. An error means
/// the record may not have been stored: the egress then takes no further
/// effect for that connection and calls its `on_log_failure` (D8).
pub trait LogSink: Send + Sync {
    /// Appends `line` whole; concurrent appends never interleave.
    fn append(&self, line: &str) -> io::Result<()>;
}

/// The binary's sink: standard output. Each line is written with one
/// `write_all` and a `flush` under the stdout lock, so lines of concurrent
/// connections never interleave. The runner reads the stream and stores
/// it as evidence (#32).
#[derive(Clone, Copy, Debug, Default)]
pub struct StdoutSink;

impl LogSink for StdoutSink {
    fn append(&self, line: &str) -> io::Result<()> {
        let mut out = io::stdout().lock();
        out.write_all(line.as_bytes())?;
        out.flush()
    }
}
