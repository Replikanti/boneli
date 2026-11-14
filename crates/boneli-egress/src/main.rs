//! `boneli-egress`: the egress proxy of one run phase (ADR-006, D1).
//!
//! `boneli-egress --socket <path> --allow <host:port> [--allow ...]
//! [--nat64-prefix <ipv6>/<len> ...]`
//!
//! Binds the socket, discovers the NAT64 prefixes, writes the `start`
//! record and serves until the runner ends the process. The connection log
//! goes to stdout, diagnostics to stderr. Exit codes: 2 for a usage error,
//! 1 when binding, discovery or accepting fails, 3 when the log cannot be
//! written. A panic aborts the process, so a log is never left with an
//! `open` and no `close` while the egress goes on serving.

use std::collections::BTreeSet;
use std::os::unix::net::UnixListener;
use std::process;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use boneli_egress::{
    Allowlist, Args, Config, MonotonicClock, Settings, StdoutSink, TcpUpstream, USAGE, launch,
};

fn main() {
    // The clock's origin is the egress's start (D8).
    let clock = MonotonicClock::new();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        process::abort();
    }));

    let args = match Args::parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(e) => fail(2, &format!("{e}\n{USAGE}")),
    };
    let entries: Vec<&str> = args.allow.iter().map(String::as_str).collect();
    let allowlist = match Allowlist::parse(&entries) {
        Ok(allowlist) => allowlist,
        Err(e) => fail(2, &format!("{e}\n{USAGE}")),
    };
    // Bind never replaces what is at the path: an existing file or symlink
    // is `EADDRINUSE` (D1).
    let listener = match UnixListener::bind(&args.socket) {
        Ok(listener) => listener,
        Err(e) => fail(1, &format!("binding the socket failed: {e}")),
    };
    let config = Config {
        allowlist,
        nat64: args.nat64.iter().copied().collect::<BTreeSet<_>>(),
        upstream: Arc::new(TcpUpstream),
        sink: Arc::new(StdoutSink),
        clock: Box::new(clock),
        settings: Settings::production(),
        on_log_failure: Box::new(|| fail(3, "the connection log could not be written")),
    };
    let error = launch(listener, config, unix_ms);
    fail(error.exit_code(), &error.to_string());
}

/// Milliseconds since the Unix epoch, 0 before it, saturating.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn fail(code: i32, message: &str) -> ! {
    eprintln!("boneli-egress: {message}");
    process::exit(code);
}
