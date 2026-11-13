//! Prints the probe line, then the rendered domain scenarios (ADR-002).

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let rendered = match boneli_replay_check::render() {
        Ok(text) => text,
        Err(error) => {
            eprintln!("boneli-replay-check: a scenario has an invalid budget: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout().lock();
    let written = out
        .write_all(boneli_replay_check::probe().as_bytes())
        .and_then(|()| out.write_all(rendered.as_bytes()))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("boneli-replay-check: cannot write the output: {error}");
            ExitCode::FAILURE
        }
    }
}
