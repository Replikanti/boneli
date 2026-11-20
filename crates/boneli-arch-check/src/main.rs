//! The architecture check of the workspace (ADR-015). Run it through
//! tools/check-architecture.sh, which builds it first.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(boneli_arch_check::run(
        std::env::args_os().skip(1).collect(),
    ))
}
