//! Integration tests of `boneli-git-cli` (#30, ADR-010; #19, ADR-014): the
//! `Git` contract on `GitCli` over fixture repositories, the acceptance
//! tests, the environment and steering tests of the git runner, and branch
//! push and credentials.
//!
//! The tests run the first `git` on `PATH`, which must be at least the
//! adapter's floor (2.39.1). Fixture repositories are built by that git
//! with a cleared environment, so a developer's global config cannot leak
//! in. They need no root and no network; `network::` is ignored and
//! fetches this repository from GitHub:
//! `cargo test -p boneli-git-cli --test boneli_git_cli_tests -- --ignored network::`
//! `open::fresh_executables_start_under_concurrent_spawns` is ignored too:
//! a stress test of the harness's own fake gits (`support::write_executable`).

mod support;

mod apply;
mod contract;
mod credentials;
mod diff;
mod environment;
mod fetch;
mod network;
mod open;
mod push;
mod read;
mod snapshot;
