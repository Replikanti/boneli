//! The `Forge` contract suite (ADR-004, D2) on `GitHubForge`, with a `Git`
//! double and the fake GitHub.

mod support;

use std::sync::Arc;

use boneli_app::contract::{self, SilentFailure};
use boneli_domain::{Ticket, TicketSource};
use support::*;

#[test]
fn github_forge_passes_contract() {
    // Only an issue number of the configured repository can take a
    // comment, so the suite's ticket is GitHub issue 1.
    let ticket = Ticket {
        source: TicketSource::GitHub,
        key: "1".to_owned(),
        title: "Contract suite ticket".to_owned(),
        body: String::new(),
    };
    let working = || {
        let clock = FakeClock::at(T0);
        let hub = Hub::new(clock.clone());
        let fake = hub.fake(|_| None);
        forge(tokens(&fake, &clock), Arc::new(FakeGit::default()))
    };
    // Every answer a 503 with an empty body: the token exchange fails, so
    // every operation does, with no error output.
    let silent = || {
        let clock = FakeClock::at(T0);
        let fake = Fake::new(|_| Reply::status(503));
        SilentFailure {
            adapter: forge(tokens(&fake, &clock), Arc::new(FakeGit::default())),
            status: "503".to_owned(),
        }
    };
    assert_eq!(contract::forge::run(working, silent, &ticket), Ok(()));
}
