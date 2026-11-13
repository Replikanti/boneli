//! Every in-memory adapter passes its port's contract suite (ADR-004, D2).

use boneli_app::contract::{self, SilentFailure};
use boneli_app::{RootCauseReport, TriageReport, Written};
use boneli_domain::{CitationStatus, CommitSha, FixChecks, TriageVerdict};
use boneli_memory::{
    AgentScript, ForgeScript, MemoryAgent, MemoryEventStore, MemoryForge, MemoryVerifier, Response,
    ScriptedFailure, SequentialIds, StepClock, VerifierScript,
};

/// The status the silent-failure fixtures report.
pub const STATUS: &str = "exit status 3";

/// Every operation fails silently.
pub fn fails<T>() -> Vec<Response<T>> {
    vec![Response::Fail(silent())]
}

/// A failure with no error output and the status [`STATUS`].
pub fn silent() -> ScriptedFailure {
    ScriptedFailure {
        error_output: String::new(),
        status: String::from(STATUS),
        cost_micro_usd: 10,
    }
}

/// An agent whose every operation fails silently.
pub fn silent_agent() -> SilentFailure<MemoryAgent> {
    SilentFailure {
        adapter: MemoryAgent::new(AgentScript {
            triage: fails(),
            write_reproduction: fails(),
            analyze_root_cause: fails(),
            write_fix: fails(),
        }),
        status: String::from(STATUS),
    }
}

/// A verifier whose every operation fails silently.
pub fn silent_verifier() -> SilentFailure<MemoryVerifier> {
    SilentFailure {
        adapter: MemoryVerifier::new(VerifierScript {
            check_reproduction: vec![Response::Fail(silent())],
            verify_citations: vec![Response::Fail(silent())],
            verify_fix: vec![Response::Fail(silent())],
        }),
        status: String::from(STATUS),
    }
}

/// A verifier that answers the suite's sample citations.
pub fn answering_verifier() -> contract::verifier::Answering<MemoryVerifier> {
    let base = CommitSha::parse("0123456789abcdef0123456789abcdef01234567").expect("valid SHA");
    let citations = contract::verifier::sample(&base);
    let statuses = vec![CitationStatus::Verified; citations.len()];
    contract::verifier::Answering {
        adapter: MemoryVerifier::new(VerifierScript {
            verify_citations: vec![Response::Answer(statuses)],
            ..VerifierScript::default()
        }),
        base,
        citations,
    }
}

/// A forge whose every operation fails silently.
pub fn silent_forge() -> SilentFailure<MemoryForge> {
    SilentFailure {
        adapter: MemoryForge::scripted(ForgeScript {
            post_questions: vec![Response::Fail(silent())],
            open_pull_request: vec![Response::Fail(silent())],
        }),
        status: String::from(STATUS),
    }
}

#[test]
fn in_memory_event_store_passes_contract() {
    assert_eq!(contract::event_store::run(MemoryEventStore::new), Ok(()));
}

// The Evidence suite runs in the unit tests of `src/evidence.rs`: its
// `tampered-content-rejected` clause writes behind the store, which only
// test code inside the crate may do (ADR-004, D9).

#[test]
fn in_memory_clock_passes_contract() {
    assert_eq!(contract::clock::run(&StepClock::new(0, 1_000)), Ok(()));
    assert_eq!(contract::clock::run(&StepClock::new(7, 0)), Ok(()));
    // Saturates instead of wrapping.
    assert_eq!(
        contract::clock::run(&StepClock::new(u64::MAX - 1, 1)),
        Ok(())
    );
}

#[test]
fn in_memory_ids_passes_contract() {
    assert_eq!(contract::ids::run(&SequentialIds::new()), Ok(()));
}

#[test]
fn in_memory_agent_passes_contract() {
    assert_eq!(contract::agent::run(silent_agent), Ok(()));
}

#[test]
fn in_memory_verifier_passes_contract() {
    assert_eq!(
        contract::verifier::run(answering_verifier, silent_verifier),
        Ok(())
    );
}

#[test]
fn in_memory_forge_passes_contract() {
    assert_eq!(contract::forge::run(MemoryForge::new, silent_forge), Ok(()));
}

/// The scripts answer in order and an exhausted queue fails with the
/// operation's name instead of panicking.
#[test]
fn scripts_answer_in_order_then_fail_by_name() {
    use boneli_app::{Agent, TriageRequest, Verifier};
    let agent = MemoryAgent::new(AgentScript {
        triage: vec![
            Response::Answer(TriageReport {
                verdict: TriageVerdict::Ready,
                cost_micro_usd: 1,
            }),
            Response::Fail(silent()),
        ],
        write_reproduction: vec![Response::Answer(Written {
            content: b"t".to_vec(),
            cost_micro_usd: 2,
        })],
        analyze_root_cause: vec![Response::Answer(RootCauseReport {
            analysis: b"a".to_vec(),
            citations: vec![],
            cost_micro_usd: 3,
        })],
        write_fix: vec![],
    });
    let base = CommitSha::parse("0123456789abcdef0123456789abcdef01234567").expect("valid SHA");
    let request = TriageRequest {
        ticket: boneli_domain::Ticket {
            source: boneli_domain::TicketSource::Jira,
            key: String::from("K-1"),
            title: String::from("t"),
            body: String::new(),
        },
        base: base.clone(),
        previous: None,
    };
    assert_eq!(agent.triage(&request).map(|r| r.cost_micro_usd), Ok(1));
    let failed = agent.triage(&request).expect_err("scripted failure");
    assert_eq!(failed.detail(), "exit status 3, no error output");
    assert_eq!(failed.cost_micro_usd(), 10);
    let exhausted = agent.triage(&request).expect_err("script used up");
    assert_eq!(exhausted.detail(), "no scripted response for triage");
    assert_eq!(exhausted.cost_micro_usd(), 0);
    assert_eq!(agent.requests().len(), 3);

    let verifier = MemoryVerifier::new(VerifierScript::default());
    let checks = verifier.verify_fix(&base, b"d", b"t");
    assert_eq!(
        checks.map_err(|f| f.detail().to_owned()),
        Err::<FixChecks, _>(String::from("no scripted response for verify_fix"))
    );
}
