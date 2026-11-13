//! Every contract clause case is killed by its own mutant (ADR-004, D2).

use std::collections::BTreeSet;

use boneli_app::contract;
use boneli_replay_check::mutants::{blank_status_violations, mutants};

#[test]
fn every_clause_is_killed() {
    for m in mutants() {
        let (port, clause, operation) = (m.port, m.clause, m.operation);
        match (m.run)() {
            Ok(()) => panic!("the {port} mutant for {clause} {operation} passed its suite"),
            Err(violation) => {
                assert_eq!(
                    (violation.port, violation.clause),
                    (port, clause),
                    "the {port} mutant for {clause} {operation} broke another clause first: \
                     {violation:?}"
                );
                // A per-operation mutant must be caught by that operation's
                // check, not an earlier one.
                assert!(
                    operation.is_empty() || violation.detail.starts_with(&format!("{operation}:")),
                    "the {port} mutant for {operation} was caught elsewhere: {violation:?}"
                );
            }
        }
    }
}

/// Every clause has a mutant, and `silent-failure-detail` has one per
/// operation of its port.
#[test]
fn mutant_table_covers_every_clause() {
    let suites: [(&str, &[&str], &[&str]); 7] = [
        ("EventStore", contract::event_store::CLAUSES, &[]),
        ("Evidence", contract::evidence::CLAUSES, &[]),
        ("Clock", contract::clock::CLAUSES, &[]),
        ("Ids", contract::ids::CLAUSES, &[]),
        (
            "Agent",
            contract::agent::CLAUSES,
            contract::agent::OPERATIONS,
        ),
        (
            "Verifier",
            contract::verifier::CLAUSES,
            contract::verifier::OPERATIONS,
        ),
        (
            "Forge",
            contract::forge::CLAUSES,
            contract::forge::OPERATIONS,
        ),
    ];
    let mut wanted = BTreeSet::new();
    let mut clauses = 0;
    for (port, names, operations) in suites {
        for &clause in names {
            clauses += 1;
            if clause == "silent-failure-detail" {
                for &operation in operations {
                    wanted.insert((port, clause, operation));
                }
            } else {
                wanted.insert((port, clause, ""));
            }
        }
    }
    let table = mutants();
    let have: BTreeSet<(&str, &str, &str)> = table
        .iter()
        .map(|m| (m.port, m.clause, m.operation))
        .collect();
    assert_eq!(have.len(), table.len(), "a case has two mutants");
    assert_eq!(have, wanted, "mutants and clause cases are not a bijection");
    // The counts ADR-004 and the pull request quote come from here.
    println!(
        "contract counts: {clauses} clauses, {} mutant cases",
        table.len()
    );
}

/// A blank fixture status is a violation, not a pass: every detail
/// contains the empty string.
#[test]
fn blank_fixture_status_is_a_violation() {
    for (port, result) in blank_status_violations() {
        let violation = result.expect_err("a blank fixture status must not pass");
        assert_eq!(
            (violation.port, violation.clause),
            (port, "silent-failure-detail")
        );
        assert!(violation.detail.contains("is blank"), "{violation:?}");
    }
}
