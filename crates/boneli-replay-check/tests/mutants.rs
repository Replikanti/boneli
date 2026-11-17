//! Every contract clause case is killed by its own mutant (ADR-004, D2).

use std::collections::BTreeSet;

use boneli_app::contract;
use boneli_replay_check::mutants::{
    blank_status_violations, mutants, regression_mutants, vacuous_fixture_violations,
};

/// Every mutant, and every regression mutant from review, fails its suite
/// at its own clause case.
#[test]
fn every_clause_is_killed() {
    for m in mutants().into_iter().chain(regression_mutants()) {
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

/// Every clause has a mutant, and a clause with sub-checks has one per
/// sub-check: `silent-failure-detail` per operation of its port,
/// `tampered-refused` per pull, `workspace-metadata-inert` per sub-check.
#[test]
fn mutant_table_covers_every_clause() {
    type SubChecks = &'static [(&'static str, &'static [&'static str])];
    let suites: [(&str, &[&str], SubChecks); 11] = [
        ("EventStore", contract::event_store::CLAUSES, &[]),
        ("Evidence", contract::evidence::CLAUSES, &[]),
        ("Clock", contract::clock::CLAUSES, &[]),
        ("Ids", contract::ids::CLAUSES, &[]),
        (
            "Agent",
            contract::agent::CLAUSES,
            &[("silent-failure-detail", contract::agent::OPERATIONS)],
        ),
        (
            "Verifier",
            contract::verifier::CLAUSES,
            &[("silent-failure-detail", contract::verifier::OPERATIONS)],
        ),
        (
            "Forge",
            contract::forge::CLAUSES,
            &[("silent-failure-detail", contract::forge::OPERATIONS)],
        ),
        ("Sandbox", contract::sandbox::CLAUSES, &[]),
        (
            "Git",
            contract::git::CLAUSES,
            &[("workspace-metadata-inert", contract::git::METADATA_CHECKS)],
        ),
        (
            "ImageStore",
            contract::image::CLAUSES,
            &[("tampered-refused", contract::image::TAMPERED_PULLS)],
        ),
        ("DataSnapshot", contract::data::CLAUSES, &[]),
    ];
    let mut wanted = BTreeSet::new();
    let mut clauses = 0;
    for (port, names, sub_checks) in suites {
        for &clause in names {
            clauses += 1;
            match sub_checks.iter().find(|(c, _)| *c == clause) {
                Some((_, subs)) => {
                    for &sub in *subs {
                        wanted.insert((port, clause, sub));
                    }
                }
                None => {
                    wanted.insert((port, clause, ""));
                }
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

/// Regression mutants name clause cases that the bijective table already
/// covers, so the table stays one mutant per case.
#[test]
fn regression_mutants_name_covered_cases() {
    let table: BTreeSet<(&str, &str, &str)> = mutants()
        .iter()
        .map(|m| (m.port, m.clause, m.operation))
        .collect();
    let regressions = regression_mutants();
    assert!(!regressions.is_empty());
    for m in regressions {
        assert!(
            table.contains(&(m.port, m.clause, m.operation)),
            "{} {} {} has no primary mutant",
            m.port,
            m.clause,
            m.operation
        );
    }
}

/// An `edit` hook that never writes metadata is a fixture violation of
/// `workspace-metadata-inert`, not a pass (review of #61).
#[test]
fn metadata_skipping_edit_is_a_violation() {
    for (bug, result) in vacuous_fixture_violations() {
        let violation = result.expect_err("a vacuous fixture must not pass");
        assert_eq!(
            (violation.port, violation.clause),
            ("Git", "workspace-metadata-inert"),
            "{bug}"
        );
        assert!(
            violation.detail.starts_with("fixture:"),
            "{bug}: {violation:?}"
        );
    }
}
