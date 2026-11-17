//! "A replayed run reaches the same state as the original" (#4): the
//! domain's scenario corpus, stored and replayed after a restart.

use std::collections::BTreeSet;

use boneli_app::{EventStore, RunStart, replay};
use boneli_domain::{EventKind, RunCommand, RunEvent, RunId, scenarios};
use boneli_store_fs::FsStore;

use crate::support::TempDir;

/// Every scenario whose `Run::new` succeeds: its accepted events are
/// stored, the store is dropped and reopened, and the replay of the loaded
/// log equals the fold's run and its commands. Every event kind is stored
/// at least once.
#[test]
fn domain_corpus_replays_after_reopen() {
    let tmp = TempDir::new("corpus");
    let root = tmp.path().join("store");
    let mut expected = Vec::new();
    let mut kinds = BTreeSet::new();
    {
        let store = FsStore::open(&root).expect("open");
        for scenario in scenarios::all() {
            let Ok(trace) = scenarios::fold(&scenario) else {
                continue;
            };
            let run = RunId::new(String::from(scenario.name));
            let start = RunStart {
                budget: scenario.budget,
                previous: None,
            };
            store.create(&run, &start).expect("create");
            let mut commands: Vec<RunCommand> = Vec::new();
            for (event, entry) in scenario.events.iter().zip(&trace.entries) {
                if let Ok(more) = &entry.result {
                    store.append(&run, event).expect("append");
                    kinds.insert(kind_index(event));
                    commands.extend(more.iter().cloned());
                }
            }
            expected.push((run, trace.run, commands));
        }
    }
    let store = FsStore::open(&root).expect("reopen");
    for (run, want_run, want_commands) in &expected {
        let log = store.load(run).expect("load");
        let replayed = replay(run, &log).expect("replays");
        assert_eq!(&replayed.0, want_run, "{run:?}");
        assert_eq!(&replayed.1, want_commands, "{run:?}");
    }
    println!("replayed {} scenarios after a reopen", expected.len());
    assert!(expected.len() > 50, "{}", expected.len());
    assert_eq!(kinds.len(), EventKind::ALL.len(), "{kinds:?}");
}

fn kind_index(event: &RunEvent) -> usize {
    EventKind::ALL
        .iter()
        .position(|k| *k == event.kind())
        .expect("a listed kind")
}
