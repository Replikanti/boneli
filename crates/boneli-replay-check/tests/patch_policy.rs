//! The patch policy on inputs the domain's own tests cannot hold
//! (ADR-013): the core token scan covers every file of the domain
//! package, so realistic JavaScript (`async`, `await`, `process.env`) and
//! the timing tests, which need a clock, live here.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use boneli_domain::{
    BaseLink, Change, ChangeProblem, Entry, EntryKind, Marker, Patch, PatchLimits, PatchVerdict,
    PatchViolation, TestDisabling, patch_policy,
};

/// A bound on hostile shapes in a debug build. A quadratic algorithm on
/// the same input takes hours, so the margin is wide.
const DEADLINE: Duration = Duration::from_secs(60);

fn entry(kind: EntryKind, data: &[u8]) -> Option<Entry> {
    Some(Entry {
        kind,
        data: data.to_vec(),
    })
}

fn file(text: &str) -> Option<Entry> {
    entry(EntryKind::File, text.as_bytes())
}

fn change(path: &str, before: Option<Entry>, after: Option<Entry>) -> Change {
    Change {
        path: path.to_owned(),
        before,
        after,
    }
}

fn judge(changes: Vec<Change>, base_links: Vec<BaseLink>) -> (PatchVerdict, Duration) {
    let patch = Patch {
        changes,
        base_links,
    };
    let start = Instant::now();
    let verdict = patch_policy(&patch, &PatchLimits::DEFAULT);
    (verdict, start.elapsed())
}

/// Myers is cut off at the line budget: on a 200,000-line file (distinct
/// lines) with edits spread evenly, the work is O(N * budget), not the
/// 4 * 10^10 cells of an LCS table.
#[test]
fn line_distance_is_linear_in_size_times_budget() {
    const LINES: usize = 200_000;
    let base: Vec<String> = (0..LINES).map(|k| format!("line {k}\n")).collect();
    let edited = |edits: usize| -> String {
        let step = LINES / edits;
        let mut lines = base.clone();
        for k in 0..edits {
            lines[k * step + step / 2] = format!("edited {k}\n");
        }
        lines.concat()
    };
    let before = base.concat();
    for (edits, want) in [
        (
            499,
            PatchVerdict::Pass {
                files: 1,
                lines: 998,
            },
        ),
        (
            501,
            PatchVerdict::Reject(vec![PatchViolation::TooManyLines { limit: 1000 }]),
        ),
    ] {
        let (verdict, took) = judge(
            vec![change("src/big.ts", file(&before), file(&edited(edits)))],
            Vec::new(),
        );
        assert_eq!(verdict, want, "{edits} edits");
        eprintln!("{edits} edits on {LINES} lines: {took:?}");
        assert!(took < DEADLINE, "{edits} edits took {took:?}");
    }
}

/// 25 links whose 4,095-byte targets walk 2,047 components deep along the
/// shared prefix of 25 base links, plus a file 50,000 directories deep:
/// the walk is one trie step per component.
#[test]
fn link_walk_is_bounded() {
    let prefix = "a/".repeat(2047);
    let target = format!("{prefix}a");
    assert_eq!(target.len(), 4095);
    let base_links: Vec<BaseLink> = (0..25)
        .map(|k| BaseLink {
            path: format!("{prefix}b{k:02}"),
            target: b"x".to_vec(),
        })
        .collect();
    let mut changes: Vec<Change> = vec![change(
        &format!("{}deep.txt", "d/".repeat(50_000)),
        None,
        file("x\n"),
    )];
    changes.extend((0..24).map(|k| {
        change(
            &format!("l{k:02}"),
            None,
            entry(EntryKind::Symlink, target.as_bytes()),
        )
    }));
    let (verdict, took) = judge(changes, base_links);
    assert_eq!(
        verdict,
        PatchVerdict::Pass {
            files: 25,
            lines: 25
        }
    );
    eprintln!("link walks: {took:?}");
    assert!(took < DEADLINE, "took {took:?}");
}

const REAL_SUITE: &str = r#"import { describe, expect, it, beforeEach } from 'vitest'
import { calculateTotals } from '../totals'

const describeIfDb = process.env.DATABASE_URL ? describe : describe.skip

describe('calculateTotals', () => {
  beforeEach(async () => {
    await resetFixtures()
  })

  it('sums three lines without rounding drift', async () => {
    const totals = await calculateTotals([0.1, 0.2, 0.3])
    expect(totals.amount).toBe(0.6)
  })

  it('handles an empty invoice', async () => {
    expect(await calculateTotals([])).toEqual({ amount: 0 })
  })
})
"#;

/// Realistic test files with `async`, `await` and `process.env`, which the
/// core token scan bans in domain sources. The shapes the measurement of
/// ADR-013 (D8) found in human fixes are refused.
#[test]
fn realistic_js_fixtures() {
    let path = "apps/web/test/totals.test.ts";
    let skip = PatchVerdict::Reject(vec![PatchViolation::DisablesTests {
        index: 0,
        reason: TestDisabling::Marker(Marker::Skip),
    }]);
    let without_gate = REAL_SUITE.replace(
        "const describeIfDb = process.env.DATABASE_URL ? describe : describe.skip\n",
        "",
    );
    // The environment-gated skip added to a file without one.
    let (verdict, _) = judge(
        vec![change(path, file(&without_gate), file(REAL_SUITE))],
        Vec::new(),
    );
    assert_eq!(verdict, skip);
    // A conditional skip inside a test.
    let conditional = REAL_SUITE.replace(
        "  it('handles an empty invoice', async () => {\n",
        "  it('handles an empty invoice', async () => {\n    test.skip(!process.env.CI, 'flaky on CI')\n",
    );
    let (verdict, _) = judge(
        vec![change(path, file(REAL_SUITE), file(&conditional))],
        Vec::new(),
    );
    assert_eq!(verdict, skip);
    // An unrelated edit to a real test file passes.
    let edited = REAL_SUITE.replace("toBe(0.6)", "toBeCloseTo(0.6)");
    let (verdict, _) = judge(
        vec![change(path, file(REAL_SUITE), file(&edited))],
        Vec::new(),
    );
    assert_eq!(verdict, PatchVerdict::Pass { files: 1, lines: 2 });
    // So does a new reproduction test next to the existing ones.
    let last = "    expect(await calculateTotals([])).toEqual({ amount: 0 })\n  })\n";
    let added = REAL_SUITE.replace(
        last,
        &format!(
            "{last}\n  it('rounds a cent the same way twice', async () => {{\n    expect((await calculateTotals([0.005])).amount).toBe(0.01)\n  }})\n"
        ),
    );
    assert_ne!(added, REAL_SUITE);
    let (verdict, _) = judge(
        vec![change(path, file(REAL_SUITE), file(&added))],
        Vec::new(),
    );
    assert!(
        matches!(verdict, PatchVerdict::Pass { files: 1, .. }),
        "{verdict:?}"
    );
}

/// xorshift64*, so the run is the same on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const COMPONENTS: &[&str] = &[
    "a",
    "b",
    "A",
    "src",
    ".github",
    "workflows",
    "Dockerfile",
    "x.test.ts",
    "__tests__",
    "vite.config.ts",
    "l",
    "..",
    ".",
    "",
    "\u{200B}",
    "c:d",
    "git~1",
    ".git",
    "package.json",
];

const SNIPPETS: &[&str] = &[
    "it(",
    "it.skip(",
    "test.fail(",
    "expect.fail(",
    "xit(",
    "{ skip: 1 }",
    "'only'",
    "[",
    "]",
    "\n",
    "\r\n",
    "// ",
    "/*",
    "*/",
    "\\u0069",
    "\\u{",
    "\\x",
    ".",
    "/",
    "\u{202E}",
    "\u{2028}",
    "\u{A0}",
    "test:",
    "x",
];

const TARGET_PARTS: &[&str] = &[
    "..",
    ".",
    "a",
    "b",
    "l",
    "",
    ".github",
    "/",
    "\\",
    ":",
    "A",
    ". ",
    "x.test.ts",
];

fn random_path(rng: &mut Rng) -> String {
    let depth = 1 + rng.below(3);
    (0..depth)
        .map(|_| rng.pick(COMPONENTS))
        .collect::<Vec<_>>()
        .join("/")
}

fn random_entry(rng: &mut Rng) -> Entry {
    let kind = [
        EntryKind::File,
        EntryKind::File,
        EntryKind::Executable,
        EntryKind::Symlink,
        EntryKind::Gitlink,
    ][rng.below(5)];
    let data = match kind {
        EntryKind::Symlink => (0..rng.below(5))
            .map(|_| rng.pick(TARGET_PARTS))
            .collect::<Vec<_>>()
            .join("/")
            .into_bytes(),
        _ => {
            let mut data: Vec<u8> = (0..rng.below(12))
                .flat_map(|_| rng.pick(SNIPPETS).as_bytes().to_vec())
                .collect();
            match rng.below(10) {
                0 => data.push(0),
                1 => data.push(0xFF),
                _ => {}
            }
            data
        }
    };
    Entry { kind, data }
}

/// A random base tree, a random mutation of it, and the patch between the
/// two (so most patches pass validation and reach the later rules), with
/// a corruption now and then.
fn random_patch(rng: &mut Rng) -> (Patch, PatchLimits) {
    let mut base = BTreeMap::new();
    for _ in 0..rng.below(8) {
        base.insert(random_path(rng), random_entry(rng));
    }
    let mut after = base.clone();
    for _ in 0..1 + rng.below(6) {
        let path = random_path(rng);
        if rng.below(3) == 0 {
            after.remove(&path);
        } else {
            after.insert(path, random_entry(rng));
        }
    }
    let mut paths: Vec<&String> = base.keys().chain(after.keys()).collect();
    paths.sort();
    paths.dedup();
    let mut changes: Vec<Change> = paths
        .into_iter()
        .filter(|p| base.get(*p) != after.get(*p))
        .map(|p| change(p, base.get(p).cloned(), after.get(p).cloned()))
        .collect();
    let mut base_links: Vec<BaseLink> = base
        .iter()
        .filter(|(_, e)| e.kind == EntryKind::Symlink)
        .map(|(p, e)| BaseLink {
            path: p.clone(),
            target: e.data.clone(),
        })
        .collect();
    match rng.below(8) {
        0 if !changes.is_empty() => {
            let k = rng.below(changes.len());
            changes.push(changes[k].clone());
        }
        1 => base_links.reverse(),
        2 => changes.reverse(),
        _ => {}
    }
    let limit =
        |rng: &mut Rng| NonZeroU32::new([1, 2, 5, 25, 1000][rng.below(5)]).expect("non-zero");
    let limits = PatchLimits {
        max_changed_files: limit(rng),
        max_changed_lines: limit(rng),
    };
    (
        Patch {
            changes,
            base_links,
        },
        limits,
    )
}

/// 10,000 pseudo-random patches never panic, always give the same verdict
/// twice, and a pass respects the limits.
#[test]
fn policy_never_panics() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut passes = 0;
    let mut judged = 0;
    for _ in 0..10_000 {
        let (patch, limits) = random_patch(&mut rng);
        let verdict = patch_policy(&patch, &limits);
        assert_eq!(verdict, patch_policy(&patch, &limits), "{patch:?}");
        match &verdict {
            PatchVerdict::Pass { files, lines } => {
                passes += 1;
                assert_eq!(*files as usize, patch.changes.len());
                assert!(*files <= limits.max_changed_files.get());
                assert!(*lines <= limits.max_changed_lines.get());
            }
            PatchVerdict::Reject(violations) => {
                assert!(!violations.is_empty());
                let malformed = violations.iter().any(|v| {
                    matches!(
                        v,
                        PatchViolation::Malformed { .. } | PatchViolation::BaseLinkMalformed { .. }
                    )
                });
                if !malformed && !matches!(violations[0], PatchViolation::TooManyFiles { .. }) {
                    judged += 1;
                }
                if violations.iter().any(|v| {
                    matches!(
                        v,
                        PatchViolation::Malformed {
                            problem: ChangeProblem::BaseLinkMismatch,
                            ..
                        }
                    )
                }) {
                    assert!(
                        !patch.changes.is_empty(),
                        "a mismatch needs a change: {patch:?}"
                    );
                }
            }
        }
    }
    eprintln!("{passes} passed, {judged} judged past validation");
    assert!(passes > 100 && judged > 1000, "{passes} {judged}");
}
