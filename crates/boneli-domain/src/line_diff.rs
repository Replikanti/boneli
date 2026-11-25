//! Line and byte cost of a change for the patch policy's size rule
//! (ADR-013, D3).
//!
//! A line is a run of bytes up to and including `\n`, plus a final run
//! without one if it is not empty, as git counts lines. The cost of a
//! change is the least number of inserted plus deleted lines that turns
//! one side into the other, and the bytes of those lines: Myers' greedy
//! forward pass ("An O(ND) Difference Algorithm and Its Variations",
//! 1986), cut off at the line budget, with the edit script recovered from
//! the furthest points of every step.
//!
//! Time is O(total bytes + (N + M) * D) and memory linear with a small
//! constant. The line-count and byte-length differences cut the search off
//! before anything is allocated; common leading and trailing lines are
//! stripped by walking both sides; each remaining line is hashed once (8
//! bytes per line), the search compares hashes, and the edit script it
//! recovers is verified byte for byte once, so a hash collision can only
//! refuse. The trace holds one entry per diagonal and step, at most
//! (D + 1)(D + 2) / 2 for a distance of D.
//!
//! The time is pinned by two measures of [`Work`], not by a clock: the
//! bytes hashed (each line of the middles exactly once) and the probes of
//! the search (calls of the line comparison, within Myers' O((N + M) D)
//! bound for D up to the budget).

use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

/// The number of lines of `data`: `""` has none, `"a"`, `"a\n"` and `"\n"`
/// have one, `"a\nb"` has two.
pub fn line_count(data: &[u8]) -> usize {
    let newlines = data.iter().filter(|b| **b == b'\n').count();
    newlines + usize::from(data.last().is_some_and(|b| *b != b'\n'))
}

/// The cost of a change: inserted plus deleted lines and their bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Inserted plus deleted lines.
    pub lines: usize,
    /// The bytes of those lines, newlines included.
    pub bytes: usize,
}

/// Which budget a change crosses first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    /// The line budget, or a hash collision the verification found (the
    /// cost cannot be decided, so it refuses).
    Lines,
    /// The byte budget.
    Bytes,
}

/// The end (exclusive) of the line that starts at `from`.
fn line_end(s: &[u8], from: usize) -> usize {
    s.get(from..)
        .and_then(|rest| rest.iter().position(|b| *b == b'\n'))
        .map_or(s.len(), |at| from + at + 1)
}

/// The start of the line that ends at `end` (exclusive, `end > 0`).
fn line_start(s: &[u8], end: usize) -> usize {
    s.get(..end.saturating_sub(1))
        .and_then(|body| body.iter().rposition(|b| *b == b'\n'))
        .map_or(0, |at| at + 1)
}

/// Line `i` of `s`, by its start in `starts`.
fn line_at<'s>(s: &'s [u8], starts: &[usize], i: usize) -> Option<&'s [u8]> {
    starts
        .get(i)
        .and_then(|from| s.get(*from..line_end(s, *from)))
}

/// The lines of `s`, in order, without collecting them.
fn lines(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split_inclusive(|b| *b == b'\n')
}

/// FNV-1a, 64 bits. Not collision resistant, and it need not be: equal
/// hashes are verified byte for byte (traced) or compared directly. Adds
/// the bytes of `line` to `hashed`.
fn hash(line: &[u8], hashed: &Cell<usize>) -> u64 {
    hashed.set(hashed.get().saturating_add(line.len()));
    line.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Above this many lines of budget, the edit script is not recovered: the
/// trace would pass 8.4 million entries. The search then compares lines
/// byte for byte on equal hashes, and the bytes are bounded by both middles
/// together, which refuses more, never less.
const MAX_TRACED: usize = 4096;

/// The cost of turning `a` into `b`, or the budget it crosses first.
pub fn cost(a: &[u8], b: &[u8], max_lines: usize, max_bytes: usize) -> Result<Cost, Over> {
    cost_counted(a, b, max_lines, max_bytes, &mut Work::default())
}

/// The work of one [`cost`], counted where it happens, so a test can pin
/// how memory and time grow without a clock.
#[derive(Debug, Default)]
pub(crate) struct Work {
    /// Every per-line and per-step cell allocated.
    pub(crate) cells: usize,
    /// The bytes passed through the line hash.
    pub(crate) hashed: Cell<usize>,
    /// The calls of the line comparison in the search.
    pub(crate) probes: usize,
}

/// [`cost`], adding its work to `work`.
pub(crate) fn cost_counted(
    a: &[u8],
    b: &[u8],
    max_lines: usize,
    max_bytes: usize,
    work: &mut Work,
) -> Result<Cost, Over> {
    if line_count(a).abs_diff(line_count(b)) > max_lines {
        return Err(Over::Lines);
    }
    // Common lines are equal on both sides, so the length difference is a
    // lower bound of the changed bytes.
    if a.len().abs_diff(b.len()) > max_bytes {
        return Err(Over::Bytes);
    }
    let (mut pa, mut pb) = (0, 0);
    while pa < a.len() && pb < b.len() {
        let (ea, eb) = (line_end(a, pa), line_end(b, pb));
        if a.get(pa..ea) != b.get(pb..eb) {
            break;
        }
        (pa, pb) = (ea, eb);
    }
    let (mut sa, mut sb) = (a.len(), b.len());
    while sa > pa && sb > pb {
        let (la, lb) = (line_start(a, sa).max(pa), line_start(b, sb).max(pb));
        if a.get(la..sa) != b.get(lb..sb) {
            break;
        }
        (sa, sb) = (la, lb);
    }
    let a = a.get(pa..sa).unwrap_or(&[]);
    let b = b.get(pb..sb).unwrap_or(&[]);
    let limit = max_lines.min(line_count(a).saturating_add(line_count(b)));
    let traced = limit <= MAX_TRACED;
    let ha: Vec<u64> = lines(a).map(|l| hash(l, &work.hashed)).collect();
    let hb: Vec<u64> = lines(b).map(|l| hash(l, &work.hashed)).collect();
    work.cells = work.cells.saturating_add(ha.len() + hb.len());
    // Untraced, an equal hash is checked against the bytes on the spot.
    let starts = |s: &[u8]| -> Vec<usize> {
        let mut at = 0;
        lines(s)
            .map(|l| {
                let start = at;
                at += l.len();
                start
            })
            .collect()
    };
    let (sa_, sb_) = if traced {
        (Vec::new(), Vec::new())
    } else {
        (starts(a), starts(b))
    };
    let same = |x: usize, y: usize| -> bool {
        if ha.get(x) != hb.get(y) {
            return false;
        }
        if traced {
            return true;
        }
        line_at(a, &sa_, x) == line_at(b, &sb_, y)
    };
    let script = myers(
        ha.len(),
        hb.len(),
        limit,
        traced,
        &same,
        &mut work.cells,
        &mut work.probes,
    )
    .ok_or(Over::Lines)?;
    let bytes = if traced {
        verified_bytes(a, b, &script).ok_or(Over::Lines)?
    } else {
        a.len().saturating_add(b.len())
    };
    if bytes > max_bytes {
        return Err(Over::Bytes);
    }
    Ok(Cost {
        lines: script.distance,
        bytes,
    })
}

/// Walks both middles along the recovered script: the bytes of the
/// deleted and inserted lines, or `None` when two lines the script matches
/// differ (a hash collision).
fn verified_bytes(a: &[u8], b: &[u8], script: &Script) -> Option<usize> {
    let mut deleted = script.deleted.iter().peekable();
    let mut inserted = script.inserted.iter().peekable();
    let mut left = lines(a).enumerate();
    let mut right = lines(b).enumerate();
    let mut total = 0usize;
    loop {
        let next_left = left.next();
        let mut keep_left = None;
        if let Some((x, line)) = next_left {
            if deleted.peek() == Some(&&x) {
                deleted.next();
                total = total.saturating_add(line.len());
                continue;
            }
            keep_left = Some(line);
        }
        // Skip inserted lines of `b` up to the next kept one.
        let mut keep_right = None;
        for (y, line) in right.by_ref() {
            if inserted.peek() == Some(&&y) {
                inserted.next();
                total = total.saturating_add(line.len());
                continue;
            }
            keep_right = Some(line);
            break;
        }
        match (keep_left, keep_right) {
            (None, None) => return Some(total),
            (Some(l), Some(r)) if l == r => {}
            _ => return None,
        }
    }
}

/// The result of the search.
struct Script {
    distance: usize,
    /// Indices of deleted lines of `a`, ascending (traced only).
    deleted: Vec<usize>,
    /// Indices of inserted lines of `b`, ascending (traced only).
    inserted: Vec<usize>,
}

/// Whether a move down onto diagonal `k` from x on diagonal `k + 1` stays
/// inside the grid: the new y, `x - k`, is at most `m`.
fn fits_down(x: usize, k: isize, m: usize) -> bool {
    match (isize::try_from(x), isize::try_from(m)) {
        (Ok(x), Ok(m)) => x - k <= m,
        _ => false,
    }
}

/// The start of diagonal `k` from step `d - 1`: down from `k + 1` (an
/// insertion) or right from `k - 1` (a deletion), whichever reaches
/// further inside the grid; down on a tie.
fn start(down: Option<usize>, right: Option<usize>, k: isize, n: usize, m: usize) -> Option<usize> {
    let down = down.filter(|x| fits_down(*x, k, m));
    let right = right.filter(|x| *x < n).map(|x| x + 1);
    match (down, right) {
        (Some(p), Some(q)) => Some(p.max(q)),
        (p, q) => p.or(q),
    }
}

/// The search, adding its cells to `cells` and every call of `same` to
/// `probes`.
fn myers(
    n: usize,
    m: usize,
    limit: usize,
    traced: bool,
    same: &dyn Fn(usize, usize) -> bool,
    cells: &mut usize,
    probes: &mut usize,
) -> Option<Script> {
    let width = limit.checked_mul(2)?.checked_add(3)?;
    let offset = isize::try_from(limit.checked_add(1)?).ok()?;
    let at = |k: isize| usize::try_from(k.checked_add(offset)?).ok();
    let mut v: Vec<Option<usize>> = vec![None; width];
    *cells = cells.saturating_add(width);
    // trace[d] holds the x of every diagonal of step d, from k = -d up.
    let mut trace: Vec<Vec<Option<usize>>> = Vec::new();
    for d in 0..=limit {
        let d_i = isize::try_from(d).ok()?;
        let mut row = Vec::new();
        let mut k = -d_i;
        while k <= d_i {
            let first = if d == 0 {
                Some(0)
            } else {
                let down = v.get(at(k + 1)?).copied().flatten();
                let right = v.get(at(k - 1)?).copied().flatten();
                start(down, right, k, n, m)
            };
            let mut found = None;
            if let Some(mut x) = first {
                let mut y = usize::try_from(isize::try_from(x).ok()?.checked_sub(k)?).ok()?;
                while x < n && y < m {
                    *probes = probes.saturating_add(1);
                    if !same(x, y) {
                        break;
                    }
                    x += 1;
                    y += 1;
                }
                found = Some(x);
                if x == n && y == m {
                    if traced {
                        trace.push(row);
                    }
                    return Some(backtrack(&trace, d, k, traced, n, m));
                }
            }
            if traced {
                row.push(found);
            }
            *v.get_mut(at(k)?)? = found;
            k += 2;
        }
        if traced {
            *cells = cells.saturating_add(row.len());
            trace.push(row);
        }
    }
    None
}

/// The x of diagonal `k` at step `d` in the trace.
fn traced_x(trace: &[Vec<Option<usize>>], d: usize, k: isize) -> Option<usize> {
    let d_i = isize::try_from(d).ok()?;
    if k < -d_i || k > d_i {
        return None;
    }
    let index = usize::try_from((k + d_i) / 2).ok()?;
    trace.get(d)?.get(index).copied().flatten()
}

/// Walks the trace back from the end at step `d`, diagonal `k`, and
/// collects the deleted and inserted line indices.
fn backtrack(
    trace: &[Vec<Option<usize>>],
    d: usize,
    mut k: isize,
    traced: bool,
    n: usize,
    m: usize,
) -> Script {
    let mut script = Script {
        distance: d,
        deleted: Vec::new(),
        inserted: Vec::new(),
    };
    if !traced {
        return script;
    }
    for step_d in (1..=d).rev() {
        let previous = step_d - 1;
        let down = traced_x(trace, previous, k + 1).filter(|x| fits_down(*x, k, m));
        let right = traced_x(trace, previous, k - 1).filter(|x| *x < n);
        // The same choice as the forward pass (`start`): down unless right
        // reaches strictly further.
        let go_down = match (down, right) {
            (Some(p), Some(q)) => p > q,
            (Some(_), None) => true,
            _ => false,
        };
        if go_down {
            let x = down.unwrap_or(0);
            let y = usize::try_from(isize::try_from(x).unwrap_or(0) - (k + 1)).unwrap_or(0);
            script.inserted.push(y);
            k += 1;
        } else {
            script.deleted.push(right.unwrap_or(0));
            k -= 1;
        }
    }
    script.deleted.reverse();
    script.inserted.reverse();
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    fn lines_of(a: &str, b: &str, max: usize) -> Option<usize> {
        cost(a.as_bytes(), b.as_bytes(), max, usize::MAX)
            .ok()
            .map(|c| c.lines)
    }

    fn split(s: &[u8]) -> Vec<&[u8]> {
        s.split_inclusive(|b| *b == b'\n').collect()
    }

    /// The textbook LCS table: insertions plus deletions = n + m - 2 * LCS.
    fn reference(a: &[u8], b: &[u8]) -> usize {
        let (a, b) = (split(a), split(b));
        let mut table = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in 0..a.len() {
            for j in 0..b.len() {
                table[i + 1][j + 1] = if a[i] == b[j] {
                    table[i][j] + 1
                } else {
                    table[i][j + 1].max(table[i + 1][j])
                };
            }
        }
        a.len() + b.len() - 2 * table[a.len()][b.len()]
    }

    #[test]
    fn line_count_follows_git() {
        assert_eq!(line_count(b""), 0);
        assert_eq!(line_count(b"a"), 1);
        assert_eq!(line_count(b"a\n"), 1);
        assert_eq!(line_count(b"\n"), 1);
        assert_eq!(line_count(b"a\nb"), 2);
        assert_eq!(line_count(b"a\r\nb\r\n"), 2);
    }

    #[test]
    fn cost_cases() {
        assert_eq!(lines_of("", "", 0), Some(0));
        assert_eq!(lines_of("a\n", "a\n", 0), Some(0));
        assert_eq!(lines_of("a\n", "b\n", 2), Some(2));
        assert_eq!(lines_of("a\n", "b\n", 1), None);
        assert_eq!(lines_of("a", "a\n", 5), Some(2));
        assert_eq!(lines_of("a\nb\n", "b\na\n", 5), Some(2));
        assert_eq!(lines_of("", "a\nb\nc\n", 3), Some(3));
        assert_eq!(lines_of("", "a\nb\nc\n", 2), None);
        assert_eq!(lines_of("a\nb\nc\n", "", 3), Some(3));
        assert_eq!(lines_of("a\r\nb\r\nc\r\n", "a\nb\nc\n", 6), Some(6));
        assert_eq!(lines_of("x\na\nb\ny\n", "x\nb\na\ny\n", 1), None);
        assert_eq!(lines_of("x\na\nb\ny\n", "x\nb\na\ny\n", 2), Some(2));
        // A prefix that is a whole line of the other side.
        assert_eq!(lines_of("a\na\n", "a\n", 5), Some(1));
        assert_eq!(lines_of("a\n", "a\na", 5), Some(1));
    }

    #[test]
    fn bytes_are_the_changed_lines() {
        let c = cost(b"keep\nold line\nkeep\n", b"keep\nnew\nkeep\n", 10, 100);
        assert_eq!(
            c,
            Ok(Cost {
                lines: 2,
                bytes: 9 + 4
            })
        );
        assert_eq!(
            cost(b"keep\nold line\nkeep\n", b"keep\nnew\nkeep\n", 10, 12),
            Err(Over::Bytes)
        );
        // One long line: one line, all its bytes.
        let long = "x".repeat(50_000);
        assert_eq!(
            cost(b"", long.as_bytes(), 10, 100_000),
            Ok(Cost {
                lines: 1,
                bytes: 50_000
            })
        );
        assert_eq!(cost(b"", long.as_bytes(), 10, 49_999), Err(Over::Bytes));
        // The line budget is checked first.
        assert_eq!(cost(b"", b"a\nb\nc\n", 2, 1), Err(Over::Lines));
    }

    #[test]
    fn two_block_swap_costs_both_blocks() {
        let first: String = (0..10).map(|k| format!("a{k}\n")).collect();
        let second: String = (0..10).map(|k| format!("b{k}\n")).collect();
        let before = format!("{first}{second}");
        let after = format!("{second}{first}");
        assert_eq!(lines_of(&before, &after, 100), Some(20));
        assert_eq!(lines_of(&before, &after, 19), None);
    }

    /// Myers against the LCS table on every pair of short sequences over a
    /// two-line alphabet, at every budget around the answer, and the bytes
    /// against the lines (every line here is two bytes).
    #[test]
    fn cost_matches_the_lcs_table() {
        let mut all: Vec<String> = vec![String::new()];
        for len in 1..=6u32 {
            for bits in 0..(1u32 << len) {
                all.push(
                    (0..len)
                        .map(|k| if (bits >> k) & 1 == 1 { "y\n" } else { "x\n" })
                        .collect(),
                );
            }
        }
        for a in all.iter().step_by(3) {
            for b in all.iter().step_by(2) {
                let want = reference(a.as_bytes(), b.as_bytes());
                let got = cost(a.as_bytes(), b.as_bytes(), want, usize::MAX);
                assert_eq!(
                    got,
                    Ok(Cost {
                        lines: want,
                        bytes: 2 * want
                    }),
                    "{a:?} {b:?}"
                );
                assert_eq!(lines_of(a, b, usize::MAX), Some(want), "{a:?} {b:?}");
                if want > 0 {
                    assert_eq!(lines_of(a, b, want - 1), None, "{a:?} {b:?}");
                }
            }
        }
    }

    /// Bytes from the recovered script against a brute force over lines of
    /// different lengths: the script is a minimal one, so its bytes are the
    /// bytes of some minimal edit; check it against the line count and the
    /// byte totals of both sides.
    #[test]
    fn recovered_script_is_consistent() {
        let words = ["a\n", "bb\n", "ccc\n"];
        let mut all: Vec<String> = vec![String::new()];
        for len in 1..=5u32 {
            for code in 0..3u32.pow(len) {
                let mut c = code;
                let mut s = String::new();
                for _ in 0..len {
                    s.push_str(words[(c % 3) as usize]);
                    c /= 3;
                }
                all.push(s);
            }
        }
        for a in all.iter().step_by(7) {
            for b in all.iter().step_by(5) {
                let got =
                    cost(a.as_bytes(), b.as_bytes(), usize::MAX, usize::MAX).expect("no budget");
                assert_eq!(got.lines, reference(a.as_bytes(), b.as_bytes()));
                // Deleted minus inserted bytes is the length difference.
                assert!(got.bytes >= a.len().abs_diff(b.len()), "{a:?} {b:?}");
                assert!(got.bytes <= a.len() + b.len(), "{a:?} {b:?}");
                assert_eq!((got.bytes + a.len() + b.len()) % 2, 0, "{a:?} {b:?}");
            }
        }
    }

    /// Memory is one hash per line of the middles plus cells sized by the
    /// budget and the distance; a 10 MB addition is cut off by the line
    /// count before anything is allocated or hashed.
    #[test]
    fn memory_is_independent_of_the_file_size() {
        let base: Vec<u8> = (0..2_000_000u32)
            .flat_map(|k| format!("{k}\n").into_bytes())
            .collect();
        let mut edited = b"first\n".to_vec();
        edited.extend_from_slice(&base);
        edited.extend_from_slice(b"last\n");
        let mut work = Work::default();
        assert_eq!(
            cost_counted(&base, &edited, 1000, 100_000, &mut work),
            Ok(Cost {
                lines: 2,
                bytes: 11
            })
        );
        // One hash per line of the middles (both whole files here, since
        // the edits sit at both ends), a row sized by the budget
        // (2 * 1000 + 3) and a trace sized by the distance.
        assert!(work.cells <= 4_000_002 + 2_010, "{} cells", work.cells);
        let mut work = Work::default();
        let added = vec![b'\n'; 10_000_000];
        assert_eq!(
            cost_counted(b"", &added, 1000, usize::MAX, &mut work),
            Err(Over::Lines)
        );
        assert_eq!(work.cells, 0);
        assert_eq!(work.hashed.get(), 0);
        assert_eq!(work.probes, 0);
        // A length difference over the byte budget is cut off before any
        // line is hashed, too.
        let mut work = Work::default();
        let mut longer = b"x\n".to_vec();
        longer.extend_from_slice(&[b'y'; 42_001]);
        assert_eq!(
            cost_counted(b"x\n", &longer, 1000, 42_000, &mut work),
            Err(Over::Bytes)
        );
        assert_eq!(work.cells, 0);
        assert_eq!(work.hashed.get(), 0);
        assert_eq!(work.probes, 0);
        // Spread edits: the cells follow the distance, not the size.
        let spread: Vec<u8> = (0..2_000_000u32)
            .flat_map(|k| {
                if k % 100_000 == 50_000 {
                    format!("x{k}\n").into_bytes()
                } else {
                    format!("{k}\n").into_bytes()
                }
            })
            .collect();
        let mut work = Work::default();
        let got = cost_counted(&base, &spread, 1000, usize::MAX, &mut work).expect("in budget");
        assert_eq!(got.lines, 40);
        assert!(
            work.cells <= 4_000_000 + 2_003 + 41 * 42,
            "{} cells",
            work.cells
        );
    }

    /// At most one probe per diagonal and step of a search that never
    /// follows a snake: `(limit + 1)(limit + 2) / 2`.
    fn steps(limit: usize) -> usize {
        (limit + 1) * (limit + 2) / 2
    }

    /// `lines` distinct lines of `len` + 10 bytes, the tag at byte 0
    /// (the shape of `line_cost_is_linear_in_bytes` in
    /// `boneli-replay-check`).
    fn distinct(tag: char, lines: usize, len: usize) -> String {
        let pad = "x".repeat(len);
        (0..lines).map(|k| format!("{tag}{k:08}{pad}\n")).collect()
    }

    /// Review round 2 of PR #70 (item 2), without a clock (#128): the line
    /// cost hashes every line of the middles exactly once, so long distinct
    /// lines cost their bytes once, not once per search step. A ladder of
    /// growing shapes, smallest first, so a rehash per probe or per step
    /// fails on the first rung in milliseconds. The top traced rung is the
    /// 400 + 400 x 25 KB case: 800 x 25,010 = 20,008,000 bytes hashed, at
    /// most 801 x 802 / 2 = 321,201 probes. The last rung takes a budget
    /// above `MAX_TRACED`, where the search compares bytes on equal hashes
    /// (none here), which is not hashing.
    #[test]
    fn line_cost_hashes_each_line_once() {
        for (lines, len, max_lines, max_bytes, want) in [
            (
                10,
                1_000,
                1000,
                42_000,
                Ok(Cost {
                    lines: 20,
                    bytes: 20_200,
                }),
            ),
            (40, 1_000, 1000, 42_000, Err(Over::Bytes)),
            (400, 25_000, 1000, 42_000, Err(Over::Bytes)),
            (2_500, 0, 5000, 42_000, Err(Over::Bytes)),
        ] {
            let (a, b) = (distinct('a', lines, len), distinct('b', lines, len));
            let mut work = Work::default();
            let got = cost_counted(a.as_bytes(), b.as_bytes(), max_lines, max_bytes, &mut work);
            assert_eq!(got, want, "{lines} lines of {len}");
            assert_eq!(
                work.hashed.get(),
                a.len() + b.len(),
                "{lines} lines of {len}: bytes hashed"
            );
            let limit = max_lines.min(2 * lines);
            assert!(
                work.probes <= steps(limit),
                "{lines} lines of {len}: {} probes over {}",
                work.probes,
                steps(limit)
            );
        }
    }

    /// Common head and tail lines are stripped before hashing: only the
    /// changed middles are hashed. Identical sides hash and probe nothing;
    /// an empty side hashes the other side's bytes and probes nothing.
    #[test]
    fn line_cost_hashes_only_the_middles() {
        let head = format!("{}\n", "h".repeat(25_000));
        let tail = format!("{}\n", "t".repeat(25_000));
        let (left, right) = ("a1\na2\na3\n", "bb1\nbb2\nbb3\n");
        let a = format!("{head}{left}{tail}");
        let b = format!("{head}{right}{tail}");
        let mut work = Work::default();
        assert_eq!(
            cost_counted(a.as_bytes(), b.as_bytes(), 1000, 42_000, &mut work),
            Ok(Cost {
                lines: 6,
                bytes: left.len() + right.len()
            })
        );
        assert_eq!(work.hashed.get(), left.len() + right.len());
        assert!(work.probes <= steps(6), "{} probes", work.probes);

        let mut work = Work::default();
        assert_eq!(
            cost_counted(a.as_bytes(), a.as_bytes(), 1000, 42_000, &mut work),
            Ok(Cost { lines: 0, bytes: 0 })
        );
        assert_eq!(work.hashed.get(), 0);
        assert_eq!(work.probes, 0);

        let added = "p\nqq\nrrr\n";
        for (a, b) in [("", added), (added, "")] {
            let mut work = Work::default();
            assert_eq!(
                cost_counted(a.as_bytes(), b.as_bytes(), 1000, 42_000, &mut work),
                Ok(Cost {
                    lines: 3,
                    bytes: added.len()
                })
            );
            assert_eq!(work.hashed.get(), added.len());
            assert_eq!(work.probes, 0);
        }
    }

    /// Myers is cut off at the line budget, without a clock (#128; the
    /// shape of `line_distance_is_linear_in_size_times_budget` in
    /// `boneli-replay-check`): distinct lines with edits spread evenly, 499
    /// edits in budget (998 lines of 1000), 501 over. The probes stay
    /// within Myers' O((N + M) D) bound, `(limit + 1)(n + m)` matches
    /// along snakes (each diagonal's x only grows) plus one failing probe
    /// per diagonal and step. Measured at 200,000 lines: 697,700 probes
    /// (499 edits) and 700,501 (501 edits) against a bound of 400,901,501;
    /// at 20,000 lines 518,420 and 520,501. An LCS table would need n x m
    /// probes: 4 x 10^8 at 20,000 lines against a bound of 4 x 10^7.
    #[test]
    fn line_search_is_bounded_by_size_times_budget() {
        for size in [2_000usize, 20_000, 200_000] {
            let base: Vec<String> = (0..size).map(|k| format!("line {k}\n")).collect();
            let edited = |edits: usize| -> String {
                let step = size / edits;
                let mut lines = base.clone();
                for k in 0..edits {
                    lines[k * step + step / 2] = format!("edited {k}\n");
                }
                lines.iter().map(String::as_str).collect::<String>()
            };
            let before = base.iter().map(String::as_str).collect::<String>();
            for (edits, lines) in [(499, Some(998)), (501, None)] {
                let after = edited(edits);
                let mut work = Work::default();
                let got = cost_counted(
                    before.as_bytes(),
                    after.as_bytes(),
                    1000,
                    usize::MAX,
                    &mut work,
                );
                assert_eq!(got.ok().map(|c| c.lines), lines, "{edits} edits on {size}");
                if lines.is_none() {
                    assert_eq!(got, Err(Over::Lines), "{edits} edits on {size}");
                }
                let bound = 1001 * (2 * size) + steps(1000);
                assert!(
                    work.probes <= bound,
                    "{edits} edits on {size}: {} probes over {bound}",
                    work.probes
                );
            }
        }
    }

    /// A script that matches two different lines (what a hash collision
    /// would produce) fails the verification, so the cost refuses.
    #[test]
    fn verification_catches_a_false_match() {
        let script = Script {
            distance: 0,
            deleted: Vec::new(),
            inserted: Vec::new(),
        };
        assert_eq!(verified_bytes(b"a\n", b"a\n", &script), Some(0));
        assert_eq!(verified_bytes(b"a\n", b"b\n", &script), None);
        let script = Script {
            distance: 2,
            deleted: vec![0],
            inserted: vec![1],
        };
        assert_eq!(verified_bytes(b"x\nk\n", b"k\nyy\n", &script), Some(5));
        assert_eq!(verified_bytes(b"x\nk\n", b"j\nyy\n", &script), None);
    }
}
