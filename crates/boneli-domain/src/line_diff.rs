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
//! Memory stays independent of the file size: nothing is collected per
//! line. Common leading and trailing lines are stripped by walking both
//! sides, the length differences cut the search off before it starts, each
//! diagonal keeps a byte cursor into both sides instead of a line index,
//! and the trace holds one entry per diagonal and step, at most
//! (D + 1)(D + 2) / 2 for a distance of D.

use alloc::vec;
use alloc::vec::Vec;

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
    /// The line budget.
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

fn line(s: &[u8], from: usize) -> &[u8] {
    s.get(from..line_end(s, from)).unwrap_or(&[])
}

/// Above this many lines of budget, the edit script is not recovered and
/// the bytes are bounded by both middles (D3): the trace would hold more
/// than about 8.4 million entries.
const MAX_TRACED: usize = 4096;

/// The cost of turning `a` into `b`, or the budget it crosses first.
pub fn cost(a: &[u8], b: &[u8], max_lines: usize, max_bytes: usize) -> Result<Cost, Over> {
    cost_counted(a, b, max_lines, max_bytes, &mut 0)
}

/// [`cost`], adding to `cells` every per-step cell it allocates, so a test
/// can pin that memory does not grow with the file.
pub(crate) fn cost_counted(
    a: &[u8],
    b: &[u8],
    max_lines: usize,
    max_bytes: usize,
    cells: &mut usize,
) -> Result<Cost, Over> {
    if line_count(a).abs_diff(line_count(b)) > max_lines {
        return Err(Over::Lines);
    }
    // Strip common leading lines, then common trailing lines of the rest.
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
    let (n, m) = (line_count(a), line_count(b));
    // Matched lines are equal on both sides, so the byte difference of the
    // middles is a lower bound of the changed bytes.
    if a.len().abs_diff(b.len()) > max_bytes {
        return Err(Over::Bytes);
    }
    let limit = max_lines.min(n.saturating_add(m));
    let lines = myers(a, b, n, m, limit, cells).ok_or(Over::Lines)?;
    let bytes = if lines.traced {
        changed_bytes(a, &lines.deleted).saturating_add(changed_bytes(b, &lines.inserted))
    } else {
        a.len().saturating_add(b.len())
    };
    if bytes > max_bytes {
        return Err(Over::Bytes);
    }
    Ok(Cost {
        lines: lines.distance,
        bytes,
    })
}

/// The bytes of the lines of `s` at the sorted `indices`.
fn changed_bytes(s: &[u8], indices: &[usize]) -> usize {
    let mut total = 0usize;
    let mut wanted = indices.iter().peekable();
    let (mut at, mut index) = (0, 0usize);
    while at < s.len() && wanted.peek().is_some() {
        let end = line_end(s, at);
        if wanted.peek() == Some(&&index) {
            total = total.saturating_add(end - at);
            wanted.next();
        }
        (at, index) = (end, index + 1);
    }
    total
}

/// The result of the search.
struct Script {
    distance: usize,
    /// Whether `deleted` and `inserted` were recovered.
    traced: bool,
    /// Indices of deleted lines of `a`, ascending.
    deleted: Vec<usize>,
    /// Indices of inserted lines of `b`, ascending.
    inserted: Vec<usize>,
}

/// The furthest point of a diagonal: its x and the byte offsets of line x
/// of `a` and line y of `b`.
#[derive(Clone, Copy)]
struct Point {
    x: usize,
    a: usize,
    b: usize,
}

/// The start of diagonal `k` at step `d` from the points of step `d - 1`:
/// down from `k + 1` (an insertion) or right from `k - 1` (a deletion),
/// whichever reaches further inside the grid; down on a tie. `true` means
/// down.
fn step(
    down: Option<Point>,
    right: Option<Point>,
    k: isize,
    n: usize,
    m: usize,
    a: &[u8],
    b: &[u8],
) -> Option<(Point, bool)> {
    let down = down.filter(|p| fits_down(p.x, k, m));
    let right = right.filter(|p| p.x < n);
    let below = |p: Point| Point {
        x: p.x,
        a: p.a,
        b: line_end(b, p.b),
    };
    match (down, right) {
        (Some(p), Some(q)) if p.x > q.x => Some((below(p), true)),
        (Some(p), None) => Some((below(p), true)),
        (_, Some(q)) => Some((
            Point {
                x: q.x + 1,
                a: line_end(a, q.a),
                b: q.b,
            },
            false,
        )),
        (None, None) => None,
    }
}

/// Whether a move down onto diagonal `k` from x on diagonal `k + 1` stays
/// inside the grid: the new y, `x - k`, is at most `m`.
fn fits_down(x: usize, k: isize, m: usize) -> bool {
    match (isize::try_from(x), isize::try_from(m)) {
        (Ok(x), Ok(m)) => x - k <= m,
        _ => false,
    }
}

fn myers(
    a: &[u8],
    b: &[u8],
    n: usize,
    m: usize,
    limit: usize,
    cells: &mut usize,
) -> Option<Script> {
    let traced = limit <= MAX_TRACED;
    let width = limit.checked_mul(2)?.checked_add(3)?;
    let offset = isize::try_from(limit.checked_add(1)?).ok()?;
    let at = |k: isize| usize::try_from(k.checked_add(offset)?).ok();
    let mut v: Vec<Option<Point>> = vec![None; width];
    *cells = cells.saturating_add(width);
    // trace[d] holds the x of every diagonal of step d, from k = -d up.
    let mut trace: Vec<Vec<Option<usize>>> = Vec::new();
    for d in 0..=limit {
        let d_i = isize::try_from(d).ok()?;
        let mut row = Vec::new();
        let mut k = -d_i;
        while k <= d_i {
            let start = if d == 0 {
                Some(Point { x: 0, a: 0, b: 0 })
            } else {
                let down = v.get(at(k + 1)?).copied().flatten();
                let right = v.get(at(k - 1)?).copied().flatten();
                step(down, right, k, n, m, a, b).map(|(p, _)| p)
            };
            let mut found = None;
            if let Some(mut p) = start {
                let mut y = usize::try_from(isize::try_from(p.x).ok()?.checked_sub(k)?).ok()?;
                while p.x < n && y < m && line(a, p.a) == line(b, p.b) {
                    p = Point {
                        x: p.x + 1,
                        a: line_end(a, p.a),
                        b: line_end(b, p.b),
                    };
                    y += 1;
                }
                found = Some(p);
                if p.x == n && y == m {
                    if traced {
                        row.push(Some(p.x));
                        trace.push(row);
                    }
                    return Some(backtrack(&trace, d, k, traced, n, m));
                }
            }
            if traced {
                row.push(found.map(|p| p.x));
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
        traced,
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
        // The same choice as the forward pass (`step`): down unless right
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
            let x = right.unwrap_or(0);
            script.deleted.push(x);
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

    /// Memory does not grow with the file: a one-line edit at each end of
    /// a 2-million-line file allocates a few cells, and a 10 MB addition is
    /// cut off by the line count before any search.
    #[test]
    fn memory_is_independent_of_the_file_size() {
        let base: Vec<u8> = (0..2_000_000u32)
            .flat_map(|k| format!("{k}\n").into_bytes())
            .collect();
        let mut edited = b"first\n".to_vec();
        edited.extend_from_slice(&base);
        edited.extend_from_slice(b"last\n");
        let mut cells = 0;
        assert_eq!(
            cost_counted(&base, &edited, 1000, 100_000, &mut cells),
            Ok(Cost {
                lines: 2,
                bytes: 11
            })
        );
        // The cursor row is sized by the budget (2 * 1000 + 3), the trace by
        // the distance: neither by the file.
        assert!(cells < 2_010, "{cells} cells");
        let mut cells = 0;
        let added = vec![b'\n'; 10_000_000];
        assert_eq!(
            cost_counted(b"", &added, 1000, usize::MAX, &mut cells),
            Err(Over::Lines)
        );
        assert_eq!(cells, 0);
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
        let mut cells = 0;
        let got = cost_counted(&base, &spread, 1000, usize::MAX, &mut cells).expect("in budget");
        assert_eq!(got.lines, 40);
        assert!(cells < 2_003 + 41 * 42, "{cells} cells");
    }
}
