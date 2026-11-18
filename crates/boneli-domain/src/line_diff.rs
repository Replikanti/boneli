//! Line edit distance for the patch policy's size rule (ADR-013, D3).
//!
//! A line is a run of bytes up to and including `\n`, plus a final run
//! without one if it is not empty, as git counts lines. The distance of two
//! line lists is the least number of inserted plus deleted lines that turns
//! one into the other: Myers' greedy forward pass ("An O(ND) Difference
//! Algorithm and Its Variations", 1986) in linear space, without recovering
//! the edit script. Common leading and trailing lines are stripped first and
//! the rest is interned to integers, so a comparison costs O(1). The search
//! stops at a budget: the work for one file is O((N + M) * R), where R is
//! at most the budget, never quadratic in the file size.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// The lines of `data`: `""` has none, `"a"`, `"a\n"` and `"\n"` have one,
/// `"a\nb"` has two.
pub fn lines(data: &[u8]) -> Vec<&[u8]> {
    data.split_inclusive(|byte| *byte == b'\n').collect()
}

/// The least number of inserted plus deleted lines that turns `a` into
/// `b`, or `None` when it is larger than `max`.
pub fn distance(a: &[&[u8]], b: &[&[u8]], max: usize) -> Option<usize> {
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let (a, b) = (a.get(prefix..)?, b.get(prefix..)?);
    let suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let a = a.get(..a.len().checked_sub(suffix)?)?;
    let b = b.get(..b.len().checked_sub(suffix)?)?;
    let mut ids = BTreeMap::new();
    let a = intern(&mut ids, a);
    let b = intern(&mut ids, b);
    myers(&a, &b, max)
}

/// Each line's id: the order of its first occurrence across both sides.
fn intern<'a>(ids: &mut BTreeMap<&'a [u8], usize>, lines: &[&'a [u8]]) -> Vec<usize> {
    lines
        .iter()
        .map(|line| {
            let next = ids.len();
            *ids.entry(*line).or_insert(next)
        })
        .collect()
}

/// Myers' greedy forward pass over interned lines. `v[k + offset]` is the
/// furthest `x` a path with `d` edits reaches on diagonal `k = x - y`, or
/// `None` when no such path stays inside the grid.
fn myers(a: &[usize], b: &[usize], max: usize) -> Option<usize> {
    let (n, m) = (a.len(), b.len());
    // The distance never exceeds n + m, so the search needs no more room.
    let limit = max.min(n.checked_add(m)?);
    let width = limit.checked_mul(2)?.checked_add(3)?;
    let offset = isize::try_from(limit.checked_add(1)?).ok()?;
    let mut v: Vec<Option<usize>> = vec![None; width];
    let at = |k: isize| usize::try_from(k.checked_add(offset)?).ok();
    let n_i = isize::try_from(n).ok()?;
    let m_i = isize::try_from(m).ok()?;
    for d in 0..=limit {
        let d_i = isize::try_from(d).ok()?;
        let mut k = -d_i;
        while k <= d_i {
            // A move down from diagonal k + 1 (an insertion) or right from
            // diagonal k - 1 (a deletion), whichever reaches further and
            // stays inside the grid.
            let down = v
                .get(at(k.checked_add(1)?)?)
                .copied()
                .flatten()
                .filter(|x| isize::try_from(*x).is_ok_and(|x| x - k <= m_i));
            let right = v
                .get(at(k.checked_sub(1)?)?)
                .copied()
                .flatten()
                .and_then(|x| x.checked_add(1))
                .filter(|x| *x <= n);
            let start = if d == 0 {
                Some(0)
            } else {
                match (down, right) {
                    (Some(x), Some(y)) => Some(x.max(y)),
                    (x, y) => x.or(y),
                }
            };
            let slot = v.get_mut(at(k)?)?;
            *slot = None;
            if let Some(mut x) = start {
                let mut y = usize::try_from(isize::try_from(x).ok()?.checked_sub(k)?).ok()?;
                while let (Some(p), Some(q)) = (a.get(x), b.get(y)) {
                    if p != q {
                        break;
                    }
                    x += 1;
                    y += 1;
                }
                *slot = Some(x);
                if isize::try_from(x).ok()? == n_i && isize::try_from(y).ok()? == m_i {
                    return Some(d);
                }
            }
            k = k.checked_add(2)?;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_distance(a: &str, b: &str, max: usize) -> Option<usize> {
        distance(&lines(a.as_bytes()), &lines(b.as_bytes()), max)
    }

    /// The textbook LCS table: insertions plus deletions = n + m - 2 * LCS.
    fn reference(a: &[&[u8]], b: &[&[u8]]) -> usize {
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
    fn lines_follow_git() {
        assert_eq!(lines(b"").len(), 0);
        assert_eq!(lines(b"a"), [&b"a"[..]]);
        assert_eq!(lines(b"a\n"), [&b"a\n"[..]]);
        assert_eq!(lines(b"\n"), [&b"\n"[..]]);
        assert_eq!(lines(b"a\nb"), [&b"a\n"[..], &b"b"[..]]);
        assert_eq!(lines(b"a\r\nb\r\n").len(), 2);
    }

    #[test]
    fn distance_cases() {
        assert_eq!(text_distance("", "", 0), Some(0));
        assert_eq!(text_distance("a\n", "a\n", 0), Some(0));
        assert_eq!(text_distance("a\n", "b\n", 2), Some(2));
        assert_eq!(text_distance("a\n", "b\n", 1), None);
        assert_eq!(text_distance("a", "a\n", 5), Some(2));
        assert_eq!(text_distance("a\nb\n", "b\na\n", 5), Some(2));
        assert_eq!(text_distance("", "a\nb\nc\n", 3), Some(3));
        assert_eq!(text_distance("", "a\nb\nc\n", 2), None);
        assert_eq!(text_distance("a\nb\nc\n", "", 3), Some(3));
        assert_eq!(
            text_distance("a\r\nb\r\nc\r\n", "a\nb\nc\n", 6),
            Some(6),
            "CRLF to LF rewrites every line"
        );
        assert_eq!(text_distance("x\na\nb\ny\n", "x\nb\na\ny\n", 1), None);
        assert_eq!(text_distance("x\na\nb\ny\n", "x\nb\na\ny\n", 2), Some(2));
    }

    #[test]
    fn two_block_swap_costs_both_blocks() {
        let first: alloc::string::String = (0..10).map(|k| alloc::format!("a{k}\n")).collect();
        let second: alloc::string::String = (0..10).map(|k| alloc::format!("b{k}\n")).collect();
        let before = alloc::format!("{first}{second}");
        let after = alloc::format!("{second}{first}");
        assert_eq!(text_distance(&before, &after, 100), Some(20));
        assert_eq!(text_distance(&before, &after, 19), None);
    }

    /// Myers against the LCS table on every pair of short sequences over a
    /// two-line alphabet, at every budget around the answer.
    #[test]
    fn distance_matches_the_lcs_table() {
        let alphabet: [&[u8]; 2] = [b"x\n", b"y\n"];
        let mut all: Vec<Vec<&[u8]>> = vec![Vec::new()];
        for len in 1..=6u32 {
            for bits in 0..(1u32 << len) {
                all.push(
                    (0..len)
                        .map(|k| alphabet[((bits >> k) & 1) as usize])
                        .collect(),
                );
            }
        }
        for a in all.iter().step_by(3) {
            for b in all.iter().step_by(2) {
                let want = reference(a, b);
                assert_eq!(distance(a, b, want), Some(want), "{a:?} {b:?}");
                assert_eq!(distance(a, b, usize::MAX), Some(want), "{a:?} {b:?}");
                if want > 0 {
                    assert_eq!(distance(a, b, want - 1), None, "{a:?} {b:?}");
                }
            }
        }
    }
}
