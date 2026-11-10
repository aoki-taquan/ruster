//! What a new configuration would change, shown before it is applied (`ruster diff`,
//! `docs/design/router-box.md`, "反映の流れ").
//!
//! confd reads the file as `ruster apply` would, puts it in use nowhere, and answers
//! with text for a person in four parts:
//!
//! 1. The lock form: a line diff from the latest version to the file's lock form, in
//!    the unified format (`---`, `+++`, `@@` hunks with three lines of context).
//! 2. The FE's tables that confd writes: entries removed (`-`) and added (`+`); a
//!    changed entry is both. They are worked out with the values the sources have
//!    now (a PPPoE session, a delegated prefix), so they change as those do.
//! 3. The routes confd offers ribd (static and connected), likewise. Which routes the
//!    FE ends up with is ribd's choice among all its sources.
//! 4. A section for each process that takes a part ([`crate::part`]): what it says
//!    taking its part would change (`ruster-unbound`, `ruster-kea` and `ruster-frr`
//!    diff the files they write; `ruster-pppoed`, `ruster-dhcpc` and neighd's RA
//!    diff the settings and name what would start, start again or stop), "no
//!    change", the reason it would refuse it, "not connected", or "did not answer in
//!    time" (after 3 s, [`crate::apply::ANSWER_WAIT_MS`]). Processes that are not
//!    connected are named only when the file has their module.
//!
//! Not shown: NAT sessions that would end, and what `--kernel` would change on the
//! kernel side. A process cannot foresee everything either: the software a bridge
//! drives may still refuse the file when it reads it.
//! Firewall rules are numbered by place, so a rule added near the top shows each rule
//! after it as removed and added (the FE gets all those changes too).
//!
//! The line diff is the longest common subsequence of the lines after the lines the
//! two share at the start and the end. When that middle is too large to compare
//! (more than [`MAX_CELLS`] line pairs), it is shown as all removed and all added.
//!
//! # Standards
//!
//! - The unified diff format of POSIX `diff -u` (IEEE Std 1003.1-2017).
//!
//! Deviations: no file times on the `---` and `+++` lines (they name the version and
//! the candidate instead); `\ No newline at end of file` is not written.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ruster_proto::table::{entry_line, Key, Value};

/// Lines of context around each change.
const CONTEXT: usize = 3;

/// The most line pairs compared; past this the middle is shown as replaced.
pub const MAX_CELLS: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Same,
    Removed,
    Added,
}

/// The unified diff from `before` to `after`, whose names go on the `---` and `+++`
/// lines; empty when the lines are the same.
pub fn lines(before: &str, after: &str, names: (&str, &str)) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let ops = ops(&a, &b);
    let mut at = Vec::with_capacity(ops.len());
    let (mut i, mut j) = (0, 0);
    for op in &ops {
        at.push((i, j));
        match op {
            Op::Same => (i, j) = (i + 1, j + 1),
            Op::Removed => i += 1,
            Op::Added => j += 1,
        }
    }
    let changed: Vec<usize> = (0..ops.len()).filter(|&k| ops[k] != Op::Same).collect();
    if changed.is_empty() {
        return String::new();
    }
    let mut out = format!("--- {}\n+++ {}\n", names.0, names.1);
    let mut k = 0;
    while k < changed.len() {
        let start = changed[k].saturating_sub(CONTEXT);
        let mut end = changed[k];
        // Changes with at most twice the context between them share a hunk.
        while k + 1 < changed.len() && changed[k + 1] - end <= 2 * CONTEXT + 1 {
            k += 1;
            end = changed[k];
        }
        k += 1;
        let stop = (end + CONTEXT + 1).min(ops.len());
        let span = &ops[start..stop];
        let a_len = span.iter().filter(|op| **op != Op::Added).count();
        let b_len = span.iter().filter(|op| **op != Op::Removed).count();
        let (a0, b0) = at[start];
        let _ = writeln!(out, "@@ -{} +{} @@", range(a0, a_len), range(b0, b_len));
        for (op, (i, j)) in span.iter().zip(&at[start..stop]) {
            let _ = match op {
                Op::Same => writeln!(out, " {}", a[*i]),
                Op::Removed => writeln!(out, "-{}", a[*i]),
                Op::Added => writeln!(out, "+{}", b[*j]),
            };
        }
    }
    out
}

/// A hunk's range of lines from index `at`: `first,count`, only `first` for one line,
/// and for none the line before it.
fn range(at: usize, len: usize) -> String {
    match len {
        0 => format!("{at},0"),
        1 => format!("{}", at + 1),
        _ => format!("{},{len}", at + 1),
    }
}

/// The edit from `a` to `b`, one step per line.
fn ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let head = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (a_mid, b_mid) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let mut ops = vec![Op::Same; head];
    let (n, m) = (a_mid.len(), b_mid.len());
    if (n + 1).saturating_mul(m + 1) > MAX_CELLS {
        ops.extend(std::iter::repeat_n(Op::Removed, n));
        ops.extend(std::iter::repeat_n(Op::Added, m));
    } else {
        // longest[i][j]: the longest common subsequence of a_mid[i..] and b_mid[j..].
        let width = m + 1;
        let mut longest = vec![0u32; (n + 1) * width];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                longest[i * width + j] = if a_mid[i] == b_mid[j] {
                    longest[(i + 1) * width + j + 1] + 1
                } else {
                    longest[(i + 1) * width + j].max(longest[i * width + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n || j < m {
            if i < n && j < m && a_mid[i] == b_mid[j] {
                ops.push(Op::Same);
                (i, j) = (i + 1, j + 1);
            } else if j == m
                || (i < n && longest[(i + 1) * width + j] >= longest[i * width + j + 1])
            {
                ops.push(Op::Removed);
                i += 1;
            } else {
                ops.push(Op::Added);
                j += 1;
            }
        }
    }
    ops.extend(std::iter::repeat_n(Op::Same, tail));
    ops
}

/// The entries removed (`- `) and added (`+ `) from `before` to `after`, one per
/// line, in key order; empty when they are the same.
pub fn tables(before: &BTreeMap<Key, Value>, after: &BTreeMap<Key, Value>) -> String {
    let mut out = String::new();
    let mut keys: Vec<&Key> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    for key in keys {
        let (old, new) = (before.get(key), after.get(key));
        if old == new {
            continue;
        }
        if let Some(value) = old {
            let _ = writeln!(out, "- {}", entry(key, value));
        }
        if let Some(value) = new {
            let _ = writeln!(out, "+ {}", entry(key, value));
        }
    }
    out
}

/// An entry as `ruster show` prints it, or as confd holds it for the tables that
/// `ruster show` does not print (firewall, NAT, punt classes).
fn entry(key: &Key, value: &Value) -> String {
    entry_line(key, value).unwrap_or_else(|| format!("{key:?} = {value:?}"))
}
