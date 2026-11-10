//! The text of `ruster diff`: line diffs in the unified format, and table changes.

use std::collections::BTreeMap;

use ruster_confd::diff::{lines, tables, MAX_CELLS};
use ruster_proto::table::{Key, Value};

const NAMES: (&str, &str) = ("version 1", "new");

#[test]
fn the_same_text_has_no_diff() {
    assert_eq!(lines("a\nb\n", "a\nb\n", NAMES), "");
    assert_eq!(lines("", "", NAMES), "");
}

#[test]
fn a_changed_line_is_shown_with_its_context_as_diff_u_does() {
    let before = "1\n2\n3\n4\n5\n6\n7\n8\n";
    let after = "1\n2\n3\n4\nfive\n6\n7\n8\n";
    assert_eq!(
        lines(before, after, NAMES),
        "--- version 1\n+++ new\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
    );
}

#[test]
fn ranges_of_one_line_and_of_none_are_written_as_posix_says() {
    assert_eq!(
        lines("", "x\n", NAMES),
        "--- version 1\n+++ new\n@@ -0,0 +1 @@\n+x\n"
    );
    assert_eq!(
        lines("x\n", "", NAMES),
        "--- version 1\n+++ new\n@@ -1 +0,0 @@\n-x\n"
    );
}

#[test]
fn changes_far_apart_get_hunks_of_their_own() {
    let before: String = (1..=20).map(|n| format!("l{n}\n")).collect();
    let after = before
        .replace("l2\n", "two\n")
        .replace("l19\n", "nineteen\n");
    let diff = lines(&before, &after, NAMES);
    let hunks: Vec<&str> = diff.lines().filter(|l| l.starts_with("@@")).collect();
    assert_eq!(hunks, ["@@ -1,5 +1,5 @@", "@@ -16,5 +16,5 @@"], "{diff}");
    // Close changes share one.
    let after = before
        .replace("l5\n", "five\n")
        .replace("l11\n", "eleven\n");
    let diff = lines(&before, &after, NAMES);
    let hunks: Vec<&str> = diff.lines().filter(|l| l.starts_with("@@")).collect();
    assert_eq!(hunks, ["@@ -2,13 +2,13 @@"], "{diff}");
}

#[test]
fn added_and_removed_lines_keep_the_lines_between() {
    let diff = lines("a\nb\nc\nd\n", "a\nx\nc\nd\ne\n", NAMES);
    assert_eq!(
        diff,
        "--- version 1\n+++ new\n@@ -1,4 +1,5 @@\n a\n-b\n+x\n c\n d\n+e\n"
    );
}

#[test]
fn a_middle_too_large_to_compare_is_shown_as_replaced() {
    let n = 1_100;
    assert!(n * n > MAX_CELLS);
    let before: String = (0..n).map(|i| format!("a{i}\n")).collect();
    let after: String = (0..n).map(|i| format!("b{i}\n")).collect();
    let diff = lines(
        &format!("head\n{before}tail\n"),
        &format!("head\n{after}tail\n"),
        NAMES,
    );
    assert_eq!(diff.lines().filter(|l| l.starts_with('-')).count(), n + 1);
    assert_eq!(diff.lines().filter(|l| l.starts_with('+')).count(), n + 1);
    assert!(diff.contains(&format!("@@ -1,{} +1,{} @@", n + 2, n + 2)));
}

#[test]
fn table_changes_are_removed_and_added_entries() {
    let entry = |prefix_len| {
        (
            Key::Address {
                interface: "lan".into(),
                address: "192.0.2.1".parse().unwrap(),
            },
            Value::Address { prefix_len },
        )
    };
    let gone = (
        Key::Address {
            interface: "wan".into(),
            address: "198.51.100.2".parse().unwrap(),
        },
        Value::Address { prefix_len: 24 },
    );
    let before = BTreeMap::from([entry(24), gone]);
    let after = BTreeMap::from([entry(25)]);
    assert_eq!(
        tables(&before, &after),
        "- address lan 192.0.2.1/24\n+ address lan 192.0.2.1/25\n- address wan 198.51.100.2/24\n"
    );
    assert_eq!(tables(&after, &after), "");
}
