#!/bin/sh
set -eu

ledger=${1:-docs/requirements-v0.2.md}
rows=$(mktemp)
tests=$(mktemp)
trap 'rm -f "$rows" "$tests"' EXIT

awk -F '|' '
function trim(value) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return value
}
/^\| Requirement ID / {
    table = 1
    next
}
table && /^\|---/ {
    next
}
table && /^\|/ {
    if (NF != 7) {
        printf "%s:%d: requirement row must have five columns\n", FILENAME, NR > "/dev/stderr"
        failed = 1
        next
    }
    id = trim($2)
    test = trim($4)
    status = trim($5)
    note = trim($6)
    if (id !~ /^[A-Z][A-Z0-9-]*[[:space:]]+[^[:space:]]/) {
        printf "%s:%d: malformed requirement ID/title\n", FILENAME, NR > "/dev/stderr"
        failed = 1
    }
    split(id, id_parts, /[[:space:]]+/)
    requirement_id = id_parts[1]
    if (status != "implemented" && status != "deferred" && status != "deviation") {
        printf "%s:%d: invalid status %s\n", FILENAME, NR, status > "/dev/stderr"
        failed = 1
    }
    if (status == "deviation" && (note == "" || note == "なし")) {
        printf "%s:%d: deviation %s requires a note\n", FILENAME, NR, id > "/dev/stderr"
        failed = 1
    }
    if (seen[requirement_id]++) {
        printf "%s:%d: duplicate requirement ID %s\n", FILENAME, NR, requirement_id > "/dev/stderr"
        failed = 1
    }
    if (test == "—") {
        if (status != "deferred") {
            printf "%s:%d: only deferred requirements may use — for Test ID\n", FILENAME, NR > "/dev/stderr"
            failed = 1
        }
        if (note == "" || note == "なし") {
            printf "%s:%d: deferred requirement %s with — requires a note\n", FILENAME, NR, id > "/dev/stderr"
            failed = 1
        }
        next
    }
    if (test !~ /^`[a-zA-Z0-9_]+`$/) {
        printf "%s:%d: Test ID must be one backticked Rust test name or deferred —\n", FILENAME, NR > "/dev/stderr"
        failed = 1
        next
    }
    gsub(/`/, "", test)
    print requirement_id "\t" test
    next
}
table {
    table = 0
}
END {
    if (failed) exit 1
}' "$ledger" > "$rows"

test -s "$rows" || {
    echo "$ledger: no requirement rows found" >&2
    exit 1
}

cargo test --workspace --all-targets --all-features --locked -- --list > "$tests"
while IFS="$(printf '\t')" read -r id test_id; do
    if ! grep -Eq "(^|::)${test_id}: test$" "$tests"; then
        echo "$ledger: $id references missing test $test_id" >&2
        exit 1
    fi
done < "$rows"
