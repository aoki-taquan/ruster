#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixtures="$script_dir/fixtures/requirements"
output=$(mktemp)
trap 'rm -f "$output"' EXIT

assert_rejected() {
    fixture=$1
    expected=$2

    if "$script_dir/check-requirements.sh" "$fixtures/$fixture" > "$output" 2>&1; then
        echo "$fixture: negative fixture unexpectedly passed" >&2
        exit 1
    fi
    if ! grep -F "$expected" "$output" >/dev/null; then
        echo "$fixture: expected diagnostic not found: $expected" >&2
        sed 's/^/  /' "$output" >&2
        exit 1
    fi
}

cd "$repo_root"
assert_rejected invalid-status.md "invalid status invalid"
assert_rejected duplicate-id.md "duplicate requirement ID FIX-001"
assert_rejected implemented-without-test.md "only deferred requirements may use"
assert_rejected deviation-without-note.md "requires a note"
assert_rejected malformed-test-id.md "Test ID must be one backticked Rust test name"
assert_rejected missing-test.md \
    "references missing test requirements_gate_fixture_intentionally_missing_test"
