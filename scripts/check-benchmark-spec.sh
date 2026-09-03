#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
spec=${1:-"$repo_root/docs/benchmark-spec-v0.2.md"}
identity=${2:-"$repo_root/crates/bench/src/spec.rs"}

command -v iconv >/dev/null 2>&1 || {
    echo "iconv is required to validate canonical UTF-8 bytes" >&2
    exit 1
}

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/ruster-benchmark-spec.XXXXXX")
cleanup() {
    rm -rf "$temporary_dir"
}
trap cleanup 0
trap 'cleanup; exit 1' 1 2 3 15
spec_snapshot="$temporary_dir/spec.md"
identity_snapshot="$temporary_dir/spec.rs"

# A small R17 Rust helper performs one bounded, no-follow, nonblocking read of
# each input and writes a create-new private snapshot. Shell-only `test -f`
# followed by `cp` would leave a FIFO/symlink replacement race here. The
# helper is bootstrapped through the existing package; it does not invoke this
# script while compiling.
run_benchmark_helper() {
    (CDPATH= cd -- "$repo_root" && cargo run --quiet --locked -p ruster-bench -- "$@") 2>/dev/null
}

if ! run_benchmark_helper --snapshot-benchmark-file "$spec" "$spec_snapshot"; then
    echo "benchmark specification input could not be snapshotted" >&2
    exit 1
fi
if ! run_benchmark_helper --snapshot-benchmark-file "$identity" "$identity_snapshot"; then
    echo "identity source input could not be snapshotted" >&2
    exit 1
fi

if ! iconv -f UTF-8 -t UTF-8 "$spec_snapshot" >/dev/null 2>&1; then
    echo "benchmark specification input is not valid UTF-8" >&2
    exit 1
fi

prefix=$(od -An -t x1 -N 3 "$spec_snapshot" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
if [ "$prefix" = "efbbbf" ]; then
    echo "benchmark specification input contains a UTF-8 BOM" >&2
    exit 1
fi

carriage_return=$(printf '\015')
if LC_ALL=C grep -n "$carriage_return" "$spec_snapshot" >/dev/null 2>&1; then
    echo "benchmark specification input must use LF-only line endings" >&2
    exit 1
fi

if LC_ALL=C awk '/[[:blank:]]$/ { found = 1; exit } END { exit(found ? 0 : 1) }' "$spec_snapshot"; then
    echo "benchmark specification input contains trailing whitespace" >&2
    exit 1
fi

if [ ! -s "$spec_snapshot" ]; then
    echo "benchmark specification input must be non-empty" >&2
    exit 1
fi
last_byte=$(tail -c 1 "$spec_snapshot" | od -An -t x1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
if [ "$last_byte" != "0a" ]; then
    echo "benchmark specification input must end with one final LF" >&2
    exit 1
fi

last_two_bytes=$(tail -c 2 "$spec_snapshot" | od -An -t x1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
if [ "$last_two_bytes" = "0a0a" ]; then
    echo "benchmark specification input must have exactly one final LF" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$spec_snapshot" | awk 'NR == 1 { print $1; exit }')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$spec_snapshot" | awk 'NR == 1 { print $1; exit }')
elif command -v openssl >/dev/null 2>&1; then
    actual=$(openssl dgst -sha256 "$spec_snapshot" | awk 'NR == 1 { print $NF; exit }')
else
    echo "sha256sum, shasum -a 256, or openssl dgst -sha256 is required" >&2
    exit 1
fi

if ! printf '%s\n' "$actual" | awk 'length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid = 1 } END { exit !valid }'; then
    echo "benchmark specification digest calculation returned an invalid value" >&2
    exit 1
fi
if LC_ALL=C grep -F "$actual" "$spec_snapshot" >/dev/null 2>&1; then
    echo "benchmark specification input must not contain its own digest" >&2
    exit 1
fi

if ! identity_values=$(run_benchmark_helper --parse-benchmark-identity "$identity_snapshot"); then
    echo "identity source parser rejected the input" >&2
    exit 1
fi
compiled_values=$(printf '%s\n' "$identity_values" | awk -F= '$1 == "benchmark_compiled_sha256" { print $2 }')
typed_values=$(printf '%s\n' "$identity_values" | awk -F= '$1 == "benchmark_typed_sha256" { print $2 }')
compiled_count=$(printf '%s\n' "$identity_values" | awk -F= '$1 == "benchmark_compiled_sha256" { count += 1 } END { print count + 0 }')
if [ "$compiled_count" -ne 1 ]; then
    echo "identity source must contain exactly one compiled R17 SHA-256 string" >&2
    exit 1
fi
compiled=$(printf '%s\n' "$compiled_values" | awk 'NF { print; exit }')
if ! printf '%s\n' "$compiled" | awk 'length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid = 1 } END { exit !valid }'; then
    echo "compiled R17 SHA-256 must be lowercase 64-hex" >&2
    exit 1
fi

typed_count=$(printf '%s\n' "$identity_values" | awk -F= '$1 == "benchmark_typed_sha256" { count += 1 } END { print count + 0 }')
if [ "$typed_count" -ne 1 ]; then
    echo "identity source must contain one complete typed 32-byte R17 SHA-256 array" >&2
    exit 1
fi
typed_hex=$(printf '%s\n' "$typed_values" | awk 'NF { print; exit }')
if ! printf '%s\n' "$typed_hex" | awk 'length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid = 1 } END { exit !valid }'; then
    echo "typed R17 SHA-256 bytes must be lowercase 0x-prefixed bytes" >&2
    exit 1
fi
if [ "$actual" != "$compiled" ]; then
    echo "compiled identity drift" >&2
    exit 1
fi
if [ "$typed_hex" != "$compiled" ]; then
    echo "typed and hexadecimal benchmark identities disagree" >&2
    exit 1
fi

echo "benchmark_spec_sha256=$actual"
