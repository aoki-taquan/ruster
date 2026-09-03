#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
temporary_dir=$(mktemp -d)
output="$temporary_dir/output"
trap 'rm -rf "$temporary_dir"' 0

spec="$repo_root/docs/benchmark-spec-v0.2.md"
identity="$repo_root/crates/bench/src/spec.rs"

valid_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$identity")
actual=$(printf '%s\n' "$valid_output" | sed -n 's/^benchmark_spec_sha256=//p')
if ! printf '%s\n' "$actual" | awk 'length($0) == 64 && $0 !~ /[^0-9a-f]/ { valid = 1 } END { exit !valid }'; then
    echo "valid canonical benchmark specification did not print a machine-readable SHA-256" >&2
    exit 1
fi

assert_rejected() {
    candidate_spec=$1
    candidate_identity=$2
    expected=$3
    if "$script_dir/check-benchmark-spec.sh" "$candidate_spec" "$candidate_identity" >"$output" 2>&1; then
        echo "negative benchmark-spec fixture unexpectedly passed" >&2
        exit 1
    fi
    if ! grep -F "$expected" "$output" >/dev/null; then
        echo "expected benchmark-spec diagnostic not found: $expected" >&2
        sed 's/^/  /' "$output" >&2
        exit 1
    fi
    candidate_spec_base=$(basename "$candidate_spec")
    candidate_identity_base=$(basename "$candidate_identity")
    for forbidden in \
        "$candidate_spec" \
        "$candidate_identity" \
        "$candidate_spec_base" \
        "$candidate_identity_base" \
        "$temporary_dir" \
        "$actual"; do
        if [ -n "$forbidden" ] && grep -F "$forbidden" "$output" >/dev/null 2>&1; then
            echo "benchmark-spec diagnostic leaked sensitive input: $forbidden" >&2
            sed 's/^/  /' "$output" >&2
            exit 1
        fi
    done
    if grep -E 'INVALID_[A-Z0-9_]+|VALID_[A-Z0-9_]+|CASE_[A-Z0-9_]+' "$output" >/dev/null 2>&1; then
        echo "benchmark-spec diagnostic leaked a source identity" >&2
        sed 's/^/  /' "$output" >&2
        exit 1
    fi
}

rustc_bin=${R17_RUSTC:-rustc}
if ! command -v "$rustc_bin" >/dev/null 2>&1; then
    echo "Rust 1.97.1 compiler is required for the R17 differential" >&2
    exit 1
fi
rustc_version=$($rustc_bin --version)
case "$rustc_version" in
    "rustc 1.97.1 "*) ;;
    *)
        echo "R17 differential requires Rust 1.97.1" >&2
        exit 1
        ;;
esac

run_r17_cli() {
    (CDPATH= cd -- "$repo_root" && cargo run --quiet --locked -p ruster-bench -- "$@")
}

assert_r17_output_redacted() {
    output_file=$1
    candidate_spec=$2
    candidate_identity=$3
    candidate_spec_base=$(basename "$candidate_spec")
    candidate_identity_base=$(basename "$candidate_identity")
    for forbidden in \
        "$candidate_spec" \
        "$candidate_identity" \
        "$candidate_spec_base" \
        "$candidate_identity_base" \
        "$temporary_dir" \
        "$actual"; do
        if [ -n "$forbidden" ] && grep -F "$forbidden" "$output_file" >/dev/null 2>&1; then
            echo "R17 output leaked sensitive input: $forbidden" >&2
            sed 's/^/  /' "$output_file" >&2
            exit 1
        fi
    done
    if grep -E 'INVALID_[A-Z0-9_]+|VALID_[A-Z0-9_]+|CASE_[A-Z0-9_]+' "$output_file" >/dev/null 2>&1; then
        echo "R17 output leaked a source identity" >&2
        sed 's/^/  /' "$output_file" >&2
        exit 1
    fi
}

assert_r17_prepared_case() {
    case_name=$1
    expected=$2
    candidate_identity=$3
    standalone=$4

    if "$rustc_bin" --edition=2021 --crate-type=lib --emit=metadata \
        -o "$temporary_dir/r17-six-$case_name.rmeta" "$standalone" \
        >"$temporary_dir/r17-six-$case_name.rustc.out" \
        2>"$temporary_dir/r17-six-$case_name.rustc.err"; then
        rustc_rc=0
    else
        rustc_rc=$?
    fi
    if [ "$expected" = valid ] && [ "$rustc_rc" -ne 0 ]; then
        echo "Rust 1.97.1 rejected valid R17 fixture: $case_name" >&2
        sed 's/^/  /' "$temporary_dir/r17-six-$case_name.rustc.err" >&2
        exit 1
    fi
    if [ "$expected" = invalid ] && [ "$rustc_rc" -eq 0 ]; then
        echo "Rust 1.97.1 accepted invalid R17 fixture: $case_name" >&2
        exit 1
    fi

    cli_out="$temporary_dir/r17-six-$case_name.cli.out"
    cli_err="$temporary_dir/r17-six-$case_name.cli.err"
    if run_r17_cli --parse-benchmark-identity "$candidate_identity" >"$cli_out" 2>"$cli_err"; then
        cli_rc=0
    else
        cli_rc=$?
    fi
    if [ "$expected" = valid ]; then
        if [ "$cli_rc" -ne 0 ] || ! cmp -s "$cli_out" "$temporary_dir/r17-canonical-cli.out"; then
            echo "CLI rejected or changed valid R17 fixture: $case_name" >&2
            sed 's/^/  /' "$cli_err" >&2
            exit 1
        fi
        if [ -s "$cli_err" ]; then
            echo "CLI emitted stderr for valid R17 fixture: $case_name" >&2
            exit 1
        fi
    else
        if [ "$cli_rc" -eq 0 ] || [ -s "$cli_out" ]; then
            echo "CLI accepted invalid R17 fixture or printed stdout: $case_name" >&2
            exit 1
        fi
        if ! grep -F "ruster-bench: identity source contains" "$cli_err" >/dev/null 2>&1; then
            echo "CLI did not emit the fixed R17 diagnostic: $case_name" >&2
            sed 's/^/  /' "$cli_err" >&2
            exit 1
        fi
        assert_r17_output_redacted "$cli_err" "$spec" "$candidate_identity"
    fi

    checker_out="$temporary_dir/r17-six-$case_name.checker.out"
    checker_err="$temporary_dir/r17-six-$case_name.checker.err"
    if "$script_dir/check-benchmark-spec.sh" "$spec" "$candidate_identity" \
        >"$checker_out" 2>"$checker_err"; then
        checker_rc=0
    else
        checker_rc=$?
    fi
    if [ "$expected" = valid ]; then
        if [ "$checker_rc" -ne 0 ] || ! grep -F "benchmark_spec_sha256=$actual" "$checker_out" >/dev/null; then
            echo "checker rejected valid R17 fixture: $case_name" >&2
            sed 's/^/  /' "$checker_err" >&2
            exit 1
        fi
    else
        if [ "$checker_rc" -eq 0 ] || [ -s "$checker_out" ]; then
            echo "checker accepted invalid R17 fixture or printed stdout: $case_name" >&2
            exit 1
        fi
        if ! grep -F "identity source parser rejected the input" "$checker_err" >/dev/null 2>&1; then
            echo "checker did not emit the fixed R17 diagnostic: $case_name" >&2
            sed 's/^/  /' "$checker_err" >&2
            exit 1
        fi
        assert_r17_output_redacted "$checker_err" "$spec" "$candidate_identity"
    fi
}

assert_r17_differential_case() {
    case_name=$1
    expected=$2
    fixture=$3
    candidate_identity="$temporary_dir/r17-six-$case_name.rs"
    standalone="$temporary_dir/r17-six-$case_name-standalone.rs"
    cp "$identity" "$candidate_identity"
    printf '%s\n' "$fixture" >>"$candidate_identity"
    printf '%s\n' "$fixture" >"$standalone"
    assert_r17_prepared_case "$case_name" "$expected" "$candidate_identity" "$standalone"
}

if ! run_r17_cli --parse-benchmark-identity "$identity" \
    >"$temporary_dir/r17-canonical-cli.out" \
    2>"$temporary_dir/r17-canonical-cli.err"; then
    echo "canonical R17 identity CLI invocation failed" >&2
    exit 1
fi
if [ -s "$temporary_dir/r17-canonical-cli.err" ]; then
    echo "canonical R17 identity CLI emitted stderr" >&2
    exit 1
fi

assert_r17_differential_case \
    invalid-cmp invalid \
    "const INVALID_CMP: bool = (1 < 2, 'a);"
assert_r17_differential_case \
    valid-label-comma valid \
    "fn VALID_LABEL_COMMA() { let _ = (1u8, 'lbl: loop { break 'lbl; }); }"
assert_r17_differential_case \
    valid-macro-start valid \
    "macro_rules! VALID_MACRO_START { ('a) => {}; }"
assert_r17_differential_case \
    invalid-after-where invalid \
    "fn VALID_WHERE<'a>() where 'a: 'a {} const INVALID_AFTER_WHERE: bool = 1, 'a;"
assert_r17_differential_case \
    invalid-after-raw-identifier invalid \
    "fn r#where() {} const INVALID_AFTER_RAW_IDENTIFIER: bool = 1, 'a;"
assert_r17_differential_case \
    invalid-raw-suffix invalid \
    'const CASE_RAW_ONE_SHORT_BODY: &str = r#"A"#B;'

# Task #100: each case is compiled by Rust 1.97.1 and then compared with the
# bounded identity lexer. Keep the corpus explicit so a changed authority
# result or parser decision is reported as a mismatch rather than normalized.
assert_r17_differential_case valid-type-alias-rhs valid \
    "struct AliasS<'a>(&'a ()); type AliasA<'a> = AliasS<'a>;"
assert_r17_differential_case valid-associated-type-rhs valid \
    "struct AssocS<'a>(&'a ()); trait AssocT<'a> { type A; } impl<'a> AssocT<'a> for () { type A = AssocS<'a>; }"
assert_r17_differential_case valid-annotation-delimiters valid \
    "struct AnnotationS<'a>(&'a ()); fn annotation<'a>() { let _: ((Option<AnnotationS<'a>>,), [Option<AnnotationS<'a>>; 1]) = ((None,), [None]); }"
assert_r17_differential_case invalid-struct-literal-field invalid \
    "struct FieldE { field: bool } fn invalid_field() { let _ = FieldE { field: (1 < 2, 'a) }; }"
assert_r17_differential_case valid-expression-turbofish valid \
    "struct TurbofishS<'a>(&'a ()); fn turbofish<'a>() { let _ = core::mem::size_of::<TurbofishS<'a>>(); }"
assert_r17_differential_case valid-path-turbofish valid \
    "struct PathS<'a>(&'a ()); impl<'a> PathS<'a> { fn f() {} } fn path<'a>() { PathS::<'a>::f(); }"
assert_r17_differential_case valid-six-angle-operators valid \
    'fn angle_operators() { let _ = 1 < 2; let _ = 1 <= 2; let _ = 1 << 2; let _ = 2 > 1; let _ = 2 >= 1; let _ = 2 >> 1; }'
assert_r17_differential_case invalid-unicode-normal-suffix invalid \
    'const NORMAL_SUFFIX: &str = "A"λ;'
assert_r17_differential_case invalid-unicode-raw-suffix invalid \
    'const RAW_SUFFIX: &str = r"A"λ;'
assert_r17_differential_case invalid-unicode-byte-suffix invalid \
    'const BYTE_SUFFIX: &[u8] = b"A"λ;'
assert_r17_differential_case invalid-unicode-raw-byte-suffix invalid \
    'const RAW_BYTE_SUFFIX: &[u8] = br"A"λ;'
assert_r17_differential_case invalid-unicode-char-suffix invalid \
    "const CHAR_SUFFIX: char = 'A'λ;"
assert_r17_differential_case invalid-unicode-byte-char-suffix invalid \
    "const BYTE_CHAR_SUFFIX: u8 = b'A'λ;"
assert_r17_differential_case valid-raw-unicode valid \
    'fn r#λ() {} fn r#℘() {} fn r#℮() {}'
assert_r17_differential_case valid-raw-unicode-continuation valid \
    'fn r#self́() {}'
assert_r17_differential_case valid-raw-unicode-digit valid \
    'fn r#self١() {}'
assert_r17_differential_case valid-raw-unicode-connector valid \
    'fn r#self‿() {} fn r#self·() {}'
assert_r17_differential_case valid-raw-unicode-mark valid \
    'fn r#selfְ() {}'
assert_r17_differential_case valid-raw-unicode-additional-mark valid \
    'fn r#self҃() {}'
assert_r17_differential_case invalid-raw-unicode-mark-start invalid \
    'fn r#ְ() {}'
assert_r17_differential_case invalid-raw-unicode-compat-start invalid \
    'fn r#Ⓐ() {}'
assert_r17_differential_case invalid-raw-unicode-numeric-continuation invalid \
    'fn r#self²() {}'
assert_r17_differential_case invalid-raw-self invalid \
    'fn r#self() {}'
assert_r17_differential_case invalid-raw-Self invalid \
    'fn r#Self() {}'
assert_r17_differential_case invalid-raw-super invalid \
    'fn r#super() {}'
assert_r17_differential_case invalid-raw-crate invalid \
    'fn r#crate() {}'
assert_r17_differential_case invalid-raw-underscore invalid \
    'fn r#_() {}'
assert_r17_differential_case valid-raw-where valid \
    'fn r#where() {}'
assert_r17_differential_case valid-raw-openers valid \
    'const RAW_OPENER: &str = r#"A"#; const RAW_BYTE_OPENER: &[u8] = br#"A"#;'

# Task #150: exercise the remaining forward-context and literal-suffix
# differentials directly against Rust 1.97.1 for every affected literal mode.
assert_r17_differential_case valid-whitespace-turbofish valid \
    "struct S<'a>(&'a ()); fn f<'a>() { let _ = core::mem::size_of:: <S<'a>>(); }"
assert_r17_differential_case valid-comment-turbofish valid \
    "struct S<'a>(&'a ()); fn f<'a>() { let _ = core::mem::size_of::/*x*/<S<'a>>(); }"
assert_r17_differential_case valid-expression-qpath valid \
    "struct S<'a>(&'a ()); trait T { fn f(); } impl<'a> T for S<'a> { fn f() {} } fn q<'a>() { <S<'a> as T>::f(); }"
assert_r17_differential_case valid-closure-annotation valid \
    "struct S<'a>(&'a ()); fn f<'a>() { let _ = |_: Option<S<'a>>| {}; }"
assert_r17_differential_case valid-nested-closure-annotation valid \
    "struct S<'a>(&'a ()); fn f<'a>() { let _ = |_: Option<S<'a>>| |_: Option<S<'a>>| {}; }"
assert_r17_differential_case valid-enum-variant-types valid \
    "struct S<'a>(&'a ()); enum E<'a> { Tuple(S<'a>), Record { field: S<'a> }, }"
assert_r17_differential_case valid-hrtb-bare-fn valid \
    "struct S<'a>(&'a ()); type F<'a> = for<'b> fn(&'b S<'a>);"
assert_r17_differential_case valid-embedded-char-expressions valid \
    "struct G<const N: usize>; type Good = G<{ 1 + 'a' as usize }>; type Array = [u8; 1 + 'a' as usize];"
assert_r17_differential_case invalid-normal-digit-suffix invalid \
    'const INVALID_NORMAL_DIGIT: &str = "A"0;'
assert_r17_differential_case invalid-raw-digit-suffix invalid \
    'const INVALID_RAW_DIGIT: &str = r"A"0;'
assert_r17_differential_case invalid-byte-digit-suffix invalid \
    'const INVALID_BYTE_DIGIT: &[u8] = b"A"0;'
assert_r17_differential_case invalid-raw-byte-digit-suffix invalid \
    'const INVALID_RAW_BYTE_DIGIT: &[u8] = br"A"0;'
assert_r17_differential_case invalid-char-digit-suffix invalid \
    "const INVALID_CHAR_DIGIT: char = 'A'0;"
assert_r17_differential_case invalid-byte-char-digit-suffix invalid \
    "const INVALID_BYTE_CHAR_DIGIT: u8 = b'A'0;"
assert_r17_differential_case invalid-normal-continue-suffix invalid \
    'const INVALID_NORMAL_CONTINUE: &str = "A"́;'
assert_r17_differential_case invalid-raw-continue-suffix invalid \
    'const INVALID_RAW_CONTINUE: &str = r"A"́;'
assert_r17_differential_case invalid-byte-continue-suffix invalid \
    'const INVALID_BYTE_CONTINUE: &[u8] = b"A"́;'
assert_r17_differential_case invalid-raw-byte-continue-suffix invalid \
    'const INVALID_RAW_BYTE_CONTINUE: &[u8] = br"A"́;'
assert_r17_differential_case invalid-char-continue-suffix invalid \
    "const INVALID_CHAR_CONTINUE: char = 'A'́;"
assert_r17_differential_case invalid-byte-char-continue-suffix invalid \
    "const INVALID_BYTE_CHAR_CONTINUE: u8 = b'A'́;"
assert_r17_differential_case invalid-const-generic-lifetime invalid \
    "struct G<const N: usize>; type Bad = G<1 + 'a as usize>;"
assert_r17_differential_case invalid-array-length-lifetime invalid \
    "type Bad = [u8; 1 + 'a as usize];"
assert_r17_differential_case invalid-logical-or-annotation invalid \
    "fn invalid<'a>(a: bool, b: bool) { let _ = a || b: &'a u8; }"

# Task #159: close the final Unicode lifetime, range endpoint, labeled-break,
# and statement-boundary differentials against Rust 1.97.1.
assert_r17_differential_case valid-xid-label-combining-mark valid \
    "fn valid() { 'á: loop { break 'á; } }"
assert_r17_differential_case valid-xid-label-connector valid \
    "fn valid() { 'a‿: loop { break 'a‿; } }"
assert_r17_differential_case valid-xid-label-middle-dot valid \
    "fn valid() { 'a·: loop { break 'a·; } }"
assert_r17_differential_case valid-range-closure valid \
    "fn valid<'a>() { let _ = .. |_: &'a ()| (); }"
assert_r17_differential_case valid-range-qpath valid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid<'a>() { let _ = .. <S<'a> as T>::C; }"
assert_r17_differential_case valid-break-label-qpath valid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid<'a>() { let _: usize = 'lbl: loop { break 'lbl <S<'a> as T>::C; }; }"
assert_r17_differential_case valid-nearby-character valid \
    "fn valid() { let _ = 1; let _ = 'a'; }"
assert_r17_differential_case valid-nearby-label valid \
    "fn valid() { 'lbl: loop { break 'lbl; } }"
assert_r17_differential_case valid-nearby-macro-lifetime valid \
    "macro_rules! valid { ('a) => {}; }"
assert_r17_differential_case valid-nearby-type-lifetime valid \
    "fn valid<'a>(value: &'a ()) { let _ = value; }"
assert_r17_differential_case valid-label-after-block valid \
    "fn valid() { {} 'lbl: loop { break 'lbl; } }"
assert_r17_differential_case invalid-lifetime-after-semicolon invalid \
    "fn invalid() { let _ = 1; 'a; }"
assert_r17_differential_case invalid-lifetime-after-empty-statements invalid \
    "fn invalid() { ;; 'a; }"
assert_r17_differential_case invalid-lifetime-after-item-semicolon invalid \
    "type A = (); 'a;"
assert_r17_differential_case invalid-lifetime-after-block-semicolon invalid \
    "fn invalid() { {}; 'a; }"
assert_r17_differential_case invalid-lifetime-after-item-body invalid \
    "fn invalid() { fn nested() {} 'a; }"
assert_r17_differential_case invalid-field-qpath invalid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } fn invalid<'a>(value: S<'a>) { let _ = value.<S<'a> as T>::C; }"
assert_r17_differential_case invalid-triple-dot-qpath invalid \
    "struct S<'a>(&'a ()); fn invalid<'a>() { let _ = ... <S<'a>>; }"

# Task #177: close the remaining expression-start, numeric, reserved-prefix,
# unknown-token, delimiter, and bounded-snapshot roots under Rust 2021.
assert_r17_differential_case valid-rem-qpath valid \
    "use core::ops::Rem; struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } struct L; impl Rem<usize> for L { type Output = (); fn rem(self, _: usize) {} } fn valid<'a>() { let _ = L % <S<'a> as T>::C; }"
assert_r17_differential_case valid-xor-qpath valid \
    "use core::ops::BitXor; struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } struct L; impl BitXor<usize> for L { type Output = (); fn bitxor(self, _: usize) {} } fn valid<'a>() { let _ = L ^ <S<'a> as T>::C; }"
assert_r17_differential_case valid-less-than-qpath valid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid<'a>() { let _ = 0 < <S<'a> as T>::C; }"
assert_r17_differential_case valid-shift-qpath valid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid<'a>() { let _ = 0usize << <S<'a> as T>::C; let _ = 0usize<<<S<'a> as T>::C; }"
assert_r17_differential_case valid-in-qpath valid \
    "struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid<'a>() { for _ in <S<'a> as T>::C..2 {} }"
assert_r17_differential_case valid-rem-closure valid \
    "use core::ops::Rem; struct L; impl<F> Rem<F> for L { type Output = (); fn rem(self, _: F) {} } fn valid<'a>() { let _ = L % |_: &'a ()| (); }"
assert_r17_differential_case valid-xor-closure valid \
    "use core::ops::BitXor; struct L; impl<F> BitXor<F> for L { type Output = (); fn bitxor(self, _: F) {} } fn valid<'a>() { let _ = L ^ |_: &'a ()| (); }"
assert_r17_differential_case valid-less-than-closure valid \
    "struct L; impl<F> PartialEq<F> for L { fn eq(&self, _: &F) -> bool { false } } impl<F> PartialOrd<F> for L { fn partial_cmp(&self, _: &F) -> Option<core::cmp::Ordering> { None } } fn valid<'a>() { let _ = L < |_: &'a ()| (); }"
assert_r17_differential_case valid-shift-closure valid \
    "use core::ops::Shl; struct L; impl<F> Shl<F> for L { type Output = (); fn shl(self, _: F) {} } fn valid<'a>() { let _ = L << |_: &'a ()| (); }"
assert_r17_differential_case valid-break-label-closure valid \
    "fn valid<'a>() { let _ = 'lbl: loop { break 'lbl |_: &'a ()| (); }; }"
assert_r17_differential_case valid-numeric-boundaries valid \
    "fn valid() { let _ = 1..2; let _ = 1e+2; let _ = 1e-2; let _ = 1e_2; let _ = 0b_1010_u8; let _ = 0o77i16; let _ = 0xffusize; let _ = 1.; let _ = 1.0f64; let _ = 1f32; }"
assert_r17_differential_case valid-c-string-prefixes valid \
    'const VALID_C: &core::ffi::CStr = c"A"; const VALID_CR: &core::ffi::CStr = cr#"A"#;'
assert_r17_differential_case valid-rust-punctuation valid \
    'macro_rules! valid { ($x:expr) => { @ # ~ ? $x }; }'
assert_r17_differential_case invalid-numeric-suffix invalid \
    "const INVALID_NUMERIC_SUFFIX: u8 = 1foo;"
assert_r17_differential_case invalid-numeric-exponent invalid \
    "const INVALID_NUMERIC_EXPONENT: f64 = 1e+;"
assert_r17_differential_case invalid-numeric-empty-radix invalid \
    "const INVALID_NUMERIC_RADIX: u8 = 0x;"
assert_r17_differential_case invalid-numeric-radix-digit invalid \
    "const INVALID_NUMERIC_RADIX_DIGIT: u8 = 0b102;"
assert_r17_differential_case invalid-reserved-string-prefix invalid \
    'const INVALID_STRING_PREFIX: &str = foo"A";'
assert_r17_differential_case invalid-reserved-character-prefix invalid \
    "const INVALID_CHARACTER_PREFIX: char = foo'a';"
assert_r17_differential_case invalid-reserved-raw-prefix invalid \
    'const INVALID_RAW_PREFIX: &str = foo#"A"#;'
assert_r17_differential_case invalid-standalone-combining-mark invalid \
    "fn invalid() { let _ = ́; }"
assert_r17_differential_case invalid-emoji-token invalid \
    "fn invalid() { let _ = 😀; }"
assert_r17_differential_case invalid-backtick-token invalid \
    'fn invalid() { let _ = `x`; }'
assert_r17_differential_case invalid-crossed-parenthesis-bracket invalid \
    "fn invalid() { let _ = (0]; }"
assert_r17_differential_case invalid-crossed-bracket-parenthesis invalid \
    "fn invalid() { let _ = [0); }"
assert_r17_differential_case invalid-crossed-brace-bracket invalid \
    "fn invalid() { let _ = [0}; }"
assert_r17_differential_case invalid-unclosed-delimiter invalid \
    "fn invalid() { let _ = (0; }"
assert_r17_differential_case invalid-unclosed-expression-angle invalid \
    "const INVALID: bool = 0 < <1;"
assert_r17_differential_case invalid-unterminated-typed-closure invalid \
    "fn invalid<'a>() { let _ = 'lbl: loop { break 'lbl |_: &'a (); }; }"
assert_r17_differential_case invalid-triple-dot-after-number invalid \
    "const INVALID: bool = 1...2;"
assert_r17_differential_case invalid-unclosed-generic-scope-pop invalid \
    "struct S; fn invalid() { let _ = <S; }"
assert_r17_differential_case valid-state-boundary-constructs valid \
    "trait T { const C: usize; } struct S; impl T for S { const C: usize = 1; } fn valid() { let _ = 0 < <S as T>::C; let _ = |_: u8| (); let _ = 1..2; let _ = 1..=2; let _: Vec<Vec<u8>> = Vec::new(); let _: Vec<Vec<u8>>=Vec::new(); let _: Vec<u8> = Vec::<u8>::new(); } macro_rules! valid_tokens { (<;>) => {}; }"

nul_case=invalid-nul-token
nul_identity="$temporary_dir/r17-six-$nul_case.rs"
nul_standalone="$temporary_dir/r17-six-$nul_case-standalone.rs"
cp "$identity" "$nul_identity"
printf 'fn invalid() { let _ = ' >>"$nul_identity"
printf 'fn invalid() { let _ = ' >"$nul_standalone"
printf '\000' >>"$nul_identity"
printf '\000' >>"$nul_standalone"
printf '; }\n' >>"$nul_identity"
printf '; }\n' >>"$nul_standalone"
assert_r17_prepared_case "$nul_case" invalid "$nul_identity" "$nul_standalone"

assert_raw_cr_rejected() {
    candidate_identity=$1
    prefix=$2
    suffix=$3
    expected_tail=$4
    tail_bytes=$5
    cp "$identity" "$candidate_identity"
    printf '%s' "$prefix" >>"$candidate_identity"
    printf '\015' >>"$candidate_identity"
    printf '%s\n' "$suffix" >>"$candidate_identity"
    raw_cr_tail=$(tail -c "$tail_bytes" "$candidate_identity" | od -An -t x1 | tr -d '[:space:]')
    if [ "$raw_cr_tail" != "$expected_tail" ]; then
        echo "raw CR fixture did not contain the expected literal body bytes" >&2
        exit 1
    fi
    assert_rejected "$spec" "$candidate_identity" "identity source parser rejected the input"
}

double_lf="$temporary_dir/double-lf.md"
cp "$spec" "$double_lf"
printf '\n' >>"$double_lf"
assert_rejected "$double_lf" "$identity" "exactly one final LF"

missing_lf="$temporary_dir/missing-lf.md"
awk '{ printf "%s%s", (NR == 1 ? "" : "\n"), $0 }' "$spec" >"$missing_lf"
assert_rejected "$missing_lf" "$identity" "one final LF"

trailing_whitespace="$temporary_dir/trailing-whitespace.md"
awk 'NR == 1 { print $0 " "; next } { print }' "$spec" >"$trailing_whitespace"
assert_rejected "$trailing_whitespace" "$identity" "trailing whitespace"

with_bom="$temporary_dir/bom.md"
{
    printf '\357\273\277'
    cat "$spec"
} >"$with_bom"
assert_rejected "$with_bom" "$identity" "UTF-8 BOM"

with_cr="$temporary_dir/cr.md"
awk 'NR == 1 { printf "%s\015\n", $0; next } { print }' "$spec" >"$with_cr"
assert_rejected "$with_cr" "$identity" "LF-only"

symlink_spec="$temporary_dir/spec-symlink.md"
ln -s "$spec" "$symlink_spec"
assert_rejected "$symlink_spec" "$identity" "benchmark specification input could not be snapshotted"

fifo_spec="$temporary_dir/spec-fifo.md"
mkfifo "$fifo_spec"
assert_rejected "$fifo_spec" "$identity" "benchmark specification input could not be snapshotted"

wrong_identity="$temporary_dir/wrong-spec.rs"
wrong_hash=0000000000000000000000000000000000000000000000000000000000000000
sed "s/$actual/$wrong_hash/g" "$identity" >"$wrong_identity"
assert_rejected "$spec" "$wrong_identity" "compiled identity drift"

malformed_identity="$temporary_dir/malformed-spec.rs"
sed "s/$actual/not-a-digest/" "$identity" >"$malformed_identity"
assert_rejected "$spec" "$malformed_identity" "identity source parser rejected the input"

uppercase_identity="$temporary_dir/uppercase-spec.rs"
uppercase_hash=$(printf '%s' "$actual" | tr '[:lower:]' '[:upper:]')
sed "s/$actual/$uppercase_hash/" "$identity" >"$uppercase_identity"
assert_rejected "$spec" "$uppercase_identity" "identity source parser rejected the input"

typed_only_identity="$temporary_dir/typed-only-drift.rs"
typed_first=$(awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ { in_array = 1; next }
in_array && /0x[0-9a-f]/ {
    value = $0
    gsub(/[[:space:]]/, "", value)
    split(value, pieces, ",")
    print pieces[1]
    exit
}
' "$identity")
case "$typed_first" in
    0x00) typed_replacement=0x01 ;;
    *) typed_replacement=0x00 ;;
esac
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ { in_array = 1; print; next }
in_array && !changed && $0 ~ original {
    sub(original, replacement)
    changed = 1
    in_array = 0
}
{ print }
' original="$typed_first" replacement="$typed_replacement" "$identity" >"$typed_only_identity"
assert_rejected "$spec" "$typed_only_identity" "typed and hexadecimal benchmark identities disagree"

content_drift="$temporary_dir/content-drift.md"
sed '1s/v0.2/v0.2 content-drift/' "$spec" >"$content_drift"
assert_rejected "$content_drift" "$identity" "compiled identity drift"

missing_identity="$temporary_dir/missing-spec.rs"
sed '/R17_BENCHMARK_SPEC_SHA256_HEX/d' "$identity" >"$missing_identity"
assert_rejected "$spec" "$missing_identity" "identity source parser rejected the input"

one_digit_typed="$temporary_dir/one-digit-typed.rs"
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ { in_array = 1 }
in_array && !changed && /0x[0-9a-f][0-9a-f]/ {
    sub(/0x[0-9a-f][0-9a-f]/, "0x0")
    changed = 1
    in_array = 0
}
{ print }
' "$identity" >"$one_digit_typed"
assert_rejected "$spec" "$one_digit_typed" "identity source parser rejected the input"

uppercase_typed="$temporary_dir/uppercase-typed.rs"
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ { in_array = 1 }
in_array && !changed && /0x[0-9a-f][0-9a-f]/ {
    sub(/0x[0-9a-f][0-9a-f]/, "0xA0")
    changed = 1
    in_array = 0
}
{ print }
' "$identity" >"$uppercase_typed"
assert_rejected "$spec" "$uppercase_typed" "identity source parser rejected the input"

typed_33_bytes="$temporary_dir/typed-33-bytes.rs"
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ && !changed {
    sub(/\[/, "[0x00, ")
    changed = 1
}
{ print }
' "$identity" >"$typed_33_bytes"
assert_rejected "$spec" "$typed_33_bytes" "identity source parser rejected the input"

typed_31_bytes="$temporary_dir/typed-31-bytes.rs"
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256:.*from_bytes/ { in_array = 1 }
in_array && !changed && /0x[0-9a-f][0-9a-f]/ {
    sub(/0x[0-9a-f][0-9a-f],[[:space:]]*/, "")
    changed = 1
    in_array = 0
}
{ print }
' "$identity" >"$typed_31_bytes"
assert_rejected "$spec" "$typed_31_bytes" "identity source parser rejected the input"

duplicate_identity="$temporary_dir/duplicate-spec.rs"
cp "$identity" "$duplicate_identity"
awk '
/^pub const R17_BENCHMARK_SPEC_SHA256_HEX:/ { capture = 1 }
capture { print; if ($0 ~ /;/) exit }
' "$identity" >"$temporary_dir/compiled-declaration"
printf '\n' >>"$duplicate_identity"
cat "$temporary_dir/compiled-declaration" >>"$duplicate_identity"
assert_rejected "$spec" "$duplicate_identity" "identity source parser rejected the input"

malformed_declaration="$temporary_dir/malformed-declaration.rs"
sed 's/R17_BENCHMARK_SPEC_SHA256_HEX: \&str/R17_BENCHMARK_SPEC_SHA256_HEX: u32/' "$identity" >"$malformed_declaration"
assert_rejected "$spec" "$malformed_declaration" "identity source parser rejected the input"

comment_only_identity="$temporary_dir/comment-only-spec.rs"
printf '%s\n' \
    '/* pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000"; */' \
    '// pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([]);' \
    >"$comment_only_identity"
assert_rejected "$spec" "$comment_only_identity" "identity source parser rejected the input"

string_only_identity="$temporary_dir/string-only-spec.rs"
printf '%s\n' \
    'const LOOKALIKE = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"0000000000000000000000000000000000000000000000000000000000000000\";";' \
    'const OTHER_LOOKALIKE = "pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([]);";' \
    >"$string_only_identity"
assert_rejected "$spec" "$string_only_identity" "identity source parser rejected the input"

indented_identity="$temporary_dir/indented-spec.rs"
awk '/^pub const R17_BENCHMARK_SPEC_SHA256/ {$0 = " " $0} { print }' "$identity" >"$indented_identity"
assert_rejected "$spec" "$indented_identity" "identity source parser rejected the input"

comment_and_string_identity="$temporary_dir/comment-and-string-spec.rs"
cp "$identity" "$comment_and_string_identity"
printf '%s\n' \
    '/* pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = "not-a-declaration"; */' \
    'const LOOKALIKE = "pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([]);";' \
    >"$temporary_dir/comment-and-string-tail"
cat "$temporary_dir/comment-and-string-tail" >>"$comment_and_string_identity"
comment_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$comment_and_string_identity")
if ! printf '%s\n' "$comment_output" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "valid declarations surrounded by comments and strings were rejected" >&2
    exit 1
fi

valid_literals_identity="$temporary_dir/valid-literals-spec.rs"
cp "$identity" "$valid_literals_identity"
printf '%s\n' \
    'const VALID_RAW: &str = r"raw /* comment */ and // text";' \
    'const VALID_RAW_HASH: &str = r#"raw " quote"#;' \
    'const VALID_RAW_BYTE_HASH: &[u8] = br##"raw # "##;' \
    'const VALID_STRING: &str = "escaped quote: \"";' \
    "const VALID_CHAR: char = '\\n';" \
    "const VALID_PLAIN_CHAR: char = 'x';" \
    "const VALID_ESCAPED_TAB_CHAR: char = '\\t';" \
    "const VALID_UNICODE_CHAR: char = '\\u{03bb}';" \
    "const VALID_HEX_CHAR: char = '\\x7f';" \
    "const VALID_BYTE_CHAR: u8 = b'x';" \
    "const VALID_ESCAPED_DOUBLE_QUOTE: u8 = b'\\\"';" \
    "const VALID_BYTE_QUOTE: u8 = b'\\'';" \
    "const VALID_BYTE_BACKSLASH: u8 = b'\\\\';" \
    "const VALID_BYTE_NEWLINE: u8 = b'\\n';" \
    "const VALID_BYTE_CARRIAGE_RETURN: u8 = b'\\r';" \
    "const VALID_BYTE_TAB: u8 = b'\\t';" \
    "const VALID_BYTE_NUL: u8 = b'\\0';" \
    "const VALID_BYTE_HEX: u8 = b'\\x7f';" \
    '/* valid outer comment with a nested /* block */ comment */' \
    >>"$valid_literals_identity"
literal_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$valid_literals_identity")
if ! printf '%s\n' "$literal_output" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "valid raw/string/char/comment literals were rejected" >&2
    exit 1
fi

append_hashes() {
    hash_count=$1
    while [ "$hash_count" -gt 0 ]; do
        printf '#'
        hash_count=$((hash_count - 1))
    done
}

valid_boundaries_identity="$temporary_dir/valid-boundaries-spec.rs"
cp "$identity" "$valid_boundaries_identity"
printf '%s' 'const VALID_NORMAL_LF: &str = "A' >>"$valid_boundaries_identity"
printf '\012' >>"$valid_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_boundaries_identity"
printf '%s' 'const VALID_NORMAL_CRLF: &str = "A' >>"$valid_boundaries_identity"
printf '\015\012' >>"$valid_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_boundaries_identity"
printf '%s' 'const VALID_BYTE_LF: &[u8] = b"A' >>"$valid_boundaries_identity"
printf '\012' >>"$valid_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_boundaries_identity"
printf '%s' 'const VALID_BYTE_CRLF: &[u8] = b"A' >>"$valid_boundaries_identity"
printf '\015\012' >>"$valid_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_boundaries_identity"
printf '%s' 'const VALID_STRING_CONTINUATION: &str = "A\' >>"$valid_boundaries_identity"
printf '\012' >>"$valid_boundaries_identity"
printf '\011' >>"$valid_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_boundaries_identity"
boundary_bytes=$(tail -c 300 "$valid_boundaries_identity" | od -An -t x1 | tr -d '[:space:]')
for expected_boundary in 22410a42223b0a 22410d0a42223b0a 6222410a42223b0a 6222410d0a42223b0a 22415c0a0942223b0a; do
    case "$boundary_bytes" in
        *"$expected_boundary"*) ;;
        *)
            echo "valid string boundary fixture did not contain expected bytes: $expected_boundary" >&2
            exit 1
            ;;
    esac
done
boundary_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$valid_boundaries_identity")
if ! printf '%s\n' "$boundary_output" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "valid normal/byte LF, CRLF, or continuation fixtures were rejected" >&2
    exit 1
fi

valid_raw_boundaries_identity="$temporary_dir/valid-raw-boundaries-spec.rs"
cp "$identity" "$valid_raw_boundaries_identity"
printf '%s' 'const VALID_RAW_LF: &str = r"A' >>"$valid_raw_boundaries_identity"
printf '\012' >>"$valid_raw_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_raw_boundaries_identity"
printf '%s' 'const VALID_RAW_CRLF: &str = r"A' >>"$valid_raw_boundaries_identity"
printf '\015\012' >>"$valid_raw_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_raw_boundaries_identity"
printf '%s' 'const VALID_RAW_BYTE_LF: &[u8] = br"A' >>"$valid_raw_boundaries_identity"
printf '\012' >>"$valid_raw_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_raw_boundaries_identity"
printf '%s' 'const VALID_RAW_BYTE_CRLF: &[u8] = br"A' >>"$valid_raw_boundaries_identity"
printf '\015\012' >>"$valid_raw_boundaries_identity"
printf '%s\n' 'B";' >>"$valid_raw_boundaries_identity"
raw_boundary_bytes=$(tail -c 180 "$valid_raw_boundaries_identity" | od -An -t x1 | tr -d '[:space:]')
for expected_raw_boundary in 22410a42223b0a 22410d0a42223b0a 627222410a42223b0a 627222410d0a42223b0a; do
    case "$raw_boundary_bytes" in
        *"$expected_raw_boundary"*) ;;
        *)
            echo "valid raw string boundary fixture did not contain expected bytes: $expected_raw_boundary" >&2
            exit 1
            ;;
    esac
done
raw_boundary_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$valid_raw_boundaries_identity")
if ! printf '%s\n' "$raw_boundary_output" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "valid raw/raw-byte LF or CRLF fixtures were rejected" >&2
    exit 1
fi

valid_raw_hash_identity="$temporary_dir/valid-raw-hash-spec.rs"
cp "$identity" "$valid_raw_hash_identity"
printf '%s' 'const VALID_RAW_255: &str = r' >>"$valid_raw_hash_identity"
append_hashes 255 >>"$valid_raw_hash_identity"
printf '%s' '"A"' >>"$valid_raw_hash_identity"
append_hashes 255 >>"$valid_raw_hash_identity"
printf '%s\n' ';' >>"$valid_raw_hash_identity"
printf '%s' 'const VALID_RAW_BYTE_255: &[u8] = br' >>"$valid_raw_hash_identity"
append_hashes 255 >>"$valid_raw_hash_identity"
printf '%s' '"A"' >>"$valid_raw_hash_identity"
append_hashes 255 >>"$valid_raw_hash_identity"
printf '%s\n' ';' >>"$valid_raw_hash_identity"
raw_hash_output=$("$script_dir/check-benchmark-spec.sh" "$spec" "$valid_raw_hash_identity")
if ! printf '%s\n' "$raw_hash_output" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "valid 255-hash raw fixtures were rejected" >&2
    exit 1
fi

normal_escape_identity="$temporary_dir/invalid-normal-escape-spec.rs"
cp "$identity" "$normal_escape_identity"
printf '%s\n' 'const INVALID_NORMAL_ESCAPE: &str = "A\qB";' >>"$normal_escape_identity"
assert_rejected "$spec" "$normal_escape_identity" "identity source parser rejected the input"

char_scalar_identity="$temporary_dir/invalid-char-scalar-spec.rs"
cp "$identity" "$char_scalar_identity"
printf '%s\n' 'const INVALID_CHAR_SCALAR: char = '\''\u{110000}'\'';' >>"$char_scalar_identity"
assert_rejected "$spec" "$char_scalar_identity" "identity source parser rejected the input"

byte_string_identity="$temporary_dir/invalid-byte-string-spec.rs"
cp "$identity" "$byte_string_identity"
printf '%s\n' 'const INVALID_BYTE_UNICODE: &[u8] = b"\u{12}";' >>"$byte_string_identity"
assert_rejected "$spec" "$byte_string_identity" "identity source parser rejected the input"
printf '%s\n' 'const INVALID_BYTE_UTF8: &[u8] = b"AλB";' >>"$byte_string_identity"
assert_rejected "$spec" "$byte_string_identity" "identity source parser rejected the input"

raw_byte_identity="$temporary_dir/invalid-raw-byte-string-spec.rs"
cp "$identity" "$raw_byte_identity"
printf '%s\n' 'const INVALID_RAW_BYTE_UTF8: &[u8] = br"AλB";' >>"$raw_byte_identity"
assert_rejected "$spec" "$raw_byte_identity" "identity source parser rejected the input"

normal_lone_cr_identity="$temporary_dir/invalid-normal-lone-cr-spec.rs"
cp "$identity" "$normal_lone_cr_identity"
printf '%s' 'const INVALID_NORMAL_LONE_CR: &str = "A' >>"$normal_lone_cr_identity"
printf '\015' >>"$normal_lone_cr_identity"
printf '%s\n' 'B";' >>"$normal_lone_cr_identity"
normal_lone_cr_tail=$(tail -c 5 "$normal_lone_cr_identity" | od -An -t x1 | tr -d '[:space:]')
[ "$normal_lone_cr_tail" = "0d42223b0a" ] || {
    echo "normal lone-CR fixture did not contain 0x0d inside the literal" >&2
    exit 1
}
assert_rejected "$spec" "$normal_lone_cr_identity" "identity source parser rejected the input"

byte_lone_cr_identity="$temporary_dir/invalid-byte-lone-cr-spec.rs"
cp "$identity" "$byte_lone_cr_identity"
printf '%s' 'const INVALID_BYTE_LONE_CR: &[u8] = b"A' >>"$byte_lone_cr_identity"
printf '\015' >>"$byte_lone_cr_identity"
printf '%s\n' 'B";' >>"$byte_lone_cr_identity"
byte_lone_cr_tail=$(tail -c 5 "$byte_lone_cr_identity" | od -An -t x1 | tr -d '[:space:]')
[ "$byte_lone_cr_tail" = "0d42223b0a" ] || {
    echo "byte lone-CR fixture did not contain 0x0d inside the literal" >&2
    exit 1
}
assert_rejected "$spec" "$byte_lone_cr_identity" "identity source parser rejected the input"

raw_extra_hash_identity="$temporary_dir/invalid-raw-extra-hash-spec.rs"
cp "$identity" "$raw_extra_hash_identity"
printf '%s' 'const INVALID_RAW_EXTRA_HASH: &str = r' >>"$raw_extra_hash_identity"
append_hashes 1 >>"$raw_extra_hash_identity"
printf '%s' '"A"' >>"$raw_extra_hash_identity"
append_hashes 2 >>"$raw_extra_hash_identity"
printf '%s\n' ';' >>"$raw_extra_hash_identity"
raw_extra_hash_tail=$(tail -c 7 "$raw_extra_hash_identity" | od -An -t x1 | tr -d '[:space:]')
[ "$raw_extra_hash_tail" = "22412223233b0a" ] || {
    echo "raw extra-hash fixture did not contain the expected delimiter bytes" >&2
    exit 1
}
assert_rejected "$spec" "$raw_extra_hash_identity" "identity source parser rejected the input"

raw_256_identity="$temporary_dir/invalid-raw-256-hash-spec.rs"
cp "$identity" "$raw_256_identity"
printf '%s' 'const INVALID_RAW_256_HASH: &str = r' >>"$raw_256_identity"
append_hashes 256 >>"$raw_256_identity"
printf '%s' '"A"' >>"$raw_256_identity"
append_hashes 256 >>"$raw_256_identity"
printf '%s\n' ';' >>"$raw_256_identity"
raw_256_prefix=$(tail -c 520 "$raw_256_identity" | od -An -t x1 | tr -d '[:space:]')
case "$raw_256_prefix" in
    *"2241"*) ;;
    *)
        echo "256-hash raw fixture did not contain an actual quote/body boundary" >&2
        exit 1
        ;;
esac
assert_rejected "$spec" "$raw_256_identity" "identity source parser rejected the input"

raw_tab_identity="$temporary_dir/raw-tab-byte-char-spec.rs"
cp "$identity" "$raw_tab_identity"
printf '%s' "const RAW_TAB_BYTE: u8 = b'" >>"$raw_tab_identity"
printf '\011' >>"$raw_tab_identity"
printf '%s\n' "';" >>"$raw_tab_identity"
raw_tab_suffix=$(tail -c 4 "$raw_tab_identity" | od -An -t x1 | tr -d '[:space:]')
if [ "$raw_tab_suffix" != "09273b0a" ]; then
    echo "raw TAB byte-character fixture did not contain a literal 0x09 before its closing quote" >&2
    exit 1
fi
assert_rejected "$spec" "$raw_tab_identity" "identity source parser rejected the input"

raw_tab_char_identity="$temporary_dir/raw-tab-char-spec.rs"
cp "$identity" "$raw_tab_char_identity"
printf '%s' "const RAW_TAB_CHAR: char = '" >>"$raw_tab_char_identity"
printf '\011' >>"$raw_tab_char_identity"
printf '%s\n' "';" >>"$raw_tab_char_identity"
raw_tab_char_suffix=$(tail -c 4 "$raw_tab_char_identity" | od -An -t x1 | tr -d '[:space:]')
if [ "$raw_tab_char_suffix" != "09273b0a" ]; then
    echo "raw TAB char fixture did not contain a literal 0x09 before its closing quote" >&2
    exit 1
fi
assert_rejected "$spec" "$raw_tab_char_identity" "identity source parser rejected the input"

assert_raw_cr_rejected \
    "$temporary_dir/raw-cr-string-spec.rs" \
    'const RAW_CR_STRING: &str = r"A' \
    'B";' \
    "0d42223b0a" \
    5
assert_raw_cr_rejected \
    "$temporary_dir/raw-cr-byte-string-spec.rs" \
    'const RAW_CR_BYTE_STRING: &[u8] = br"A' \
    'B";' \
    "0d42223b0a" \
    5
assert_raw_cr_rejected \
    "$temporary_dir/raw-cr-hash-string-spec.rs" \
    'const RAW_CR_HASH_STRING: &str = r#"A' \
    'B"#;' \
    "0d4222233b0a" \
    6
assert_raw_cr_rejected \
    "$temporary_dir/raw-cr-byte-hash-string-spec.rs" \
    'const RAW_CR_BYTE_HASH_STRING: &[u8] = br##"A' \
    'B"##;' \
    "0d422223233b0a" \
    7

unterminated_raw_identity="$temporary_dir/unterminated-raw-spec.rs"
cp "$identity" "$unterminated_raw_identity"
printf '%s\n' 'const MALFORMED_RAW: &str = r"unterminated' >>"$unterminated_raw_identity"
assert_rejected "$spec" "$unterminated_raw_identity" "identity source parser rejected the input"

unterminated_raw_hash_identity="$temporary_dir/unterminated-raw-hash-spec.rs"
cp "$identity" "$unterminated_raw_hash_identity"
printf '%s\n' 'const MALFORMED_RAW_HASH: &str = r###"unterminated' >>"$unterminated_raw_hash_identity"
assert_rejected "$spec" "$unterminated_raw_hash_identity" "identity source parser rejected the input"

unterminated_raw_byte_identity="$temporary_dir/unterminated-raw-byte-spec.rs"
cp "$identity" "$unterminated_raw_byte_identity"
printf '%s\n' 'const MALFORMED_RAW_BYTE: &[u8] = br"unterminated' >>"$unterminated_raw_byte_identity"
assert_rejected "$spec" "$unterminated_raw_byte_identity" "identity source parser rejected the input"

unterminated_raw_byte_hash_identity="$temporary_dir/unterminated-raw-byte-hash-spec.rs"
cp "$identity" "$unterminated_raw_byte_hash_identity"
printf '%s\n' 'const MALFORMED_RAW_BYTE_HASH: &[u8] = br##"unterminated' >>"$unterminated_raw_byte_hash_identity"
assert_rejected "$spec" "$unterminated_raw_byte_hash_identity" "identity source parser rejected the input"

unterminated_string_identity="$temporary_dir/unterminated-string-spec.rs"
cp "$identity" "$unterminated_string_identity"
printf '%s\n' 'const MALFORMED_STRING: &str = "unterminated' >>"$unterminated_string_identity"
assert_rejected "$spec" "$unterminated_string_identity" "identity source parser rejected the input"

unterminated_char_identity="$temporary_dir/unterminated-char-spec.rs"
cp "$identity" "$unterminated_char_identity"
printf '%s\n' "const MALFORMED_CHAR: char = 'x" >>"$unterminated_char_identity"
assert_rejected "$spec" "$unterminated_char_identity" "identity source parser rejected the input"

unterminated_byte_char_identity="$temporary_dir/unterminated-byte-char-spec.rs"
cp "$identity" "$unterminated_byte_char_identity"
printf '%s\n' "const MALFORMED_BYTE_CHAR: u8 = b'x;" >>"$unterminated_byte_char_identity"
assert_rejected "$spec" "$unterminated_byte_char_identity" "identity source parser rejected the input"

malformed_byte_char_identity="$temporary_dir/malformed-byte-char-spec.rs"
cp "$identity" "$malformed_byte_char_identity"
printf '%s\n' "const MALFORMED_BYTE_ESCAPE: u8 = b'\\x7;" >>"$malformed_byte_char_identity"
assert_rejected "$spec" "$malformed_byte_char_identity" "identity source parser rejected the input"

unterminated_comment_identity="$temporary_dir/unterminated-comment-spec.rs"
cp "$identity" "$unterminated_comment_identity"
printf '%s\n' '/* unterminated nested /* block comment' >>"$unterminated_comment_identity"
assert_rejected "$spec" "$unterminated_comment_identity" "identity source parser rejected the input"

if ! run_r17_cli --parse-benchmark-identity "$identity" \
    >"$temporary_dir/r17-canonical-cli.out" \
    2>"$temporary_dir/r17-canonical-cli.err"; then
    echo "canonical identity CLI invocation failed" >&2
    exit 1
fi
if [ -s "$temporary_dir/r17-canonical-cli.err" ]; then
    echo "canonical identity CLI invocation emitted stderr" >&2
    exit 1
fi

operator_fixture='const INVALID_CMP: bool = (1 < 2, '\''a);'
operator_hex=$(printf '%s' "$operator_fixture" | od -An -t x1 | tr -d '[:space:]')
case "$operator_hex" in
    *2831203c20322c202761293b*) ;;
    *)
        echo "operator fixture did not preserve the required raw bytes" >&2
        exit 1
        ;;
esac
assert_r17_differential_case invalid_cmp invalid "$operator_fixture"
assert_r17_differential_case valid_label_comma valid \
    "fn VALID_LABEL_COMMA() { let _ = (1u8, 'lbl: loop { break 'lbl; }); }"
assert_r17_differential_case valid_macro_start valid \
    "macro_rules! VALID_MACRO_START { ('a) => {}; }"
assert_r17_differential_case invalid_after_where invalid \
    "fn VALID_WHERE<'a>() where 'a: 'a {} const INVALID_AFTER_WHERE: bool = 1, 'a;"
assert_r17_differential_case invalid_after_raw_identifier invalid \
    "fn r#where() {} const INVALID_AFTER_RAW_IDENTIFIER: bool = 1, 'a;"
raw_suffix_hex=$(printf '%s' 'r#"A"#B' | od -An -t x1 | tr -d '[:space:]')
if [ "$raw_suffix_hex" != "72232241222342" ]; then
    echo "raw suffix fixture did not preserve the required literal bytes" >&2
    exit 1
fi
assert_r17_differential_case raw_one_short_body invalid \
    'const CASE_RAW_ONE_SHORT_BODY: &str = r#"A"#B;'

printed=$("$script_dir/print-benchmark-spec.sh" "$spec" "$identity")
if ! printf '%s\n' "$printed" | grep -F "benchmark_spec_sha256=$actual" >/dev/null; then
    echo "benchmark-spec printer did not report the verified SHA-256" >&2
    exit 1
fi
