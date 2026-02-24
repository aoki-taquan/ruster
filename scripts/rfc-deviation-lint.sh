#!/bin/bash
# rfc-deviation-lint.sh -- Validate and catalog RFC-DEVIATION comments
#
# Scans all Rust source files for RFC-DEVIATION comment blocks and
# validates they have required fields: reason, impact, issue, plan.
#
# Usage:
#   bash scripts/rfc-deviation-lint.sh              # Lint only
#   bash scripts/rfc-deviation-lint.sh --registry   # Generate registry file
#   bash scripts/rfc-deviation-lint.sh --json       # Output JSON report
#
# Exit codes:
#   0  All RFC-DEVIATION comments have required fields
#   1  One or more blocks are missing required fields

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
REQUIRED_FIELDS=("reason" "impact" "issue" "plan")
REGISTRY_FILE="docs/rfc-deviations.tsv"
MODE="lint"  # lint | registry | json
EXIT_CODE=0
DEVIATION_COUNT=0
ERROR_COUNT=0

# Temporary directory for collecting results
TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT
ERRORS_FILE="$TMPDIR_WORK/errors.txt"

: > "$ERRORS_FILE"

# ── Parse arguments ───────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --registry)
            MODE="registry"
            shift
            ;;
        --json)
            MODE="json"
            shift
            ;;
        --help|-h)
            echo "Usage: bash scripts/rfc-deviation-lint.sh [--registry|--json]"
            echo ""
            echo "Options:"
            echo "  --registry  Generate docs/rfc-deviations.tsv registry file"
            echo "  --json      Output machine-readable JSON report"
            echo "  --help      Show this help"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ── Extract field value from a block ──────────────────────
# Reads a field value from comment lines like "// reason: some text"
extract_field() {
    local block="$1"
    local field="$2"
    local match
    match=$(echo "$block" | grep -E "//[[:space:]]*${field}:" || true)
    if [ -n "$match" ]; then
        echo "$match" | head -1 | sed -E "s|.*//[[:space:]]*${field}:[[:space:]]*||"
    fi
}

# ── Scan all .rs files ────────────────────────────────────
# Each deviation is stored as a separate file in TMPDIR_WORK/devN
while IFS= read -r file; do
    # Get line numbers of RFC-DEVIATION markers
    line_nums=$(grep -n "RFC-DEVIATION:" "$file" 2>/dev/null | cut -d: -f1 || true)

    for line_num in $line_nums; do
        DEVIATION_COUNT=$((DEVIATION_COUNT + 1))
        dev_file="$TMPDIR_WORK/dev${DEVIATION_COUNT}"

        # Extract the block: RFC-DEVIATION line + next 10 lines
        block=$(sed -n "${line_num},$((line_num + 10))p" "$file")

        # Validate required fields
        for field in "${REQUIRED_FIELDS[@]}"; do
            has_field=$(echo "$block" | grep -cE "//[[:space:]]*${field}:" || true)
            if [ "$has_field" -eq 0 ]; then
                echo "ERROR: ${file}:${line_num} -- RFC-DEVIATION missing '${field}:'" >> "$ERRORS_FILE"
                ERROR_COUNT=$((ERROR_COUNT + 1))
                EXIT_CODE=1
            fi
        done

        # Extract field values
        reason_val=$(extract_field "$block" "reason")
        impact_val=$(extract_field "$block" "impact")
        issue_val=$(extract_field "$block" "issue")
        plan_val=$(extract_field "$block" "plan")

        # Check for empty field values (field present but no value)
        for field in "${REQUIRED_FIELDS[@]}"; do
            val=$(extract_field "$block" "$field")
            has_field=$(echo "$block" | grep -cE "//[[:space:]]*${field}:" || true)
            if [ "$has_field" -gt 0 ] && [ -z "$val" ]; then
                echo "ERROR: ${file}:${line_num} -- RFC-DEVIATION field '${field}:' is empty" >> "$ERRORS_FILE"
                ERROR_COUNT=$((ERROR_COUNT + 1))
                EXIT_CODE=1
            fi
        done

        # Store deviation data in individual file (avoids TSV empty-field issues)
        {
            echo "FILE=${file}"
            echo "LINE=${line_num}"
            echo "REASON=${reason_val}"
            echo "IMPACT=${impact_val}"
            echo "ISSUE=${issue_val}"
            echo "PLAN=${plan_val}"
        } > "$dev_file"
    done
done < <(find . -name "*.rs" -not -path "./target/*" -not -path "./.worktrees/*" -not -path "./.claude/*" | sort)

# ── Helper: iterate stored deviations ────────────────────
# Reads a field from a deviation file
read_dev_field() {
    local dev_file="$1"
    local field="$2"
    grep "^${field}=" "$dev_file" | sed "s/^${field}=//"
}

# ── Output: Lint mode (default) ──────────────────────────
if [ "$MODE" = "lint" ]; then
    # Print errors
    if [ -s "$ERRORS_FILE" ]; then
        echo "=== RFC-DEVIATION Lint Errors ==="
        cat "$ERRORS_FILE"
        echo ""
    fi

    # Print summary
    echo "=== RFC-DEVIATION Summary ==="
    echo "Total deviations found: ${DEVIATION_COUNT}"
    echo "Errors: ${ERROR_COUNT}"

    if [ "$DEVIATION_COUNT" -gt 0 ]; then
        echo ""
        echo "--- Deviation List ---"
        printf '%-50s %-6s %-8s\n' "FILE" "LINE" "ISSUE"
        local i
        for i in $(seq 1 "$DEVIATION_COUNT"); do
            dev_file="$TMPDIR_WORK/dev${i}"
            [ -f "$dev_file" ] || continue
            d_file=$(read_dev_field "$dev_file" "FILE")
            d_line=$(read_dev_field "$dev_file" "LINE")
            d_issue=$(read_dev_field "$dev_file" "ISSUE")
            printf '%-50s %-6s %-8s\n' "$d_file" "$d_line" "$d_issue"
        done
    fi

    if [ "$EXIT_CODE" -eq 0 ]; then
        echo ""
        echo "OK: All RFC-DEVIATION comments have required fields."
    else
        echo ""
        echo "FAIL: ${ERROR_COUNT} error(s) found in RFC-DEVIATION comments."
    fi
fi

# ── Output: JSON mode ────────────────────────────────────
if [ "$MODE" = "json" ]; then
    JSON_FILE="$TMPDIR_WORK/report.json"

    echo '{' > "$JSON_FILE"
    echo '  "total_deviations": '"${DEVIATION_COUNT}"',' >> "$JSON_FILE"
    echo '  "errors": '"${ERROR_COUNT}"',' >> "$JSON_FILE"
    echo '  "valid": '"$([ "$EXIT_CODE" -eq 0 ] && echo "true" || echo "false")"',' >> "$JSON_FILE"
    echo '  "deviations": [' >> "$JSON_FILE"

    if [ "$DEVIATION_COUNT" -gt 0 ]; then
        for i in $(seq 1 "$DEVIATION_COUNT"); do
            dev_file="$TMPDIR_WORK/dev${i}"
            [ -f "$dev_file" ] || continue
            d_file=$(read_dev_field "$dev_file" "FILE")
            d_line=$(read_dev_field "$dev_file" "LINE")
            d_reason=$(read_dev_field "$dev_file" "REASON" | sed 's/"/\\"/g')
            d_impact=$(read_dev_field "$dev_file" "IMPACT" | sed 's/"/\\"/g')
            d_issue=$(read_dev_field "$dev_file" "ISSUE" | sed 's/"/\\"/g')
            d_plan=$(read_dev_field "$dev_file" "PLAN" | sed 's/"/\\"/g')

            if [ "$i" -gt 1 ]; then
                echo ',' >> "$JSON_FILE"
            fi
            cat >> "$JSON_FILE" <<ENTRY
    {
      "file": "${d_file}",
      "line": ${d_line},
      "reason": "${d_reason}",
      "impact": "${d_impact}",
      "issue": "${d_issue}",
      "plan": "${d_plan}"
    }
ENTRY
        done
    fi

    echo '  ],' >> "$JSON_FILE"

    # Add errors array
    echo '  "error_details": [' >> "$JSON_FILE"
    first=true
    if [ -s "$ERRORS_FILE" ]; then
        while IFS= read -r err_line; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ',' >> "$JSON_FILE"
            fi
            err_line=$(echo "$err_line" | sed 's/"/\\"/g')
            echo "    \"${err_line}\"" >> "$JSON_FILE"
        done < "$ERRORS_FILE"
    fi
    echo '  ]' >> "$JSON_FILE"
    echo '}' >> "$JSON_FILE"

    cat "$JSON_FILE"
fi

# ── Output: Registry mode ────────────────────────────────
if [ "$MODE" = "registry" ]; then
    # Print lint errors first (if any)
    if [ -s "$ERRORS_FILE" ]; then
        echo "=== RFC-DEVIATION Lint Errors ==="
        cat "$ERRORS_FILE"
        echo ""
    fi

    # Generate the TSV registry file
    {
        printf '# RFC-DEVIATION Registry\n'
        printf '# Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '# Total deviations: %d\n' "$DEVIATION_COUNT"
        printf '#\n'
        printf 'file\tline\treason\timpact\tissue\tplan\n'
        if [ "$DEVIATION_COUNT" -gt 0 ]; then
            for i in $(seq 1 "$DEVIATION_COUNT"); do
                dev_file="$TMPDIR_WORK/dev${i}"
                [ -f "$dev_file" ] || continue
                d_file=$(read_dev_field "$dev_file" "FILE")
                d_line=$(read_dev_field "$dev_file" "LINE")
                d_reason=$(read_dev_field "$dev_file" "REASON")
                d_impact=$(read_dev_field "$dev_file" "IMPACT")
                d_issue=$(read_dev_field "$dev_file" "ISSUE")
                d_plan=$(read_dev_field "$dev_file" "PLAN")
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$d_file" "$d_line" "$d_reason" "$d_impact" "$d_issue" "$d_plan"
            done
        fi
    } > "$REGISTRY_FILE"

    echo "Registry written to ${REGISTRY_FILE} (${DEVIATION_COUNT} deviation(s))"

    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "OK: All RFC-DEVIATION comments have required fields."
    else
        echo "FAIL: ${ERROR_COUNT} error(s) found in RFC-DEVIATION comments."
    fi
fi

exit "$EXIT_CODE"
