#!/bin/bash
# rfc-deviation-registry.sh -- Generate RFC-DEVIATION registry from source
#
# Scans all Rust source files for RFC-DEVIATION comment blocks and
# writes a TSV registry to docs/rfc-deviations.tsv.
#
# This is a convenience wrapper around rfc-deviation-lint.sh --registry.
#
# Usage:
#   bash scripts/rfc-deviation-registry.sh
#
# Output:
#   docs/rfc-deviations.tsv  -- Tab-separated registry of all deviations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec bash "${SCRIPT_DIR}/rfc-deviation-lint.sh" --registry
