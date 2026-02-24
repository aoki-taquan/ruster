#!/bin/bash
# soak-test.sh — Main orchestrator for ruster long-running stability tests
#
# Runs the ruster binary for an extended period while monitoring for:
#   - Process stability (no crashes)
#   - Memory stability (no unbounded RSS growth)
#   - CPU anomalies
#   - File descriptor leaks
#
# Modes:
#   standalone    — Runs ruster binary with health monitoring (default)
#   containerlab  — Full E2E with containerlab topology and real traffic
#
# Environment variables:
#   SOAK_DURATION_MIN    — Test duration in minutes (default: 30)
#   SOAK_MODE            — "standalone" or "containerlab" (default: standalone)
#   SOAK_CHECK_INTERVAL  — Health check interval in seconds (default: 60)
#   SOAK_OUTPUT_DIR      — Output directory for reports (default: auto-generated)
#   RUSTER_BIN           — Path to ruster binary (default: auto-detected from cargo)
#   RUSTER_CONFIG        — Path to router.toml config (default: tests/containerlab/configs/ruster.toml)
#   CLAB_TOPO_NAME       — Containerlab topology name (default: ruster-e2e)
#
# Usage:
#   bash soak-test.sh                              # 30-min standalone
#   SOAK_DURATION_MIN=5 bash soak-test.sh          # 5-min quick soak
#   SOAK_MODE=containerlab bash soak-test.sh       # containerlab mode

set -uo pipefail

# ── Configuration ───────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SOAK_DURATION_MIN="${SOAK_DURATION_MIN:-30}"
SOAK_DURATION_SEC=$((SOAK_DURATION_MIN * 60))
SOAK_MODE="${SOAK_MODE:-standalone}"
SOAK_CHECK_INTERVAL="${SOAK_CHECK_INTERVAL:-60}"
CLAB_TOPO_NAME="${CLAB_TOPO_NAME:-ruster-e2e}"
export CLAB_TOPO_NAME

# Output directory
if [ -z "${SOAK_OUTPUT_DIR:-}" ]; then
    SOAK_OUTPUT_DIR="${SCRIPT_DIR}/results/$(date '+%Y%m%d-%H%M%S')"
fi

# Binary and config paths
RUSTER_BIN="${RUSTER_BIN:-${PROJECT_ROOT}/target/release/ruster}"
RUSTER_CONFIG="${RUSTER_CONFIG:-${PROJECT_ROOT}/tests/containerlab/configs/ruster.toml}"

THRESHOLDS_FILE="${SCRIPT_DIR}/thresholds.toml"
METRICS_FILE="${SOAK_OUTPUT_DIR}/metrics.tsv"
REPORT_FILE="${SOAK_OUTPUT_DIR}/report.md"

# PID tracking
RUSTER_PID=""
TRAFFIC_PID=""
RUSTER_DIED=""

# ── Logging ─────────────────────────────────────────────
log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak] $*"
}

log_error() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [soak] ERROR: $*" >&2
}

# ── Cleanup handler ─────────────────────────────────────
cleanup() {
    local exit_code=$?
    log "Cleaning up..."

    # Stop traffic generator
    if [ -n "$TRAFFIC_PID" ] && kill -0 "$TRAFFIC_PID" 2>/dev/null; then
        log "Stopping traffic generator (PID: $TRAFFIC_PID)"
        kill "$TRAFFIC_PID" 2>/dev/null || true
        wait "$TRAFFIC_PID" 2>/dev/null || true
    fi

    # Stop ruster process
    if [ -n "$RUSTER_PID" ] && kill -0 "$RUSTER_PID" 2>/dev/null; then
        log "Stopping ruster (PID: $RUSTER_PID)"
        kill "$RUSTER_PID" 2>/dev/null || true
        # Give it a moment for graceful shutdown
        sleep 2
        if kill -0 "$RUSTER_PID" 2>/dev/null; then
            log "Force-killing ruster (PID: $RUSTER_PID)"
            kill -9 "$RUSTER_PID" 2>/dev/null || true
        fi
        wait "$RUSTER_PID" 2>/dev/null || true
    fi

    # Destroy containerlab topology if in containerlab mode
    if [ "$SOAK_MODE" = "containerlab" ]; then
        log "Destroying containerlab topology (name: ${CLAB_TOPO_NAME})..."
        sudo containerlab destroy --name "$CLAB_TOPO_NAME" --cleanup 2>/dev/null || true
    fi

    log "Cleanup complete (exit code: $exit_code)"
    exit "$exit_code"
}

trap cleanup EXIT INT TERM

# ── Pre-flight checks ──────────────────────────────────

preflight() {
    log "Running pre-flight checks..."

    # Check thresholds file
    if [ ! -f "$THRESHOLDS_FILE" ]; then
        log_error "Thresholds file not found: $THRESHOLDS_FILE"
        exit 1
    fi

    # Build ruster if binary not found
    if [ ! -f "$RUSTER_BIN" ]; then
        log "Ruster binary not found at $RUSTER_BIN — building..."
        if ! cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1; then
            log_error "Failed to build ruster"
            exit 1
        fi

        # Re-check after build
        if [ ! -f "$RUSTER_BIN" ]; then
            log_error "Ruster binary still not found after build: $RUSTER_BIN"
            log "Available binaries:"
            ls -la "$PROJECT_ROOT/target/release/" 2>/dev/null | head -20
            exit 1
        fi
    fi

    log "  Binary:     $RUSTER_BIN"
    log "  Config:     $RUSTER_CONFIG"
    log "  Mode:       $SOAK_MODE"
    log "  Duration:   ${SOAK_DURATION_MIN} min (${SOAK_DURATION_SEC}s)"
    log "  Interval:   ${SOAK_CHECK_INTERVAL}s"
    log "  Output:     $SOAK_OUTPUT_DIR"

    # Containerlab-specific checks
    if [ "$SOAK_MODE" = "containerlab" ]; then
        if ! command -v containerlab > /dev/null 2>&1; then
            log_error "containerlab not found in PATH"
            exit 1
        fi
        if ! command -v docker > /dev/null 2>&1; then
            log_error "docker not found in PATH"
            exit 1
        fi
    fi

    log "Pre-flight checks passed"
}

# ── Create output directory ────────────────────────────

setup_output() {
    mkdir -p "$SOAK_OUTPUT_DIR"

    # Write TSV header as a comment
    printf '# timestamp\tpid_alive\trss_kb\tcpu_percent\topen_fds\tuptime_sec\n' > "$METRICS_FILE"

    log "Output directory created: $SOAK_OUTPUT_DIR"
}

# ── Start ruster process ──────────────────────────────

start_ruster() {
    log "Starting ruster..."

    local ruster_log="${SOAK_OUTPUT_DIR}/ruster.log"

    # Start ruster with the test config
    "$RUSTER_BIN" --config "$RUSTER_CONFIG" > "$ruster_log" 2>&1 &
    RUSTER_PID=$!

    log "Ruster started (PID: $RUSTER_PID)"

    # Give it a moment to initialize
    sleep 2

    # Check if process is still running — fail fast if it exited
    if ! kill -0 "$RUSTER_PID" 2>/dev/null; then
        log_error "Ruster process exited during startup"
        log_error "Ruster log (last 30 lines):"
        tail -30 "$ruster_log" 2>/dev/null | while IFS= read -r line; do
            log_error "  $line"
        done
        log_error "Soak test requires a running ruster process"
        exit 1
    fi
}

# ── Start traffic generation ──────────────────────────

start_traffic() {
    log "Starting traffic generation (mode: $SOAK_MODE)..."

    bash "$SCRIPT_DIR/traffic-gen.sh" "$SOAK_MODE" "$SOAK_DURATION_SEC" &
    TRAFFIC_PID=$!

    log "Traffic generator started (PID: $TRAFFIC_PID)"
}

# ── Deploy containerlab topology ──────────────────────

deploy_containerlab() {
    if [ "$SOAK_MODE" != "containerlab" ]; then
        return
    fi

    log "Deploying containerlab topology (name: ${CLAB_TOPO_NAME})..."

    cd "$PROJECT_ROOT/tests/containerlab"
    if ! sudo containerlab deploy --topo topology.yml --name "$CLAB_TOPO_NAME"; then
        log_error "Failed to deploy containerlab topology"
        exit 1
    fi

    # Wait for topology to settle
    log "Waiting for topology to settle (10s)..."
    sleep 10

    log "Containerlab topology deployed"
}

# ── Health monitoring loop ────────────────────────────

run_health_checks() {
    log "Starting health monitoring (interval: ${SOAK_CHECK_INTERVAL}s)..."

    local elapsed=0
    local check_count=0

    while [ "$elapsed" -lt "$SOAK_DURATION_SEC" ]; do
        # Collect metrics
        check_count=$((check_count + 1))
        bash "$SCRIPT_DIR/check-health.sh" "$RUSTER_PID" "$METRICS_FILE" > /dev/null 2>&1

        # Check if process died unexpectedly
        if ! kill -0 "$RUSTER_PID" 2>/dev/null; then
            log_error "Ruster process died at ${elapsed}s (check #${check_count})"
            log_error "This is a stability failure — ruster must survive the full soak duration"
            # Record the death in metrics
            bash "$SCRIPT_DIR/check-health.sh" "$RUSTER_PID" "$METRICS_FILE" > /dev/null 2>&1
            # Set flag to indicate early termination
            RUSTER_DIED=true
            break
        fi

        # Progress logging (every 5 minutes or at the end of each check)
        if [ $((elapsed % 300)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then
            # Read latest RSS from metrics
            local latest_rss
            latest_rss=$(tail -1 "$METRICS_FILE" | cut -f3)
            latest_rss="${latest_rss:-0}"
            local rss_mb
            rss_mb=$(awk "BEGIN { printf \"%.1f\", $latest_rss / 1024.0 }")
            log "Progress: ${elapsed}s / ${SOAK_DURATION_SEC}s | RSS: ${rss_mb} MB | Check #${check_count}"
        fi

        # Sleep until next check
        remaining=$((SOAK_DURATION_SEC - elapsed))
        if [ "$remaining" -le 0 ]; then
            break
        fi

        if [ "$remaining" -lt "$SOAK_CHECK_INTERVAL" ]; then
            sleep "$remaining"
            elapsed=$SOAK_DURATION_SEC
        else
            sleep "$SOAK_CHECK_INTERVAL"
            elapsed=$((elapsed + SOAK_CHECK_INTERVAL))
        fi
    done

    # Final health check
    bash "$SCRIPT_DIR/check-health.sh" "$RUSTER_PID" "$METRICS_FILE" > /dev/null 2>&1

    log "Health monitoring complete (${check_count} checks over ${elapsed}s)"
}

# ── Generate report ───────────────────────────────────

generate_report() {
    log "Generating report..."

    # Filter out comment lines from metrics before passing to report.sh
    local clean_metrics="${SOAK_OUTPUT_DIR}/metrics-clean.tsv"
    grep -v '^#' "$METRICS_FILE" > "$clean_metrics" 2>/dev/null || true

    if ! bash "$SCRIPT_DIR/report.sh" "$clean_metrics" "$THRESHOLDS_FILE" "$REPORT_FILE" "$SOAK_DURATION_SEC"; then
        log "RESULT: FAIL — threshold violations detected"
        return 1
    else
        log "RESULT: PASS — all thresholds within limits"
        return 0
    fi
}

# ── Main ──────────────────────────────────────────────

main() {
    echo ""
    echo "================================================================"
    echo "  ruster Soak Test"
    echo "================================================================"
    echo ""
    echo "  Mode:       ${SOAK_MODE}"
    echo "  Duration:   ${SOAK_DURATION_MIN} min"
    echo "  Started:    $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo ""

    preflight
    setup_output

    # Deploy containerlab if needed
    deploy_containerlab

    # Start ruster
    start_ruster

    # Collect baseline metric
    log "Collecting baseline metric..."
    bash "$SCRIPT_DIR/check-health.sh" "$RUSTER_PID" "$METRICS_FILE"

    # Start traffic generation in background
    start_traffic

    # Run health monitoring loop (blocks for soak duration)
    run_health_checks

    # Stop traffic generator
    if [ -n "$TRAFFIC_PID" ] && kill -0 "$TRAFFIC_PID" 2>/dev/null; then
        kill "$TRAFFIC_PID" 2>/dev/null || true
        wait "$TRAFFIC_PID" 2>/dev/null || true
    fi
    TRAFFIC_PID=""

    # If ruster died during the soak, force FAIL
    local result=0
    if [ "$RUSTER_DIED" = "true" ]; then
        log_error "Ruster process did not survive the full soak duration — forcing FAIL"
        result=1
    fi

    # Generate report and check thresholds
    if ! generate_report; then
        result=1
    fi

    echo ""
    echo "================================================================"
    echo "  Soak Test Complete"
    echo "================================================================"
    echo ""
    echo "  Ended:      $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "  Report:     $REPORT_FILE"
    echo "  Metrics:    $METRICS_FILE"
    echo ""

    exit "$result"
}

main
