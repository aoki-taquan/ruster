#!/bin/bash
# e2e-helpers.sh — Shared helper functions for E2E test scripts
#
# Source this file at the top of each E2E script:
#   source "$(dirname "$0")/e2e-helpers.sh"
#
# Provides:
#   wait_container_ready <container_name> [max_attempts] [interval]
#   wait_all_containers_ready <prefix> <node1> <node2> ...
#   arp_warmup <prefix>

# ── Container readiness ─────────────────────────────

# Wait until a single container accepts docker exec commands.
# Returns 0 on success, 1 if all retries exhausted.
wait_container_ready() {
    local container="$1"
    local max_attempts="${2:-30}"
    local interval="${3:-1}"

    for attempt in $(seq 1 "$max_attempts"); do
        if docker exec "$container" true > /dev/null 2>&1; then
            return 0
        fi
        sleep "$interval"
    done

    echo "[e2e-helpers] ERROR: container ${container} not ready after ${max_attempts} attempts" >&2
    echo "[e2e-helpers]   state: $(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || echo 'not_found')" >&2
    return 1
}

# Wait until all specified nodes accept docker exec commands.
# Usage: wait_all_containers_ready "clab-ruster-e2e" ruster lan-host wan-host
wait_all_containers_ready() {
    local prefix="$1"; shift
    local nodes=("$@")

    echo "[e2e-helpers] Waiting for containers to be ready..."
    for node in "${nodes[@]}"; do
        local container="${prefix}-${node}"
        if ! wait_container_ready "$container" 30 1; then
            echo "[e2e-helpers] ERROR: container ${container} failed readiness check" >&2
            return 1
        fi
        echo "[e2e-helpers]   ${node}: ready"
    done
    echo "[e2e-helpers] All containers ready."
    return 0
}

# ── ARP warmup ──────────────────────────────────────

# Send pings to warm up ARP tables between hosts and ruster.
# This ensures L2 resolution is complete before tests start.
arp_warmup() {
    local prefix="$1"

    echo "[e2e-helpers] ARP warmup: resolving MAC addresses..."
    # lan-host → ruster (192.168.1.1)
    docker exec "${prefix}-lan-host" ping -c 2 -W 2 192.168.1.1 > /dev/null 2>&1 || true
    # wan-host → ruster (10.0.0.1)
    docker exec "${prefix}-wan-host" ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1 || true
    # Wait for ARP entries to settle
    sleep 1
    echo "[e2e-helpers] ARP warmup complete."
}
