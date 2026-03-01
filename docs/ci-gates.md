# CI Gate Definitions

This document describes the CI gates for the ruster project, their purpose,
and the process for promoting informational gates to required status.

---

## Overview

ruster uses two E2E workflow files to separate **required** gates (must pass
to merge) from **informational** gates (expected to fail during early
development). Both run on every push to `main` and on pull requests targeting
`main`.

| Workflow file | Name | Status | Suites |
|---------------|------|--------|--------|
| `e2e-baseline.yml` | E2E Baseline (L2/L3 -- required) | **Required** | `l2`, `l3` |
| `e2e-strict.yml` | E2E Strict (dataplane-only -- required) | **Required** | `dataplane` |

In addition to E2E, the following workflows also run:

| Workflow file | Name | Status |
|---------------|------|--------|
| `ci.yml` | CI (build, test, lint, fmt) | **Required** |
| `rfc-check.yml` | RFC-DEVIATION lint | **Required** |
| `runner-health.yml` | Self-hosted runner health check | Informational |

---

## Gate Details

### E2E Baseline (`e2e-baseline.yml`) -- REQUIRED

**What it checks:**

- L2 connectivity: ARP resolution, MAC forwarding between LAN and WAN hosts
  through the ruster node.
- L3 connectivity: IP routing, ICMP reachability across subnets via kernel
  forwarding configured by ruster.

**Why it is required:**

These tests validate the core v0.1 functionality -- process startup and basic
L2/L3 packet forwarding. Failures here indicate a regression in fundamental
router behavior.

**Topology:** containerlab with `ruster`, `lan-host`, `wan-host` nodes.

**Environment variable:** `CLAB_TOPO_NAME=ruster-e2e-baseline-${{ github.run_id }}`
ensures unique topology names for concurrent runs.

### E2E Strict (`e2e-strict.yml`) -- REQUIRED

**What it checks:**

- Dataplane-only forwarding: Deploys a strict containerlab topology where
  kernel `ip_forward=0` on all nodes. Traffic can ONLY pass through the
  ruster dataplane.
- Three-phase validation:
  1. Without ruster: ping fails (no kernel bypass)
  2. With ruster: ping succeeds (dataplane forwarding works)
  3. Without ruster: ping fails again (confirms ruster was forwarding)

**Why it is required:**

The strict test validates that ruster's dataplane can independently forward
packets without relying on kernel forwarding. This was promoted from
informational to required after demonstrating 4+ consecutive passing runs
on `main`.

**Environment variable:** `CLAB_TOPO_NAME=ruster-e2e-strict-${{ github.run_id }}`
ensures unique topology names for concurrent runs.

---

## Promotion History

### E2E Strict: Informational → Required (2026-03-01)

The E2E Strict gate was promoted from informational to required after
verifying 4+ consecutive passing runs on `main`. Changes made:

1. Removed `continue-on-error: true` from the job definition.
2. Renamed workflow from "informational" to "required".
3. Updated this document to reflect the new status.
4. **Remaining:** Add the strict job name to branch protection rules in
   GitHub repository settings.

---

## Topology Naming

Both workflows use the `CLAB_TOPO_NAME` environment variable with a
`github.run_id` suffix to ensure unique containerlab topology names. This
prevents collisions when multiple CI runs execute concurrently on the same
self-hosted runner.

- Baseline: `ruster-e2e-baseline-<run_id>`
- Strict: `ruster-e2e-strict-<run_id>`
