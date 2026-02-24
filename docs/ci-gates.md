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
| `e2e-strict.yml` | E2E Strict (NAT/FW -- informational) | Informational | `nat`, `fw` |

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

### E2E Strict (`e2e-strict.yml`) -- INFORMATIONAL

**What it checks:**

- NAT: Source NAT (SNAT/masquerade) for LAN-to-WAN traffic, correct
  translation and de-translation of addresses/ports.
- FW: Stateful firewall rules, connection tracking, default-deny policies.

**Why it is informational (expected-fail in v0.1):**

v0.1 uses `MockPacketIo` for the dataplane, which does not perform real
packet manipulation. NAT and firewall require a real dataplane to rewrite
headers and track connections. These tests are expected to fail until the
dataplane is implemented with real packet I/O (targeted for v0.2+).

The workflow uses `continue-on-error: true` at the job level so failures
do not block PR merges or mark the overall CI status as failed.

**Environment variable:** `CLAB_TOPO_NAME=ruster-e2e-strict-${{ github.run_id }}`
ensures unique topology names for concurrent runs.

**Current expected-fail status:**

- `nat` suite: Expected to fail (MockPacketIo cannot rewrite packet headers)
- `fw` suite: Expected to fail (MockPacketIo cannot enforce firewall rules)

---

## Promoting Strict Tests to Required

When the real dataplane is implemented and NAT/FW tests pass reliably, follow
these steps to promote the strict gate to required:

1. **Verify stability.** Confirm that `e2e-strict.yml` passes consistently
   on `main` for at least 5 consecutive runs.

2. **Remove `continue-on-error`.** In `e2e-strict.yml`, delete the
   `continue-on-error: true` line from the job definition.

3. **Add to branch protection.** In the GitHub repository settings under
   *Branches > Branch protection rules > main*, add the strict job name
   (`E2E Strict (NAT + FW -- expected-fail in v0.1)`) to the list of
   required status checks.

4. **Update this document.** Change the strict gate status from
   "Informational" to "Required" in the table above and remove the
   expected-fail notes.

5. **Rename the workflow.** Update the `name` fields to remove
   "expected-fail" and "informational" labels. Suggested:
   - Workflow name: `E2E Strict (NAT/FW -- required)`
   - Job name: `E2E Strict (NAT + FW)`

---

## Topology Naming

Both workflows use the `CLAB_TOPO_NAME` environment variable with a
`github.run_id` suffix to ensure unique containerlab topology names. This
prevents collisions when multiple CI runs execute concurrently on the same
self-hosted runner.

- Baseline: `ruster-e2e-baseline-<run_id>`
- Strict: `ruster-e2e-strict-<run_id>`
