#!/usr/bin/env bash
# Runs every netns test on AF_XDP and on AF_PACKET and says which failed.
# Run as root, after `cargo build`:  sudo scripts/netns-all.sh [target/debug]
set -uo pipefail
bin=${1:-target/debug}
here=$(dirname "$(realpath "$0")")
failed=()
for backend in af-xdp af-packet; do
  for test in "$here"/netns-*.sh; do
    name=$(basename "$test" .sh)
    [[ "$name" == netns-all ]] && continue
    if FE_BACKEND=$backend bash "$test" "$bin" >/dev/null 2>&1; then
      echo "pass  $backend $name"
    else
      echo "FAIL  $backend $name"
      failed+=("$backend $name")
    fi
  done
done
# The skeleton again with two forwarding workers on two queues.
if FE_BACKEND=af-xdp FE_WORKERS=2 bash "$here/netns-skeleton.sh" "$bin" >/dev/null 2>&1; then
  echo "pass  af-xdp netns-skeleton (2 workers)"
else
  echo "FAIL  af-xdp netns-skeleton (2 workers)"
  failed+=("af-xdp netns-skeleton (2 workers)")
fi
(( ${#failed[@]} == 0 )) || { echo "failed: ${failed[*]}"; exit 1; }
echo "all passed"
