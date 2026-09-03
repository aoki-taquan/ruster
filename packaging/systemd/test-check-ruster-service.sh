#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
unit=${1:-"$script_dir/ruster.service"}

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [unit-file]" >&2
    exit 2
fi
if [ ! -f "$unit" ]; then
    echo "unit file does not exist" >&2
    exit 2
fi

setting() {
    key=$1
    awk -v key="$key" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            value = $0
            sub("^[[:space:]]*" key "[[:space:]]*=", "", value)
            print value
            found = 1
            exit
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$unit"
}

assert_setting() {
    key=$1
    expected=$2
    count=$(awk -v key="$key" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { count++ }
        END { print count + 0 }
    ' "$unit")
    if [ "$count" -ne 1 ]; then
        echo "$key: expected exactly one setting, found $count" >&2
        exit 1
    fi
    if ! actual=$(setting "$key"); then
        actual='<unset>'
    fi
    if [ "$actual" != "$expected" ]; then
        echo "$key: expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

assert_setting CapabilityBoundingSet 'CAP_BPF CAP_NET_ADMIN CAP_NET_RAW'
assert_setting AmbientCapabilities 'CAP_BPF CAP_NET_ADMIN CAP_NET_RAW'
assert_setting RestrictAddressFamilies 'AF_UNIX AF_PACKET AF_XDP AF_NETLINK'

if grep -Eq '(^|[[:space:]])CAP_SYS_ADMIN([[:space:]]|$)' "$unit"; then
    echo 'CAP_SYS_ADMIN must not be granted by the unit' >&2
    exit 1
fi

echo "validated $unit"
