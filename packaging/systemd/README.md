# systemd deployment

`ruster.service` runs the live AF_PACKET backend as the dedicated `ruster`
service user. It expects the installed executable and configuration at the
paths used by the unit:

- executable: `/usr/bin/ruster`
- configuration: `/etc/ruster/config.toml`

## Install

Install a release binary, create the service identity, install the
configuration, and install the unit (run as root):

```sh
sudo install -D -m 0755 target/release/ruster /usr/bin/ruster
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin ruster
sudo install -d -o root -g ruster -m 0750 /etc/ruster
sudo install -o root -g ruster -m 0640 ./config.toml /etc/ruster/config.toml
sudo install -D -m 0644 packaging/systemd/ruster.service \
  /etc/systemd/system/ruster.service
sudo systemctl daemon-reload
sudo systemctl enable --now ruster.service
```

If the `ruster` user already exists, skip `useradd`. Adjust the source path of
`config.toml` as needed, but keep the installed path
`/etc/ruster/config.toml` unless the unit is deliberately customized. The
configuration should be owned by `root:ruster` and readable by the service
user; mode `0640` keeps it out of unrelated users.

`ConditionPathExists` in the unit only checks that
`/etc/ruster/config.toml` exists. It does not prove that the service user can
read the file or that its TOML contents are valid; the ownership/mode setup
and the daemon's validation are separate checks.

Before starting, validate the configuration without requiring privileges:

```sh
/usr/bin/ruster validate /etc/ruster/config.toml
/usr/bin/ruster plan /etc/ruster/config.toml
```

## Reload

`systemctl reload ruster` sends `SIGHUP` through the unit's
`ExecReload=/bin/kill -HUP $MAINPID`. The signal requests a reload; the daemon
then reads, parses, and validates `/etc/ruster/config.toml` before comparing its
exact source bytes with the active configuration identity. The identity is not
a canonicalized semantic value: changing comments, whitespace, or source order
also counts as a change.

Reload is not a zero-downtime operation. When the validated source bytes differ
and the successor is applied, ruster advances the generation, rotates the
UDP/TCP NAT and firewall hash keys, prepares the candidate on the cold path,
and publishes it in place when the successor is eligible. The publication
flushes and rebinds runtime state, so established NAT/firewall sessions and NAT
mappings are lost and traffic is interrupted. Do not assume established
sessions survive a changed reload.

When the validated source bytes are identical, the result is `Unchanged`: the
active generation, storage, and established NAT/firewall state and
session/mapping state remain in use, with no data-plane publication. A parse or
validation failure, or a rejected, deferred, or `RestartRequired` successor,
also leaves the old active publication in place; it is not a successful config
change.

## Permissions and networking

The service runs with `User=ruster` and `Group=ruster`. Creating the
AF_PACKET `SOCK_RAW` sockets require `CAP_NET_RAW`. The AF_XDP path also
uses BPF objects and interface/XDP setup, so it requires `CAP_BPF` and
`CAP_NET_ADMIN`; the unit grants exactly these three through both
`CapabilityBoundingSet` and `AmbientCapabilities`. It intentionally does not
grant `CAP_SYS_ADMIN` or a root-wide capability set. The configured interfaces
must exist and be visible in the service's host network namespace, and the
service user must be able to read the configuration.

The unit uses the minimal address-family allow-list
`AF_UNIX AF_PACKET AF_XDP AF_NETLINK`. `RestrictAddressFamilies=` is an
allow-list unless prefixed with `~`, and systemd documents it as restricting
families available through `socket(2)` (socket activation and `socketpair()`
are separate cases). `AF_PACKET` and `AF_XDP` cover the two packet backends;
`AF_NETLINK` is retained because libc's `if_nametoindex` may use netlink;
`AF_UNIX` is required by the sd_notify datagram. systemd 255.4 in the
development environment accepts all four names; target hosts must use a
systemd build that recognizes `AF_XDP` and a kernel/libc stack that provides
that family. `systemd.exec(5)` documents `RestrictAddressFamilies=` as
available since systemd 211, while the exact family-name table is a systemd
implementation compatibility point, so `systemd-analyze verify` must be run
on the target host as described below.

An AF_PACKET-only deployment can reduce the capability set to
`CAP_NET_RAW` and the address-family list to `AF_UNIX AF_PACKET AF_NETLINK`
in a separately maintained unit. This unit is intentionally shared by both
backend choices: `backend.kind` is a runtime configuration value, and a
single static unit cannot conditionally change its capability or address
family sandbox after parsing that file. Keeping the AF_XDP permissions in the
shared unit avoids a configuration-dependent startup failure; operators that
need the tighter AF_PACKET-only boundary should install a distinct static
unit and configuration contract.

The unit keeps the default network namespace. `NoNewPrivileges`,
`ProtectSystem`, `ProtectHome`, `PrivateTmp`, and the kernel-control
restrictions are filesystem/process hardening that do not remove the listed
networking operations.

## Lifecycle and watchdog

The unit uses `Type=notify`; the daemon must send `READY=1` only after its
interfaces are bound and forwarding can proceed. With `WatchdogSec=30s`,
systemd supplies a 30-second watchdog interval and the daemon sends
`WATCHDOG=1` every 15 seconds, but only while its tick loop is making
progress. On SIGTERM it sends `STOPPING=1` and performs ordered shutdown.

`SHUTDOWN_QUIESCENCE_TIMEOUT_SECS` in the daemon is 5 seconds. The unit uses
`TimeoutStopSec=10s`, calculated as the full 5-second quiescence wait plus a
5-second margin for signal handling, cleanup, and scheduling overhead.
`Restart=on-abnormal` restarts crashes, watchdog expiry, and forced
termination, while clean shutdown and ordinary configuration/permission
failures do not trigger an automatic restart. Automatic abnormal retries are
also limited to three starts per 60 seconds by the unit's start limit.

## Verification

Run the repository's static unit contract test from the checkout:

```sh
packaging/systemd/test-check-ruster-service.sh
```

It checks the exact capability and address-family values and rejects
`CAP_SYS_ADMIN`; it does not silently skip when the unit is missing.

Run the following on the target host after installing the unit:

```sh
systemd-analyze verify /etc/systemd/system/ruster.service
```

`systemd-analyze verify` is environment-dependent and is not a substitute
for starting the service with the intended binary, user, interfaces, and
configuration. Verification status for the packaging files must be recorded
from the environment where that command is actually run; this repository
README does not claim a successful target-host verification result. In the
development workspace, `systemd-analyze verify packaging/systemd/ruster.service`
was run, but returned exit 1 because `/usr/bin/ruster` is not installed there;
target-host verification remains unverified until the binary and `ruster` user
are installed.
