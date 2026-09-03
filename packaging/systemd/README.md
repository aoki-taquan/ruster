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

## Permissions and networking

The service runs with `User=ruster` and `Group=ruster`. Creating the
AF_PACKET `SOCK_RAW` sockets requires `CAP_NET_RAW`, which the unit grants
through `CapabilityBoundingSet` and `AmbientCapabilities`. It intentionally
does not grant root or `CAP_NET_ADMIN`: the daemon resolves configured names
with `if_nametoindex` and binds existing interfaces, but does not configure
interfaces. The configured interfaces must exist and be visible in the
service's host network namespace, and the service user must be able to read
the configuration.

The unit keeps the default network namespace and does not restrict socket
address families. This preserves AF_PACKET forwarding, libc interface-index
lookup (which may use AF_NETLINK), and sd_notify's AF_UNIX datagram socket.
`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, and the
kernel-control restrictions are filesystem/process hardening that do not
remove those networking operations.

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
