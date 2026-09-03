# ruster packages

This directory describes the Debian and RPM packaging for the `ruster-cli`
release binary.  The packaged executable is `/usr/bin/ruster`; the packaged
unit is the existing `packaging/systemd/ruster.service` copied unchanged to
the platform's systemd unit directory.  The unit therefore expects:

- executable: `/usr/bin/ruster`
- configuration: `/etc/ruster/config.toml`
- service identity: user and group `ruster`

The example configuration uses `eth0`/`eth1` and documentation-only addresses
from RFC 5737.  Replace the interfaces, addresses, routes, neighbors, and MAC
addresses with the host's actual network plan before validating or starting
the daemon.  The service can forward packets and must not be enabled on a
production host without that review.

## Debian package

`packaging/deb/build-deb.sh` builds the release binary, runs `ldd` on
`target/release/ruster`, maps every resolved library to its installed Debian
package with `dpkg-query`, and refuses to build if that result differs from
`DEBIAN/control`.  In the build environment used for this package, `ldd`
reported `libgcc_s.so.1`, `libc.so.6`, and `/lib64/ld-linux-x86-64.so.2`.
They belong to `libgcc-s1` and `libc6` (`libc6` owns both the C library and
the loader), so the minimal binary dependency is:

```
Depends: libc6, libgcc-s1
```

Build the package into `.pkgwork` (the script does not write a `.deb` into
the source tree):

```sh
export PATH="/home/coder/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin:$PATH"
export TMPDIR=/home/coder/ruster/.pkgwork
mkdir -p "$TMPDIR"
packaging/deb/build-deb.sh
```

The script requires `cargo`, `dpkg-deb`, `fakeroot`, `ldd`, and `dpkg-query`.
The resulting package is named like
`.pkgwork/ruster_0.2.0-1_amd64.deb`.  Inspect it without installing it:

```sh
dpkg-deb --info .pkgwork/ruster_0.2.0-1_amd64.deb
dpkg-deb --contents .pkgwork/ruster_0.2.0-1_amd64.deb
```

The package contains the binary, `/lib/systemd/system/ruster.service`, the
example `/etc/ruster/config.toml`, and documentation under
`/usr/share/doc/ruster/`.  The example is registered in `DEBIAN/conffiles`.
Consequently, a locally changed configuration is retained by normal Debian
upgrades.  `remove` also retains it; only an explicit `purge` removes the
file.  The postinst enforces directory mode `0750` and configuration owner
`root:ruster` with mode `0640` after creating the system account.

The maintainer scripts deliberately do not enable or start the service.
`postinst` creates the `ruster` system group/user only when absent and calls
`systemctl daemon-reload` when a running systemd is present.  `prerm` stops
the service for removal or upgrade but never disables it.  `postrm` leaves
the configuration on `remove`, removes it only for `purge`, and removes the
configuration directory only if it is empty.  The `ruster` user and group
are retained even after purge so operator-owned files do not become
unowned and a future package cannot unexpectedly reuse another identity's
UID/GID.  Each script is safe to rerun and treats non-systemd environments
as an install-time environment without a daemon reload/stop operation.

After installing the package, validate the edited configuration first, then
start it explicitly if desired:

```sh
sudo -u ruster /usr/bin/ruster validate /etc/ruster/config.toml
sudo -u ruster /usr/bin/ruster plan /etc/ruster/config.toml
sudo systemctl daemon-reload
sudo systemctl enable --now ruster.service
```

The last command is intentionally an operator action.  It is not performed
by package installation because it would start packet forwarding
unexpectedly.  The existing [systemd deployment guide](systemd/README.md)
contains the same unit's capability, permission, lifecycle, and target-host
verification details.  It installs a manually managed unit under
`/etc/systemd/system`; the Debian package uses Debian's `/lib/systemd/system`
location instead.

## RPM spec

`packaging/rpm/ruster.spec` builds the same release binary from a source
archive named `ruster-0.2.0.tar.gz`, installs the unit using RPM's
`%{_unitdir}`, marks the configuration `%config(noreplace)`, and includes the
two packaging documents.  `%pre`, `%post`, `%preun`, and `%postun` create the
account, fix configuration ownership, reload systemd when available, and
stop the service for erase/upgrade without enabling or starting it.  RPM has
no separate purge transaction; its native `%config(noreplace)` behavior
protects local changes during upgrades, and the service account is retained.

`rpmbuild` is not installed in this environment.  The RPM spec has therefore
not been syntax-checked or built here and is explicitly **unverified**.  Do
not report it as verified.  On an RPM build host, place the source archive in
the normal `SOURCES` directory and run, for example:

```sh
rpmbuild -bb packaging/rpm/ruster.spec
```

The RPM `Requires` entries are the conventional RPM names `glibc` and
`libgcc`; unlike the Debian build, no RPM dependency resolution was possible
in this environment.
