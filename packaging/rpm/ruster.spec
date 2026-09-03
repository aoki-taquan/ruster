# UNVERIFIED: rpmbuild is not installed in the development environment used
# for this repository.  This spec has not been syntax-checked or built here.
# Do not treat it as verified until rpmbuild runs successfully on an RPM host.

Name:           ruster
Version:        0.2.0
Release:        1%{?dist}
Summary:        Rust packet forwarding daemon
License:        MIT OR Apache-2.0
URL:            https://example.invalid/ruster
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
Requires:       glibc
Requires:       libgcc
BuildArch:      x86_64

%description
ruster is a Rust packet forwarding daemon for Linux AF_PACKET interfaces.
It provides bounded packet processing with a systemd service integration.

%prep
%autosetup -p1

%build
cargo build --release -p ruster-cli

%install
rm -rf %{buildroot}
install -D -m 0755 target/release/ruster \
    %{buildroot}%{_bindir}/ruster
install -D -m 0644 packaging/systemd/ruster.service \
    %{buildroot}%{_unitdir}/ruster.service
install -D -m 0640 packaging/deb/etc/ruster/config.toml \
    %{buildroot}%{_sysconfdir}/ruster/config.toml
install -D -m 0644 packaging/README.md \
    %{buildroot}%{_docdir}/ruster/README.md
install -D -m 0644 packaging/systemd/README.md \
    %{buildroot}%{_docdir}/ruster/systemd.md

%pre
if ! getent group ruster >/dev/null 2>&1; then
    /usr/sbin/groupadd --system ruster
fi
if ! getent passwd ruster >/dev/null 2>&1; then
    /usr/sbin/useradd --system \
        --gid ruster \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        ruster
fi

%post
install -d -o root -g ruster -m 0750 %{_sysconfdir}/ruster
if [ -f %{_sysconfdir}/ruster/config.toml ]; then
    chown root:ruster %{_sysconfdir}/ruster/config.toml
    chmod 0640 %{_sysconfdir}/ruster/config.toml
fi
if command -v systemctl >/dev/null 2>&1 \
    && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ "$1" -eq 0 ] || [ "$1" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1 \
        && [ -d /run/systemd/system ]; then
        systemctl stop ruster.service >/dev/null 2>&1 || :
    fi
fi

%postun
if [ "$1" -eq 0 ] || [ "$1" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1 \
        && [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || :
    fi
fi
# There is no separate RPM purge transaction.  The service identity is kept,
# and %config(noreplace) protects local configuration during upgrades.

%files
%{_bindir}/ruster
%{_unitdir}/ruster.service
%dir %attr(0750,root,root) %{_sysconfdir}/ruster
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/ruster/config.toml
%doc %{_docdir}/ruster/README.md
%doc %{_docdir}/ruster/systemd.md

%changelog
* Tue Sep 01 2026 Ruster developers <ruster@example.invalid> - 0.2.0-1
- Package the ruster daemon, systemd unit, example configuration, and docs.
