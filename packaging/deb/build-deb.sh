#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
package_dir=$script_dir
pkg_work=$repo_root/.pkgwork

# Keep cargo's temporary files, the staging tree, ldd report, and resulting
# package out of the worktree.  This is intentionally independent of the
# caller's TMPDIR so a normal invocation cannot scatter build files elsewhere.
export TMPDIR=$pkg_work
mkdir -p "$pkg_work"

control=$package_dir/DEBIAN/control
version=$(awk -F': ' '$1 == "Version" { print $2; exit }' "$control")
architecture=$(dpkg --print-architecture)
declared_architecture=$(awk -F': ' '$1 == "Architecture" { print $2; exit }' "$control")

if [ "$architecture" != "$declared_architecture" ]; then
    printf '%s\n' "control targets $declared_architecture, but dpkg reports $architecture" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    printf 'usage: %s [output.deb]\n' "$0" >&2
    exit 2
fi

output=${1:-$pkg_work/ruster_${version}_${architecture}.deb}
case "$output" in
    /*) ;;
    *) output=$repo_root/$output ;;
esac

# The output is an artifact of this local packaging workflow.  Keeping it in
# .pkgwork also makes an accidental invocation unable to add a .deb to the
# source tree.
case "$output" in
    "$pkg_work"/*) ;;
    *)
        printf '%s\n' "output must be inside $pkg_work" >&2
        exit 2
        ;;
esac
mkdir -p "$(dirname -- "$output")"

if command -v cargo >/dev/null 2>&1; then
    cargo_command=$(command -v cargo)
else
    printf '%s\n' "cargo is not on PATH; export the requested Rust toolchain first" >&2
    exit 1
fi

(cd "$repo_root" && "$cargo_command" build --release -p ruster-cli)
binary=$repo_root/target/release/ruster
if [ ! -x "$binary" ]; then
    printf '%s\n' "release binary is missing or not executable: $binary" >&2
    exit 1
fi

ldd_report=$pkg_work/ldd-ruster.txt
if ! ldd "$binary" >"$ldd_report"; then
    printf '%s\n' "ldd failed for $binary" >&2
    cat "$ldd_report" >&2
    exit 1
fi
if grep -q 'not found' "$ldd_report"; then
    printf '%s\n' "ldd reported an unresolved library" >&2
    cat "$ldd_report" >&2
    exit 1
fi

printf '%s\n' "ldd $binary:" >&2
cat "$ldd_report" >&2

# Resolve every absolute library path shown by ldd to the Debian package that
# owns it.  This prevents Depends from being added by guesswork.  The loader
# line has no => marker, so it is parsed separately.
ldd_paths=$(awk '
    $2 == "=>" && $3 ~ /^\// { print $3 }
    $1 ~ /^\// && $2 ~ /^\(/ { print $1 }
' "$ldd_report")
detected_depends_file=$pkg_work/ldd-depends.txt
: >"$detected_depends_file"
for library_path in $ldd_paths; do
    resolved_path=$(readlink -f "$library_path")
    owner_record=$(dpkg-query -S "$resolved_path" 2>/dev/null || true)
    if [ -z "$owner_record" ]; then
        printf '%s\n' "no installed Debian package owns ldd library $resolved_path" >&2
        exit 1
    fi
    owner_package=${owner_record%%:*}
    printf '%s\n' "$owner_package" >>"$detected_depends_file"
done
detected_depends=$(sort -u "$detected_depends_file" | paste -sd, -)
declared_depends=$(awk -F': ' '$1 == "Depends" { print $2; exit }' "$control" \
    | tr ',' '\n' \
    | sed 's/[[:space:]]//g;/^$/d' \
    | sort -u \
    | paste -sd, -)

printf 'Depends selected from ldd: %s\n' "$detected_depends" >&2
if [ "$detected_depends" != "$declared_depends" ]; then
    printf '%s\n' "control Depends does not match the ldd-derived packages" >&2
    printf 'declared: %s\n' "$declared_depends" >&2
    printf 'detected: %s\n' "$detected_depends" >&2
    exit 1
fi

stage=$(mktemp -d "$pkg_work/ruster-deb.XXXXXX")
cleanup() {
    rm -rf "$stage"
}
trap cleanup EXIT HUP INT TERM

mkdir -p \
    "$stage/DEBIAN" \
    "$stage/usr/bin" \
    "$stage/lib/systemd/system" \
    "$stage/etc/ruster" \
    "$stage/usr/share/doc/ruster"

# Do not let the caller's umask turn package directories into group-writable
# paths.  The configuration directory is intentionally stricter because the
# service account reads the 0640 conffile from it.
chmod 0755 \
    "$stage/etc" \
    "$stage/usr" \
    "$stage/usr/bin" \
    "$stage/usr/share" \
    "$stage/usr/share/doc" \
    "$stage/usr/share/doc/ruster" \
    "$stage/lib" \
    "$stage/lib/systemd" \
    "$stage/lib/systemd/system"
chmod 0750 "$stage/etc/ruster"

install -m 0644 "$package_dir/DEBIAN/control" "$stage/DEBIAN/control"
install -m 0644 "$package_dir/DEBIAN/conffiles" "$stage/DEBIAN/conffiles"
install -m 0755 "$package_dir/DEBIAN/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$package_dir/DEBIAN/prerm" "$stage/DEBIAN/prerm"
install -m 0755 "$package_dir/DEBIAN/postrm" "$stage/DEBIAN/postrm"

install -m 0755 "$binary" "$stage/usr/bin/ruster"
install -m 0644 "$repo_root/packaging/systemd/ruster.service" \
    "$stage/lib/systemd/system/ruster.service"
install -m 0640 "$package_dir/etc/ruster/config.toml" \
    "$stage/etc/ruster/config.toml"
install -m 0644 "$repo_root/packaging/README.md" \
    "$stage/usr/share/doc/ruster/README.md"
install -m 0644 "$repo_root/packaging/systemd/README.md" \
    "$stage/usr/share/doc/ruster/systemd.md"

rm -f "$output"
fakeroot dpkg-deb --build "$stage" "$output"
printf '%s\n' "$output"
