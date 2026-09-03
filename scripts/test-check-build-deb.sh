#!/bin/sh
set -eu

# Packaging regression harness.  Keep this file POSIX sh so it can also run in
# the small build images used by the packaging jobs.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ruster-package-test.XXXXXX")
trap 'rc=$?; rm -rf "$WORK"; exit "$rc"' 0 HUP INT TERM

fail()
{
	echo "test-check-build-deb.sh: FAIL: $*" >&2
	exit 1
}

ok()
{
	echo "test-check-build-deb.sh: ok: $*"
}

need_file()
{
	[ -f "$1" ] || fail "missing file: $1"
}

assert_file_contains()
{
	_file=$1
	_pattern=$2
	_description=$3
	awk -v pat="$_pattern" 'index($0, pat) { found = 1 } END { exit(found ? 0 : 1) }' "$_file" \
		|| fail "$_description"
}

assert_file_matches()
{
	_file=$1
	_pattern=$2
	_description=$3
	awk -v pat="$_pattern" '$0 ~ pat { found = 1 } END { exit(found ? 0 : 1) }' "$_file" \
		|| fail "$_description"
}

assert_log_has()
{
	_log=$1
	_pattern=$2
	_description=$3
	assert_file_matches "$_log" "$_pattern" "$_description"
}

assert_log_lacks()
{
	_log=$1
	_pattern=$2
	_description=$3
	if awk -v pat="$_pattern" '$0 ~ pat { found = 1 } END { exit(found ? 0 : 1) }' "$_log"; then
		fail "$_description"
	fi
}

assert_file_lacks_literal()
{
	_file=$1
	_needle=$2
	_description=$3
	if awk -v needle="$_needle" 'index($0, needle) { found = 1 } END { exit(found ? 0 : 1) }' "$_file"; then
		fail "$_description"
	fi
}

POSTINST=$REPO_ROOT/packaging/deb/DEBIAN/postinst
PRERM=$REPO_ROOT/packaging/deb/DEBIAN/prerm
DEBIAN_CONTROL=$REPO_ROOT/packaging/deb/DEBIAN/control
RPM_SPEC=$REPO_ROOT/packaging/rpm/ruster.spec
BUILD_DEB=$REPO_ROOT/packaging/deb/build-deb.sh

need_file "$POSTINST"
need_file "$PRERM"
need_file "$DEBIAN_CONTROL"
need_file "$RPM_SPEC"
need_file "$BUILD_DEB"

fake_bin=$WORK/bin
mkdir -p "$fake_bin"

make_fake()
{
	_name=$1
	body=$2
	printf '%s\n' "$body" > "$fake_bin/$_name"
	chmod +x "$fake_bin/$_name"
}

make_fake chown '#!/bin/sh
set -eu
path=
for arg
do
    path=$arg
done
[ -n "$path" ]
resolved=$(readlink -f -- "$path")
printf "chown path=%s resolved=%s args=%s\n" "$path" "$resolved" "$*" >> "${PKG_TEST_LOG:?}"
exit 0'
make_fake chmod '#!/bin/sh
set -eu
path=
for arg
do
    path=$arg
done
[ -n "$path" ]
resolved=$(readlink -f -- "$path")
printf "chmod path=%s resolved=%s args=%s\n" "$path" "$resolved" "$*" >> "${PKG_TEST_LOG:?}"
exit 0'
make_fake install '#!/bin/sh
set -eu
path=
for arg
do
    path=$arg
done
[ -n "$path" ]
resolved=$(readlink -f -- "$path")
printf "install path=%s resolved=%s args=%s\n" "$path" "$resolved" "$*" >> "${PKG_TEST_LOG:?}"
exit 0'
make_fake getent '#!/bin/sh
set -eu
printf "getent %s\n" "$*" >> "${PKG_TEST_LOG:?}"
exit 2'
make_fake groupadd '#!/bin/sh
set -eu
printf "groupadd %s\n" "$*" >> "${PKG_TEST_LOG:?}"
exit 0'
make_fake useradd '#!/bin/sh
set -eu
printf "useradd %s\n" "$*" >> "${PKG_TEST_LOG:?}"
exit 0'
make_fake systemctl '#!/bin/sh
set -eu
printf "systemctl %s\n" "$*" >> "${PKG_TEST_LOG:?}"
case "${1-}" in
  is-active|is-enabled) exit "${PKG_TEST_SYSTEMCTL_QUERY_RC:-0}" ;;
  *) exit "${PKG_TEST_SYSTEMCTL_RC:-0}" ;;
esac'

copy_with_root()
{
	_src=$1
	_dst=$2
	_root=$3
	# Replacing both common absolute spellings keeps the fixture independent of
	# whether the maintainer script uses /etc/ruster or /etc/ruster/config.toml.
	sed "s#/etc/ruster/config.toml#$_root/etc/ruster/config.toml#g; s#/etc/ruster#$_root/etc/ruster#g; s#/run/systemd/system#$_root/run/systemd/system#g; s#/run/ruster-upgrade-needed#$_root/run/ruster-upgrade-needed#g" "$_src" > "$_dst"
	chmod +x "$_dst"
}

run_script()
{
	_script=$1
	shift
	PKG_TEST_LOG=$WORK/operations.log
	export PKG_TEST_LOG
	: > "$PKG_TEST_LOG"
	PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
		sh "$_script" "$@"
}

assert_no_secret_target_changes()
{
	_fixture_name=$1
	_fixture=$2
	_log=$3
	_secret=$4
	assert_file_lacks_literal "$_log" "resolved=$_secret" \
		"$_fixture_name reached the symlink target"
}

test_debian_dependency()
{
	awk -F': ' -v dependency=passwd '
		$1 == "Depends" {
			count = split($2, dependencies, ",")
			for (i = 1; i <= count; i++) {
				gsub(/[[:space:]]/, "", dependencies[i])
				if (dependencies[i] == dependency) {
					found = 1
				}
			}
		}
		END { exit(found ? 0 : 1) }
	' "$DEBIAN_CONTROL" || fail "Debian control Depends does not declare passwd"
	ok "Debian control declares passwd in Depends"
}

test_build_deb_dependency_parser()
{
	assert_file_contains "$BUILD_DEB" 'maintainer_script_depends=passwd' \
		"build-deb.sh does not identify passwd as a non-ELF maintainer dependency"
	assert_file_contains "$BUILD_DEB" 'comm -12 "$declared_depends_file" "$maintainer_script_depends_file"' \
		"build-deb.sh does not select declared non-ELF maintainer dependencies"
	assert_file_contains "$BUILD_DEB" 'comm -23 "$declared_depends_file" "$maintainer_script_depends_file"' \
		"build-deb.sh does not exclude non-ELF maintainer dependencies from ELF comparison"
	ok "build-deb.sh treats passwd as a non-ELF maintainer dependency"
}

test_debian_symlink_safety()
{
	_root=$WORK/debian-root
	mkdir -p "$_root/etc/ruster" "$WORK/secret-dir"
	printf '%s\n' 'secret = true' > "$WORK/secret-config.toml"
	printf '%s\n' 'private' > "$WORK/secret-dir/private"

	# A config-file symlink must not cause chmod/chown/install to reach outside
	# the package root.
	ln -s "$WORK/secret-config.toml" "$_root/etc/ruster/config.toml"
	copy_with_root "$POSTINST" "$WORK/debian-file-postinst" "$_root"
	if run_script "$WORK/debian-file-postinst" configure 1.0; then :; else
		fail "Debian postinst failed in config-file symlink fixture"
	fi
	assert_no_secret_target_changes "Debian config-file symlink" "$_root/etc/ruster/config.toml" "$PKG_TEST_LOG" "$WORK/secret-config.toml"

	# A config-directory symlink must be treated with the same boundary.
	rm -f "$_root/etc/ruster/config.toml"
	rmdir "$_root/etc/ruster"
	ln -s "$WORK/secret-dir" "$_root/etc/ruster"
	copy_with_root "$POSTINST" "$WORK/debian-dir-postinst" "$_root"
	if run_script "$WORK/debian-dir-postinst" configure 1.0; then :; else
		fail "Debian postinst failed in config-directory symlink fixture"
	fi
	assert_no_secret_target_changes "Debian config-directory symlink" "$_root/etc/ruster" "$PKG_TEST_LOG" "$WORK/secret-dir"
	case "$(readlink "$_root/etc/ruster")" in
		"$WORK/secret-dir") : ;;
		*) fail "Debian config-directory symlink fixture was unexpectedly replaced" ;;
	esac
	ok "Debian postinst rejects file and directory symlink escapes"
}

test_rpm_static()
{
	assert_file_matches "$RPM_SPEC" 'Requires[[:space:]]*[(](pre|pretrans)[^)]*[)][[:space:]]*:[[:space:]]*shadow-utils' \
		"RPM spec lacks Requires(pre): shadow-utils"

	# Match the complete %files entries so ownership cannot be inferred from a
	# path containing "ruster" or from an unrelated %attr entry.
	awk '
		/^%files([[:space:]]|$)/ { in_files = 1; next }
		in_files && /^%changelog([[:space:]]|$)/ { in_files = 0 }
		in_files && NF == 3 && \
			$1 == "%dir" && \
			$2 == "%attr(0750,root,ruster)" && \
			$3 == "%{_sysconfdir}/ruster" { directory = 1 }
		in_files && NF == 3 && \
			$1 == "%config(noreplace)" && \
			$2 == "%attr(0640,root,ruster)" && \
			$3 == "%{_sysconfdir}/ruster/config.toml" { config = 1 }
		END { exit(directory && config ? 0 : 1) }
	' "$RPM_SPEC" || fail "RPM %files lacks exact root/ruster ownership for directory and config.toml"

	awk '
		/^%post([[:space:]]|$)/ { in_post = 1; next }
		in_post && /^%[A-Za-z]/ { exit(found ? 0 : 1) }
		in_post && /-L|readlink|symlink|test[[:space:]].*-e|[!-]e/ { found = 1 }
		END { exit(found ? 0 : 1) }
	' "$RPM_SPEC" || fail "RPM %post lacks a static symlink-safety condition"
	ok "RPM spec declares dependency, permissions, and %post boundary check"
}

extract_section()
{
	_spec=$1
	_section=$2
	_output=$3
	awk -v wanted="$_section" '
		$0 ~ "^%" wanted "([[:space:]]|$)" { in_section = 1; next }
		in_section && /^%[A-Za-z]/ { exit }
		in_section { print }
	' "$_spec" > "$_output"
	[ -s "$_output" ]
}

scriptlet_or_empty()
{
	_section=$1
	_output=$2
	if extract_section "$RPM_SPEC" "$_section" "$_output"; then
		return 0
	fi
	: > "$_output"
	return 1
}

test_rpm_symlink_safety()
{
	rpm_post=$WORK/rpm-post
	rpm_post_expanded=$WORK/rpm-post-expanded
	if ! extract_section "$RPM_SPEC" post "$rpm_post"; then
		fail "RPM %post scriptlet could not be extracted"
	fi
	# Expand the spec macro before applying the fixture root.  The extracted
	# scriptlet otherwise addresses the literal %{_sysconfdir} path.
	sed 's#%{_sysconfdir}#/etc#g' "$rpm_post" > "$rpm_post_expanded"

	_root=$WORK/rpm-symlink-root
	mkdir -p "$_root/etc/ruster" "$WORK/rpm-secret-dir"
	printf '%s\n' 'secret = true' > "$WORK/rpm-secret-config.toml"
	printf '%s\n' 'private' > "$WORK/rpm-secret-dir/private"

	# A config-file symlink must not cause the extracted RPM %post to reach its
	# target with chown or chmod.
	ln -s "$WORK/rpm-secret-config.toml" "$_root/etc/ruster/config.toml"
	copy_with_root "$rpm_post_expanded" "$WORK/rpm-file-post" "$_root"
	PKG_TEST_LOG=$WORK/rpm-file-post.log
	export PKG_TEST_LOG
	: > "$PKG_TEST_LOG"
	PATH=$fake_bin:/usr/bin:/bin sh "$WORK/rpm-file-post" 2
	assert_no_secret_target_changes "RPM config-file symlink" \
		"$_root/etc/ruster/config.toml" "$PKG_TEST_LOG" \
		"$WORK/rpm-secret-config.toml"

	# A config-directory symlink must not make either operation reach outside
	# the package root.
	rm -f "$_root/etc/ruster/config.toml"
	rmdir "$_root/etc/ruster"
	ln -s "$WORK/rpm-secret-dir" "$_root/etc/ruster"
	copy_with_root "$rpm_post_expanded" "$WORK/rpm-dir-post" "$_root"
	PKG_TEST_LOG=$WORK/rpm-dir-post.log
	export PKG_TEST_LOG
	: > "$PKG_TEST_LOG"
	PATH=$fake_bin:/usr/bin:/bin sh "$WORK/rpm-dir-post" 2
	assert_no_secret_target_changes "RPM config-directory symlink" \
		"$_root/etc/ruster" "$PKG_TEST_LOG" "$WORK/rpm-secret-dir"
	case "$(readlink "$_root/etc/ruster")" in
		"$WORK/rpm-secret-dir") : ;;
		*) fail "RPM config-directory symlink fixture was unexpectedly replaced" ;;
	esac
	ok "RPM %post executes file and directory symlink safety checks"
}

run_lifecycle()
{
	_prerm_script=$1
	_postinst_script=$2
	_mode=$3
	_root=$WORK/lifecycle-$_mode
	mkdir -p "$_root/etc/ruster" "$_root/run/systemd/system"
	copy_with_root "$PRERM" "$WORK/prerm-$_mode" "$_root"
	copy_with_root "$POSTINST" "$WORK/postinst-$_mode" "$_root"
	if [ -n "$_prerm_script" ]; then
		copy_with_root "$_prerm_script" "$WORK/rpm-prerm-$_mode" "$_root"
		_prerm=$WORK/rpm-prerm-$_mode
	else
		_prerm=$WORK/prerm-$_mode
	fi
	if [ -n "$_postinst_script" ]; then
		copy_with_root "$_postinst_script" "$WORK/rpm-postinst-$_mode" "$_root"
		_postinst=$WORK/rpm-postinst-$_mode
	else
		_postinst=$WORK/postinst-$_mode
	fi

	PKG_TEST_LOG=$WORK/lifecycle-$_mode.log
	export PKG_TEST_LOG
	: > "$PKG_TEST_LOG"
	case "$_mode" in
		debian)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" upgrade 1.0
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" configure 1.0
			;;
		rpm)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" 1
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" 2
			;;
		*)
			fail "unknown lifecycle mode: $_mode"
			;;
	esac

	assert_log_has "$PKG_TEST_LOG" 'systemctl stop' "$_mode lifecycle did not stop before upgrade"
	assert_log_has "$PKG_TEST_LOG" 'systemctl is-active --quiet ruster.service' \
		"$_mode lifecycle did not check that the service was active"
	assert_log_has "$PKG_TEST_LOG" 'systemctl is-enabled --quiet ruster.service' \
		"$_mode lifecycle did not check that the service was enabled"
	assert_log_has "$PKG_TEST_LOG" 'systemctl daemon-reload' "$_mode lifecycle did not reload systemd"
	assert_log_has "$PKG_TEST_LOG" 'systemctl restart' "$_mode lifecycle did not restart after upgrade"
	awk '
		/systemctl stop/ { stop = NR }
		/systemctl daemon-reload/ { reload = NR }
		/systemctl restart/ { restart = NR }
		END { exit(stop && reload && restart && stop < reload && reload < restart ? 0 : 1) }
	' "$PKG_TEST_LOG" || fail "$_mode lifecycle order is not stop, daemon-reload, restart"
	[ ! -e "$_root/run/ruster-upgrade-needed" ] || fail "$_mode lifecycle did not remove the upgrade marker"
	[ ! -L "$_root/run/ruster-upgrade-needed" ] || fail "$_mode lifecycle left an upgrade-marker symlink"

	PKG_TEST_LOG=$WORK/lifecycle-$_mode-noop.log
	: > "$PKG_TEST_LOG"
	case "$_mode" in
		debian)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" install 1.0
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" configure 1.0
			;;
		rpm)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" 0
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" 1
			;;
		*)
			fail "unknown lifecycle mode: $_mode"
			;;
	esac
	assert_log_lacks "$PKG_TEST_LOG" 'systemctl restart' "$_mode install/disabled lifecycle restarted"

	PKG_TEST_LOG=$WORK/lifecycle-$_mode-erase.log
	: > "$PKG_TEST_LOG"
	case "$_mode" in
		debian)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" remove 1.0
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" configure 1.0
			;;
		rpm)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_prerm" 0
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=1 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" 1
			;;
		*)
			fail "unknown lifecycle mode: $_mode"
			;;
	esac
	assert_log_lacks "$PKG_TEST_LOG" 'systemctl restart' "$_mode erase/disabled lifecycle restarted"

	# A marker left by an unrelated or interrupted transaction must not make a
	# fresh install restart the service.  Debian's configure hook has no old
	# version argument in this case; RPM's %post receives $1=1.
	stale_marker=$_root/run/ruster-upgrade-needed
	: > "$stale_marker"
	PKG_TEST_LOG=$WORK/lifecycle-$_mode-stale.log
	export PKG_TEST_LOG
	: > "$PKG_TEST_LOG"
	case "$_mode" in
		debian)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" configure
			;;
		rpm)
			PATH=$fake_bin:/usr/bin:/bin PKG_TEST_SYSTEMCTL_QUERY_RC=0 PKG_TEST_SYSTEMCTL_RC=0 \
				sh "$_postinst" 1
			;;
		*)
			fail "unknown lifecycle mode: $_mode"
			;;
	esac
	assert_log_lacks "$PKG_TEST_LOG" 'systemctl restart' \
		"$_mode normal install consumed a stale upgrade marker"
	rm -f "$stale_marker"
}

test_debian_lifecycle()
{
	assert_file_contains "$PRERM" upgrade "Debian prerm lacks the upgrade argument"
	assert_file_contains "$POSTINST" daemon-reload "Debian postinst lacks daemon-reload lifecycle handling"
	run_lifecycle '' '' debian
	ok "Debian upgrade, stale-marker, and no-op cases"
}

test_rpm_lifecycle()
{
	rpm_prerm=$WORK/rpm-prerm
	rpm_postinst_raw=$WORK/rpm-postinst-raw
	rpm_postinst=$WORK/rpm-postinst
	if scriptlet_or_empty preun "$rpm_prerm" \
		&& scriptlet_or_empty post "$rpm_postinst_raw"; then
		# The spec macro is expanded before the fixture root is substituted.  A
		# literal macro would address the caller's cwd instead of the temp root.
		sed 's#%{_sysconfdir}#/etc#g' "$rpm_postinst_raw" > "$rpm_postinst"
		assert_file_lacks_literal "$rpm_postinst" '%{_sysconfdir}' \
			"RPM lifecycle fixture retained the %{_sysconfdir} macro"
		chmod +x "$rpm_prerm" "$rpm_postinst"
		if run_lifecycle "$rpm_prerm" "$rpm_postinst" rpm; then
			ok "RPM upgrade, stale-marker, and no-op lifecycle scriptlets"
		else
			fail "RPM scriptlet lifecycle execution failed"
		fi
	else
		# If rpm/rpmbuild is unavailable, still make the lifecycle contract
		# explicit from the spec instead of silently skipping this test.
		assert_file_contains "$RPM_SPEC" '%preun' "RPM spec lacks %preun scriptlet"
		assert_file_contains "$RPM_SPEC" '%post' "RPM spec lacks %post scriptlet"
		assert_file_contains "$RPM_SPEC" 'upgrade' "RPM lifecycle lacks upgrade argument"
		assert_file_contains "$RPM_SPEC" 'daemon-reload' "RPM lifecycle lacks daemon-reload"
		assert_file_matches "$RPM_SPEC" 'restart|try-restart' "RPM lifecycle lacks restart condition"
		assert_file_matches "$RPM_SPEC" 'marker|upgrade' "RPM lifecycle lacks an explicit marker"
		ok "RPM lifecycle statically checked (scriptlet extraction unavailable)"
	fi
}

test_build_deb_boundary()
{
	readme_snapshot=$WORK/README.md
	readme_hash=$(sha256sum "$REPO_ROOT/README.md" | awk '{ print $1 }')
	cp "$REPO_ROOT/README.md" "$readme_snapshot"
	build_log=$WORK/build.log
	: > "$build_log"

	make_fake cargo '#!/bin/sh
set -eu
printf "cargo reached\n" >> "${PKG_TEST_LOG:?}"
exit 99'
	make_fake fakeroot '#!/bin/sh
set -eu
printf "fakeroot reached\n" >> "${PKG_TEST_LOG:?}"
exit 99'

	# Run the repository's script so its script_dir/repo_root resolution is
	# exercised.  The invalid .pkgwork/../README.md input must be diagnosed
	# before cargo/fakeroot is reached, and the real repository README must stay.
	if (cd "$REPO_ROOT" && PATH=$fake_bin:/usr/bin:/bin PKG_TEST_LOG="$build_log" \
		sh "$BUILD_DEB" .pkgwork/../README.md > "$WORK/build.stdout" 2> "$WORK/build.stderr"); then
		fail "build-deb.sh accepted .pkgwork/../README.md"
	fi
	assert_file_matches "$WORK/build.stderr" 'boundary|outside|inside|README|path|invalid' \
		"build-deb.sh did not report a useful output-boundary diagnostic"
	cmp -s "$readme_snapshot" "$REPO_ROOT/README.md" \
		|| fail "build-deb.sh modified README.md content"
	[ "$(sha256sum "$REPO_ROOT/README.md" | awk '{ print $1 }')" = "$readme_hash" ] \
		|| fail "build-deb.sh modified README.md hash"
	assert_log_lacks "$build_log" 'cargo reached' "build-deb.sh reached cargo before path validation"
	assert_log_lacks "$build_log" 'fakeroot reached' "build-deb.sh reached fakeroot before path validation"
	ok "build-deb.sh rejects output-boundary escape before heavy build"
}

test_debian_symlink_safety
test_debian_dependency
test_build_deb_dependency_parser
test_rpm_static
test_rpm_symlink_safety
test_debian_lifecycle
test_rpm_lifecycle
test_build_deb_boundary

echo "test-check-build-deb.sh: PASS"
