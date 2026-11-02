//! The `ruster run` config open: regular files only, strict permissions.

use std::path::Path;

use super::{
    check_directory, check_permissions, load_validated_regular, parse_effective_uid, LoadError,
};

#[test]
fn strict_permissions_refuse_writable_or_foreign_files() {
    assert_eq!(check_permissions(0o100_644, 1000, 1000), Ok(()));
    assert_eq!(check_permissions(0o100_600, 0, 1000), Ok(()), "root-owned");
    assert_eq!(check_permissions(0o100_400, 0, 0), Ok(()));
    assert_eq!(
        check_permissions(0o100_664, 1000, 1000),
        Err("WRITABLE_BY_OTHERS")
    );
    assert_eq!(
        check_permissions(0o100_646, 0, 0),
        Err("WRITABLE_BY_OTHERS")
    );
    assert_eq!(
        check_permissions(0o100_644, 1001, 1000),
        Err("UNTRUSTED_OWNER")
    );
    assert_eq!(
        LoadError::Insecure("UNTRUSTED_OWNER").render(),
        "stage=permissions code=UNTRUSTED_OWNER"
    );
    // Directories on the way: owner root or euid; no group/other write
    // except a root-owned sticky directory.
    assert_eq!(check_directory(0o040_755, 0, 1000), Ok(()));
    assert_eq!(check_directory(0o040_700, 1000, 1000), Ok(()));
    assert_eq!(check_directory(0o041_777, 0, 1000), Ok(()), "/tmp");
    assert_eq!(
        check_directory(0o041_777, 1000, 1000),
        Err("WRITABLE_DIRECTORY"),
        "sticky but not root-owned"
    );
    assert_eq!(
        check_directory(0o040_775, 1000, 1000),
        Err("WRITABLE_DIRECTORY")
    );
    assert_eq!(check_directory(0o040_757, 0, 0), Err("WRITABLE_DIRECTORY"));
    assert_eq!(
        check_directory(0o040_755, 1001, 1000),
        Err("UNTRUSTED_DIRECTORY")
    );
    let status = "Name:\truster\nUid:\t1000\t0\t0\t0\nGid:\t1\t1\t1\t1\n";
    assert_eq!(parse_effective_uid(status), Some(0));
    assert_eq!(parse_effective_uid("Uid:\t1000\n"), None);
    assert_eq!(parse_effective_uid("Uid:\t1\tx\t1\t1\n"), None);
    assert_eq!(parse_effective_uid("Gid:\t1\t1\n"), None);
}

#[cfg(target_os = "linux")]
#[test]
fn run_config_opens_regular_files_only() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/m1/router-v1.toml");
    // The checked-out fixture is the test user's and not group/other
    // writable unless the checkout umask says otherwise; only assert the
    // strict result when the mode allows it.
    assert!(load_validated_regular(&fixture, false).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(&fixture).expect("fixture");
        let expected = check_permissions(
            metadata.mode(),
            metadata.uid(),
            parse_effective_uid(&std::fs::read_to_string("/proc/self/status").expect("status"))
                .expect("euid"),
        );
        let strict = load_validated_regular(&fixture, true).map(drop);
        let euid =
            parse_effective_uid(&std::fs::read_to_string("/proc/self/status").expect("status"))
                .expect("euid");
        let canonical = std::fs::canonicalize(&fixture).expect("canonical");
        let expected = expected.and_then(|()| {
            canonical.ancestors().skip(1).try_for_each(|directory| {
                let metadata = std::fs::metadata(directory).expect("directory");
                check_directory(metadata.mode(), metadata.uid(), euid)
            })
        });
        match expected {
            Ok(()) => assert!(strict.is_ok()),
            Err(code) => assert!(matches!(strict, Err(LoadError::Insecure(c)) if c == code)),
        }
    }
    for not_a_file in ["/dev/null", "/"] {
        assert!(
            matches!(
                load_validated_regular(Path::new(not_a_file), false),
                Err(LoadError::NotAFile) | Err(LoadError::Read(_))
            ),
            "{not_a_file}"
        );
    }
    assert!(matches!(
        load_validated_regular(Path::new("/dev/null"), true),
        Err(LoadError::NotAFile)
    ));
}
