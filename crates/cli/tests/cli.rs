//! The `ruster` command without a running router.

use std::process::Command;

fn ruster(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ruster"))
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

#[test]
fn check_says_whether_a_configuration_file_is_good() {
    let dir = std::env::temp_dir().join(format!("ruster-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.toml");
    std::fs::write(
        &good,
        "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv4 = \"192.0.2.1/24\"\n",
    )
    .unwrap();
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "[[interface]]\nname = \"lan\"\n").unwrap();
    let (ok, text) = ruster(&["check", good.to_str().unwrap()]);
    assert!(ok, "{text}");
    assert!(text.contains("ok (1 interfaces, 0 routes)"), "{text}");
    let (ok, text) = ruster(&["check", bad.to_str().unwrap()]);
    assert!(!ok);
    assert!(text.contains("mac"), "{text}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn show_and_route_fail_clearly_without_a_router() {
    let (ok, text) = ruster(&["--run-dir", "/nonexistent", "show"]);
    assert!(!ok);
    assert!(text.contains("fe/state.sock"), "{text}");
    let (ok, text) = ruster(&["route", "add", "10.0.0.0/8", "dev", "lan"]);
    assert!(!ok);
    assert!(text.contains("--source"), "{text}");
    let (ok, text) = ruster(&["route", "add", "--source", "x", "10.0.0.1/8", "dev", "lan"]);
    assert!(!ok);
    assert!(text.contains("not a prefix"), "{text}");
}
