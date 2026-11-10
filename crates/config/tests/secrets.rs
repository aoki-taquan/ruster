//! A password does not show in `Debug` or in an error about the text that holds it.

fn pppoe_part(password_line: &str) -> String {
    format!(
        r#"version = {version}
[[pppoe]]
source = "wan1"
interface = "ppp0"
vrf = "default"
parent = "eth1"
mac = "02:00:00:00:00:01"
user = "u"
{password_line}
service = ""
ac-name = []
ipv6 = false
echo-interval = 10
echo-failures = 3
default-route = true
"#,
        version = ruster_config::VERSION
    )
}

#[test]
fn debug_hides_the_password() {
    let pppoe = ruster_config::parse_pppoe_part(&pppoe_part(r#"password = "hunter2""#)).unwrap();
    assert_eq!(pppoe[0].password, "hunter2");
    let shown = format!("{pppoe:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains(ruster_config::HIDDEN), "{shown}");
}

#[test]
fn an_error_on_the_password_line_does_not_quote_it() {
    for line in [
        r#"password = "hunter2"#,
        "password = 4242424242",
        r#"password = "hunter2" x"#,
    ] {
        let error = ruster_config::parse_pppoe_part(&pppoe_part(line)).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        assert!(!error.contains("4242424242"), "{error}");
        assert!(error.contains("line 9"), "{error}");
    }
}

#[test]
fn an_error_elsewhere_says_where_but_not_the_line() {
    let text =
        pppoe_part(r#"password = "hunter2""#).replace("echo-failures = 3", "echo-failures = \"x\"");
    let error = ruster_config::parse_pppoe_part(&text).unwrap_err();
    assert!(error.contains("line 14"), "{error}");
    assert!(!error.contains("hunter2"), "{error}");
}
