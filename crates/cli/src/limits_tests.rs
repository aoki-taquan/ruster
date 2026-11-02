//! H3: the validation limits of `ruster validate`/`plan` per backend, and
//! the fixture helpers the `ruster run` startup tests share.

use ruster_config::{
    parse, ValidationLimits, MAX_ADDRESSES, MAX_BACKEND_PORTS, MAX_CONFIG_BYTES,
    MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_NEIGHBORS, MAX_ROUTES, PRODUCTION_VALIDATION_LIMITS,
};
use ruster_sim_scenario::SIM_VALIDATION_LIMITS;

use crate::config_cmd::{limits_for, load_bytes, plan_with, validate_bytes, validate_loaded};

/// Every table at the production per-table limit (fixture header).
pub const MAXIMAL: &str = include_str!("../../../fixtures/limits/router-production-max.toml");

/// Runtime storage of [`MAXIMAL`] in bytes (111.25 MiB).
pub const MAXIMAL_STORAGE_BYTES: u64 = 116_654_016;

/// Every operator-sized runtime table: TOML section, key, schema path.
pub const CAPACITY_FIELDS: [(&str, &str, &str); 11] = [
    (
        "resolution.capacity",
        "states",
        "resolution.capacity.states",
    ),
    (
        "resolution.capacity",
        "actions",
        "resolution.capacity.actions",
    ),
    (
        "resolution.capacity",
        "dynamic-neighbors",
        "resolution.capacity.dynamic-neighbors",
    ),
    (
        "resolution.capacity",
        "failure-holds",
        "resolution.capacity.failure-holds",
    ),
    (
        "icmpv4-errors.capacity",
        "states",
        "icmpv4-errors.capacity.states",
    ),
    (
        "icmpv4-errors.capacity",
        "actions",
        "icmpv4-errors.capacity.actions",
    ),
    (
        "nat44.udp.capacity",
        "mappings",
        "nat44.udp.capacity.mappings",
    ),
    ("nat44.udp.capacity", "peers", "nat44.udp.capacity.peers"),
    (
        "nat44.tcp.capacity",
        "mappings",
        "nat44.tcp.capacity.mappings",
    ),
    (
        "nat44.tcp.capacity",
        "sessions",
        "nat44.tcp.capacity.sessions",
    ),
    ("firewall.capacity", "states", "firewall.capacity.states"),
];

/// `text` with the first `key = ...` line after `[section]` set to `value`.
pub fn with_capacity(text: &str, section: &str, key: &str, value: u32) -> String {
    let header = format!("[{section}]\n");
    let start = text.find(&header).expect("section") + header.len();
    let prefix = format!("\n{key} = ");
    let line = start - 1 + text[start - 1..].find(&prefix).expect("key") + 1;
    let end = line + text[line..].find('\n').expect("line end");
    format!("{}{key} = {value}{}", &text[..line], &text[end..])
}

/// `text` with its `[backend]` section (at the end) removed: a sim backend.
pub fn as_sim(text: &str) -> String {
    let at = text.find("\n[backend]\n").expect("backend section");
    text[..=at].to_owned()
}

/// The limits each command applies. A change here is a change of what
/// `ruster run` (or `run-sim`) accepts: update the runbook table too.
#[test]
fn the_limits_table_is_pinned() {
    assert_eq!(
        SIM_VALIDATION_LIMITS,
        ValidationLimits {
            max_slots_per_table: 65_536,
            max_runtime_bytes: 64 << 20,
        }
    );
    assert_eq!(
        PRODUCTION_VALIDATION_LIMITS,
        ValidationLimits {
            max_slots_per_table: 65_536,
            max_runtime_bytes: 128 << 20,
        }
    );
    // Schema bounds of the parse stage, the same for every backend.
    assert_eq!(
        (
            MAX_CONFIG_BYTES,
            MAX_INTERFACES,
            MAX_ADDRESSES,
            MAX_ROUTES,
            MAX_NEIGHBORS,
            MAX_FIREWALL_RULES,
            MAX_BACKEND_PORTS,
        ),
        (1 << 20, 256, 1_024, 4_096, 4_096, 4_096, 256)
    );
    // Every table at the production slot limit fits the production byte
    // budget, so the per-table limit is the one that binds; the same
    // document is above the simulator's budget.
    let max = usize::try_from(MAXIMAL_STORAGE_BYTES).expect("fits");
    assert!(max <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes);
    assert!(max > SIM_VALIDATION_LIMITS.max_runtime_bytes);
}

#[test]
fn limits_follow_the_backend_kind() {
    let limits = |text: &str| limits_for(&parse(text.as_bytes()).expect("parse"));
    assert_eq!(limits(MAXIMAL), PRODUCTION_VALIDATION_LIMITS);
    assert_eq!(
        limits(&as_sim(MAXIMAL)),
        SIM_VALIDATION_LIMITS,
        "no [backend]"
    );
    let explicit = format!("{}\n[backend]\nkind = \"sim\"\n", as_sim(MAXIMAL));
    assert_eq!(limits(&explicit), SIM_VALIDATION_LIMITS);
}

fn validate_text(text: &str) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = validate_loaded(load_bytes(text.as_bytes()), &mut out, &mut err);
    (
        status,
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

/// `validate` of an af-xdp document applies the production limits: every
/// table at the limit is accepted, the same document with a sim backend
/// is refused by the simulator's byte budget.
#[test]
fn validate_accepts_the_maximal_af_xdp_config_and_refuses_it_as_sim() {
    let (status, out, err) = validate_text(MAXIMAL);
    assert_eq!(status, 0, "{err}");
    assert!(
        out.contains(&format!(
            " storage-bytes={MAXIMAL_STORAGE_BYTES} backend=af-xdp "
        )),
        "{out}"
    );
    let (status, out, err) = validate_text(&as_sim(MAXIMAL));
    assert_eq!(status, crate::EXIT_INVALID);
    assert!(out.is_empty());
    assert_eq!(
        err,
        format!(
            "ruster: invalid config: stage=validate code=RUNTIME_STORAGE_BYTES_EXCEEDED \
             limit={} actual={MAXIMAL_STORAGE_BYTES}\n",
            SIM_VALIDATION_LIMITS.max_runtime_bytes
        )
    );
}

/// One slot above the per-table limit, for every table, is a typed,
/// value-free refusal with the schema path; at the limit it is accepted
/// (every table of [`MAXIMAL`] is at the limit).
#[test]
fn validate_refuses_each_table_one_slot_above_the_production_limit() {
    let limit = PRODUCTION_VALIDATION_LIMITS.max_slots_per_table;
    for (section, key, path) in CAPACITY_FIELDS {
        let at = with_capacity(MAXIMAL, section, key, limit);
        assert_eq!(at, MAXIMAL, "{path} is at the limit in the fixture");
        let above = with_capacity(MAXIMAL, section, key, limit + 1);
        let (status, out, err) = validate_text(&above);
        assert_eq!(status, crate::EXIT_INVALID, "{path}");
        assert!(out.is_empty());
        assert_eq!(
            err,
            format!(
                "ruster: invalid config: stage=validate code=CAPACITY_LIMIT_EXCEEDED \
                 path={path} limit={limit} actual={}\n",
                limit + 1
            )
        );
        // The loader `ruster run` uses gives the same refusal.
        let Err(error) = validate_bytes(above.as_bytes()) else {
            panic!("{path} above the limit is refused");
        };
        assert_eq!(format!("ruster: invalid config: {}\n", error.render()), err);
    }
}

/// `plan` loads both sides with the limits of their own backend.
#[test]
fn plan_loads_each_side_with_its_backend_limits() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = plan_with(
        load_bytes,
        MAXIMAL.as_bytes(),
        MAXIMAL.as_bytes(),
        &mut out,
        &mut err,
    );
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(String::from_utf8(out)
        .expect("utf-8")
        .starts_with("plan: reloadable\nrestart-required: none\nchanges: 0\n"));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = plan_with(
        load_bytes,
        as_sim(MAXIMAL).as_bytes(),
        MAXIMAL.as_bytes(),
        &mut out,
        &mut err,
    );
    assert_eq!(status, crate::EXIT_INVALID);
    assert!(String::from_utf8(err).expect("utf-8").starts_with(
        "ruster: invalid current config: stage=validate code=RUNTIME_STORAGE_BYTES_EXCEEDED"
    ));
}
