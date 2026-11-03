//! H3: the validation limits of `ruster validate`/`plan` per backend, and
//! the fixture helpers the `ruster run` startup tests share.

use ruster_config::{
    parse, ValidationLimits, MAX_ADDRESSES, MAX_BACKEND_PORTS, MAX_CONFIG_BYTES,
    MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_NEIGHBORS, MAX_ROUTES, PRODUCTION_VALIDATION_LIMITS,
};
use ruster_sim_scenario::SIM_VALIDATION_LIMITS;

use crate::config_cmd::{
    limits_for, load_bytes, load_validated_regular, plan_with, validate_bytes, validate_loaded,
    LoadError,
};

/// Every table at its production limit (fixture header).
pub const MAXIMAL: &str = include_str!("../../../fixtures/limits/router-production-max.toml");

/// Runtime storage of [`MAXIMAL`] in bytes (63.94 MiB; ARP-033 added two
/// 48-byte announcement slots, 96 bytes, to the 67_050_176 before it).
pub const MAXIMAL_STORAGE_BYTES: u64 = 67_050_272;

/// Which production bound a table has.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bound {
    /// Each slot holds a quoted datagram: `max_quote_slots_per_table`.
    Quote,
    /// Every other table: `max_slots_per_table`.
    Table,
}

impl Bound {
    /// The production limit of this kind of table.
    pub const fn production(self) -> u32 {
        match self {
            Self::Quote => PRODUCTION_VALIDATION_LIMITS.max_quote_slots_per_table,
            Self::Table => PRODUCTION_VALIDATION_LIMITS.max_slots_per_table,
        }
    }
}

/// Every operator-sized runtime table: TOML section, key, schema path,
/// and its production bound.
pub const CAPACITY_FIELDS: [(&str, &str, &str, Bound); 12] = [
    (
        "resolution.capacity",
        "states",
        "resolution.capacity.states",
        Bound::Table,
    ),
    (
        "resolution.capacity",
        "actions",
        "resolution.capacity.actions",
        Bound::Table,
    ),
    (
        "resolution.capacity",
        "dynamic-neighbors",
        "resolution.capacity.dynamic-neighbors",
        Bound::Table,
    ),
    (
        "resolution.capacity",
        "failure-holds",
        "resolution.capacity.failure-holds",
        Bound::Quote,
    ),
    (
        "icmpv4-errors.capacity",
        "states",
        "icmpv4-errors.capacity.states",
        Bound::Table,
    ),
    (
        "icmpv4-errors.capacity",
        "actions",
        "icmpv4-errors.capacity.actions",
        Bound::Quote,
    ),
    (
        "nat44.udp.capacity",
        "mappings",
        "nat44.udp.capacity.mappings",
        Bound::Table,
    ),
    (
        "nat44.udp.capacity",
        "peers",
        "nat44.udp.capacity.peers",
        Bound::Table,
    ),
    (
        "nat44.tcp.capacity",
        "mappings",
        "nat44.tcp.capacity.mappings",
        Bound::Table,
    ),
    (
        "nat44.tcp.capacity",
        "sessions",
        "nat44.tcp.capacity.sessions",
        Bound::Table,
    ),
    (
        "nat44.tcp.capacity",
        "unsolicited-syn-holds",
        "nat44.tcp.capacity.unsolicited-syn-holds",
        Bound::Quote,
    ),
    (
        "firewall.capacity",
        "states",
        "firewall.capacity.states",
        Bound::Table,
    ),
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

/// The refusal line of one slot above `limit` at `path`.
pub fn above_line(path: &str, limit: u32) -> String {
    format!(
        "ruster: invalid config: stage=validate code=CAPACITY_LIMIT_EXCEEDED \
         path={path} limit={limit} actual={}\n",
        limit + 1
    )
}

/// The limits each command applies. A change here is a change of what
/// `ruster run` (or `run-sim`) accepts: update the runbook table too.
#[test]
fn the_limits_table_is_pinned() {
    assert_eq!(
        SIM_VALIDATION_LIMITS,
        ValidationLimits {
            max_slots_per_table: 65_536,
            max_quote_slots_per_table: 65_536,
            max_runtime_bytes: 64 << 20,
        }
    );
    assert_eq!(
        PRODUCTION_VALIDATION_LIMITS,
        ValidationLimits {
            max_slots_per_table: 65_536,
            max_quote_slots_per_table: 4_096,
            max_runtime_bytes: 64 << 20,
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
    // Every table at its production limit fits the production byte budget,
    // so the per-table limits are the ones that bind.
    let max = usize::try_from(MAXIMAL_STORAGE_BYTES).expect("fits");
    assert!(max <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes);
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

/// `validate` accepts every table at its production limit, as af-xdp and
/// as sim (the simulator's limits are at least as wide).
#[test]
fn validate_accepts_the_maximal_production_config() {
    for text in [MAXIMAL.to_owned(), as_sim(MAXIMAL)] {
        let (status, out, err) = validate_text(&text);
        assert_eq!(status, 0, "{err}");
        assert!(
            out.contains(&format!(" storage-bytes={MAXIMAL_STORAGE_BYTES} backend=")),
            "{out}"
        );
    }
}

/// For every table: at its production limit accepted (every table of
/// [`MAXIMAL`] is), one slot above refused with a typed, value-free line
/// and exit 2, by `validate` and by the loader `ruster run` uses. A quote
/// table above the production limit is still within the simulator's, so
/// the same document with a sim backend is accepted: `validate` (and
/// `run`) of af-xdp must not fall back to the sim limits.
#[test]
fn validate_refuses_each_table_one_slot_above_the_production_limit() {
    for (section, key, path, bound) in CAPACITY_FIELDS {
        let limit = bound.production();
        let at = with_capacity(MAXIMAL, section, key, limit);
        assert_eq!(at, MAXIMAL, "{path} is at the limit in the fixture");
        let above = with_capacity(MAXIMAL, section, key, limit + 1);
        let (status, out, err) = validate_text(&above);
        assert_eq!(status, crate::EXIT_INVALID, "{path}");
        assert!(out.is_empty());
        assert_eq!(err, above_line(path, limit));
        let Err(error) = validate_bytes(above.as_bytes()) else {
            panic!("{path} above the limit is refused");
        };
        assert_eq!(format!("ruster: invalid config: {}\n", error.render()), err);
        let (status, _, err) = validate_text(&as_sim(&above));
        match bound {
            Bound::Quote => assert_eq!(status, 0, "{path} as sim: {err}"),
            Bound::Table => assert_eq!(err, above_line(path, limit), "{path} as sim"),
        }
    }
    // The simulator's own bound for the quote tables is unchanged.
    let sim = with_capacity(
        &as_sim(MAXIMAL),
        "resolution.capacity",
        "failure-holds",
        SIM_VALIDATION_LIMITS.max_quote_slots_per_table + 1,
    );
    let (status, _, err) = validate_text(&sim);
    assert_eq!(status, crate::EXIT_INVALID);
    assert_eq!(
        err,
        above_line(
            "resolution.capacity.failure-holds",
            SIM_VALIDATION_LIMITS.max_quote_slots_per_table
        )
    );
}

/// H4b review: `validate` of an af-xdp document warns (exit 0, value-free)
/// when a resolution table takes more than about 1 s (1000 ticks) to sweep;
/// the maximal config is tuned below that, a sim document never warns.
#[test]
fn validate_warns_about_a_slow_resolution_sweep() {
    let (status, _, err) = validate_text(MAXIMAL);
    assert_eq!((status, err.as_str()), (0, ""));
    for (from, to, line) in [
        (
            "resolution-timer-scans = 128",
            "resolution-timer-scans = 16",
            "ruster: warning: RESOLUTION_SWEEP_SLOW table=states ticks=4096\n",
        ),
        (
            "resolution-timer-scans = 128",
            "resolution-timer-scans = 0",
            "ruster: warning: RESOLUTION_SWEEP_SLOW table=states ticks=never\n",
        ),
        (
            "failure-dispatch-scans = 16",
            "failure-dispatch-scans = 4",
            "ruster: warning: RESOLUTION_SWEEP_SLOW table=failure-holds ticks=1024\n",
        ),
    ] {
        let text = MAXIMAL.replacen(from, to, 1);
        assert_ne!(text, MAXIMAL, "{from}");
        let (status, out, err) = validate_text(&text);
        assert_eq!(status, 0, "{err}");
        assert!(out.starts_with("valid: "), "{out}");
        assert_eq!(err, line);
        let (status, _, err) = validate_text(&as_sim(&text));
        assert_eq!((status, err.as_str()), (0, ""), "as sim");
    }
    // Exactly at the threshold is not slow: 65536 / 66 = 993.0.. -> 994.
    let at = MAXIMAL.replacen(
        "resolution-timer-scans = 128",
        "resolution-timer-scans = 66",
        1,
    );
    assert_eq!(validate_text(&at).2, "");
    let over = MAXIMAL.replacen(
        "resolution-timer-scans = 128",
        "resolution-timer-scans = 65",
        1,
    );
    assert_eq!(
        validate_text(&over).2,
        "ruster: warning: RESOLUTION_SWEEP_SLOW table=states ticks=1009\n"
    );
}

/// Follow-up #337 sec L4: `ingress-share-percent` is a cap, not a
/// reservation; `validate` warns (exit 0, value-free, every backend) when
/// `share × (interfaces − 1) ≥ 100`, so the other ingresses can take the
/// whole table. 100/N or less keeps an entry for each.
#[test]
fn validate_warns_about_an_overcommitted_fragment_share() {
    const NATFRAG: &str = include_str!("../../../fixtures/natfrag/router.toml");
    let third = "[[interfaces]]\nid = 3\nname = \"dmz\"\ndevice = \"sim2\"\n\
                 mac = \"02:00:00:00:00:03\"\n\n[[addresses]]\n";
    // Three interfaces need three ICMPv4 limiter states each (the shared
    // class, Fragmentation Needed, Redirect) plus Port Unreachable.
    let three = NATFRAG.replacen("[[addresses]]\n", third, 1).replacen(
        "[icmpv4-errors.capacity]\nstates = 8\n",
        "[icmpv4-errors.capacity]\nstates = 10\n",
        1,
    );
    assert_ne!(three, NATFRAG);
    // Two interfaces at the default 50: no warning.
    assert_eq!(validate_text(NATFRAG).2, "");
    // Three at 50: 50 × 2 = 100, overcommitted. 34 × 2 = 68 < 100 leaves
    // the third ingress 82 of 256 entries (two take 87 each).
    for (share, line) in [
        (
            "",
            "ruster: warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED \
             share-percent=50 interfaces=3 entries=256 held=64\n",
        ),
        ("ingress-share-percent = 34\n", ""),
        ("ingress-share-percent = 33\n", ""),
        ("ingress-share-percent = 100\n", ""),
    ] {
        let text = three.replacen(
            "timeout-ms = 1000\n",
            &format!("timeout-ms = 1000\n{share}"),
            1,
        );
        let (status, out, err) = validate_text(&text);
        assert_eq!(status, 0, "{err}");
        assert!(out.starts_with("valid: "), "{out}");
        assert_eq!(err, line, "{share}");
    }
    let refuse = three.replacen("mode = \"associate\"", "mode = \"refuse\"", 1);
    assert_eq!(validate_text(&refuse).2, "", "no table in refuse mode");
    // The rule uses the share the table enforces: 3 entries at 50 % give
    // each ingress one, and two leave the third one entry (no warning);
    // at 67 % each takes two, and two take all three.
    let small = three
        .replacen("entries = 256\n", "entries = 3\n", 1)
        .replacen("held-fragments = 64\n", "held-fragments = 3\n", 1);
    assert_ne!(small, three);
    assert_eq!(validate_text(&small).2, "");
    let small = small.replacen(
        "timeout-ms = 1000\n",
        "timeout-ms = 1000\ningress-share-percent = 67\n",
        1,
    );
    assert_eq!(
        validate_text(&small).2,
        "ruster: warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED \
         share-percent=67 interfaces=3 entries=3 held=3\n"
    ); // The held slots round the same way: at 34 % the entries leave room
       // (87 × 2 < 256), but 2 held slots give each ingress one, and two take
       // both; 3 leave one.
    let held = three
        .replacen(
            "timeout-ms = 1000\n",
            "timeout-ms = 1000\ningress-share-percent = 34\n",
            1,
        )
        .replacen("held-fragments = 64\n", "held-fragments = 2\n", 1);
    assert_eq!(
        validate_text(&held).2,
        "ruster: warning: FRAGMENT_INGRESS_SHARE_OVERCOMMITTED \
         share-percent=34 interfaces=3 entries=256 held=2\n"
    );
    let held = held.replacen("held-fragments = 2\n", "held-fragments = 3\n", 1);
    assert_eq!(validate_text(&held).2, "");
}

/// `plan` loads both sides with the limits of their own backend.
#[test]
fn plan_loads_each_side_with_its_backend_limits() {
    let plan = |current: &str, next: &str| {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let status = plan_with(
            load_bytes,
            current.as_bytes(),
            next.as_bytes(),
            &mut out,
            &mut err,
        );
        (
            status,
            String::from_utf8(out).expect("utf-8"),
            String::from_utf8(err).expect("utf-8"),
        )
    };
    let (status, out, err) = plan(MAXIMAL, MAXIMAL);
    assert_eq!(status, 0, "{err}");
    assert!(out.starts_with("plan: reloadable\nrestart-required: none\nchanges: 0\n"));
    let wide = |text: &str| {
        with_capacity(
            text,
            "resolution.capacity",
            "failure-holds",
            Bound::Quote.production() + 1,
        )
    };
    // A sim current side may use the simulator's wider bound...
    let (status, _, err) = plan(&wide(&as_sim(MAXIMAL)), MAXIMAL);
    assert_eq!(status, 0, "{err}");
    // ...an af-xdp next side may not.
    let (status, _, err) = plan(MAXIMAL, &wide(MAXIMAL));
    assert_eq!(status, crate::EXIT_INVALID);
    assert_eq!(
        err,
        above_line(
            "resolution.capacity.failure-holds",
            Bound::Quote.production()
        )
        .replace("invalid config", "invalid next config")
    );
}

/// The file loader of `ruster run` (startup and reload) applies the
/// production limits to a file on disk.
#[test]
fn the_run_file_loader_applies_the_production_limits() {
    let dir = std::env::temp_dir().join(format!("ruster-h3-limits-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let at = dir.join("at.toml");
    let above = dir.join("above.toml");
    std::fs::write(&at, MAXIMAL).expect("write");
    let limit = Bound::Quote.production();
    std::fs::write(
        &above,
        with_capacity(MAXIMAL, "icmpv4-errors.capacity", "actions", limit + 1),
    )
    .expect("write");
    let loaded = load_validated_regular(&at, false);
    let rejected = load_validated_regular(&above, false);
    std::fs::remove_dir_all(&dir).expect("cleanup");
    let Ok(config) = loaded else {
        panic!("the maximal file loads");
    };
    assert_eq!(
        u64::try_from(config.storage_shape().required_bytes).expect("fits"),
        MAXIMAL_STORAGE_BYTES
    );
    let Err(error @ LoadError::Rejected(_)) = rejected else {
        panic!("one slot above is refused");
    };
    assert_eq!(
        format!("ruster: invalid config: {}\n", error.render()),
        above_line("icmpv4-errors.capacity.actions", limit)
    );
}
