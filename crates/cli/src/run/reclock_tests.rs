//! The run loop never stamps RX with a clock reading taken before slow
//! work: after cold pre-tick work (such as a reload outcome written to
//! stderr) it reads the clock again right before the tick, and a tick that
//! publishes a reload reads it again after the publication phase, before
//! RX. The unsolicited-SYN hold (RFC 5382 REQ-4, NAT44-038) shows which
//! reading the tick used.

use std::io::Write;

use super::*;

/// Admits new WAN -> LAN TCP flows to every inside destination, so an
/// unsolicited SYN is held (REQ-4 a).
const ADMIT_INBOUND_TCP: &str = r#"
[[firewall.rules]]
id = 90
ingress = "wan"
egress = "lan"
source = "0.0.0.0/0"
destination = "0.0.0.0/0"
protocol = "tcp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 1
last = 65535

[firewall.rules.destination-ports]
first = 1
last = 65535
"#;

/// The slow work between two readings: far above the 2 ms margin.
const SLOW_US: u64 = 50_000;

fn document(edit: impl Fn(String) -> String) -> ValidatedConfigV1 {
    let base = include_str!("../../../../fixtures/m1/router-v1.toml");
    let text = edit(format!("{base}\n{BACKEND}\n{ADMIT_INBOUND_TCP}"));
    match crate::config_cmd::validate_bytes(text.as_bytes()) {
        Ok(config) => config,
        Err(error) => panic!("valid config: {}", error.render()),
    }
}

fn fold(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An unsolicited SYN from 198.51.100.20:5555 (routed out of the WAN) to
/// the public port 40003, which has no mapping.
fn unsolicited_syn() -> Vec<u8> {
    let (remote, public) = ([198, 51, 100, 20], [203, 0, 113, 2]);
    let mut tcp = vec![0_u8; 20];
    tcp[0..2].copy_from_slice(&5555_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&40_003_u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&777_u32.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&8192_u16.to_be_bytes());
    let mut pseudo = [remote, public].concat();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&tcp);
    let sum = fold(&pseudo);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 40, 0, 21, 0x40, 0, 64, 6, 0, 0];
    ip.extend_from_slice(&remote);
    ip.extend_from_slice(&public);
    let sum = fold(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0xfe, 0x08, 0x00];
    frame.extend(ip);
    frame.extend(tcp);
    frame.resize(60, 0);
    frame
}

/// Requests one reload after a few ticks; stops once the clock passed
/// `offset_ms` after the hook fired (or after far too many ticks).
struct StopAfterHook {
    state: Rc<State>,
    offset_ms: u64,
    requested: Cell<bool>,
}

impl StopSignal for StopAfterHook {
    fn stop(&self) -> bool {
        match self.state.hook_mark_ms.get() {
            Some(mark) => self.state.clock_seen_us.get() / 1_000 >= mark + self.offset_ms,
            None => self.state.io_calls.get() > 1_000_000,
        }
    }

    fn force(&self) -> bool {
        false
    }

    fn take_reload(&self) -> bool {
        if self.requested.get() || self.state.io_calls.get() < 3 {
            return false;
        }
        self.requested.set(true);
        true
    }
}

/// stderr that, when the reload outcome `needle` is written, schedules the
/// SYN for this iteration's tick and makes the write slow.
struct SlowOutcome {
    state: Rc<State>,
    needle: &'static str,
    text: Vec<u8>,
}

impl Write for SlowOutcome {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.text.extend_from_slice(bytes);
        let fired = self.state.hook_mark_ms.get().is_some();
        if !fired && String::from_utf8_lossy(&self.text).contains(self.needle) {
            let tick = self.state.io_calls.get() + 1;
            self.state
                .inject_at
                .borrow_mut()
                .push_back((tick, IfId(WAN), unsolicited_syn()));
            self.state.slow_down();
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs, with the clock at 1 ms per reading, until it is `offset_ms` past
/// the hook; returns the final stats and stderr.
fn run_hooked(
    host: &FakeHost,
    reloaded: ValidatedConfigV1,
    needle: &'static str,
    offset_ms: u64,
) -> (String, String) {
    host.state.slow_us.set(SLOW_US);
    let stop = StopAfterHook {
        state: Rc::clone(&host.state),
        offset_ms,
        requested: Cell::new(false),
    };
    let mut settings = settings(CheckPolicy::default(), 0);
    settings.health_interval_ms = 1_000;
    settings.link_interval_ms = 1_000;
    let mut out = Vec::new();
    let mut err = SlowOutcome {
        state: Rc::clone(&host.state),
        needle,
        text: Vec::new(),
    };
    let status = execute_with(
        host,
        document(|text| text),
        FakeSource::with([Ok(reloaded)]),
        settings,
        &mut FakeClock {
            step_us: 1_000,
            state: Some(Rc::clone(&host.state)),
            ..FakeClock::default()
        },
        &stop,
        &mut out,
        &mut err,
    );
    let err = String::from_utf8(err.text).expect("utf-8");
    assert_eq!(status, 0, "{err}");
    assert!(host.state.hook_mark_ms.get().is_some(), "hook fired: {err}");
    (String::from_utf8(out).expect("utf-8"), err)
}

/// The SYN was held once; whether its hold is still pending at the end.
fn hold_pending(out: &str) -> bool {
    assert_eq!(
        ops::line_value(out, "nat44_tcp.unsolicited_syn_held"),
        Some("1"),
        "{out}"
    );
    let resolved = [
        "icmp_queued",
        "icmp_suppressed",
        "superseded",
        "firewall_denied",
    ]
    .iter()
    .map(|key| {
        ops::line_value(out, &format!("nat44_tcp.unsolicited_syn_{key}"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("{key} in {out}"))
    })
    .sum::<u64>();
    resolved == 0
}

/// A refused reload's outcome is written (slowly) before the tick whose RX
/// takes the SYN: the tick reads the clock again, so the hold runs from
/// after the write. 30 ms after the pre-write reading plus 6 s the hold
/// is still pending (from the earlier reading it would have matured at
/// +6002 ms); 60 ms after it, it has matured.
#[test]
fn a_slow_reload_outcome_write_does_not_shorten_the_hold() {
    let refused = || document(|text| text.replacen("frame-count = 256", "frame-count = 512", 1));
    for (offset_ms, pending) in [(6_030, true), (6_060, false)] {
        let host = FakeHost::default();
        let (out, err) = run_hooked(&host, refused(), "reload refused", offset_ms);
        assert!(
            err.contains("reload refused: code=RESTART_REQUIRED"),
            "{err}"
        );
        assert_eq!(hold_pending(&out), pending, "{offset_ms}: {out}");
        assert!(!host.state.clock_out_of_order.get());
    }
}

/// A slow apply of a pending reload (the clock jumps between the
/// quiescence probe and the end of the publication phase) with the SYN in
/// the ring: the tick reads the clock again after publishing, so the hold
/// runs from the post-publication reading.
#[test]
fn a_slow_apply_does_not_shorten_the_hold() {
    let applied = || document(|text| text.replace("echo-reply = true", "echo-reply = false"));
    for (offset_ms, pending) in [(6_030, true), (6_060, false)] {
        let host = FakeHost::default();
        *host.state.frame_on_quiesce.borrow_mut() = Some((IfId(WAN), unsolicited_syn()));
        let (out, err) = run_hooked(&host, applied(), "never written", offset_ms);
        assert!(err.contains("reload applied: generation=2"), "{err}");
        assert_eq!(hold_pending(&out), pending, "{offset_ms}: {out}");
        assert!(!host.state.clock_out_of_order.get());
    }
}
