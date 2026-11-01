//! Cold-path stats blocks of `ruster run` on stdout.
//!
//! A block is a header line, `section.key=value` lines in the fixed
//! visiting order of each [`ObservableFields`] value, and `end`:
//!
//! ```text
//! ruster-run-stats kind=periodic uptime-ms=60000
//! observability.generation=1
//! ...
//! af_xdp.ports=2
//! ...
//! if1.af_xdp_port.queue=0
//! ...
//! end
//! ```
//!
//! Redaction: only counters, gauges, flags, fixed labels, generation, and
//! interface ids appear. No hash key, key-source byte, NAT allocator seed,
//! address, MAC, device name, packet byte, fd, or pointer is ever part of
//! an observable field.

use std::fmt::Write as _;

use ruster_core::{FieldValue, FieldVisitor, IfId, MonotonicMillis, ObservableFields};
use ruster_runtime::{ObservabilitySnapshot, ServiceCounters};

/// Which block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKind {
    Periodic,
    Final,
}

impl BlockKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Periodic => "periodic",
            Self::Final => "final",
        }
    }
}

struct Lines<'a> {
    out: &'a mut String,
    prefix: Option<IfId>,
}

impl FieldVisitor for Lines<'_> {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        let out = &mut *self.out;
        if let Some(interface) = self.prefix {
            let _ = write!(out, "if{}.", interface.0);
        }
        let _ = match value {
            FieldValue::Count(value) => writeln!(out, "{section}.{key}={value}"),
            FieldValue::Flag(value) => writeln!(out, "{section}.{key}={value}"),
            FieldValue::Millis(Some(value)) => writeln!(out, "{section}.{key}={}", value.0),
            FieldValue::Generation(Some(value)) => writeln!(out, "{section}.{key}={value}"),
            FieldValue::Millis(None) | FieldValue::Generation(None) => {
                writeln!(out, "{section}.{key}=none")
            }
            FieldValue::Label(value) => writeln!(out, "{section}.{key}={value}"),
        };
    }
}

/// Appends the fields of `value`, each line prefixed with `if<id>.` when
/// `port` is given.
pub fn write_fields<T: ObservableFields>(out: &mut String, port: Option<IfId>, value: &T) {
    value.visit_fields(&mut Lines { out, prefix: port });
}

/// One complete block: header, worker observability, service counters,
/// the backend lines written by `backend`, and `end`.
pub fn block(
    kind: BlockKind,
    now: MonotonicMillis,
    snapshot: &ObservabilitySnapshot,
    services: &ServiceCounters,
    backend: impl FnOnce(&mut String),
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ruster-run-stats kind={} uptime-ms={}",
        kind.label(),
        now.0
    );
    write_fields(&mut out, None, snapshot);
    write_fields(&mut out, None, services);
    backend(&mut out);
    out.push_str("end\n");
    out
}
