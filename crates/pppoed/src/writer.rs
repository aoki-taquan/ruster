//! Where the client's sessions go: each session's values to its confd source
//! (`confd/source/<name>.sock`), and the default routes to ribd as the route source
//! `pppoed` (`docs/design/ce-processes.md`, "送り手").
//!
//! A [`Writer`] ([`ruster_proto::writer`]) keeps what its receiver should hold and
//! writes it there. For confd it sends everything again every [`REFRESH_MS`], well
//! within [`LIFETIME`], so the values last while the client runs and run out about
//! a minute after it stops.
//!
//! # Standards
//!
//! - draft-ietf-core-comi-21 and RFC 8132: the values and routes are written with
//!   iPATCH on `c`.
//! - RFC 8349: a default route is 0.0.0.0/0 out of the session interface, on-link
//!   (the session is point-to-point, RFC 1661).
//!
//! Deviations: resync-begin, resync-end, sync-done and the lifetimes are ruster's own.

use std::net::Ipv4Addr;

use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
pub use ruster_proto::writer::Writer;

use crate::session::SessionUp;

/// How long a value sent to confd lasts, in seconds.
pub const LIFETIME: u32 = 60;
/// How often the values are sent to confd again.
pub const REFRESH_MS: u64 = 20_000;

/// A session's values for its source: set while it is up, deleted when not.
pub fn source_values(source: &str, up: Option<&SessionUp>) -> Vec<Change> {
    let session = Key::SourcePppoe {
        source: source.to_owned(),
    };
    let address = Key::SourceIpv4 {
        source: source.to_owned(),
    };
    let Some(up) = up else {
        return vec![Change::delete(session), Change::delete(address)];
    };
    let mut out = vec![Change::set(
        session,
        Value::SourcePppoe {
            session: up.session_id,
            peer: up.ac,
            mtu: up.mtu,
            lifetime: LIFETIME,
        },
    )];
    out.push(match up.ipv4 {
        Some(ipv4) => Change::set(
            address,
            Value::SourceIpv4 {
                address: ipv4,
                prefix_len: 32,
                lifetime: LIFETIME,
            },
        ),
        None => Change::delete(address),
    });
    out
}

/// The IPv4 default route of `vrf` out of the session `interface`: set while the
/// session is up with an address, deleted when not.
pub fn default_route(vrf: &str, interface: &str, up: Option<&SessionUp>) -> Change {
    let key = Key::Route {
        vrf: vrf.to_owned(),
        prefix: Ipv4Addr::UNSPECIFIED.into(),
        len: 0,
    };
    if up.is_some_and(|up| up.ipv4.is_some()) {
        Change::set(
            key,
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: interface.to_owned(),
                address: None,
            }])),
        )
    } else {
        Change::delete(key)
    }
}
