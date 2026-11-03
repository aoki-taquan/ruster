//! The device facts a session reads before it acquires anything: the MTU
//! and the TX queue count, from one rtnetlink `RTM_GETLINK` request in the
//! caller's network namespace (OPS-EXIT item 3).
//!
//! `NativeSession::open` used to read both from sysfs
//! (`/sys/class/net/<dev>/{mtu,queues/tx-<queue>}`), whose view belongs to
//! the network namespace that mounted it, not necessarily the caller's (a
//! process that `setns`es without remounting sees another namespace's
//! devices, and only an `ifindex` match guarded against it). An rtnetlink
//! socket always speaks for the namespace of the thread that created it,
//! which is the namespace the AF_XDP socket binds in. The request names
//! the resolved interface index (no dump); the kernel answers with exactly
//! one `RTM_NEWLINK` while handling the `sendto`, so the receive never
//! blocks.
//!
//! `IFLA_NUM_TX_QUEUES` is the device's allocated TX queue count
//! (`dev->num_tx_queues`), never below the active one
//! (`real_num_tx_queues`, which rtnetlink does not report). A queue id at or
//! above it has no TX queue at all; the active count can still be lower
//! after `ethtool -L`, which the session narrows from sysfs only where the
//! sysfs view proves to describe the resolved device (see
//! `SessionStage::TxQueueCheck`).
//!
//! This module is the pure, safe half: the request bytes and a fail-closed
//! parser of the reply. The syscalls live in the private `native_unsafe`
//! module.

use std::fmt;

/// `RTM_NEWLINK`.
const RTM_NEWLINK: u16 = 16;
/// `RTM_GETLINK`.
const RTM_GETLINK: u16 = 18;
/// `NLMSG_ERROR`.
const NLMSG_ERROR: u16 = 2;
/// `NLM_F_REQUEST`.
const NLM_F_REQUEST: u16 = 1;
/// `struct nlmsghdr` bytes.
const HEADER_LEN: usize = 16;
/// `struct ifinfomsg` bytes.
const IFINFOMSG_LEN: usize = 16;
/// `IFLA_IFNAME`.
const IFLA_IFNAME: u16 = 3;
/// `IFLA_MTU`.
const IFLA_MTU: u16 = 4;
/// `IFLA_NUM_TX_QUEUES`.
const IFLA_NUM_TX_QUEUES: u16 = 31;
/// Attribute type bits (without `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER`).
const NLA_TYPE_MASK: u16 = 0x3fff;
/// `ENODEV` as the kernel reports it in `NLMSG_ERROR`.
const KERNEL_ENODEV: i32 = -19;

/// Bytes of [`request`].
pub(crate) const REQUEST_LEN: usize = HEADER_LEN + IFINFOMSG_LEN;
/// Receive buffer of the query (an `RTM_NEWLINK` with statistics is a few
/// KiB; a longer datagram is [`LinkQueryError::Truncated`]).
pub(crate) const RECEIVE_BUFFER: usize = 32 * 1024;
/// Datagrams read before the query gives up.
pub(crate) const MAX_DATAGRAMS: u32 = 8;

/// The link facts a session needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkAttributes {
    /// `IFLA_MTU`: the L3 MTU, without the Ethernet header.
    pub mtu: u32,
    /// `IFLA_NUM_TX_QUEUES`: the allocated TX queue count.
    pub tx_queues: u32,
}

/// Why the rtnetlink link query failed. Value-free: errnos and kernel
/// errors are numbers, never names or addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkQueryError {
    /// `socket(AF_NETLINK, NETLINK_ROUTE)` failed with this errno.
    Socket(u16),
    /// `sendto` failed with this errno (or sent part of the request: 0).
    Send(u16),
    /// `getsockname` failed with this errno.
    Address(u16),
    /// `recvfrom` failed with this errno; `EAGAIN` (11) means no answer was
    /// queued.
    Receive(u16),
    /// A datagram did not fit the receive buffer.
    Truncated,
    /// A datagram did not come from the kernel.
    NotFromKernel,
    /// The answer named another netlink port id than this socket's.
    UnexpectedPort,
    /// The answer described another interface index.
    UnexpectedLink,
    /// The answer's `IFLA_IFNAME` is not the configured name (the index
    /// was renamed or reused between the lookup and the query). An
    /// alternative name (`ip link property add ... altname`) resolves to
    /// the index but is not `IFLA_IFNAME`, so a config that names a port
    /// by its altname is refused here: use the primary name.
    NameMismatch,
    /// The kernel refused the request with this (negative) error;
    /// `-19` (`ENODEV`) means the index is gone.
    Kernel(i32),
    /// A header, `ifinfomsg`, or attribute was malformed, an attribute was
    /// duplicated or wrongly sized, or `IFLA_IFNAME`, `IFLA_MTU`, or
    /// `IFLA_NUM_TX_QUEUES` was missing.
    Malformed,
    /// No answer within eight datagrams.
    NoAnswer,
}

impl LinkQueryError {
    /// Whether the kernel said the index does not exist.
    #[must_use]
    pub const fn is_no_device(self) -> bool {
        matches!(self, Self::Kernel(KERNEL_ENODEV))
    }
}

impl fmt::Display for LinkQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LinkQueryError {}

/// The 32-byte `RTM_GETLINK` request for interface `ifindex` (no dump).
pub(crate) fn request(sequence: u32, ifindex: u32) -> [u8; REQUEST_LEN] {
    let mut out = [0_u8; REQUEST_LEN];
    out[0..4].copy_from_slice(&(REQUEST_LEN as u32).to_ne_bytes());
    out[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
    out[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    out[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // nlmsg_pid 0 (the kernel); ifinfomsg AF_UNSPEC with the index.
    out[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&ifindex.to_ne_bytes());
    out
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let raw = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_ne_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Parses one datagram answering [`request`] `sequence` for `ifindex` on
/// the socket with port id `port`; `name` is the configured device name
/// (without NUL). `Ok(None)` if the datagram holds no message of this
/// request.
pub(crate) fn parse_reply(
    datagram: &[u8],
    sequence: u32,
    port: u32,
    ifindex: u32,
    name: &[u8],
) -> Result<Option<LinkAttributes>, LinkQueryError> {
    let mut at = 0;
    while at < datagram.len() {
        let rest = &datagram[at..];
        let len = u32_at(rest, 0).ok_or(LinkQueryError::Malformed)? as usize;
        if len < HEADER_LEN || len > rest.len() {
            return Err(LinkQueryError::Malformed);
        }
        let kind = u16_at(rest, 4).ok_or(LinkQueryError::Malformed)?;
        let seq = u32_at(rest, 8).ok_or(LinkQueryError::Malformed)?;
        let pid = u32_at(rest, 12).ok_or(LinkQueryError::Malformed)?;
        let message = &rest[..len];
        if seq == sequence {
            if pid != port {
                return Err(LinkQueryError::UnexpectedPort);
            }
            return match kind {
                NLMSG_ERROR => {
                    let error = u32_at(message, HEADER_LEN).ok_or(LinkQueryError::Malformed)?;
                    let error = i32::from_ne_bytes(error.to_ne_bytes());
                    Err(if error < 0 {
                        LinkQueryError::Kernel(error)
                    } else {
                        // An acknowledgement: never sent without NLM_F_ACK.
                        LinkQueryError::Malformed
                    })
                }
                RTM_NEWLINK => parse_link(message, ifindex, name).map(Some),
                _ => Err(LinkQueryError::Malformed),
            };
        }
        let advance = len.div_ceil(4) * 4;
        if advance >= rest.len() {
            break;
        }
        at += advance;
    }
    Ok(None)
}

fn parse_link(message: &[u8], ifindex: u32, name: &[u8]) -> Result<LinkAttributes, LinkQueryError> {
    if message.len() < HEADER_LEN + IFINFOMSG_LEN {
        return Err(LinkQueryError::Malformed);
    }
    let index = u32_at(message, HEADER_LEN + 4).ok_or(LinkQueryError::Malformed)?;
    if index != ifindex {
        return Err(LinkQueryError::UnexpectedLink);
    }
    let mut mtu = None;
    let mut tx_queues = None;
    let mut found_name: Option<&[u8]> = None;
    let mut at = HEADER_LEN + IFINFOMSG_LEN;
    while at < message.len() {
        let attribute_len = u16_at(message, at).ok_or(LinkQueryError::Malformed)? as usize;
        let kind = u16_at(message, at + 2).ok_or(LinkQueryError::Malformed)? & NLA_TYPE_MASK;
        if attribute_len < 4 || at + attribute_len > message.len() {
            return Err(LinkQueryError::Malformed);
        }
        let payload = &message[at + 4..at + attribute_len];
        let number = || -> Result<u32, LinkQueryError> {
            if payload.len() != 4 {
                return Err(LinkQueryError::Malformed);
            }
            u32_at(payload, 0).ok_or(LinkQueryError::Malformed)
        };
        match kind {
            IFLA_MTU => {
                if mtu.replace(number()?).is_some() {
                    return Err(LinkQueryError::Malformed);
                }
            }
            IFLA_NUM_TX_QUEUES => {
                if tx_queues.replace(number()?).is_some() {
                    return Err(LinkQueryError::Malformed);
                }
            }
            IFLA_IFNAME => {
                // NUL-terminated, at most IFNAMSIZ (16) bytes with the NUL.
                let end = payload
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(LinkQueryError::Malformed)?;
                if end == 0 || end >= 16 || found_name.replace(&payload[..end]).is_some() {
                    return Err(LinkQueryError::Malformed);
                }
            }
            _ => {}
        }
        at += attribute_len.div_ceil(4) * 4;
    }
    let (Some(mtu), Some(tx_queues), Some(found_name)) = (mtu, tx_queues, found_name) else {
        return Err(LinkQueryError::Malformed);
    };
    if found_name != name {
        return Err(LinkQueryError::NameMismatch);
    }
    Ok(LinkAttributes { mtu, tx_queues })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn reply(sequence: u32, pid: u32, index: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![0_u8; IFINFOMSG_LEN];
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        for attribute in attributes {
            body.extend_from_slice(attribute);
        }
        let mut out = Vec::new();
        out.extend_from_slice(
            &u32::try_from(HEADER_LEN + body.len())
                .unwrap()
                .to_ne_bytes(),
        );
        out.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
        out.extend_from_slice(&0_u16.to_ne_bytes());
        out.extend_from_slice(&sequence.to_ne_bytes());
        out.extend_from_slice(&pid.to_ne_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn good() -> Vec<Vec<u8>> {
        vec![
            attribute(IFLA_IFNAME, b"veth0\0"),
            attribute(IFLA_MTU, &1_500_u32.to_ne_bytes()),
            attribute(IFLA_NUM_TX_QUEUES, &2_u32.to_ne_bytes()),
            // An unknown nested attribute is skipped.
            attribute(0x8000 | 26, &[0; 8]),
        ]
    }

    #[test]
    fn the_request_is_exact() {
        let bytes = request(9, 7);
        let mut expected = [0_u8; 32];
        expected[0..4].copy_from_slice(&32_u32.to_ne_bytes());
        expected[4..6].copy_from_slice(&18_u16.to_ne_bytes());
        expected[6..8].copy_from_slice(&1_u16.to_ne_bytes());
        expected[8..12].copy_from_slice(&9_u32.to_ne_bytes());
        expected[20..24].copy_from_slice(&7_u32.to_ne_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn a_reply_parses_and_every_deviation_fails_closed() {
        let ok = reply(9, 5, 7, &good());
        assert_eq!(
            parse_reply(&ok, 9, 5, 7, b"veth0"),
            Ok(Some(LinkAttributes {
                mtu: 1_500,
                tx_queues: 2
            }))
        );
        // Another request's late answer is skipped.
        assert_eq!(
            parse_reply(&reply(8, 5, 7, &good()), 9, 5, 7, b"veth0"),
            Ok(None)
        );
        assert_eq!(
            parse_reply(&ok, 9, 6, 7, b"veth0"),
            Err(LinkQueryError::UnexpectedPort)
        );
        assert_eq!(
            parse_reply(&reply(9, 5, 8, &good()), 9, 5, 7, b"veth0"),
            Err(LinkQueryError::UnexpectedLink)
        );
        assert_eq!(
            parse_reply(&ok, 9, 5, 7, b"veth1"),
            Err(LinkQueryError::NameMismatch)
        );
        for missing in 0..3 {
            let mut attributes = good();
            attributes.remove(missing);
            assert_eq!(
                parse_reply(&reply(9, 5, 7, &attributes), 9, 5, 7, b"veth0"),
                Err(LinkQueryError::Malformed),
                "attribute {missing} missing"
            );
        }
        let mut duplicated = good();
        duplicated.push(attribute(IFLA_MTU, &9_000_u32.to_ne_bytes()));
        assert_eq!(
            parse_reply(&reply(9, 5, 7, &duplicated), 9, 5, 7, b"veth0"),
            Err(LinkQueryError::Malformed)
        );
        let mut short = good();
        short[1] = attribute(IFLA_MTU, &[1, 2]);
        assert_eq!(
            parse_reply(&reply(9, 5, 7, &short), 9, 5, 7, b"veth0"),
            Err(LinkQueryError::Malformed)
        );
        let mut unterminated = good();
        unterminated[0] = attribute(IFLA_IFNAME, b"veth0");
        assert_eq!(
            parse_reply(&reply(9, 5, 7, &unterminated), 9, 5, 7, b"veth0"),
            Err(LinkQueryError::Malformed)
        );
        assert_eq!(
            parse_reply(&ok[..ok.len() - 3], 9, 5, 7, b"veth0"),
            Err(LinkQueryError::Malformed),
            "header longer than the datagram"
        );
        // NLMSG_ERROR: a negative error is the kernel's; ENODEV is gone.
        let mut error = vec![0_u8; 36];
        error[0..4].copy_from_slice(&36_u32.to_ne_bytes());
        error[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        error[8..12].copy_from_slice(&9_u32.to_ne_bytes());
        error[12..16].copy_from_slice(&5_u32.to_ne_bytes());
        error[16..20].copy_from_slice(&(-19_i32).to_ne_bytes());
        let gone = parse_reply(&error, 9, 5, 7, b"veth0").unwrap_err();
        assert!(gone.is_no_device(), "{gone}");
        error[16..20].copy_from_slice(&0_i32.to_ne_bytes());
        assert_eq!(
            parse_reply(&error, 9, 5, 7, b"veth0"),
            Err(LinkQueryError::Malformed)
        );
    }
}
