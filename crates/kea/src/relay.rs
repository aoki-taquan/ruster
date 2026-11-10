//! The DHCPv4 relay agent: a client's request in a frame from the FE becomes a
//! relayed request to Kea, and Kea's reply becomes a frame to the client.
//!
//! [`request`] takes the whole Ethernet frame the FE handed over (a BOOTREQUEST
//! from UDP port 68 to port 67, broadcast or to the router's address) and gives the
//! UDP payload to send to Kea from the interface's address, port 67: the same
//! message with `hops` one more, `giaddr` set to the interface's address, and a
//! Relay Agent Information option whose Circuit ID is the interface's name.
//! [`reply`] takes the UDP payload Kea sent back to that address and gives the
//! frame to send out of the interface: the message without the Relay Agent
//! Information option, from the interface's address and MAC, port 67, to the
//! client's port 68, broadcast or to the client's address and MAC.
//!
//! Both read untrusted bytes and return an error for anything they cannot read;
//! the caller drops it. Neither panics on any input.
//!
//! # Standards
//!
//! - RFC 951 section 3 and RFC 2131 section 2: the BOOTP message, its fixed fields
//!   and the 236 bytes before the options; RFC 2131 section 3 and RFC 2132 section
//!   2: the magic cookie 99.130.83.99 and the options (Pad, End, code, length,
//!   value).
//! - RFC 1542 section 4.1.1: a relay agent takes BOOTREQUESTs only, discards one
//!   whose `hops` exceeds its threshold (4, the RFC's default), adds one to
//!   `hops`, and puts its address on the receiving interface in a zero `giaddr`.
//! - RFC 1542 section 4.1.2 and 5.4, RFC 2131 section 4.1: a BOOTREPLY goes to the
//!   client on the interface `giaddr` names; broadcast when the BROADCAST flag is
//!   set, else to `yiaddr` at the `chaddr`
//!   hardware address, from UDP port 67 to port 68.
//! - RFC 3046 sections 2.0 and 2.1: the Relay Agent Information option (82), last
//!   before End, with a Circuit ID sub-option (1) naming the circuit, here the
//!   interface; section 2.2: the option is taken out of the reply before it goes to
//!   the client.
//! - RFC 791, RFC 768 and RFC 1071: the IPv4 header and UDP checksums are checked on
//!   requests and computed on replies.
//!
//! Deviations: a request whose `giaddr` is not zero (from another relay agent on
//! the LAN) is dropped, so are one that already carries option 82 (RFC 3046 2.1
//! allows this for an untrusted circuit), an IPv4 fragment and one with IP options;
//! the hops threshold is not configurable; the request's UDP source port is not
//! checked; Pad and what follows End are left out of the relayed request (which may
//! then be shorter than BOOTP's 300 bytes), and options without End are taken; with
//! an interface name of more than 253 bytes no option 82 is added; a reply with no
//! `yiaddr` (an answer to DHCPINFORM) goes to `ciaddr`, as RFC 2131 4.1 says for a
//! server, since RFC 1542 names only `yiaddr`; a reply whose `htype` and `hlen` are not
//! Ethernet's (1 and 6) is broadcast; a reply is sent with TTL 64; options in
//! `sname` and `file` (option overload) are passed as they are.

use std::net::Ipv4Addr;

/// One interface the relay agent serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub interface: String,
    pub mac: [u8; 6],
    /// The interface's IPv4 address: `giaddr`, and the source of the replies.
    pub address: Ipv4Addr,
}

/// The DHCP server port (RFC 2131 section 4.1).
pub const SERVER_PORT: u16 = 67;
/// The DHCP client port.
pub const CLIENT_PORT: u16 = 68;
/// A request with more hops than this is discarded (RFC 1542 4.1.1's default).
pub const MAX_HOPS: u8 = 4;
/// The largest IPv4 packet a reply is sent in: Ethernet's MTU.
pub const MAX_PACKET: usize = 1_500;

const ETHERNET: usize = 14;
const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
/// The fixed BOOTP fields and the magic cookie.
const FIXED: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTIONS: usize = FIXED + COOKIE.len();
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const PAD: u8 = 0;
const END: u8 = 255;
const RELAY_AGENT_INFORMATION: u8 = 82;
const CIRCUIT_ID: u8 = 1;
const BROADCAST_FLAG: u16 = 0x8000;
const TTL: u8 = 64;

// Offsets of the BOOTP fields.
const OP: usize = 0;
const HTYPE: usize = 1;
const HLEN: usize = 2;
const HOPS: usize = 3;
const FLAGS: usize = 10;
const CIADDR: usize = 12;
const YIADDR: usize = 16;
const GIADDR: usize = 24;
const CHADDR: usize = 28;

/// Why a message is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Not an IPv4 UDP packet to port 67 that can be read whole.
    NotDhcp,
    /// A bad IPv4 header or UDP checksum.
    Checksum,
    /// Not a BOOTREQUEST (from a client) or BOOTREPLY (from Kea).
    Op,
    /// Too short, no magic cookie, or options that run past the end.
    Malformed,
    /// More hops than [`MAX_HOPS`].
    Hops,
    /// A request with `giaddr` set, or a reply whose `giaddr` is not the link's.
    Giaddr,
    /// A request that already has a Relay Agent Information option.
    AgentOption,
    /// A reply that does not fit in one packet.
    TooLong,
}

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotDhcp => "not a DHCP request",
            Self::Checksum => "bad checksum",
            Self::Op => "wrong op",
            Self::Malformed => "malformed",
            Self::Hops => "too many hops",
            Self::Giaddr => "giaddr",
            Self::AgentOption => "already has option 82",
            Self::TooLong => "too long",
        };
        f.write_str(text)
    }
}

/// The relayed request for Kea, from a client's request in `frame` (Ethernet, no
/// VLAN tag) that came in on `link`.
pub fn request(link: &Link, frame: &[u8]) -> Result<Vec<u8>, Dropped> {
    let message = udp_payload(frame)?;
    if message.len() < OPTIONS || message[FIXED..OPTIONS] != COOKIE {
        return Err(Dropped::Malformed);
    }
    if message[OP] != BOOTREQUEST {
        return Err(Dropped::Op);
    }
    if message[HOPS] > MAX_HOPS {
        return Err(Dropped::Hops);
    }
    if message[GIADDR..GIADDR + 4] != [0; 4] {
        return Err(Dropped::Giaddr);
    }
    let mut options = Vec::new();
    for option in Options(&message[OPTIONS..]) {
        let (code, whole) = option?;
        if code == RELAY_AGENT_INFORMATION {
            return Err(Dropped::AgentOption);
        }
        options.extend_from_slice(whole);
    }
    let mut out = Vec::with_capacity(OPTIONS + options.len() + 8 + link.interface.len());
    out.extend_from_slice(&message[..OPTIONS]);
    out[HOPS] += 1;
    out[GIADDR..GIADDR + 4].copy_from_slice(&link.address.octets());
    out.extend_from_slice(&options);
    // A Circuit ID of 1 to 255 bytes in an option of at most 255.
    let name = link.interface.as_bytes();
    if let (Ok(id), Ok(all)) = (u8::try_from(name.len()), u8::try_from(name.len() + 2)) {
        if id > 0 {
            out.extend_from_slice(&[RELAY_AGENT_INFORMATION, all, CIRCUIT_ID, id]);
            out.extend_from_slice(name);
        }
    }
    out.push(END);
    Ok(out)
}

/// The frame to the client for Kea's reply `message` to `link`'s address.
pub fn reply(link: &Link, message: &[u8]) -> Result<Vec<u8>, Dropped> {
    if message.len() < OPTIONS || message[FIXED..OPTIONS] != COOKIE {
        return Err(Dropped::Malformed);
    }
    if message[OP] != BOOTREPLY {
        return Err(Dropped::Op);
    }
    if message[GIADDR..GIADDR + 4] != link.address.octets() {
        return Err(Dropped::Giaddr);
    }
    let mut payload = Vec::with_capacity(message.len());
    payload.extend_from_slice(&message[..OPTIONS]);
    for option in Options(&message[OPTIONS..]) {
        let (code, whole) = option?;
        if code != RELAY_AGENT_INFORMATION {
            payload.extend_from_slice(whole);
        }
    }
    payload.push(END);
    if IPV4_HEADER + UDP_HEADER + payload.len() > MAX_PACKET {
        return Err(Dropped::TooLong);
    }

    let address = |at: usize| {
        Ipv4Addr::new(
            message[at],
            message[at + 1],
            message[at + 2],
            message[at + 3],
        )
    };
    let flags = u16::from_be_bytes([message[FLAGS], message[FLAGS + 1]]);
    let ethernet = message[HTYPE] == 1 && message[HLEN] == 6;
    let unicast = [address(YIADDR), address(CIADDR)]
        .into_iter()
        .find(|a| !a.is_unspecified());
    let (mac, to) = match unicast {
        Some(to) if ethernet && flags & BROADCAST_FLAG == 0 => {
            let mut mac = [0; 6];
            mac.copy_from_slice(&message[CHADDR..CHADDR + 6]);
            (mac, to)
        }
        _ => ([0xff; 6], Ipv4Addr::BROADCAST),
    };
    Ok(frame(link, mac, to, &payload))
}

/// An Ethernet frame of an IPv4 UDP packet from `link`'s port 67 to `to`'s port 68.
fn frame(link: &Link, mac: [u8; 6], to: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER + payload.len();
    let ip_len = IPV4_HEADER + udp_len;
    let mut out = Vec::with_capacity(ETHERNET + ip_len);
    out.extend_from_slice(&mac);
    out.extend_from_slice(&link.mac);
    out.extend_from_slice(&[0x08, 0x00]);
    let ip = out.len();
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&(ip_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, TTL, 17, 0, 0]);
    out.extend_from_slice(&link.address.octets());
    out.extend_from_slice(&to.octets());
    let header = checksum(&out[ip..], 0);
    out[ip + 10..ip + 12].copy_from_slice(&header.to_be_bytes());
    let udp = out.len();
    out.extend_from_slice(&SERVER_PORT.to_be_bytes());
    out.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let sum = match checksum(
        &out[udp..],
        pseudo_header(&out[ip..ip + IPV4_HEADER], udp_len),
    ) {
        // RFC 768: a computed zero is sent as all ones.
        0 => 0xffff,
        sum => sum,
    };
    out[udp + 6..udp + 8].copy_from_slice(&sum.to_be_bytes());
    out
}

/// The UDP payload of an IPv4 packet to port 67 in `frame`, its checksums checked.
fn udp_payload(frame: &[u8]) -> Result<&[u8], Dropped> {
    if frame.get(12..14) != Some(&[0x08, 0x00][..]) {
        return Err(Dropped::NotDhcp);
    }
    let ip = &frame[ETHERNET..];
    // Version 4 and no IP options.
    if ip.len() < IPV4_HEADER || ip[0] != 0x45 {
        return Err(Dropped::NotDhcp);
    }
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
    if total < IPV4_HEADER + UDP_HEADER || total > ip.len() || fragment || ip[9] != 17 {
        return Err(Dropped::NotDhcp);
    }
    if checksum(&ip[..IPV4_HEADER], 0) != 0 {
        return Err(Dropped::Checksum);
    }
    let udp = &ip[IPV4_HEADER..total];
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let to = u16::from_be_bytes([udp[2], udp[3]]);
    if to != SERVER_PORT || length < UDP_HEADER || length > udp.len() {
        return Err(Dropped::NotDhcp);
    }
    let udp = &udp[..length];
    // A zero checksum is none (RFC 768).
    if udp[6..8] != [0, 0] && checksum(udp, pseudo_header(&ip[..IPV4_HEADER], length)) != 0 {
        return Err(Dropped::Checksum);
    }
    Ok(&udp[UDP_HEADER..])
}

/// The sum of the UDP pseudo-header for [`checksum`]: the addresses of the IPv4
/// `header`, the protocol and the UDP length.
fn pseudo_header(header: &[u8], udp_len: usize) -> u32 {
    let word = |at: usize| u32::from(u16::from_be_bytes([header[at], header[at + 1]]));
    // udp_len is at most a packet's length, below 65 536.
    word(12) + word(14) + word(16) + word(18) + 17 + udp_len as u32
}

/// The Internet checksum (RFC 1071) of `bytes`, starting from `sum`.
fn checksum(bytes: &[u8], sum: u32) -> u16 {
    let mut sum = u64::from(sum);
    let mut chunks = bytes.chunks_exact(2);
    for word in chunks.by_ref() {
        sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u64::from(last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The options after the magic cookie, up to End: each option's code and its
/// bytes (code, length and value). Pad is skipped; an option that runs past the
/// end is an error, and so is the rest after it.
struct Options<'a>(&'a [u8]);

impl<'a> Iterator for Options<'a> {
    type Item = Result<(u8, &'a [u8]), Dropped>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&code, rest) = self.0.split_first()?;
            match code {
                PAD => self.0 = rest,
                END => {
                    self.0 = &[];
                    return None;
                }
                _ => {
                    let Some(&len) = rest.first() else {
                        self.0 = &[];
                        return Some(Err(Dropped::Malformed));
                    };
                    let end = 2 + usize::from(len);
                    let Some(whole) = self.0.get(..end) else {
                        self.0 = &[];
                        return Some(Err(Dropped::Malformed));
                    };
                    self.0 = &self.0[end..];
                    return Some(Ok((code, whole)));
                }
            }
        }
    }
}
