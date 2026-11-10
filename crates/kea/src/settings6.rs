//! Kea's DHCPv6 settings for the `dhcp6` entries of the `dhcp` part.
//!
//! As for DHCPv4 ([`crate::settings`]), ruster-kea writes one file that the
//! operator's `kea-dhcp6.conf` includes inside its `Dhcp6` map, followed by the
//! operator's own members (the lease database, the server identifier, the control
//! socket, logging). The file holds:
//!
//! - `interfaces-config`: Kea listens only on the address ruster-kea relays to
//!   (`lo/::1` unless told otherwise), as a unicast address, so it needs no LAN
//!   port.
//! - `subnet6`: a subnet per entry, the prefix of the interface's address. Kea picks
//!   it by the Relay-forward's link-address, which is in it. Its id is a hash of the
//!   prefix, so it stays the same when other entries come and go. Each has the pool,
//!   the lifetimes and the `dns-servers` option.
//!
//! Every value written is read again as an address, number or interface name.
//! Kea reads it again on `config-reload` ([`crate::settings::reload`]) on its own
//! DHCPv6 control socket.
//!
//! # Standards
//!
//! - RFC 3646 section 3: the DNS Recursive Name Server option (`dns-servers`).
//! - RFC 8415 section 21.6: the preferred and valid lifetimes of the addresses.
//!
//! Deviations: none of DHCPv6 itself is here; Kea implements it.

use std::fmt::Write as _;
use std::net::Ipv6Addr;

use ruster_config::Dhcp6;

use crate::relay6::Link6;

/// The first line of the file.
pub const HEADER: &str =
    "// Written by ruster-kea from confd's dhcp6 entries; it is replaced on each change.";

/// Where Kea's DHCPv6 listens: an interface and its IPv6 address (`lo/::1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen6 {
    pub interface: String,
    pub address: Ipv6Addr,
}

impl Listen6 {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("{text:?} is not like lo/::1");
        let (interface, address) = text.split_once('/').ok_or_else(bad)?;
        let named = !interface.is_empty()
            && interface.len() <= 15
            && interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !named {
            return Err(bad());
        }
        Ok(Self {
            interface: interface.to_owned(),
            address: address.parse().map_err(|_| bad())?,
        })
    }
}

/// One `dhcp6` entry, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served6 {
    pub link: Link6,
    pub len: u8,
    pub pool: (Ipv6Addr, Ipv6Addr),
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub dns: Vec<Ipv6Addr>,
}

impl Served6 {
    /// The subnet's address.
    pub fn subnet(&self) -> Ipv6Addr {
        let mask = u128::MAX
            .checked_shl(128 - u32::from(self.len))
            .unwrap_or(0);
        Ipv6Addr::from(u128::from(self.link.address) & mask)
    }

    /// Kea's id for the subnet: from 1 to 2^31, from a hash (FNV-1a) of the prefix.
    pub fn id(&self) -> u32 {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in self.subnet().octets().into_iter().chain([self.len]) {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        (hash & 0x7fff_ffff) + 1
    }
}

/// Reads the `dhcp6` entries of a part. confd checked them; this reads them again
/// so that only addresses and numbers are written.
pub fn read(dhcp6: &[Dhcp6]) -> Result<Vec<Served6>, String> {
    let served: Vec<Served6> = dhcp6
        .iter()
        .map(|entry| {
            let at = format!("dhcp6 {:?}", entry.interface);
            let address = |text: &str| {
                text.parse::<Ipv6Addr>()
                    .map_err(|_| format!("{at}: {text:?} is not an IPv6 address"))
            };
            let (own, len) = entry
                .address
                .split_once('/')
                .ok_or_else(|| format!("{at}: address has no prefix length"))?;
            let len: u8 = len
                .parse()
                .ok()
                .filter(|len| *len <= 128)
                .ok_or_else(|| format!("{at}: bad prefix length"))?;
            let (first, last) = entry
                .pool
                .split_once('-')
                .ok_or_else(|| format!("{at}: pool is not a range"))?;
            let mut mac = [0; 6];
            let mut parts = entry.mac.split(':');
            for byte in &mut mac {
                *byte = parts
                    .next()
                    .and_then(|p| u8::from_str_radix(p, 16).ok())
                    .ok_or_else(|| format!("{at}: bad mac"))?;
            }
            if entry.interface.is_empty() || entry.interface.len() > 255 {
                return Err(format!("{at}: bad interface name"));
            }
            Ok(Served6 {
                link: Link6 {
                    interface: entry.interface.clone(),
                    mac,
                    link_local: address(&entry.link_local)?,
                    address: address(own)?,
                },
                len,
                pool: (address(first)?, address(last)?),
                preferred_lifetime: entry.preferred_lifetime,
                valid_lifetime: entry.valid_lifetime,
                dns: entry
                    .dns
                    .iter()
                    .map(|a| address(a))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect::<Result<_, String>>()?;
    for (at, s) in served.iter().enumerate() {
        if let Some(other) = served[..at].iter().find(|o| o.id() == s.id()) {
            return Err(format!(
                "dhcp6 {:?} and {:?}: their subnets get the same id",
                other.link.interface, s.link.interface
            ));
        }
    }
    Ok(served)
}

/// The text of the included file.
pub fn settings(listen: &Listen6, served: &[Served6]) -> String {
    let mut out = format!("{HEADER}\n\"interfaces-config\": {{\n    \"interfaces\": [");
    if !served.is_empty() {
        let _ = write!(out, " \"{}/{}\" ", listen.interface, listen.address);
    }
    out.push_str("]\n},\n\"subnet6\": [");
    for (at, s) in served.iter().enumerate() {
        let dns = s
            .dns
            .iter()
            .map(Ipv6Addr::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let options = if dns.is_empty() {
            String::new()
        } else {
            format!("{{ \"name\": \"dns-servers\", \"data\": \"{dns}\" }}")
        };
        let _ = write!(
            out,
            "{}\n    {{\n        \"id\": {},\n        \"subnet\": \"{}/{}\",\n        \
             \"preferred-lifetime\": {},\n        \"valid-lifetime\": {},\n        \
             \"pools\": [ {{ \"pool\": \"{} - {}\" }} ],\n        \
             \"option-data\": [ {options} ]\n    }}",
            if at == 0 { "" } else { "," },
            s.id(),
            s.subnet(),
            s.len,
            s.preferred_lifetime,
            s.valid_lifetime,
            s.pool.0,
            s.pool.1,
        );
    }
    out.push_str(if served.is_empty() { "]\n" } else { "\n]\n" });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Dhcp6 {
        Dhcp6 {
            interface: "lan".into(),
            mac: "02:00:00:00:00:01".into(),
            link_local: "fe80::ff:fe00:1".into(),
            address: "2001:db8:1::1/64".into(),
            pool: "2001:db8:1::1000-2001:db8:1::1fff".into(),
            preferred_lifetime: 600,
            valid_lifetime: 1_200,
            dns: vec!["2001:db8:1::1".into()],
            punt_rate: 200,
            punt_burst: 100,
        }
    }

    #[test]
    fn a_subnet_per_interface() {
        let served = read(&[entry()]).unwrap();
        assert_eq!(
            served[0].link.link_local,
            "fe80::ff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
        let text = settings(&Listen6::parse("lo/::1").unwrap(), &served);
        for want in [
            "\"interfaces\": [ \"lo/::1\" ]",
            "\"subnet\": \"2001:db8:1::/64\"",
            "\"preferred-lifetime\": 600",
            "\"valid-lifetime\": 1200",
            "\"pool\": \"2001:db8:1::1000 - 2001:db8:1::1fff\"",
            "{ \"name\": \"dns-servers\", \"data\": \"2001:db8:1::1\" }",
            &format!("\"id\": {}", served[0].id()),
        ] {
            assert!(text.contains(want), "{want} in {text}");
        }
        let none = settings(&Listen6::parse("lo/::1").unwrap(), &[]);
        assert!(
            none.contains("\"interfaces\": []") && none.contains("\"subnet6\": []"),
            "{none}"
        );
        let mut bad = entry();
        bad.dns = vec!["\" }, evil".into()];
        assert!(read(&[bad]).is_err());
        assert!(Listen6::parse("lo/127.0.0.1").is_err());
    }
}
