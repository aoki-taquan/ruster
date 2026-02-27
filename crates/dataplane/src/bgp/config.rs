//! BGP configuration types for the dataplane BGP engine.
//!
//! These are the parsed, validated configuration values derived from
//! [`ruster_config::model::BgpConfig`].  Raw string addresses are
//! converted to `[u8; 4]` at construction time so the engine can work
//! with binary representations throughout.
//!
//! RFC-REF: RFC 4271 Section 3
//! "The data exchanged via BGP supports only the destination-based
//! forwarding paradigm, which assumes that a router forwards a packet
//! based solely on the destination address carried in the IP header
//! of the packet."

use std::fmt;

/// Parsed BGP peer configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPeerConfig {
    /// Peer IPv4 address.
    pub address: [u8; 4],
    /// Remote autonomous system number.
    pub remote_as: u32,
    /// Negotiated hold time in seconds.
    ///
    /// RFC-REF: RFC 4271 Section 4.2
    /// "The Hold Time MUST be either zero or at least three seconds."
    pub hold_time: u16,
}

/// Parsed BGP engine configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpEngineConfig {
    /// Local autonomous system number.
    pub local_as: u32,
    /// BGP router ID as a 4-byte IPv4 address.
    ///
    /// RFC-REF: RFC 4271 Section 1
    /// "A BGP speaker is identified by its BGP Identifier (a 4-octet
    /// unsigned integer)."
    pub router_id: [u8; 4],
    /// List of configured eBGP peers.
    pub peers: Vec<BgpPeerConfig>,
}

/// Error returned when BGP configuration cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpConfigError {
    /// The router_id string could not be parsed as an IPv4 address.
    InvalidRouterId(String),
    /// A peer address could not be parsed as an IPv4 address.
    InvalidPeerAddress(String),
    /// Hold time is non-zero but less than 3 seconds.
    InvalidHoldTime(u16),
}

impl fmt::Display for BgpConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRouterId(s) => write!(f, "invalid BGP router-id: \"{s}\""),
            Self::InvalidPeerAddress(s) => write!(f, "invalid BGP peer address: \"{s}\""),
            Self::InvalidHoldTime(t) => {
                write!(f, "invalid BGP hold time: {t} (must be 0 or >= 3)")
            }
        }
    }
}

impl std::error::Error for BgpConfigError {}

impl BgpEngineConfig {
    /// Parse a [`BgpEngineConfig`] from the config model's [`BgpConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`BgpConfigError`] if any address string is unparseable
    /// or the hold time is invalid.
    pub fn from_model(cfg: &ruster_config::model::BgpConfig) -> Result<Self, BgpConfigError> {
        let router_id = parse_ipv4(&cfg.router_id)
            .ok_or_else(|| BgpConfigError::InvalidRouterId(cfg.router_id.clone()))?;

        let mut peers = Vec::with_capacity(cfg.peers.len());
        for p in &cfg.peers {
            let addr = parse_ipv4(&p.address)
                .ok_or_else(|| BgpConfigError::InvalidPeerAddress(p.address.clone()))?;

            // RFC-REF: RFC 4271 Section 4.2
            // "The Hold Time MUST be either zero or at least three seconds."
            if p.hold_time != 0 && p.hold_time < 3 {
                return Err(BgpConfigError::InvalidHoldTime(p.hold_time));
            }

            peers.push(BgpPeerConfig {
                address: addr,
                remote_as: p.remote_as,
                hold_time: p.hold_time,
            });
        }

        Ok(Self {
            local_as: cfg.local_as,
            router_id,
            peers,
        })
    }
}

/// Parse an IPv4 dotted-decimal string into a 4-byte array.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse::<u8>().ok()?;
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_config::model::{BgpConfig, BgpPeerConfig as ModelPeerConfig};

    #[test]
    fn parse_valid_config() {
        let model = BgpConfig {
            local_as: 65001,
            router_id: "10.0.0.1".to_string(),
            peers: vec![ModelPeerConfig {
                address: "10.0.0.2".to_string(),
                remote_as: 65002,
                hold_time: 90,
            }],
        };
        let cfg = BgpEngineConfig::from_model(&model).unwrap();
        assert_eq!(cfg.local_as, 65001);
        assert_eq!(cfg.router_id, [10, 0, 0, 1]);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].address, [10, 0, 0, 2]);
        assert_eq!(cfg.peers[0].remote_as, 65002);
        assert_eq!(cfg.peers[0].hold_time, 90);
    }

    #[test]
    fn reject_invalid_router_id() {
        let model = BgpConfig {
            local_as: 65001,
            router_id: "not-an-ip".to_string(),
            peers: vec![],
        };
        let err = BgpEngineConfig::from_model(&model).unwrap_err();
        assert!(matches!(err, BgpConfigError::InvalidRouterId(_)));
    }

    #[test]
    fn reject_invalid_peer_address() {
        let model = BgpConfig {
            local_as: 65001,
            router_id: "10.0.0.1".to_string(),
            peers: vec![ModelPeerConfig {
                address: "bad".to_string(),
                remote_as: 65002,
                hold_time: 90,
            }],
        };
        let err = BgpEngineConfig::from_model(&model).unwrap_err();
        assert!(matches!(err, BgpConfigError::InvalidPeerAddress(_)));
    }

    #[test]
    fn reject_hold_time_too_low() {
        let model = BgpConfig {
            local_as: 65001,
            router_id: "10.0.0.1".to_string(),
            peers: vec![ModelPeerConfig {
                address: "10.0.0.2".to_string(),
                remote_as: 65002,
                hold_time: 2,
            }],
        };
        let err = BgpEngineConfig::from_model(&model).unwrap_err();
        assert!(matches!(err, BgpConfigError::InvalidHoldTime(2)));
    }

    #[test]
    fn hold_time_zero_is_valid() {
        let model = BgpConfig {
            local_as: 65001,
            router_id: "10.0.0.1".to_string(),
            peers: vec![ModelPeerConfig {
                address: "10.0.0.2".to_string(),
                remote_as: 65002,
                hold_time: 0,
            }],
        };
        let cfg = BgpEngineConfig::from_model(&model).unwrap();
        assert_eq!(cfg.peers[0].hold_time, 0);
    }

    #[test]
    fn parse_ipv4_valid() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
    }
}
