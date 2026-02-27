//! SRv6 endpoint actions (SID behaviors).
//!
//! RFC-REF: RFC 8986 Section 4
//! This module implements the SRv6 Network Programming behaviors
//! that are triggered when a packet matches a local SID.
//!
//! Supported actions:
//! - End: Basic endpoint behavior (RFC 8986 Section 4.1)
//! - End.DT4: Decapsulate and lookup in IPv4 table (RFC 8986 Section 4.1.4)
//! - End.DT6: Decapsulate and lookup in IPv6 table (RFC 8986 Section 4.1.5)
//! - uN: uSID shift behavior (RFC 8986 Section 4.3.1)

use super::config::LocalSidConfig;

/// SRv6 endpoint actions.
///
/// RFC-REF: RFC 8986 Section 4
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6Action {
    /// End: Basic SRv6 endpoint.
    ///
    /// RFC-REF: RFC 8986 Section 4.1
    /// "When a node N receives a packet whose DA is S and S is a
    /// local SID, N does: Decrement SL, update DA with SID[SL],
    /// submit to IPv6 module for forwarding."
    End,

    /// End.DT4: Decapsulate and forward in IPv4 table.
    ///
    /// RFC-REF: RFC 8986 Section 4.1.4
    /// "Pop the outer IPv6 header with its SRH. Submit the inner
    /// IPv4 packet to the IPv4 FIB lookup."
    EndDT4 {
        /// VRF table name for the IPv4 lookup (e.g., "default").
        table: String,
    },

    /// End.DT6: Decapsulate and forward in IPv6 table.
    ///
    /// RFC-REF: RFC 8986 Section 4.1.5
    /// "Pop the outer IPv6 header with its SRH. Submit the inner
    /// IPv6 packet to the IPv6 FIB lookup."
    EndDT6 {
        /// VRF table name for the IPv6 lookup (e.g., "default").
        table: String,
    },

    /// uN: uSID shift endpoint behavior.
    ///
    /// RFC-REF: RFC 8986 Section 4.3.1
    /// "Shift the uSID container: advance to the next micro-SID
    /// by left-shifting the uSID portion and updating the DA."
    UN,
}

impl Srv6Action {
    /// Build an SRv6 action from a configuration entry.
    pub fn from_config(cfg: &LocalSidConfig) -> Self {
        match cfg.action.to_lowercase().as_str() {
            "end" => Srv6Action::End,
            "end_dt4" | "end.dt4" => Srv6Action::EndDT4 {
                table: cfg.table.clone().unwrap_or_else(|| "default".to_string()),
            },
            "end_dt6" | "end.dt6" => Srv6Action::EndDT6 {
                table: cfg.table.clone().unwrap_or_else(|| "default".to_string()),
            },
            "un" | "u_n" | "usid_shift" => Srv6Action::UN,
            _ => {
                // RFC-DEVIATION:
                // reason: Unknown actions default to End for forward-compat
                // impact: Unsupported actions will behave as basic endpoint
                // issue: #160
                // plan: v0.2 で全 RFC 8986 actions をサポート
                Srv6Action::End
            }
        }
    }

    /// Returns a human-readable name for the action.
    pub fn name(&self) -> &'static str {
        match self {
            Srv6Action::End => "End",
            Srv6Action::EndDT4 { .. } => "End.DT4",
            Srv6Action::EndDT6 { .. } => "End.DT6",
            Srv6Action::UN => "uN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_from_config_end() {
        let cfg = LocalSidConfig {
            sid: "fd00::1".to_string(),
            action: "end".to_string(),
            table: None,
        };
        assert_eq!(Srv6Action::from_config(&cfg), Srv6Action::End);
    }

    #[test]
    fn action_from_config_end_dt4() {
        let cfg = LocalSidConfig {
            sid: "fd00::2".to_string(),
            action: "end_dt4".to_string(),
            table: Some("default".to_string()),
        };
        assert_eq!(
            Srv6Action::from_config(&cfg),
            Srv6Action::EndDT4 {
                table: "default".to_string(),
            }
        );
    }

    #[test]
    fn action_from_config_end_dt6() {
        let cfg = LocalSidConfig {
            sid: "fd00::3".to_string(),
            action: "end_dt6".to_string(),
            table: Some("v6table".to_string()),
        };
        assert_eq!(
            Srv6Action::from_config(&cfg),
            Srv6Action::EndDT6 {
                table: "v6table".to_string(),
            }
        );
    }

    #[test]
    fn action_from_config_un() {
        let cfg = LocalSidConfig {
            sid: "fd00::/32".to_string(),
            action: "un".to_string(),
            table: None,
        };
        assert_eq!(Srv6Action::from_config(&cfg), Srv6Action::UN);
    }

    #[test]
    fn action_from_config_unknown_defaults_to_end() {
        let cfg = LocalSidConfig {
            sid: "fd00::1".to_string(),
            action: "end_x_not_supported".to_string(),
            table: None,
        };
        assert_eq!(Srv6Action::from_config(&cfg), Srv6Action::End);
    }

    #[test]
    fn action_name() {
        assert_eq!(Srv6Action::End.name(), "End");
        assert_eq!(
            Srv6Action::EndDT4 {
                table: "default".to_string()
            }
            .name(),
            "End.DT4"
        );
        assert_eq!(
            Srv6Action::EndDT6 {
                table: "default".to_string()
            }
            .name(),
            "End.DT6"
        );
        assert_eq!(Srv6Action::UN.name(), "uN");
    }
}
