//! SRv6 (Segment Routing over IPv6) processing engine.
//!
//! RFC-REF: RFC 8986 (SRv6 Network Programming)
//! RFC-REF: RFC 8754 (IPv6 Segment Routing Header)
//!
//! This module implements the SRv6 data plane processing:
//! - SRH (Segment Routing Header) parsing and serialization
//! - uSID (micro-SID) compressed segment handling
//! - Local SID table with action dispatch
//! - SRv6 endpoint behaviors (End, End.DT4, End.DT6, uN)
//!
//! # Architecture
//!
//! The SRv6 engine integrates with the IPv6 forwarding pipeline:
//!
//! ```text
//! IPv6 packet → check NH=43(Routing) → parse SRH →
//!   → lookup DA in Local SID table →
//!     → match: execute action (End, uN, End.DT4, etc.)
//!     → no match: forward as normal IPv6 packet
//! ```

pub mod actions;
pub mod config;
pub mod policy;
pub mod sid_table;
pub mod srh;
pub mod usid;

use actions::Srv6Action;
use config::Srv6Config;
use sid_table::{SidTable, SidTableError};
use srh::{Srh, IPV6_NH_ROUTING};
use usid::UsidContainer;

/// Drop reasons specific to SRv6 processing.
///
/// These are returned when a packet fails SRv6 validation or processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Srv6DropReason {
    /// SRH is too short to contain a valid header.
    SrhTooShort,
    /// SRH has an invalid Routing Type (expected 4).
    InvalidRoutingType { found: u8 },
    /// Segment list length is not a multiple of 16 bytes.
    InvalidSegmentListLength,
    /// Segments Left > Last Entry.
    SegmentsLeftExceedsLastEntry,
    /// Last Entry does not match the actual segment count.
    InvalidLastEntry,
    /// SRH Segments Left is 0 but no local SID action matched.
    NoLocalSidMatch,
    /// The inner packet after decapsulation is invalid.
    InvalidInnerPacket,
    /// Hop Limit expired during SRv6 processing.
    HopLimitExpired,
    /// The SRH is missing when expected.
    MissingSrh,
}

impl std::fmt::Display for Srv6DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SrhTooShort => write!(f, "SRH too short"),
            Self::InvalidRoutingType { found } => {
                write!(f, "invalid SRH routing type {found} (expected 4)")
            }
            Self::InvalidSegmentListLength => write!(f, "invalid SRH segment list length"),
            Self::SegmentsLeftExceedsLastEntry => {
                write!(f, "SRH Segments Left > Last Entry")
            }
            Self::InvalidLastEntry => write!(f, "SRH Last Entry mismatch"),
            Self::NoLocalSidMatch => write!(f, "no Local SID match"),
            Self::InvalidInnerPacket => write!(f, "invalid inner packet after decap"),
            Self::HopLimitExpired => write!(f, "hop limit expired in SRv6"),
            Self::MissingSrh => write!(f, "SRH missing when expected"),
        }
    }
}

/// Result of SRv6 processing for a single packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6Decision {
    /// Continue forwarding with updated DA and hop limit.
    ///
    /// The pipeline should update the IPv6 DA to `new_da` and
    /// decrement the Hop Limit, then forward via normal IPv6 routing.
    Forward {
        /// New IPv6 Destination Address (updated SID).
        new_da: [u8; 16],
        /// Whether the SRH Segments Left was modified.
        srh_modified: bool,
    },

    /// Decapsulate the packet and process the inner IPv4 packet.
    ///
    /// The outer IPv6 header (and SRH) should be stripped, and the
    /// inner IPv4 packet submitted to the IPv4 FIB.
    DecapIpv4 {
        /// VRF table for the IPv4 lookup.
        table: String,
    },

    /// Decapsulate the packet and process the inner IPv6 packet.
    ///
    /// The outer IPv6 header (and SRH) should be stripped, and the
    /// inner IPv6 packet submitted to the IPv6 FIB.
    DecapIpv6 {
        /// VRF table for the IPv6 lookup.
        table: String,
    },

    /// Packet was dropped during SRv6 processing.
    Drop { reason: Srv6DropReason },

    /// This is not an SRv6 packet (no SRH, DA not in Local SID table).
    /// The pipeline should continue with normal IPv6 forwarding.
    NotSrv6,
}

/// The SRv6 processing engine.
///
/// Holds the Local SID table and uSID configuration, and provides
/// the main `process()` method for SRv6 packet handling.
#[derive(Debug, Clone)]
pub struct Srv6Engine {
    /// SRv6 configuration (block/uSID parameters).
    config: Srv6Config,
    /// Local SID table mapping SIDs to actions.
    sid_table: SidTable,
}

impl Srv6Engine {
    /// Create a new SRv6 engine from configuration.
    ///
    /// Validates the configuration before building the SID table.
    /// Returns an error if validation fails or the SID table cannot be built.
    pub fn from_config(config: Srv6Config) -> Result<Self, SidTableError> {
        let validation_errors = config.validate();
        if !validation_errors.is_empty() {
            return Err(SidTableError {
                messages: validation_errors,
            });
        }
        let sid_table = SidTable::from_config(&config.local_sids)?;
        Ok(Self { config, sid_table })
    }

    /// Create an SRv6 engine with no local SIDs (effectively disabled).
    pub fn disabled() -> Self {
        Self {
            config: Srv6Config::default(),
            sid_table: SidTable::new(),
        }
    }

    /// Process an IPv6 packet for SRv6 handling.
    ///
    /// This is the main entry point called by the IPv6 forwarding pipeline.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - The IPv6 Destination Address of the packet.
    /// * `next_header` - The Next Header field of the IPv6 header.
    /// * `payload` - The payload starting after the IPv6 fixed header.
    /// * `hop_limit` - Current Hop Limit.
    ///
    /// # Returns
    ///
    /// An [`Srv6Decision`] indicating what the pipeline should do next.
    ///
    /// RFC-REF: RFC 8986 Section 4
    /// "When a node receives a packet destined to a SID in its local
    /// SID table, the node executes the function bound to that SID."
    pub fn process(
        &self,
        dst_addr: &[u8; 16],
        next_header: u8,
        payload: &[u8],
        hop_limit: u8,
    ) -> Srv6Decision {
        // Step 1: Check if the DA matches a local SID.
        let sid_entry = match self.sid_table.lookup(dst_addr) {
            Some(entry) => entry,
            None => return Srv6Decision::NotSrv6,
        };

        // Step 2: Parse SRH if present (Next Header = 43).
        let srh = if next_header == IPV6_NH_ROUTING {
            match Srh::parse(payload) {
                Ok(srh) => Some(srh),
                Err(reason) => return Srv6Decision::Drop { reason },
            }
        } else {
            None
        };

        // Step 3: Execute the action bound to the SID.
        match &sid_entry.action {
            Srv6Action::End => self.process_end(srh.as_ref(), hop_limit),
            Srv6Action::UN => self.process_un(dst_addr, srh.as_ref(), hop_limit),
            Srv6Action::EndDT4 { table } => self.process_end_dt4(srh.as_ref(), table),
            Srv6Action::EndDT6 { table } => self.process_end_dt6(srh.as_ref(), table),
        }
    }

    /// Process the End action (basic SRv6 endpoint).
    ///
    /// RFC-REF: RFC 8986 Section 4.1
    /// 1. If SL == 0, drop (upper-layer processing not supported in v0.1).
    /// 2. Decrement SL.
    /// 3. Update DA to SID[SL].
    /// 4. Forward to next hop.
    fn process_end(&self, srh: Option<&Srh>, hop_limit: u8) -> Srv6Decision {
        let srh = match srh {
            Some(s) => s,
            None => {
                return Srv6Decision::Drop {
                    reason: Srv6DropReason::MissingSrh,
                }
            }
        };

        if hop_limit <= 1 {
            return Srv6Decision::Drop {
                reason: Srv6DropReason::HopLimitExpired,
            };
        }

        if srh.segments_left == 0 {
            // RFC-DEVIATION:
            // reason: When SL==0, RFC says process upper-layer header; we drop for simplicity
            // impact: Packets reaching final SID with SL==0 at an End node are dropped
            // issue: #160
            // plan: v0.2 で upper-layer processing を実装
            return Srv6Decision::Drop {
                reason: Srv6DropReason::NoLocalSidMatch,
            };
        }

        // Decrement SL and get the next SID.
        let new_sl = srh.segments_left - 1;
        let next_sid = srh.segment_list[new_sl as usize];

        Srv6Decision::Forward {
            new_da: next_sid,
            srh_modified: true,
        }
    }

    /// Process the uN action (uSID shift).
    ///
    /// RFC-REF: RFC 8986 Section 4.3.1
    /// 1. Shift the active uSID out of the DA.
    /// 2. If the next uSID is zero:
    ///    a. If SRH is present and SL > 0: decrement SL, use SID[SL] as new DA.
    ///    b. Else: drop.
    /// 3. Else: use the shifted DA as the new DA.
    fn process_un(&self, dst_addr: &[u8; 16], srh: Option<&Srh>, hop_limit: u8) -> Srv6Decision {
        if hop_limit <= 1 {
            return Srv6Decision::Drop {
                reason: Srv6DropReason::HopLimitExpired,
            };
        }

        let container = UsidContainer::from_config(*dst_addr, &self.config);
        let shifted = container.shift();
        let shifted_container =
            UsidContainer::new(shifted, self.config.block_len, self.config.usid_len);

        if shifted_container.is_active_usid_zero() {
            // The uSID container is exhausted. Move to the next SRH segment.
            match srh {
                Some(s) if s.segments_left > 0 => {
                    let new_sl = s.segments_left - 1;
                    let next_sid = s.segment_list[new_sl as usize];
                    Srv6Decision::Forward {
                        new_da: next_sid,
                        srh_modified: true,
                    }
                }
                _ => {
                    // No more segments to process.
                    Srv6Decision::Drop {
                        reason: Srv6DropReason::NoLocalSidMatch,
                    }
                }
            }
        } else {
            // Continue with the shifted DA (next uSID becomes active).
            Srv6Decision::Forward {
                new_da: shifted,
                srh_modified: false,
            }
        }
    }

    /// Process the End.DT4 action (decap and IPv4 lookup).
    ///
    /// RFC-REF: RFC 8986 Section 4.1.4
    /// "If SL != 0: drop. Otherwise, pop outer IPv6 + SRH and submit
    /// inner IPv4 to the specified FIB."
    fn process_end_dt4(&self, srh: Option<&Srh>, table: &str) -> Srv6Decision {
        // RFC-REF: RFC 8986 Section 4.1.4
        // "If Segments Left is not zero, drop."
        if let Some(s) = srh {
            if s.segments_left != 0 {
                return Srv6Decision::Drop {
                    reason: Srv6DropReason::SegmentsLeftExceedsLastEntry,
                };
            }
        }

        Srv6Decision::DecapIpv4 {
            table: table.to_string(),
        }
    }

    /// Process the End.DT6 action (decap and IPv6 lookup).
    ///
    /// RFC-REF: RFC 8986 Section 4.1.5
    /// "If SL != 0: drop. Otherwise, pop outer IPv6 + SRH and submit
    /// inner IPv6 to the specified FIB."
    fn process_end_dt6(&self, srh: Option<&Srh>, table: &str) -> Srv6Decision {
        if let Some(s) = srh {
            if s.segments_left != 0 {
                return Srv6Decision::Drop {
                    reason: Srv6DropReason::SegmentsLeftExceedsLastEntry,
                };
            }
        }

        Srv6Decision::DecapIpv6 {
            table: table.to_string(),
        }
    }

    /// Returns a reference to the Local SID table.
    pub fn sid_table(&self) -> &SidTable {
        &self.sid_table
    }

    /// Returns a reference to the SRv6 configuration.
    pub fn config(&self) -> &Srv6Config {
        &self.config
    }

    /// Check if the SRv6 engine has any local SIDs configured.
    pub fn is_enabled(&self) -> bool {
        !self.sid_table.is_empty()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use config::LocalSidConfig;

    fn make_test_config() -> Srv6Config {
        Srv6Config {
            locator_block: "fd00::".to_string(),
            block_len: 32,
            usid_len: 16,
            local_sids: vec![
                LocalSidConfig {
                    sid: "fd00::1".to_string(),
                    action: "end".to_string(),
                    table: None,
                },
                LocalSidConfig {
                    sid: "fd00::2".to_string(),
                    action: "end_dt4".to_string(),
                    table: Some("default".to_string()),
                },
                LocalSidConfig {
                    sid: "fd00::/32".to_string(),
                    action: "un".to_string(),
                    table: None,
                },
            ],
        }
    }

    fn make_engine() -> Srv6Engine {
        Srv6Engine::from_config(make_test_config()).unwrap()
    }

    // ── Engine construction ──────────────────────────────────────────

    #[test]
    fn engine_from_config() {
        let engine = make_engine();
        assert!(engine.is_enabled());
        assert_eq!(engine.sid_table().len(), 3);
    }

    #[test]
    fn engine_disabled() {
        let engine = Srv6Engine::disabled();
        assert!(!engine.is_enabled());
    }

    #[test]
    fn engine_from_config_rejects_invalid_block_len() {
        let config = Srv6Config {
            block_len: 0,
            ..Srv6Config::default()
        };
        let err = Srv6Engine::from_config(config).unwrap_err();
        assert!(
            err.messages.iter().any(|m| m.contains("block_len")),
            "expected validation error about block_len, got: {:?}",
            err.messages
        );
    }

    #[test]
    fn engine_from_config_rejects_oversized_block_plus_usid() {
        let config = Srv6Config {
            block_len: 120,
            usid_len: 16,
            ..Srv6Config::default()
        };
        let err = Srv6Engine::from_config(config).unwrap_err();
        assert!(
            err.messages.iter().any(|m| m.contains("exceeds 128 bits")),
            "expected validation error about exceeding 128 bits, got: {:?}",
            err.messages
        );
    }

    // ── End action tests ─────────────────────────────────────────────

    #[test]
    fn end_action_decrements_sl_and_updates_da() {
        let engine = make_engine();

        // DA = fd00::1 (matches End SID)
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // Build SRH payload: NH=TCP, 2 segments, SL=1
        let sid0: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]; // final dst
        let sid1: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // current (End SID)

        let srh = Srh::new(6, vec![sid0, sid1]);
        let payload = srh.serialize();

        let decision = engine.process(&da, IPV6_NH_ROUTING, &payload, 64);

        // SL was 1, should decrement to 0, new DA = SID[0] = sid0
        assert_eq!(
            decision,
            Srv6Decision::Forward {
                new_da: sid0,
                srh_modified: true,
            }
        );
    }

    #[test]
    fn end_action_sl_zero_drops() {
        let engine = make_engine();

        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // Build SRH with SL=0
        let mut srh_data = Vec::new();
        srh_data.push(6); // Next Header: TCP
        srh_data.push(2); // Hdr Ext Len
        srh_data.push(4); // Routing Type: SRH
        srh_data.push(0); // Segments Left: 0
        srh_data.push(0); // Last Entry: 0
        srh_data.push(0); // Flags
        srh_data.extend_from_slice(&[0, 0]); // Tag
                                             // 1 segment
        srh_data.extend_from_slice(&da);

        let decision = engine.process(&da, IPV6_NH_ROUTING, &srh_data, 64);
        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::NoLocalSidMatch,
            }
        );
    }

    #[test]
    fn end_action_no_srh_drops() {
        let engine = make_engine();
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // NH=TCP (not routing header), no SRH
        let decision = engine.process(&da, 6, &[], 64);
        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::MissingSrh,
            }
        );
    }

    #[test]
    fn end_action_hop_limit_expired() {
        let engine = make_engine();
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let sid: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let srh = Srh::new(6, vec![sid, da]);
        let payload = srh.serialize();

        let decision = engine.process(&da, IPV6_NH_ROUTING, &payload, 1);
        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::HopLimitExpired,
            }
        );
    }

    // ── uN action tests ──────────────────────────────────────────────

    #[test]
    fn un_action_shifts_usid() {
        let engine = make_engine();

        // DA = fd00:0001:0002:: (block=fd00::/32, active_usid=0x0001)
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];

        // No SRH needed for uN shift within container
        let decision = engine.process(&da, 6, &[], 64);

        // After shift: fd00:0002:0000:: (active_usid = 0x0002)
        let expected_da: [u8; 16] = [0xfd, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decision,
            Srv6Decision::Forward {
                new_da: expected_da,
                srh_modified: false,
            }
        );
    }

    #[test]
    fn un_action_usid_exhausted_with_srh() {
        let engine = make_engine();

        // DA = fd00:0001:0000:: (only one uSID left)
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // SRH with SL=1, segment list has the next destination
        let next_sid: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let srh = Srh::new(6, vec![next_sid, da]);
        let payload = srh.serialize();

        let decision = engine.process(&da, IPV6_NH_ROUTING, &payload, 64);

        // After shift, active uSID is zero -> fall to SRH
        assert_eq!(
            decision,
            Srv6Decision::Forward {
                new_da: next_sid,
                srh_modified: true,
            }
        );
    }

    #[test]
    fn un_action_usid_exhausted_no_srh_drops() {
        let engine = make_engine();

        // DA = fd00:0001:0000:: (only one uSID, will be exhausted)
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // No SRH
        let decision = engine.process(&da, 6, &[], 64);

        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::NoLocalSidMatch,
            }
        );
    }

    #[test]
    fn un_action_hop_limit_expired() {
        let engine = make_engine();
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];

        let decision = engine.process(&da, 6, &[], 1);
        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::HopLimitExpired,
            }
        );
    }

    // ── End.DT4 action tests ─────────────────────────────────────────

    #[test]
    fn end_dt4_decaps_when_sl_zero() {
        let engine = make_engine();

        // DA = fd00::2 (matches End.DT4 SID)
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // SRH with SL=0
        let mut srh_data = Vec::new();
        srh_data.push(4); // Next Header: IPv4
        srh_data.push(2); // Hdr Ext Len
        srh_data.push(4); // Routing Type: SRH
        srh_data.push(0); // Segments Left: 0
        srh_data.push(0); // Last Entry: 0
        srh_data.push(0); // Flags
        srh_data.extend_from_slice(&[0, 0]); // Tag
        srh_data.extend_from_slice(&da); // 1 segment

        let decision = engine.process(&da, IPV6_NH_ROUTING, &srh_data, 64);
        assert_eq!(
            decision,
            Srv6Decision::DecapIpv4 {
                table: "default".to_string(),
            }
        );
    }

    #[test]
    fn end_dt4_drops_when_sl_nonzero() {
        let engine = make_engine();

        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // Build SRH with SL=1 (2 segments)
        let sid0: [u8; 16] = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let srh = Srh::new(4, vec![sid0, da]);
        let payload = srh.serialize();

        let decision = engine.process(&da, IPV6_NH_ROUTING, &payload, 64);
        assert_eq!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::SegmentsLeftExceedsLastEntry,
            }
        );
    }

    // ── Not SRv6 tests ───────────────────────────────────────────────

    #[test]
    fn not_srv6_when_da_not_in_sid_table() {
        let engine = make_engine();

        // DA that doesn't match any SID
        let da: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let decision = engine.process(&da, 6, &[], 64);
        assert_eq!(decision, Srv6Decision::NotSrv6);
    }

    #[test]
    fn disabled_engine_returns_not_srv6() {
        let engine = Srv6Engine::disabled();
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let decision = engine.process(&da, IPV6_NH_ROUTING, &[], 64);
        assert_eq!(decision, Srv6Decision::NotSrv6);
    }

    // ── SRH parsing integration ──────────────────────────────────────

    #[test]
    fn process_with_malformed_srh() {
        let engine = make_engine();
        let da: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // Truncated SRH (only 4 bytes)
        let bad_srh = [43, 0, 4, 0];
        let decision = engine.process(&da, IPV6_NH_ROUTING, &bad_srh, 64);
        assert!(matches!(
            decision,
            Srv6Decision::Drop {
                reason: Srv6DropReason::SrhTooShort
            }
        ));
    }

    // ── Multi-hop SRv6 path simulation ───────────────────────────────

    #[test]
    fn multi_hop_end_action_walk() {
        let engine = make_engine();

        // Simulate a 3-segment SRv6 path:
        // SID[0] = 2001:db8::99 (final destination)
        // SID[1] = fd00::1     (intermediate, our End SID)
        // SID[2] = fc00::1     (entry point)
        let sid0: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
        ];
        let sid1: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sid2: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        // Packet arrives with DA=fd00::1 (sid1), SL=1
        // (the entry point already decremented SL from 2 to 1)
        let srh = Srh {
            next_header: 6,
            hdr_ext_len: 6, // (8 + 3*16)/8 - 1 = 6
            routing_type: 4,
            segments_left: 1,
            last_entry: 2,
            flags: 0,
            tag: 0,
            segment_list: vec![sid0, sid1, sid2],
            total_len: 56,
        };
        let payload = srh.serialize();

        let decision = engine.process(&sid1, IPV6_NH_ROUTING, &payload, 64);

        // End action: SL 1->0, new DA = SID[0] = 2001:db8::99
        assert_eq!(
            decision,
            Srv6Decision::Forward {
                new_da: sid0,
                srh_modified: true,
            }
        );
    }
}
