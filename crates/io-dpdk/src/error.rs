use std::fmt;

use ruster_core::IfId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// The `dpdk` feature is off, or it is on but `libdpdk` (or a compiler
    /// able to build the inline-function shim) was not found at build time.
    Unavailable,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => {
                formatter.write_str("ruster-io-dpdk was built without a usable libdpdk")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    NoPorts,
    DuplicateInterface(IfId),
    DuplicatePortId(u16),
    ZeroPoolCapacity,
    ZeroMaxFrame,
    /// `max_frame_len` plus the fixed mbuf headroom does not fit in one
    /// mbuf's `data_room_size`.
    MaxFrameExceedsDataRoom {
        max_frame_len: u16,
        data_room: u16,
    },
    ZeroTxRingDescriptors,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPorts => formatter.write_str("DPDK config binds zero interfaces to a port"),
            Self::DuplicateInterface(interface) => {
                write!(formatter, "interface {interface:?} is bound more than once")
            }
            Self::DuplicatePortId(port_id) => {
                write!(formatter, "DPDK port {port_id} is bound more than once")
            }
            Self::ZeroPoolCapacity => formatter.write_str("mbuf pool capacity cannot be zero"),
            Self::ZeroMaxFrame => formatter.write_str("max_frame_len cannot be zero"),
            Self::MaxFrameExceedsDataRoom {
                max_frame_len,
                data_room,
            } => write!(
                formatter,
                "max_frame_len {max_frame_len} does not fit in a {data_room}-byte mbuf data room"
            ),
            Self::ZeroTxRingDescriptors => {
                formatter.write_str("tx_ring_descriptors cannot be zero")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EalStage {
    Init,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthdevStage {
    Configure,
    TxQueueSetup,
    Start,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpdkError {
    Config(ConfigError),
    Platform(PlatformError),
    /// `rte_eal_init` failed; `errno` is the value of `rte_errno` sampled
    /// immediately afterward.
    Eal {
        stage: EalStage,
        errno: i32,
    },
    /// An ethdev setup call returned a negative errno for `port_id`.
    Ethdev {
        stage: EthdevStage,
        port_id: u16,
        errno: i32,
    },
    /// `port_id` is not one `rte_eth_dev_count_avail` reports as usable.
    PortUnavailable {
        port_id: u16,
        available: u16,
    },
    PoolCreateFailed,
    /// `begin_generated` was called with an [`IfId`] this backend has no
    /// port bound to. `allocate()` still succeeds (the frame is real and
    /// counted), but `finish()` always rejects it without ever calling
    /// `tx_burst`.
    UnknownEgress(IfId),
    /// `test-hooks` only: `finish()` reports this injected failure once,
    /// after performing every real reclaim/free it would have done anyway.
    #[cfg(feature = "test-hooks")]
    InjectedFinishFailure,
}

impl fmt::Display for DpdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(formatter, "invalid DPDK config: {source}"),
            Self::Platform(source) => write!(formatter, "{source}"),
            Self::Eal { stage, errno } => {
                write!(formatter, "EAL {stage:?} failed with errno {errno}")
            }
            Self::Ethdev {
                stage,
                port_id,
                errno,
            } => write!(
                formatter,
                "ethdev {stage:?} on port {port_id} failed with errno {errno}"
            ),
            Self::PortUnavailable { port_id, available } => write!(
                formatter,
                "DPDK port {port_id} is not among the {available} ports rte_eth_dev_count_avail reports"
            ),
            Self::PoolCreateFailed => formatter.write_str("rte_pktmbuf_pool_create failed"),
            Self::UnknownEgress(interface) => {
                write!(formatter, "no DPDK port is bound to interface {interface:?}")
            }
            #[cfg(feature = "test-hooks")]
            Self::InjectedFinishFailure => {
                formatter.write_str("test-hooks: injected generated-batch finish failure")
            }
        }
    }
}

impl std::error::Error for DpdkError {}

impl From<ConfigError> for DpdkError {
    fn from(source: ConfigError) -> Self {
        Self::Config(source)
    }
}
