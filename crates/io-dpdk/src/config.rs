use ruster_core::IfId;

use crate::error::ConfigError;

/// The default `RTE_PKTMBUF_HEADROOM` DPDK reserves ahead of mbuf data.
/// Fixed, rather than probed, because it is a compile-time constant of the
/// DPDK build this crate links against, not a runtime-negotiable value.
pub const DEFAULT_MBUF_HEADROOM: u16 = 128;

/// One Ruster interface bound to one DPDK ethdev port, queue 0 in both
/// directions.
///
/// Multiple logical interfaces map to distinct DPDK *ports* rather than
/// distinct queues of a single port: `af_packet` (the PMD this backend is
/// proven against, see `crates/io-dpdk` module docs) binds one port to one
/// host `iface=`, so one port per Ruster interface is the natural, portable
/// mapping and it sidesteps PMD-specific multi-queue support entirely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortBinding {
    pub interface: IfId,
    pub port_id: u16,
}

/// Unchecked construction input for [`ValidatedConfig`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpdkConfig {
    /// `argv[1..]` passed to `rte_eal_init`; `argv[0]` is supplied by the
    /// backend. For the proven no-hugepage, no-PCI, `af_packet` vdev
    /// environment this looks like
    /// `["--no-huge", "-m", "512", "-l", "0-1", "--no-pci",
    /// "--vdev=net_af_packet0,iface=veth0"]`.
    pub eal_args: Vec<String>,
    pub ports: Vec<PortBinding>,
    pub pool_capacity: u32,
    pub pool_cache_size: u32,
    /// Largest payload `allocate()` will hand out.
    pub max_frame_len: u16,
    pub tx_ring_descriptors: u16,
}

/// A [`DpdkConfig`] checked for internal consistency before any EAL or
/// ethdev call is made.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    eal_args: Vec<String>,
    ports: Vec<PortBinding>,
    pool_capacity: u32,
    pool_cache_size: u32,
    max_frame_len: u16,
    data_room_size: u16,
    tx_ring_descriptors: u16,
}

impl ValidatedConfig {
    pub fn new(config: DpdkConfig) -> Result<Self, ConfigError> {
        let DpdkConfig {
            eal_args,
            ports,
            pool_capacity,
            pool_cache_size,
            max_frame_len,
            tx_ring_descriptors,
        } = config;

        if ports.is_empty() {
            return Err(ConfigError::NoPorts);
        }
        for (index, port) in ports.iter().enumerate() {
            for earlier in &ports[..index] {
                if earlier.interface == port.interface {
                    return Err(ConfigError::DuplicateInterface(port.interface));
                }
                if earlier.port_id == port.port_id {
                    return Err(ConfigError::DuplicatePortId(port.port_id));
                }
            }
        }
        if pool_capacity == 0 {
            return Err(ConfigError::ZeroPoolCapacity);
        }
        if max_frame_len == 0 {
            return Err(ConfigError::ZeroMaxFrame);
        }
        if tx_ring_descriptors == 0 {
            return Err(ConfigError::ZeroTxRingDescriptors);
        }
        let data_room_size = u32::from(DEFAULT_MBUF_HEADROOM)
            .checked_add(u32::from(max_frame_len))
            .and_then(|room| u16::try_from(room).ok())
            .ok_or(ConfigError::MaxFrameExceedsDataRoom {
                max_frame_len,
                data_room: u16::MAX,
            })?;

        Ok(Self {
            eal_args,
            ports,
            pool_capacity,
            pool_cache_size,
            max_frame_len,
            data_room_size,
            tx_ring_descriptors,
        })
    }

    #[must_use]
    pub fn eal_args(&self) -> &[String] {
        &self.eal_args
    }

    #[must_use]
    pub fn ports(&self) -> &[PortBinding] {
        &self.ports
    }

    #[must_use]
    pub const fn pool_capacity(&self) -> u32 {
        self.pool_capacity
    }

    #[must_use]
    pub const fn pool_cache_size(&self) -> u32 {
        self.pool_cache_size
    }

    #[must_use]
    pub const fn max_frame_len(&self) -> u16 {
        self.max_frame_len
    }

    #[must_use]
    pub const fn data_room_size(&self) -> u16 {
        self.data_room_size
    }

    #[must_use]
    pub const fn tx_ring_descriptors(&self) -> u16 {
        self.tx_ring_descriptors
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, DpdkConfig, PortBinding, ValidatedConfig};
    use ruster_core::IfId;

    fn base_config() -> DpdkConfig {
        DpdkConfig {
            eal_args: Vec::new(),
            ports: vec![PortBinding {
                interface: IfId(1),
                port_id: 0,
            }],
            pool_capacity: 256,
            pool_cache_size: 32,
            max_frame_len: 1500,
            tx_ring_descriptors: 128,
        }
    }

    #[test]
    fn rejects_zero_ports() {
        let config = DpdkConfig {
            ports: Vec::new(),
            ..base_config()
        };
        assert_eq!(ValidatedConfig::new(config), Err(ConfigError::NoPorts));
    }

    #[test]
    fn rejects_duplicate_interface() {
        let mut config = base_config();
        config.ports.push(PortBinding {
            interface: IfId(1),
            port_id: 1,
        });
        assert_eq!(
            ValidatedConfig::new(config),
            Err(ConfigError::DuplicateInterface(IfId(1)))
        );
    }

    #[test]
    fn rejects_duplicate_port_id() {
        let mut config = base_config();
        config.ports.push(PortBinding {
            interface: IfId(2),
            port_id: 0,
        });
        assert_eq!(
            ValidatedConfig::new(config),
            Err(ConfigError::DuplicatePortId(0))
        );
    }

    #[test]
    fn rejects_zero_pool_capacity() {
        let config = DpdkConfig {
            pool_capacity: 0,
            ..base_config()
        };
        assert_eq!(
            ValidatedConfig::new(config),
            Err(ConfigError::ZeroPoolCapacity)
        );
    }

    #[test]
    fn rejects_zero_max_frame() {
        let config = DpdkConfig {
            max_frame_len: 0,
            ..base_config()
        };
        assert_eq!(ValidatedConfig::new(config), Err(ConfigError::ZeroMaxFrame));
    }

    #[test]
    fn rejects_zero_tx_ring_descriptors() {
        let config = DpdkConfig {
            tx_ring_descriptors: 0,
            ..base_config()
        };
        assert_eq!(
            ValidatedConfig::new(config),
            Err(ConfigError::ZeroTxRingDescriptors)
        );
    }

    #[test]
    fn computes_data_room_from_headroom_and_max_frame() {
        let validated = ValidatedConfig::new(base_config()).expect("valid config");
        assert_eq!(validated.data_room_size(), 128 + 1500);
    }
}
