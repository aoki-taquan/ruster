use ruster_core::IfId;

use crate::{ConfigError, GeometryError};

pub const TPACKET_ALIGNMENT: usize = 16;
pub const TPACKET_V3_HEADER_LEN: usize = 48;
pub const TPACKET_BLOCK_HEADER_LEN: usize = 48;
pub const TPACKET_V3_HDRLEN: usize = 68;
pub const TPACKET_V3_ETHERNET_MAC_OFFSET: usize = 82;
pub const DEFAULT_MAX_FRAME_LEN: usize = 1_514;

const PORT_TABLE_LEN: usize = u16::MAX as usize + 1;
const MISSING_PORT: u16 = u16::MAX;
const MAX_PORTS: usize = u16::MAX as usize;
const SUPPORTED_FEATURE_FLAGS: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingKind {
    Rx,
    Tx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingGeometry {
    pub block_size: u32,
    pub block_count: u32,
    pub frame_size: u32,
    pub frame_count: u32,
    pub retire_timeout_ms: u32,
    pub private_size: u32,
    pub feature_flags: u32,
}

impl RingGeometry {
    pub fn validate(
        self,
        page_size: usize,
        max_frame_len: usize,
    ) -> Result<RingLayout, GeometryError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(GeometryError::PageSizeNotPowerOfTwo { page_size });
        }
        if max_frame_len == 0 {
            return Err(GeometryError::ZeroMaxFrameLength);
        }
        if self.block_size == 0 {
            return Err(GeometryError::ZeroBlockSize);
        }
        if self.block_count == 0 {
            return Err(GeometryError::ZeroBlockCount);
        }
        if self.frame_size == 0 {
            return Err(GeometryError::ZeroFrameSize);
        }
        if self.frame_count == 0 {
            return Err(GeometryError::ZeroFrameCount);
        }

        let block_size =
            usize::try_from(self.block_size).map_err(|_| GeometryError::ArithmeticOverflow)?;
        let frame_size =
            usize::try_from(self.frame_size).map_err(|_| GeometryError::ArithmeticOverflow)?;
        if block_size % page_size != 0 {
            return Err(GeometryError::BlockSizeNotPageAligned {
                block_size: self.block_size,
                page_size,
            });
        }
        if frame_size % TPACKET_ALIGNMENT != 0 {
            return Err(GeometryError::FrameSizeNotAligned {
                frame_size: self.frame_size,
            });
        }

        let minimum = align_up(
            TPACKET_V3_ETHERNET_MAC_OFFSET
                .checked_add(max_frame_len)
                .ok_or(GeometryError::ArithmeticOverflow)?,
            TPACKET_ALIGNMENT,
        )
        .ok_or(GeometryError::ArithmeticOverflow)?;
        if frame_size < minimum {
            return Err(GeometryError::FrameTooSmall {
                frame_size: self.frame_size,
                minimum,
            });
        }
        if block_size % frame_size != 0 {
            return Err(GeometryError::FramesDoNotTileBlock {
                block_size: self.block_size,
                frame_size: self.frame_size,
            });
        }

        let frames_per_block = block_size / frame_size;
        let expected_frames = frames_per_block
            .checked_mul(
                usize::try_from(self.block_count).map_err(|_| GeometryError::ArithmeticOverflow)?,
            )
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if usize::try_from(self.frame_count).ok() != Some(expected_frames) {
            return Err(GeometryError::FrameCountMismatch {
                configured: self.frame_count,
                expected: expected_frames,
            });
        }
        if usize::try_from(self.private_size).map_err(|_| GeometryError::ArithmeticOverflow)?
            % TPACKET_ALIGNMENT
            != 0
        {
            return Err(GeometryError::PrivateAreaNotAligned {
                private_size: self.private_size,
            });
        }
        let private_end = TPACKET_BLOCK_HEADER_LEN
            .checked_add(
                usize::try_from(self.private_size)
                    .map_err(|_| GeometryError::ArithmeticOverflow)?,
            )
            .ok_or(GeometryError::ArithmeticOverflow)?;
        if private_end > block_size {
            return Err(GeometryError::PrivateAreaTooLarge {
                private_size: self.private_size,
                block_size: self.block_size,
            });
        }
        if self.feature_flags & !SUPPORTED_FEATURE_FLAGS != 0 {
            return Err(GeometryError::UnknownFeatureFlags {
                feature_flags: self.feature_flags,
            });
        }
        let block_count =
            usize::try_from(self.block_count).map_err(|_| GeometryError::ArithmeticOverflow)?;
        let map_len = block_size
            .checked_mul(block_count)
            .ok_or(GeometryError::ArithmeticOverflow)?;

        Ok(RingLayout {
            geometry: self,
            block_size,
            block_count,
            frame_size,
            frames_per_block,
            map_len,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingLayout {
    geometry: RingGeometry,
    block_size: usize,
    block_count: usize,
    frame_size: usize,
    frames_per_block: usize,
    map_len: usize,
}

impl RingLayout {
    #[must_use]
    pub const fn geometry(self) -> RingGeometry {
        self.geometry
    }

    #[must_use]
    pub const fn block_size(self) -> usize {
        self.block_size
    }

    #[must_use]
    pub const fn block_count(self) -> usize {
        self.block_count
    }

    #[must_use]
    pub const fn frame_size(self) -> usize {
        self.frame_size
    }

    #[must_use]
    pub const fn frames_per_block(self) -> usize {
        self.frames_per_block
    }

    #[must_use]
    pub const fn map_len(self) -> usize {
        self.map_len
    }

    pub fn block_range(self, block_index: usize) -> Result<std::ops::Range<usize>, GeometryError> {
        if block_index >= self.block_count {
            return Err(GeometryError::BlockIndexOutOfRange { block_index });
        }
        let start = block_index
            .checked_mul(self.block_size)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        let end = start
            .checked_add(self.block_size)
            .ok_or(GeometryError::ArithmeticOverflow)?;
        Ok(start..end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortConfig {
    pub interface: IfId,
    pub if_index: u32,
    pub rx: RingGeometry,
    pub tx: RingGeometry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortIndex(u16);

impl PortIndex {
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PortTable {
    by_interface: Box<[u16]>,
}

impl PortTable {
    fn build(ports: &[PortConfig]) -> Result<Self, ConfigError> {
        if ports.len() > MAX_PORTS {
            return Err(ConfigError::TooManyPorts { count: ports.len() });
        }
        let mut by_interface = vec![MISSING_PORT; PORT_TABLE_LEN].into_boxed_slice();
        for (index, port) in ports.iter().enumerate() {
            let entry = &mut by_interface[usize::from(port.interface.0)];
            if *entry != MISSING_PORT {
                return Err(ConfigError::DuplicateInterface {
                    interface: port.interface,
                });
            }
            *entry = u16::try_from(index)
                .map_err(|_| ConfigError::TooManyPorts { count: ports.len() })?;
        }
        Ok(Self { by_interface })
    }

    #[must_use]
    pub fn lookup(&self, interface: IfId) -> Option<PortIndex> {
        let index = self.by_interface[usize::from(interface.0)];
        (index != MISSING_PORT).then_some(PortIndex(index))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedPort {
    interface: IfId,
    if_index: u32,
    rx: RingLayout,
    tx: RingLayout,
    tx_map_offset: usize,
    combined_map_len: usize,
}

impl ValidatedPort {
    #[must_use]
    pub const fn interface(self) -> IfId {
        self.interface
    }

    #[must_use]
    pub const fn if_index(self) -> u32 {
        self.if_index
    }

    #[must_use]
    pub const fn rx(self) -> RingLayout {
        self.rx
    }

    #[must_use]
    pub const fn tx(self) -> RingLayout {
        self.tx
    }

    #[must_use]
    pub const fn tx_map_offset(self) -> usize {
        self.tx_map_offset
    }

    #[must_use]
    pub const fn combined_map_len(self) -> usize {
        self.combined_map_len
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedConfig {
    ports: Box<[ValidatedPort]>,
    table: PortTable,
}

impl ValidatedConfig {
    pub fn new(
        ports: &[PortConfig],
        page_size: usize,
        max_frame_len: usize,
    ) -> Result<Self, ConfigError> {
        if ports.is_empty() {
            return Err(ConfigError::NoPorts);
        }
        let table = PortTable::build(ports)?;
        let mut validated = Vec::with_capacity(ports.len());
        for (index, port) in ports.iter().enumerate() {
            if port.if_index == 0 {
                return Err(ConfigError::ZeroIfIndex {
                    interface: port.interface,
                });
            }
            if i32::try_from(port.if_index).is_err() {
                return Err(ConfigError::IfIndexOutOfRange {
                    interface: port.interface,
                    if_index: port.if_index,
                });
            }
            if ports[..index]
                .iter()
                .any(|candidate| candidate.if_index == port.if_index)
            {
                return Err(ConfigError::DuplicateIfIndex {
                    if_index: port.if_index,
                });
            }
            let rx = port
                .rx
                .validate(page_size, max_frame_len)
                .map_err(|source| ConfigError::Ring {
                    interface: port.interface,
                    kind: RingKind::Rx,
                    source,
                })?;
            if port.tx.feature_flags != 0 {
                return Err(ConfigError::Ring {
                    interface: port.interface,
                    kind: RingKind::Tx,
                    source: GeometryError::FeatureFlagsUnsupportedForTx {
                        feature_flags: port.tx.feature_flags,
                    },
                });
            }
            let tx = port
                .tx
                .validate(page_size, max_frame_len)
                .map_err(|source| ConfigError::Ring {
                    interface: port.interface,
                    kind: RingKind::Tx,
                    source,
                })?;
            let combined_map_len =
                rx.map_len()
                    .checked_add(tx.map_len())
                    .ok_or(ConfigError::CombinedMapOverflow {
                        interface: port.interface,
                    })?;
            validated.push(ValidatedPort {
                interface: port.interface,
                if_index: port.if_index,
                rx,
                tx,
                tx_map_offset: rx.map_len(),
                combined_map_len,
            });
        }
        Ok(Self {
            ports: validated.into_boxed_slice(),
            table,
        })
    }

    #[must_use]
    pub fn ports(&self) -> &[ValidatedPort] {
        &self.ports
    }

    #[must_use]
    pub fn port(&self, interface: IfId) -> Option<&ValidatedPort> {
        self.table
            .lookup(interface)
            .and_then(|index| self.ports.get(index.get()))
    }

    #[must_use]
    pub const fn table(&self) -> &PortTable {
        &self.table
    }
}

const fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(adjusted) => Some(adjusted & !mask),
        None => None,
    }
}
