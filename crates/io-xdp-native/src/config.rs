use crate::{
    abi::{XDP_COPY, XDP_SHARED_UMEM, XDP_SUPPORTED_BIND_FLAGS, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY},
    ConfigError,
};

/// AF_XDP bind-mode policy encoded in checked socket flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindMode {
    /// Let the kernel select zero-copy when available and otherwise copy mode.
    Automatic,
    /// Require copy mode and fail the future bind if it is unavailable.
    CopyRequired,
    /// Require zero-copy mode and fail the future bind if it is unavailable.
    ZeroCopyRequired,
}

/// Checked bind flags for the initial single-buffer, need-wakeup profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedBindFlags {
    raw: u16,
    mode: BindMode,
    shared_umem: bool,
}

impl ValidatedBindFlags {
    /// Validates raw `sockaddr_xdp.sxdp_flags`.
    ///
    /// The initial native profile requires need-wakeup, permits optional
    /// shared UMEM, and rejects scatter/gather and unknown bits. Copy and
    /// zero-copy cannot both be required.
    pub fn new(raw: u16) -> Result<Self, ConfigError> {
        let unsupported = raw & !XDP_SUPPORTED_BIND_FLAGS;
        if unsupported != 0 {
            return Err(ConfigError::UnsupportedBindFlags(unsupported));
        }
        if raw & XDP_USE_NEED_WAKEUP == 0 {
            return Err(ConfigError::NeedWakeupRequired);
        }
        if raw & XDP_COPY != 0 && raw & XDP_ZEROCOPY != 0 {
            return Err(ConfigError::ConflictingBindModes);
        }

        let mode = if raw & XDP_COPY != 0 {
            BindMode::CopyRequired
        } else if raw & XDP_ZEROCOPY != 0 {
            BindMode::ZeroCopyRequired
        } else {
            BindMode::Automatic
        };
        Ok(Self {
            raw,
            mode,
            shared_umem: raw & XDP_SHARED_UMEM != 0,
        })
    }

    /// Returns the checked UAPI flag word.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.raw
    }

    /// Returns the requested kernel copy policy.
    #[must_use]
    pub const fn mode(self) -> BindMode {
        self.mode
    }

    /// Reports whether this socket will join an existing UMEM.
    #[must_use]
    pub const fn shared_umem(self) -> bool {
        self.shared_umem
    }
}

/// One of the four AF_XDP ring capacities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingName {
    /// Application-produced UMEM addresses for receive.
    Fill,
    /// Kernel-produced packet descriptors.
    Rx,
    /// Application-produced packet descriptors.
    Tx,
    /// Kernel-produced completed UMEM addresses.
    Completion,
}

/// Checked nonzero, power-of-two ring entry count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingEntries(u32);

impl RingEntries {
    /// Validates one AF_XDP ring capacity.
    pub fn new(ring: RingName, entries: u32) -> Result<Self, ConfigError> {
        if entries == 0 || !entries.is_power_of_two() {
            return Err(ConfigError::InvalidRingEntries { ring, entries });
        }
        Ok(Self(entries))
    }

    /// Returns the checked entry count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Checked capacities for all four rings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingConfig {
    fill: RingEntries,
    rx: RingEntries,
    tx: RingEntries,
    completion: RingEntries,
}

impl RingConfig {
    /// Validates all ring capacities in deterministic ring order.
    pub fn new(fill: u32, rx: u32, tx: u32, completion: u32) -> Result<Self, ConfigError> {
        Ok(Self {
            fill: RingEntries::new(RingName::Fill, fill)?,
            rx: RingEntries::new(RingName::Rx, rx)?,
            tx: RingEntries::new(RingName::Tx, tx)?,
            completion: RingEntries::new(RingName::Completion, completion)?,
        })
    }

    /// Returns the Fill ring capacity.
    #[must_use]
    pub const fn fill(self) -> RingEntries {
        self.fill
    }

    /// Returns the RX ring capacity.
    #[must_use]
    pub const fn rx(self) -> RingEntries {
        self.rx
    }

    /// Returns the TX ring capacity.
    #[must_use]
    pub const fn tx(self) -> RingEntries {
        self.tx
    }

    /// Returns the Completion ring capacity.
    #[must_use]
    pub const fn completion(self) -> RingEntries {
        self.completion
    }
}

/// Checked aligned-chunk UMEM geometry for the initial native profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UmemConfig {
    frame_count: u32,
    frame_size: u32,
    headroom: u32,
    rx_frames: u32,
    generated_frames: u32,
    byte_len: u64,
}

impl UmemConfig {
    /// Validates fixed-frame geometry and the RX/generated frame partition.
    ///
    /// The first native profile accepts no UMEM flags: unaligned chunks,
    /// software TX checksum, and TX metadata remain deferred. Both pools must
    /// be nonempty and must partition the complete UMEM exactly.
    pub fn new(
        frame_count: u32,
        frame_size: u32,
        headroom: u32,
        rx_frames: u32,
        generated_frames: u32,
        raw_flags: u32,
    ) -> Result<Self, ConfigError> {
        if frame_count == 0 {
            return Err(ConfigError::ZeroFrameCount);
        }
        if frame_size == 0 || !frame_size.is_power_of_two() {
            return Err(ConfigError::InvalidFrameSize(frame_size));
        }
        if headroom >= frame_size {
            return Err(ConfigError::HeadroomConsumesFrame {
                headroom,
                frame_size,
            });
        }
        if raw_flags != 0 {
            return Err(ConfigError::UnsupportedUmemFlags(raw_flags));
        }
        if rx_frames == 0 {
            return Err(ConfigError::ZeroRxFrames);
        }
        if generated_frames == 0 {
            return Err(ConfigError::ZeroGeneratedFrames);
        }
        let partition = rx_frames
            .checked_add(generated_frames)
            .ok_or(ConfigError::FramePartitionOverflow)?;
        if partition != frame_count {
            return Err(ConfigError::FramePartitionMismatch {
                frame_count,
                rx_frames,
                generated_frames,
            });
        }
        let byte_len = u64::from(frame_count) * u64::from(frame_size);

        Ok(Self {
            frame_count,
            frame_size,
            headroom,
            rx_frames,
            generated_frames,
            byte_len,
        })
    }

    /// Returns the total number of frames.
    #[must_use]
    pub const fn frame_count(self) -> u32 {
        self.frame_count
    }

    /// Returns the aligned chunk size.
    #[must_use]
    pub const fn frame_size(self) -> u32 {
        self.frame_size
    }

    /// Returns the per-frame kernel headroom.
    #[must_use]
    pub const fn headroom(self) -> u32 {
        self.headroom
    }

    /// Returns the frames reserved for RX/FILL lifecycle.
    #[must_use]
    pub const fn rx_frames(self) -> u32 {
        self.rx_frames
    }

    /// Returns the frames reserved for generated packets.
    #[must_use]
    pub const fn generated_frames(self) -> u32 {
        self.generated_frames
    }

    /// Returns the complete UMEM byte length.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }
}

/// Validates one RX/TX descriptor option word for the single-buffer profile.
pub fn validate_descriptor_options(options: u32) -> Result<(), ConfigError> {
    if options == 0 {
        Ok(())
    } else {
        Err(ConfigError::UnsupportedDescriptorOptions(options))
    }
}
