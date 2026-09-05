#![deny(unsafe_code)]
#![doc = "DPDK packet-IO backend behind the `dpdk` Cargo feature."]
//!
//! This crate implements both halves of the backend contract over a real
//! DPDK port: [`ruster_core::GeneratedPacketIo`] (TX-only fresh-frame
//! generation, requirement IO-009) over `rte_pktmbuf_alloc`/`rte_eth_tx_burst`,
//! and [`ruster_core::PacketIo`] (receive, forward, recycle/consume) over
//! `rte_eth_rx_burst`/`rte_eth_tx_burst`.
//!
//! Proven environment: DPDK 23.11.4, the `af_packet` PMD bound to a Linux
//! veth with `--no-huge --no-pci`, no physical NIC and no hugepages
//! required. See `crates/io-dpdk/tests/backend_conformance.rs` for the
//! concrete EAL/vdev arguments used against that environment.
//!
//! # The `dpdk` feature
//!
//! Off by default. With it off (including on a host with no DPDK installed
//! at all), this crate is an inert stub: [`DpdkPlatform::is_supported`]
//! returns `false`, no `extern "C"` declaration is compiled, and `build.rs`
//! does not probe for or link against anything. With the feature on,
//! `build.rs` still probes for `pkg-config libdpdk` and a working C
//! compiler before compiling the real backend; if either is missing it
//! prints a `cargo:warning` and falls back to the same stub, so flipping the
//! feature on is never enough by itself to break a build that lacks DPDK.
//!
//! # Scope
//!
//! There is no software fake/mock seam for unit testing (unlike
//! `ruster-io-afpacket`'s syscall-level fake): DPDK's FFI surface does not
//! lend itself to a lightweight software double without reimplementing
//! meaningful driver internals. Correctness is instead validated by running
//! the real `ruster-io-conformance` generated and RX suites against real
//! hardware (see the crate-level test file), gated on `dpdk`.
//!
//! `GeneratedCompletionHarness`/`GeneratedCqPoolHarness`/`RxCompletionHarness`/
//! `RxCqPoolHarness` (frame-level TX completion identity) are not
//! implemented: DPDK's generic ethdev `rte_eth_tx_burst` reclaims
//! transmitted mbufs back into the pool internally, with no public API that
//! reports *which* mbuf a given reclaim corresponds to. That is unlike
//! AF_XDP's explicit completion ring, which is exactly what those
//! capabilities model.

mod config;
mod error;
mod platform;
mod stats;

#[cfg(dpdk_available)]
#[allow(unsafe_code)]
mod sys;

pub use config::{DpdkConfig, PortBinding, ValidatedConfig, DEFAULT_MBUF_HEADROOM};
pub use error::{ConfigError, DpdkError, EalStage, EthdevStage, PlatformError};
pub use platform::DpdkPlatform;
pub use stats::{BackendStat, BackendStats, BackendStatsSnapshot};

#[cfg(dpdk_available)]
pub use sys::{DpdkGeneratedBatch, DpdkGeneratedSlot, DpdkIo, DpdkPacketBatch, DpdkPacketSlot};

#[cfg(all(feature = "test-hooks", dpdk_available))]
pub use sys::{
    RecordedDisposition, RecordedGeneratedEvent, RecordedRxDisposition, RecordedRxEvent,
};
