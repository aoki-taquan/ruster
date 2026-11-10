#![forbid(unsafe_code)]
//! The PPPoE client (`ruster-pppoed`): the host side of PPPoE sessions
//! (`docs/design/router-box.md`, "自作の制御").
//!
//! The protocol code does no I/O. Each part takes a received frame and the time in
//! milliseconds, and gives back the frames to send and what happened; timers are
//! deadlines the caller asks for and passes back when they are due. The daemon
//! moves frames between these parts and the FE's punt socket.
//!
//! - [`discovery`]: PPPoE Discovery (RFC 2516 section 5).
//! - [`ppp`]: session frames and control packets.
//!
//! # Standards
//!
//! Each module lists the sections it follows and where it deviates.

pub mod discovery;
pub mod ppp;

/// An Ethernet MAC address.
pub type Mac = [u8; 6];
