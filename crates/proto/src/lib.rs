#![forbid(unsafe_code)]
//! Messages between the forwarding element (FE) and the control processes (CE).
//!
//! See `docs/design/control-protocol.md`. This crate holds the encoding pieces that
//! every process shares. For now that is only the CBOR subset ([`cbor`]).

pub mod cbor;
