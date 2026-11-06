#![forbid(unsafe_code)]
//! Messages between the forwarding element (FE) and the control processes (CE).
//!
//! See `docs/design/control-protocol.md`. This crate holds the encoding pieces that
//! every process shares: the CBOR subset ([`cbor`]) and CoAP framing for byte
//! streams ([`coap`]).

pub mod cbor;
pub mod coap;
