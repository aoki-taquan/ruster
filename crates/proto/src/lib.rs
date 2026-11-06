#![forbid(unsafe_code)]
//! Messages between the forwarding element (FE) and the control processes (CE).
//!
//! See `docs/design/control-protocol.md`. This crate holds the encoding pieces that
//! every process shares: the CBOR subset ([`cbor`]), CoAP framing for byte
//! streams ([`coap`]), the SIDs ([`sid`]) and the table entries ([`table`]).

pub mod cbor;
pub mod coap;
pub mod sid;
pub mod table;
