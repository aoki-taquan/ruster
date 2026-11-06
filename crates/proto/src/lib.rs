#![forbid(unsafe_code)]
//! Messages between the forwarding element (FE) and the control processes (CE).
//!
//! See `docs/design/control-protocol.md`. This crate holds the encoding pieces that
//! every process shares: the CBOR subset ([`cbor`]), CoAP framing for byte
//! streams ([`coap`]), the SIDs ([`sid`]), the table entries ([`table`]), one
//! connection over a Unix stream ([`conn`]), the table server and client
//! ([`session`]) and the task interface ([`task`]).

pub mod cbor;
pub mod coap;
pub mod conn;
pub mod session;
pub mod sid;
pub mod table;
pub mod task;
