#![forbid(unsafe_code)]
//! The bridge between confd and bird-rs (`docs/design/router-box.md`, "bird-rs").
//!
//! bird-rs gives its routes to ribd itself, as the route source `bird`, through its
//! `protocol ruster`. `ruster-bird` only writes bird-rs's configuration from confd's
//! `bird` part and has bird-rs apply it ([`conf`]).
//!
//! # Standards
//!
//! The standards it follows are in [`conf`].

pub mod conf;
