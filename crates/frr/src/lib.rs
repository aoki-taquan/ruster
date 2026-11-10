#![forbid(unsafe_code)]
//! The bridge between confd, ribd and FRR (`docs/design/router-box.md`, "FRR").
//!
//! FRR's zebra hands its forwarding table to an outside forwarding plane over FPM
//! (`dplane_fpm_nl`). `ruster-frr` is that plane's end: it reads the routes
//! ([`fpm`]), finds the FE interface of each next hop and gives the routes to ribd
//! as the route source `frr` ([`routes`]). It also writes FRR's configuration from
//! confd's `frr` part and has FRR apply it ([`conf`]).
//!
//! # Standards
//!
//! The standards each part follows are in [`conf`], [`fpm`] and [`routes`].

pub mod conf;
pub mod fpm;
pub mod routes;
