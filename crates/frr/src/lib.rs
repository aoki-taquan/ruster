#![forbid(unsafe_code)]
//! The bridge between confd, ribd and FRR (`docs/design/router-box.md`, "FRR").
//!
//! FRR's zebra hands its forwarding table to an outside forwarding plane over FPM
//! (`dplane_fpm_nl`). `ruster-frr` is that plane's end: it reads the routes
//! ([`fpm`]), finds the FE interface of each next hop and gives the routes to ribd
//! as the route source `frr` ([`routes`]).
//!
//! # Standards
//!
//! The standards each part follows are in [`fpm`] and [`routes`].

pub mod fpm;
pub mod routes;
