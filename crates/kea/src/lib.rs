#![forbid(unsafe_code)]
//! The bridge between confd and Kea (`docs/design/router-box.md`, "Kea").
//!
//! The LAN ports belong to the FE, so Kea, which runs in the router's kernel
//! network namespace, never sees a client's broadcast. `ruster-kea` stands between
//! them as a DHCP relay agent: the FE hands it the clients' requests (the punt
//! classes confd writes for each `[[dhcp]]` interface), it relays them to Kea over
//! UDP, and it turns Kea's replies back into frames that the FE sends out of the
//! interface ([`relay`]).

pub mod relay;
