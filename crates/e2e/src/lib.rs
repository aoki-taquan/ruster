#![forbid(unsafe_code)]
//! End-to-end tests of the skeleton: the FE, confd, ribd and neighd connected over Unix
//! sockets and run on one runner, packets through the simulated backend. The tests are
//! in `tests/`.
