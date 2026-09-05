//! Compiles and links the tiny DPDK inline-function shim, but only when the
//! `dpdk` Cargo feature is enabled and a real `libdpdk` is actually usable.
//!
//! `rte_eth_rx_burst`, `rte_eth_tx_burst`, `rte_pktmbuf_alloc`,
//! `rte_pktmbuf_free`, and `rte_pktmbuf_append` are `static inline` in the
//! DPDK headers, so they have no linkable symbol; `src/shim.c` gives each one
//! a real extern "C" entry point. This crate has no external crate
//! dependencies, so the shim is compiled by invoking the system compiler
//! directly with `std::process::Command` rather than the `cc` crate.
//!
//! Every other case (feature off, or feature on but `pkg-config libdpdk` or
//! the compiler is unavailable) leaves `dpdk_available` unset, and `src/lib.rs`
//! compiles the crate as an inert stub. This is what keeps
//! `cargo build/test/clippy --workspace` green on a host with no DPDK
//! installed.

use std::{
    env,
    path::PathBuf,
    process::{Command, Output},
};

fn main() {
    // Always declare the custom cfg so `-D warnings` never trips over
    // `unexpected_cfgs`, regardless of which branch below is taken.
    println!("cargo::rustc-check-cfg=cfg(dpdk_available)");
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DPDK");

    if env::var_os("CARGO_FEATURE_DPDK").is_none() {
        // Default host build: do not probe for or link against anything.
        return;
    }

    let Some(cflags) = pkg_config(&["--cflags", "libdpdk"]) else {
        warn_stub("pkg-config could not resolve libdpdk cflags");
        return;
    };
    let Some(libs) = pkg_config(&["--libs", "libdpdk"]) else {
        warn_stub("pkg-config could not resolve libdpdk libs");
        return;
    };

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo always sets OUT_DIR"));
    let object = out_dir.join("shim.o");
    let compiler = env::var("CC").unwrap_or_else(|_| "cc".to_string());

    let mut compile = Command::new(&compiler);
    compile
        .arg("-c")
        .arg("src/shim.c")
        .arg("-o")
        .arg(&object)
        .args(cflags.split_whitespace());
    match compile.status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            warn_stub(&format!("compiling src/shim.c exited with {status}"));
            return;
        }
        Err(source) => {
            warn_stub(&format!("could not invoke `{compiler}`: {source}"));
            return;
        }
    }

    let archive = out_dir.join("libruster_dpdk_shim.a");
    match Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&object)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            warn_stub(&format!("archiving the DPDK shim exited with {status}"));
            return;
        }
        Err(source) => {
            warn_stub(&format!("could not invoke `ar`: {source}"));
            return;
        }
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ruster_dpdk_shim");
    // Forwarded verbatim (and in order) so `-Wl,--as-needed` and the many
    // `-lrte_*`/`-lbsd` tokens keep exactly the semantics `pkg-config` chose.
    for token in libs.split_whitespace() {
        println!("cargo:rustc-link-arg={token}");
    }

    println!("cargo:rustc-cfg=dpdk_available");
}

fn warn_stub(reason: &str) {
    println!("cargo:warning=ruster-io-dpdk: {reason}; building as a stub (no real DPDK backend)");
}

fn pkg_config(args: &[&str]) -> Option<String> {
    let output: Output = Command::new("pkg-config").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}
