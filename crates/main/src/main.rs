use std::env;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Global shutdown flag, set by the signal handler.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Signal handler for SIGINT and SIGTERM.
///
/// SAFETY: This function only performs async-signal-safe operations
/// (an atomic store). It is registered via `libc::signal`-style
/// mechanism on POSIX platforms.
extern "C" fn signal_handler(_sig: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

/// Register signal handlers for SIGINT (2) and SIGTERM (15).
///
/// Uses raw POSIX `signal()` via FFI to avoid external crate dependencies.
fn register_signal_handlers() {
    // SAFETY: `signal_handler` performs only an atomic store, which is
    // async-signal-safe. We pass a valid function pointer.
    unsafe {
        // SIGINT = 2, SIGTERM = 15 (POSIX standard values)
        libc_signal(2, signal_handler as *const () as usize);
        libc_signal(15, signal_handler as *const () as usize);
    }
}

/// Minimal FFI binding to POSIX `signal()`.
///
/// We avoid depending on the `libc` crate by declaring just this one symbol.
unsafe fn libc_signal(signum: i32, handler: usize) {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: caller guarantees `handler` is a valid function pointer
    // and `signum` is a valid signal number.
    unsafe {
        signal(signum, handler);
    }
}

fn main() {
    // Parse CLI args: --config <path> / -c <path>, or default to "router.toml"
    let config_path = parse_config_path();

    // Load and validate config
    let config = match ruster_config::load_from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: failed to load config '{}': {}", config_path, e);
            process::exit(1);
        }
    };

    println!("ruster v0.1 — {}", config.meta.hostname);
    println!("Config loaded from: {}", config_path);

    // Initialize control plane (validate -> plan -> apply)
    let mut store = ruster_control::ConfigStore::new();
    if let Err(e) = store.apply(config.clone()) {
        eprintln!("Error: config apply failed: {}", e);
        process::exit(1);
    }
    store.commit().expect("commit after successful apply");

    // Initialize dataplane
    let dataplane = match ruster_dataplane::Dataplane::init(&config) {
        Ok(dp) => dp,
        Err(e) => {
            eprintln!("Error: dataplane init failed: {}", e);
            process::exit(1);
        }
    };

    println!("Dataplane initialized successfully");
    println!("  L2 bridge domains: {}", config.l2.bridge_domains.len());
    println!(
        "  Static routes: {}",
        config.routing.ipv4_static_routes.len()
    );
    println!("  NAT enabled: {}", config.nat.enabled);
    println!("  Firewall enabled: {}", config.firewall.enabled);

    // Register signal handlers for graceful shutdown
    register_signal_handlers();

    // Bridge the global static flag into an Arc for the dataplane run loop
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_poll = Arc::clone(&shutdown);

    // Spawn a monitor thread that propagates the global signal flag
    // into the Arc-based shutdown flag used by the dataplane.
    let monitor = std::thread::Builder::new()
        .name("signal-monitor".to_string())
        .spawn(move || {
            while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            shutdown_poll.store(true, Ordering::Relaxed);
        })
        .expect("failed to spawn signal-monitor thread");

    println!("\nruster: running (press Ctrl+C to stop)");

    // Select I/O backend based on config.
    let io: Box<dyn ruster_dataplane::io::PacketIo> = match config.dataplane.backend.as_str() {
        #[cfg(target_os = "linux")]
        "afpacket" => {
            let iface_map: Vec<(String, String)> = config
                .interfaces
                .iter()
                .filter(|i| i.admin_up)
                .map(|i| {
                    let linux_name = i.linux_if.clone().unwrap_or_else(|| i.name.clone());
                    (i.name.clone(), linux_name)
                })
                .collect();
            match ruster_dataplane::afpacket::AfPacketIo::new(&iface_map) {
                Ok(io) => {
                    println!("  Backend: AF_PACKET ({} interfaces)", iface_map.len());
                    Box::new(io)
                }
                Err(e) => {
                    eprintln!("Error: AF_PACKET init failed: {}", e);
                    process::exit(1);
                }
            }
        }
        "dpdk" => {
            use ruster_dataplane::dpdk;

            // TODO(#142): Replace MockDpdkBackend with real DPDK EAL initialization
            // when dpdk-sys bindings are available.
            eprintln!("  WARNING: DPDK backend selected but real DPDK is not yet integrated.");
            eprintln!("           Using mock DPDK backend. Packets will NOT be processed via DPDK.");

            // Build DpdkConfig from router.toml settings.
            let dpdk_config = dpdk::config::DpdkConfig {
                lcore_list: config.dataplane.lcore_list.clone(),
                memory_mb: config.dataplane.memory_mb,
                rx_queue_size: config.dataplane.rx_queue_size as u16,
                tx_queue_size: config.dataplane.tx_queue_size as u16,
                ports: config
                    .interfaces
                    .iter()
                    .map(|iface| {
                        let mac = ruster_dataplane::parse_mac_str(&iface.mac);
                        dpdk::config::PortConfig {
                            name: iface.name.clone(),
                            port_id: iface.port_id,
                            mtu: iface.mtu,
                            mac,
                            admin_up: iface.admin_up,
                            rx_queues: 1,
                            tx_queues: 1,
                        }
                    })
                    .collect(),
            };

            // Initialise DPDK subsystem (EAL, mempool, ports).
            let backend = dpdk::mock::MockDpdkBackend::new();
            let context = match dpdk::init_dpdk(&backend, &dpdk_config) {
                Ok(ctx) => ctx,
                Err(e) => {
                    eprintln!("Error: DPDK init failed: {}", e);
                    process::exit(1);
                }
            };

            let active_ports = context.ports.len();

            // Wrap the context in a DpdkPacketIo implementing PacketIo.
            match dpdk::packetio::DpdkPacketIo::new(context, &dpdk_config.ports) {
                Ok(io) => {
                    println!("  Backend: DPDK ({} ports)", active_ports);
                    Box::new(io)
                }
                Err(e) => {
                    eprintln!("Error: DPDK PacketIo init failed: {}", e);
                    process::exit(1);
                }
            }
        }
        "mock" => {
            println!("  Backend: mock (no real I/O)");
            Box::new(ruster_dataplane::io::MockPacketIo::new())
        }
        unknown => {
            eprintln!(
                "Error: unknown dataplane backend '{}' (expected 'afpacket', 'dpdk', or 'mock')",
                unknown
            );
            process::exit(1);
        }
    };

    if let Err(e) = dataplane.run(shutdown, io) {
        eprintln!("Error: dataplane run failed: {}", e);
        process::exit(1);
    }

    // Wait for the monitor thread to finish
    let _ = monitor.join();

    println!("ruster: shutting down...");
    println!("ruster: shutdown complete");
}

fn parse_config_path() -> String {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                return args[i + 1].clone();
            } else {
                eprintln!("Error: --config requires a path argument");
                process::exit(1);
            }
        }
        i += 1;
    }
    "router.toml".to_string()
}
