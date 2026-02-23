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

    // Enter the dataplane run loop (blocks until shutdown)
    if let Err(e) = dataplane.run(shutdown) {
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
