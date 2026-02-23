use std::env;
use std::process;

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
    let _dataplane = match ruster_dataplane::Dataplane::init(&config) {
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

    // In v0.1, we just print status and exit.
    // Real packet processing loop will be added when DPDK backend is integrated.
    println!("\nruster ready. (v0.1: init-only mode, no packet loop yet)");
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
