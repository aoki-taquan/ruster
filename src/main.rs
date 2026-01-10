use clap::{Parser, Subcommand};
use ruster::config;
use ruster::telemetry::{init_logging, MetricsRegistry};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(name = "ruster")]
#[command(about = "A software router implemented in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run the router daemon
    Run {
        /// Path to config.lock file
        #[arg(short, long, default_value = "config.lock")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Generate config.lock from config.toml
    Generate {
        /// Path to config.toml
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Output path for config.lock
        #[arg(short, long, default_value = "config.lock")]
        output: PathBuf,
    },
    /// Validate config.toml without generating lock file
    Validate {
        /// Path to config.toml
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
}

fn main() {
    // Initialize logging (RUST_LOG env var takes priority)
    init_logging(None);

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Config { action }) => match action {
            ConfigAction::Generate {
                config: config_path,
                output,
            } => {
                if let Err(e) = cmd_config_generate(&config_path, &output) {
                    eprintln!("[ERROR] {}", e);
                    std::process::exit(1);
                }
            }
            ConfigAction::Validate {
                config: config_path,
            } => {
                if let Err(e) = cmd_config_validate(&config_path) {
                    eprintln!("[ERROR] {}", e);
                    std::process::exit(1);
                }
            }
        },
        Some(Commands::Run { config: lock_path }) => {
            if let Err(e) = cmd_run(&lock_path) {
                eprintln!("[ERROR] {}", e);
                std::process::exit(1);
            }
        }
        None => {
            info!("ruster starting...");
            // Default: run with config.lock
            if let Err(e) = cmd_run(&PathBuf::from("config.lock")) {
                eprintln!("[ERROR] {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn cmd_run(lock_path: &PathBuf) -> Result<(), String> {
    use ruster::capture::AfPacketSocket;
    use ruster::dataplane::Router;
    use ruster::protocol::MacAddr;
    use tokio::runtime::Runtime;
    use tracing::{debug, error, warn};

    info!("Loading {}...", lock_path.display());

    // Read and parse lock file
    let lock_content = std::fs::read_to_string(lock_path)
        .map_err(|e| format!("Failed to read lock file: {}", e))?;
    let lock: config::ConfigLock =
        toml::from_str(&lock_content).map_err(|e| format!("Failed to parse lock file: {}", e))?;

    // Create Tokio runtime
    let rt = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;

    rt.block_on(async move {
        // Initialize metrics registry
        let metrics = Arc::new(MetricsRegistry::new());
        let mut router = Router::new(metrics.clone());

        // Configure interfaces from lock file
        for (name, iface_lock) in &lock.interfaces {
            // Parse address if present
            let (ip_addr, prefix_len) = if let Some(ref addr) = iface_lock.address {
                parse_cidr(addr)?
            } else {
                (None, None)
            };

            // Parse MAC address
            let mac_addr: MacAddr = iface_lock
                .mac
                .parse()
                .unwrap_or_else(|_| get_interface_mac(name));

            // Bind to interface
            info!("Binding to interface {}...", name);
            let socket = AfPacketSocket::bind(name).map_err(|e| {
                format!(
                    "Failed to bind to {}: {}. Run with root privileges.",
                    name, e
                )
            })?;

            router.add_interface(name.clone(), socket, mac_addr, ip_addr, prefix_len);
            info!(
                "  {} configured: MAC={}, IP={:?}/{}",
                name,
                mac_addr,
                ip_addr,
                prefix_len.unwrap_or(0)
            );
        }

        // Add routes from lock file
        for route_lock in &lock.routing.static_routes {
            if let Some(route) = parse_route(route_lock) {
                router.add_route(route);
                debug!(
                    "Added route: {} via {} ({})",
                    route_lock.destination, route_lock.gateway, route_lock.source
                );
            }
        }

        // Enable NAPT if configured
        if let Some(ref nat) = lock.nat {
            if nat.enabled {
                // Get WAN interface IP
                if let Some(wan_iface) = lock.interfaces.get(&nat.wan) {
                    if let Some(ref addr) = wan_iface.address {
                        if let (Some(ip), _) = parse_cidr(addr)? {
                            router.enable_napt(nat.wan.clone(), ip);
                            info!("NAPT enabled: WAN={}, external IP={}", nat.wan, ip);
                        }
                    }
                }
            }
        }

        // Enable stateful firewall if configured
        if let Some(ref firewall) = lock.firewall {
            if firewall.enabled {
                router.enable_firewall(firewall.wan_interfaces.clone());
                info!(
                    "Stateful firewall enabled for WAN interfaces: {:?}",
                    firewall.wan_interfaces
                );
            }
        }

        info!("Router started, processing packets...");

        // Create aging timer
        let mut aging_timer = Router::aging_interval();

        // Main loop
        let interface_names: Vec<String> = router.interface_names();

        if interface_names.is_empty() {
            return Err("No interfaces configured".to_string());
        }

        // For simplicity, handle one interface at a time
        // TODO: Use tokio::select! for multi-interface support
        let iface_name = interface_names[0].clone();

        let mut buf = vec![0u8; 2048];

        loop {
            tokio::select! {
                _ = aging_timer.tick() => {
                    router.run_aging();
                }
                result = async {
                    // Receive packet from the first interface
                    if let Some(iface) = router.get_interface_mut(&iface_name) {
                        iface.socket.recv(&mut buf).await
                    } else {
                        Err(ruster::Error::InterfaceNotFound { name: iface_name.clone() })
                    }
                } => {
                    match result {
                        Ok(rx_info) => {
                            let packet = &buf[..rx_info.len];
                            let to_send = router.process_packet(&iface_name, packet);

                            for (out_iface, frame) in to_send {
                                if let Some(iface) = router.get_interface_mut(&out_iface) {
                                    if let Err(e) = iface.socket.send(&frame).await {
                                        warn!("Failed to send on {}: {}", out_iface, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Receive error: {}", e);
                        }
                    }
                }
            }
        }
    })
}

fn parse_cidr(cidr: &str) -> Result<(Option<std::net::Ipv4Addr>, Option<u8>), String> {
    use std::net::Ipv4Addr;

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR: {}", cidr));
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP: {}", parts[0]))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix: {}", parts[1]))?;

    Ok((Some(ip), Some(prefix)))
}

fn get_interface_mac(name: &str) -> ruster::protocol::MacAddr {
    // Read MAC from /sys/class/net/{name}/address
    let path = format!("/sys/class/net/{}/address", name);
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(mac) = content.trim().parse() {
            return mac;
        }
    }
    // Fallback to zero MAC
    ruster::protocol::MacAddr::ZERO
}

fn parse_route(route_lock: &config::StaticRouteLock) -> Option<ruster::dataplane::Route> {
    use ruster::dataplane::{Route, RouteSource};
    use std::net::Ipv4Addr;

    // Parse destination CIDR
    let parts: Vec<&str> = route_lock.destination.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let destination: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    // Parse next hop (None for connected routes)
    let next_hop = if route_lock.gateway == "direct" {
        None
    } else {
        route_lock.gateway.parse().ok()
    };

    let source = match route_lock.source.as_str() {
        "auto" => RouteSource::Connected,
        "config" => RouteSource::Static,
        _ => RouteSource::Static,
    };

    Some(Route {
        destination,
        prefix_len,
        next_hop,
        interface: route_lock.interface.clone(),
        metric: 0,
        source,
    })
}

fn cmd_config_generate(config_path: &PathBuf, output_path: &PathBuf) -> Result<(), String> {
    println!("[INFO] Loading {}...", config_path.display());

    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    let cfg = config::load(config_path).map_err(|e| format!("Failed to parse config: {}", e))?;

    let validation = config::validate(&cfg);
    validation.print_diagnostics();

    if validation.has_errors() {
        return Err("Validation failed with errors".to_string());
    }

    let lock = config::generate_lock(&cfg, &content);

    let lock_toml =
        toml::to_string_pretty(&lock).map_err(|e| format!("Failed to serialize lock: {}", e))?;

    // Add header comment
    let output = format!(
        "# Generated by ruster - DO NOT EDIT\n# Source: {} (sha256: {})\n\n{}",
        config_path.display(),
        &lock.source_hash[..16],
        lock_toml
    );

    std::fs::write(output_path, output).map_err(|e| format!("Failed to write lock file: {}", e))?;

    println!("[INFO] Generated {}", output_path.display());
    Ok(())
}

fn cmd_config_validate(config_path: &PathBuf) -> Result<(), String> {
    println!("[INFO] Validating {}...", config_path.display());

    let cfg = config::load(config_path).map_err(|e| format!("Failed to parse config: {}", e))?;

    let validation = config::validate(&cfg);
    validation.print_diagnostics();

    if validation.has_errors() {
        Err("Validation failed".to_string())
    } else {
        println!("[INFO] Configuration is valid");
        Ok(())
    }
}
