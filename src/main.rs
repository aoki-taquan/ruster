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
    use ruster::dataplane::{Action, PacketFilter, Router};
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

        // Track interfaces that need DHCP or PPPoE client
        let mut dhcp_client_interfaces: Vec<String> = Vec::new();
        let mut pppoe_client_interfaces: Vec<String> = Vec::new();

        // Configure interfaces from lock file
        for (name, iface_lock) in &lock.interfaces {
            // Parse address if present (skip for DHCP/PPPoE addressing)
            let (ip_addr, prefix_len) = if iface_lock.addressing == "dhcp" {
                // DHCP interface: no static IP
                dhcp_client_interfaces.push(name.clone());
                (None, None)
            } else if iface_lock.addressing == "pppoe" {
                // PPPoE interface: no static IP
                pppoe_client_interfaces.push(name.clone());
                (None, None)
            } else if let Some(ref addr) = iface_lock.address {
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
                "  {} configured: MAC={}, IP={:?}/{}, addressing={}",
                name,
                mac_addr,
                ip_addr,
                prefix_len.unwrap_or(0),
                iface_lock.addressing
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

        // Configure packet filter if enabled
        if let Some(ref filter_lock) = lock.filtering {
            if filter_lock.enabled {
                let default_action = match filter_lock.default_action.as_str() {
                    "drop" => Action::Drop,
                    "reject" => Action::Reject,
                    _ => Action::Accept,
                };

                let mut filter = PacketFilter::new(default_action);

                for rule_lock in &filter_lock.rules {
                    if let Some(rule) = parse_filter_rule(rule_lock) {
                        filter.add_rule(rule);
                        debug!(
                            "Added filter rule: chain={}, action={:?}, priority={}",
                            rule_lock.chain, rule_lock.action, rule_lock.priority
                        );
                    }
                }

                info!(
                    "Packet filter enabled with {} rules (default: {})",
                    filter.rule_count(),
                    filter_lock.default_action
                );
                router.set_filter(filter);
            }
        }

        // Enable DHCP clients for interfaces with addressing=dhcp
        for iface_name in &dhcp_client_interfaces {
            info!("Starting DHCP client on {}...", iface_name);
            let packets = router.enable_dhcp_client(iface_name);
            // Send initial DHCP DISCOVER packets
            for (out_iface, frame) in packets {
                if let Some(iface) = router.get_interface_mut(&out_iface) {
                    if let Err(e) = iface.socket.send(&frame).await {
                        warn!("Failed to send DHCP DISCOVER on {}: {}", out_iface, e);
                    }
                }
            }
        }

        // Enable DNS forwarder if configured
        if let Some(ref dns_lock) = lock.dns_forwarder {
            if dns_lock.enabled {
                use ruster::dataplane::DnsForwarderConfig;

                let config = DnsForwarderConfig {
                    upstream_servers: dns_lock.upstream.clone(),
                    cache_size: dns_lock.cache_size,
                    query_timeout_secs: dns_lock.query_timeout,
                    negative_cache_ttl: 60,
                };

                router.enable_dns_forwarder(config);
                info!(
                    "DNS forwarder enabled with {} upstream servers, cache_size={}",
                    dns_lock.upstream.len(),
                    dns_lock.cache_size
                );
            }
        }

        // Enable PPPoE clients for interfaces with addressing=pppoe
        for iface_name in &pppoe_client_interfaces {
            // Get PPPoE config from lock file
            if let Some(pppoe_config) = lock.pppoe.get(iface_name) {
                info!("Starting PPPoE client on {}...", iface_name);
                let packets = router.enable_pppoe_client(
                    iface_name,
                    pppoe_config.username.clone(),
                    pppoe_config.password.clone(),
                    pppoe_config.service_name.clone(),
                );
                // Send initial PADI packets
                for (out_iface, frame) in packets {
                    if let Some(iface) = router.get_interface_mut(&out_iface) {
                        if let Err(e) = iface.socket.send(&frame).await {
                            warn!("Failed to send PPPoE PADI on {}: {}", out_iface, e);
                        }
                    }
                }
            } else {
                warn!(
                    "Interface {} has addressing=pppoe but no [pppoe.{}] section in config",
                    iface_name, iface_name
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
                    // Run aging and send any DHCP client packets
                    let to_send = router.run_aging();
                    for (out_iface, frame) in to_send {
                        if let Some(iface) = router.get_interface_mut(&out_iface) {
                            if let Err(e) = iface.socket.send(&frame).await {
                                warn!("Failed to send DHCP packet on {}: {}", out_iface, e);
                            }
                        }
                    }
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

fn parse_filter_rule(rule_lock: &config::FilterRuleLock) -> Option<ruster::dataplane::FilterRule> {
    use ruster::dataplane::{protocol, Action, Chain, FilterRule, IpCidr, PortRange};

    // Parse chain
    let chain = match rule_lock.chain.as_str() {
        "input" => Chain::Input,
        "output" => Chain::Output,
        "forward" => Chain::Forward,
        _ => return None,
    };

    // Parse action
    let action = match rule_lock.action.as_str() {
        "accept" => Action::Accept,
        "drop" => Action::Drop,
        "reject" => Action::Reject,
        _ => return None,
    };

    // Create base rule
    let mut rule = FilterRule::new(chain, action);
    rule.priority = rule_lock.priority;

    // Parse protocol
    if let Some(ref proto) = rule_lock.protocol {
        rule.protocol = Some(match proto.as_str() {
            "icmp" => protocol::ICMP,
            "icmpv6" => protocol::ICMPV6,
            "tcp" => protocol::TCP,
            "udp" => protocol::UDP,
            _ => proto.parse().ok()?,
        });
    }

    // Parse source IP
    if let Some(ref src) = rule_lock.src_ip {
        rule.src_ip = IpCidr::parse(src);
    }

    // Parse destination IP
    if let Some(ref dst) = rule_lock.dst_ip {
        rule.dst_ip = IpCidr::parse(dst);
    }

    // Parse source port
    if let Some(ref port) = rule_lock.src_port {
        rule.src_port = PortRange::parse(port);
    }

    // Parse destination port
    if let Some(ref port) = rule_lock.dst_port {
        rule.dst_port = PortRange::parse(port);
    }

    // Set interfaces
    rule.in_interface = rule_lock.in_interface.clone();
    rule.out_interface = rule_lock.out_interface.clone();

    Some(rule)
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
