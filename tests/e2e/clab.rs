//! Containerlab test helpers

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for unique topology names
static TOPOLOGY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Containerlab topology wrapper
pub struct Topology {
    name: String,
    topology_file: String,
    temp_file: Option<PathBuf>,
}

impl Topology {
    /// Generate a unique suffix for the topology name (PID + counter based)
    fn generate_unique_suffix() -> String {
        let count = TOPOLOGY_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("{}-{}", std::process::id(), count)
    }

    /// Deploy a containerlab topology with a unique name and network
    pub fn deploy(topology_file: impl AsRef<Path>) -> Result<Self, String> {
        let topology_file = topology_file.as_ref();
        let topology_dir = topology_file
            .parent()
            .ok_or("Could not get topology directory")?;

        // Read topology content
        let content =
            std::fs::read_to_string(topology_file).map_err(|e| format!("Read error: {}", e))?;

        let base_name = content
            .lines()
            .find(|l| l.starts_with("name:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .ok_or("Could not find topology name")?;

        // Generate unique suffix for topology name and network
        let suffix = Self::generate_unique_suffix();
        let name = format!("{}-{}", base_name, suffix);

        // Create temp topology file with unique mgmt network name
        let mgmt_section = format!(
            "\nmgmt:\n  network: clab-{}\n  ipv4-subnet: 172.100.{}.0/24\n",
            suffix,
            TOPOLOGY_COUNTER.load(Ordering::SeqCst) % 200
        );
        let modified_content = format!("{}{}", content.trim_end(), mgmt_section);

        let temp_file_path = topology_dir.join(format!(".topology-{}.yml", suffix));
        std::fs::write(&temp_file_path, &modified_content)
            .map_err(|e| format!("Failed to write temp file: {}", e))?;

        let temp_topology_path = temp_file_path
            .to_str()
            .ok_or("Invalid temp topology path")?
            .to_string();

        // Deploy topology with unique name
        let output = Command::new("sudo")
            .args([
                "containerlab",
                "deploy",
                "-t",
                &temp_topology_path,
                "--name",
                &name,
                "--reconfigure",
            ])
            .output()
            .map_err(|e| format!("Failed to run containerlab: {}", e))?;

        if !output.status.success() {
            // Clean up temp file on failure
            let _ = std::fs::remove_file(&temp_file_path);
            return Err(format!(
                "containerlab deploy failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            name,
            topology_file: temp_topology_path,
            temp_file: Some(temp_file_path),
        })
    }

    /// Execute a command in a container
    pub fn exec(&self, node: &str, cmd: &str) -> Output {
        let container_name = format!("clab-{}-{}", self.name, node);
        // No sudo needed for docker commands when user is in docker group
        Command::new("docker")
            .args(["exec", &container_name, "sh", "-c", cmd])
            .output()
            .expect("Failed to execute docker command")
    }

    /// Check if a ping succeeds
    pub fn ping(&self, from_node: &str, target_ip: &str, count: u32) -> bool {
        let cmd = format!("ping -c {} -W 2 {}", count, target_ip);
        let output = self.exec(from_node, &cmd);
        output.status.success()
    }

    /// Generate config.lock from config.toml in ruster container
    pub fn generate_config(&self) -> Output {
        self.exec(
            "ruster",
            "/usr/local/bin/ruster config generate -c /etc/ruster/config.toml -o /etc/ruster/config.lock",
        )
    }

    /// Disable Linux kernel IP forwarding on ruster node
    pub fn disable_kernel_forwarding(&self) {
        self.exec("ruster", "sysctl -w net.ipv4.ip_forward=0");
        self.exec("ruster", "sysctl -w net.ipv6.conf.all.forwarding=0");
    }

    /// Start ruster daemon in background
    /// Returns true if ruster process is running
    pub fn start_ruster(&self) -> bool {
        // Start ruster in background using nohup
        self.exec(
            "ruster",
            "nohup /usr/local/bin/ruster run -c /etc/ruster/config.lock > /tmp/ruster.log 2>&1 &",
        );

        // Wait for startup
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Check if process is running
        self.exec("ruster", "pgrep -f 'ruster run'")
            .status
            .success()
    }

    /// Stop ruster daemon
    #[allow(dead_code)]
    pub fn stop_ruster(&self) {
        self.exec("ruster", "pkill -f 'ruster run' || true");
    }

    /// Destroy the topology and clean up temp files
    pub fn destroy(&mut self) {
        let _ = Command::new("sudo")
            .args([
                "containerlab",
                "destroy",
                "-t",
                &self.topology_file,
                "--name",
                &self.name,
                "--cleanup",
            ])
            .output();

        // Clean up temp topology file
        if let Some(ref temp_file) = self.temp_file {
            let _ = std::fs::remove_file(temp_file);
        }
        self.temp_file = None;
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.destroy();
    }
}
