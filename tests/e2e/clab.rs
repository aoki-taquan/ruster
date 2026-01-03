//! Containerlab test helpers

use std::path::Path;
use std::process::{Command, Output};

/// Containerlab topology wrapper
pub struct Topology {
    name: String,
    topology_file: String,
}

impl Topology {
    /// Deploy a containerlab topology
    pub fn deploy(topology_file: impl AsRef<Path>) -> Result<Self, String> {
        let topology_file = topology_file.as_ref();
        let topology_path = topology_file
            .to_str()
            .ok_or("Invalid topology path")?
            .to_string();

        // Read topology name from file
        let content =
            std::fs::read_to_string(topology_file).map_err(|e| format!("Read error: {}", e))?;

        let name = content
            .lines()
            .find(|l| l.starts_with("name:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .ok_or("Could not find topology name")?;

        // Deploy topology
        let output = Command::new("sudo")
            .args([
                "containerlab",
                "deploy",
                "-t",
                &topology_path,
                "--reconfigure",
            ])
            .output()
            .map_err(|e| format!("Failed to run containerlab: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "containerlab deploy failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            name,
            topology_file: topology_path,
        })
    }

    /// Execute a command in a container
    pub fn exec(&self, node: &str, cmd: &str) -> Output {
        let container_name = format!("clab-{}-{}", self.name, node);
        Command::new("sudo")
            .args(["docker", "exec", &container_name, "sh", "-c", cmd])
            .output()
            .expect("Failed to execute docker command")
    }

    /// Check if a ping succeeds
    pub fn ping(&self, from_node: &str, target_ip: &str, count: u32) -> bool {
        let cmd = format!("ping -c {} -W 2 {}", count, target_ip);
        let output = self.exec(from_node, &cmd);
        output.status.success()
    }

    /// Destroy the topology
    pub fn destroy(&self) {
        let _ = Command::new("sudo")
            .args([
                "containerlab",
                "destroy",
                "-t",
                &self.topology_file,
                "--cleanup",
            ])
            .output();
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.destroy();
    }
}
