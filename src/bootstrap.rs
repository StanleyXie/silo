use crate::config::{
    AuthConfig, Config, ControlPlaneConfig, ControlPlaneTlsConfig, GatewayConfig, GatewayTlsConfig,
    StorageConfig, VaultConfig,
};
use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

pub struct BootstrapManager {
    config_path: String,
}

impl BootstrapManager {
    pub fn new(config_path: &str) -> Self {
        let abs_path = fs::canonicalize(config_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| config_path.to_string());
        Self {
            config_path: abs_path,
        }
    }

    pub fn check_vault_installed(&self) -> bool {
        Command::new("vault")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn generate_default_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let home = dirs::home_dir().ok_or("Could not find home directory")?;
        let silo_dir = home.join(".silo");
        let certs_dir = silo_dir.join("certs");

        let config = Config {
            gateway: GatewayConfig {
                address: "0.0.0.0:8443".to_string(),
                metrics_address: "0.0.0.0:6192".to_string(),
                tls: GatewayTlsConfig {
                    enabled: true,
                    cert_path: certs_dir.join("server.crt").to_string_lossy().to_string(),
                    key_path: certs_dir.join("server.key").to_string_lossy().to_string(),
                },
            },
            control_plane: ControlPlaneConfig {
                address: "127.0.0.1:50051".to_string(),
                allowed_identities: vec!["admin".to_string(), "silo-gateway".to_string()],
                tls: ControlPlaneTlsConfig {
                    ca_cert: certs_dir
                        .join("internal/ca.crt")
                        .to_string_lossy()
                        .to_string(),
                    server_cert: certs_dir
                        .join("internal/server.crt")
                        .to_string_lossy()
                        .to_string(),
                    server_key: certs_dir
                        .join("internal/server.key")
                        .to_string_lossy()
                        .to_string(),
                    client_cert: certs_dir
                        .join("internal/client.crt")
                        .to_string_lossy()
                        .to_string(),
                    client_key: certs_dir
                        .join("internal/client.key")
                        .to_string_lossy()
                        .to_string(),
                },
            },
            storage: StorageConfig {
                storage_type: "vault".to_string(),
                vault: Some(VaultConfig {
                    address: "http://127.0.0.1:8200".to_string(),
                    token: "root".to_string(),
                }),
                etcd: None,
            },
            auth: AuthConfig::default(),
            certs_dir: Some(certs_dir.to_string_lossy().to_string()),
        };

        config.save(&self.config_path)?;
        Ok(())
    }

    pub async fn start_vault_dev(&self) -> Result<std::process::Child, Box<dyn std::error::Error>> {
        let child = Command::new("vault")
            .args(["server", "-dev", "-dev-root-token-id=root"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        self.write_pid("vault.pid", pid)?;

        // Wait for Vault to be ready
        let client = reqwest::Client::new();
        for _ in 0..10 {
            if client
                .get("http://127.0.0.1:8200/v1/sys/health")
                .send()
                .await
                .is_ok()
            {
                return Ok(child);
            }
            sleep(Duration::from_millis(500)).await;
        }

        Err("Vault failed to start or respond in time".into())
    }

    pub fn start_silo_server(
        &self,
        detach: bool,
    ) -> Result<std::process::Child, Box<dyn std::error::Error>> {
        // Pre-flight: Kill any orphan processes on Silo ports
        self.cleanup_orphan_ports();

        let mut server_path = "silo-server".to_string();

        // Try local build if not in path
        if Command::new("silo-server")
            .arg("--version")
            .status()
            .is_err()
        {
            if let Ok(abs) = fs::canonicalize("./target/debug/silo-server") {
                server_path = abs.to_string_lossy().to_string();
            } else if let Ok(abs) = fs::canonicalize("../target/debug/silo-server") {
                server_path = abs.to_string_lossy().to_string();
            }
        }

        let mut cmd = Command::new(server_path);
        cmd.env("SILO_CONFIG", &self.config_path);

        if detach {
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
        }

        let child = cmd.spawn()?;
        self.write_pid("silo.pid", child.id())?;
        Ok(child)
    }

    /// Kill any orphan silo-server processes that may be holding ports
    fn cleanup_orphan_ports(&self) {
        let ports = ["50051", "8443", "6192"];
        let mut killed_any = false;

        for port in ports {
            if let Some(pids) = self.find_pids_on_port(port) {
                for pid in pids {
                    println!("⚠️  Killing orphan process on port {} (PID: {})", port, pid);
                    Self::kill_process(pid);
                    killed_any = true;
                }
            }
        }

        // Only wait if we killed something, and poll for port availability
        if killed_any {
            self.wait_for_ports_available(&ports);
        }
    }

    /// Find PIDs using a given port (cross-platform)
    fn find_pids_on_port(&self, port: &str) -> Option<Vec<u32>> {
        #[cfg(unix)]
        {
            let output = Command::new("lsof")
                .args(["-t", &format!("-i:{}", port)])
                .output()
                .ok()?;

            if output.status.success() {
                let pids: Vec<u32> = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .lines()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if !pids.is_empty() {
                    return Some(pids);
                }
            }
        }

        #[cfg(windows)]
        {
            // Use netstat on Windows
            let output = Command::new("netstat").args(["-ano"]).output().ok()?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let pids: Vec<u32> = stdout
                    .lines()
                    .filter(|line| line.contains(&format!(":{}", port)))
                    .filter_map(|line| line.split_whitespace().last()?.parse().ok())
                    .collect();
                if !pids.is_empty() {
                    return Some(pids);
                }
            }
        }

        None
    }

    /// Wait for ports to become available with exponential backoff
    fn wait_for_ports_available(&self, ports: &[&str]) {
        let max_attempts = 10;
        let mut delay_ms = 50;

        for attempt in 1..=max_attempts {
            let all_free = ports
                .iter()
                .all(|port| self.find_pids_on_port(port).is_none());

            if all_free {
                return;
            }

            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            delay_ms = (delay_ms * 2).min(500); // Exponential backoff, max 500ms

            if attempt == max_attempts {
                println!("⚠️  Warning: Some ports may still be in use after cleanup");
            }
        }
    }

    fn write_pid(&self, filename: &str, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let home = dirs::home_dir().ok_or("Could not find home directory")?;
        let silo_dir = home.join(".silo");
        fs::create_dir_all(&silo_dir)?;
        fs::write(silo_dir.join(filename), pid.to_string())?;
        Ok(())
    }

    pub fn read_pid(&self, filename: &str) -> Option<u32> {
        let home = dirs::home_dir()?;
        let silo_dir = home.join(".silo");
        let pid_str = fs::read_to_string(silo_dir.join(filename)).ok()?;
        pid_str.trim().parse::<u32>().ok()
    }

    pub fn cleanup_pid(&self, filename: &str) {
        if let Some(home) = dirs::home_dir() {
            let _ = fs::remove_file(home.join(".silo").join(filename));
        }
    }

    pub fn stop_environment(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Stop Silo
        if let Some(pid) = self.read_pid("silo.pid") {
            println!("🛑 Stopping Silo Server (PID: {})...", pid);
            Self::kill_process(pid);
            self.cleanup_pid("silo.pid");
        }

        // 2. Stop Vault
        if let Some(pid) = self.read_pid("vault.pid") {
            println!("🛑 Stopping Vault (PID: {})...", pid);
            Self::kill_process(pid);
            self.cleanup_pid("vault.pid");
        }

        Ok(())
    }

    fn kill_process(pid: u32) {
        #[cfg(unix)]
        {
            let _ = Command::new("kill")
                .arg("-SIGTERM")
                .arg(pid.to_string())
                .status();
        }
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill")
                .arg("/F")
                .arg("/PID")
                .arg(pid.to_string())
                .status();
        }
    }

    pub fn get_process_status(&self, _name: &str, pid_file: &str) -> (String, String) {
        if let Some(pid) = self.read_pid(pid_file) {
            // Check if process is actually running
            let running = match Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .stderr(Stdio::null())
                .status()
            {
                Ok(s) => s.success(),
                Err(_) => false,
            };

            if running {
                ("RUNNING".to_string(), pid.to_string())
            } else {
                ("STOPPED".to_string(), "-".to_string())
            }
        } else {
            ("NOT FOUND".to_string(), "-".to_string())
        }
    }
}
