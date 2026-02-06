use crate::config::{
    AuthConfig, Config, ControlPlaneConfig, ControlPlaneTlsConfig, GatewayConfig, GatewayTlsConfig,
    StorageConfig, VaultConfig,
};
use log::info;
use rand::Rng;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

/// Vault storage backend mode
#[derive(Debug, Clone, Copy)]
pub enum VaultStorageMode {
    /// Dev mode: in-memory, ephemeral, no persistence
    Dev,
    /// File mode: local file storage, persists across restarts
    File,
    /// Raft mode: integrated storage with HA support
    Raft,
}

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

    /// Start Vault with the specified storage mode
    /// Returns a description of the mode used
    pub async fn start_vault(
        &self,
        mode: VaultStorageMode,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let silo_dir = dirs::home_dir()
            .ok_or("Could not find home directory")?
            .join(".silo");

        fs::create_dir_all(&silo_dir)?;

        match mode {
            VaultStorageMode::Dev => self.start_vault_dev_mode().await,
            VaultStorageMode::File => self.start_vault_file_mode(&silo_dir).await,
            VaultStorageMode::Raft => self.start_vault_raft_mode(&silo_dir).await,
        }
    }

    /// Dev mode: ephemeral, in-memory storage
    async fn start_vault_dev_mode(&self) -> Result<String, Box<dyn std::error::Error>> {
        let child = Command::new("vault")
            .args(["server", "-dev", "-dev-root-token-id=root"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        self.write_pid("vault.pid", pid)?;

        // Wait for Vault to be ready
        self.wait_for_vault().await?;
        Ok("dev mode, token=root".to_string())
    }

    /// File mode: persistent local storage
    async fn start_vault_file_mode(
        &self,
        silo_dir: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let config_path = silo_dir.join("vault.hcl");
        let data_dir = silo_dir.join("vault-data");
        let keys_path = silo_dir.join("vault-keys.json");

        fs::create_dir_all(&data_dir)?;

        // Generate Vault config
        let config_content = format!(
            r#"
storage "file" {{
  path = "{}"
}}

listener "tcp" {{
  address     = "127.0.0.1:8200"
  tls_disable = true
}}

api_addr = "http://127.0.0.1:8200"
ui = true
disable_mlock = true
"#,
            data_dir.display()
        );

        let mut file = fs::File::create(&config_path)?;
        file.write_all(config_content.as_bytes())?;

        // Start Vault server
        let child = Command::new("vault")
            .args(["server", "-config", config_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        self.write_pid("vault.pid", pid)?;

        // Wait for Vault to be ready
        self.wait_for_vault().await?;

        // Initialize and unseal if needed
        let token = self.initialize_and_unseal(&keys_path).await?;
        Ok(format!("file mode, token={}", &token[..8.min(token.len())]))
    }

    /// Raft mode: HA cluster storage
    async fn start_vault_raft_mode(
        &self,
        silo_dir: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let config_path = silo_dir.join("vault-raft.hcl");
        let data_dir = silo_dir.join("vault-raft");
        let keys_path = silo_dir.join("vault-keys.json");

        fs::create_dir_all(&data_dir)?;

        // Generate Vault raft config
        let config_content = format!(
            r#"
storage "raft" {{
  path    = "{}"
  node_id = "silo-1"
}}

listener "tcp" {{
  address     = "127.0.0.1:8200"
  tls_disable = true
}}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
ui = true
disable_mlock = true
"#,
            data_dir.display()
        );

        let mut file = fs::File::create(&config_path)?;
        file.write_all(config_content.as_bytes())?;

        // Start Vault server
        let child = Command::new("vault")
            .args(["server", "-config", config_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        self.write_pid("vault.pid", pid)?;

        // Wait for Vault to be ready
        self.wait_for_vault().await?;

        // Initialize and unseal if needed
        let token = self.initialize_and_unseal(&keys_path).await?;
        Ok(format!("raft mode, token={}", &token[..8.min(token.len())]))
    }

    /// Wait for Vault to be ready (up to 10 seconds)
    async fn wait_for_vault(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        for _ in 0..20 {
            // Check sys/health with standbyok and uninitok
            if let Ok(resp) = client
                .get("http://127.0.0.1:8200/v1/sys/health?standbyok=true&uninitok=true")
                .send()
                .await
            {
                let status = resp.status().as_u16();
                if resp.status().is_success() || status == 501 || status == 503 || status == 429 {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
        Err("Vault failed to start or respond in time".into())
    }

    /// Initialize Vault and unseal, returns root token
    async fn initialize_and_unseal(
        &self,
        keys_path: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();

        // Check if already initialized
        let init_status: serde_json::Value = client
            .get("http://127.0.0.1:8200/v1/sys/init")
            .send()
            .await?
            .json()
            .await?;

        let (unseal_keys, root_token) = if init_status["initialized"].as_bool() == Some(false) {
            // Initialize Vault
            let init_resp: serde_json::Value = client
                .put("http://127.0.0.1:8200/v1/sys/init")
                .json(&serde_json::json!({
                    "secret_shares": 1,
                    "secret_threshold": 1
                }))
                .send()
                .await?
                .json()
                .await?;

            let keys: Vec<String> = init_resp["keys_base64"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let token = init_resp["root_token"].as_str().unwrap_or("").to_string();

            // Store keys in OS Keychain (with file fallback)
            let keys_data = serde_json::json!({
                "unseal_keys_b64": keys,
                "root_token": token
            });

            let mut stored_in_keychain = false;
            if let Err(e) = Self::store_keys_in_keychain(&keys_data.to_string()) {
                info!("Keychain unavailable ({}), using file fallback only", e);
            } else {
                println!("  ✅ Vault keys stored in OS Keychain");
                stored_in_keychain = true;
            }

            // Always save to file as a backup for now, to ensure reliability across reboots in all environments
            let mut file = fs::File::create(keys_path)?;
            file.write_all(serde_json::to_string_pretty(&keys_data)?.as_bytes())?;
            if !stored_in_keychain {
                println!("  ✅ Vault initialized. Keys saved to {:?}", keys_path);
            } else {
                println!(
                    "  ✅ Vault initialized. Redundant backup saved to {:?}",
                    keys_path
                );
            }

            (keys, token)
        } else {
            // Load existing keys (try keychain first, then file)
            let keys_data: serde_json::Value = match Self::load_keys_from_keychain() {
                Ok(data) => {
                    println!("  🔑 Vault keys retrieved from OS Keychain");
                    serde_json::from_str(&data)?
                }
                Err(e) => {
                    info!("Keychain lookup failed: {}. Trying file fallback...", e);
                    // Fallback to file
                    let keys_content = fs::read_to_string(keys_path).map_err(|io_e| {
                        format!("Critical: Could not retrieve Vault keys from Keychain or file ({:?}). Vault remains sealed.", io_e)
                    })?;
                    println!("  📂 Vault keys retrieved from file fallback");
                    serde_json::from_str(&keys_content)?
                }
            };

            let keys: Vec<String> = keys_data["unseal_keys_b64"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let token = keys_data["root_token"].as_str().unwrap_or("").to_string();
            (keys, token)
        };

        // Ensure silo.yaml is in sync with the current token
        if let Ok(mut config) = crate::config::Config::load(&self.config_path) {
            let current_token = config.storage.vault.as_ref().map(|v| v.token.clone());
            if current_token != Some(root_token.clone()) {
                if let Some(ref mut vault) = config.storage.vault {
                    vault.token = root_token.clone();
                } else {
                    config.storage.vault = Some(crate::config::VaultConfig {
                        address: "http://127.0.0.1:8200".to_string(),
                        token: root_token.clone(),
                    });
                }
                if config.save(&self.config_path).is_ok() {
                    println!(
                        "  ✅ Updated {} with current Vault root token",
                        self.config_path
                    );
                }
            }
        }

        // Check seal status and unseal if needed
        let seal_status: serde_json::Value = client
            .get("http://127.0.0.1:8200/v1/sys/seal-status")
            .send()
            .await?
            .json()
            .await?;

        if seal_status["sealed"].as_bool() == Some(true) {
            for key in &unseal_keys {
                let _ = client
                    .put("http://127.0.0.1:8200/v1/sys/unseal")
                    .json(&serde_json::json!({"key": key}))
                    .send()
                    .await?;
            }
            info!("Vault unsealed successfully");
        }

        Ok(root_token)
    }

    /// Store Vault keys in OS Keychain
    fn store_keys_in_keychain(data: &str) -> Result<(), keyring::Error> {
        let service = "silo.unseal.keys";
        let user = "vault.root";
        let entry = keyring::Entry::new(service, user)?;
        entry.set_password(data)?;
        Ok(())
    }

    /// Load Vault keys from OS Keychain
    fn load_keys_from_keychain() -> Result<String, keyring::Error> {
        let service = "silo.unseal.keys";
        let user = "vault.root";
        let entry = keyring::Entry::new(service, user)?;
        entry.get_password()
    }

    /// Configure Vault as OIDC Provider for Silo authentication
    pub async fn setup_vault_oidc_provider(
        &self,
        vault_address: &str,
        vault_token: &str,
        silo_redirect_uri: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();

        // 1. Create an OIDC assignment (allow all entities)
        let _ = client
            .post(format!(
                "{}/v1/identity/oidc/assignment/silo-users",
                vault_address
            ))
            .header("X-Vault-Token", vault_token)
            .json(&serde_json::json!({
                "entity_ids": ["*"],
                "group_ids": ["*"]
            }))
            .send()
            .await?;

        // 2. Create OIDC key
        let _ = client
            .post(format!("{}/v1/identity/oidc/key/silo-key", vault_address))
            .header("X-Vault-Token", vault_token)
            .json(&serde_json::json!({
                "algorithm": "RS256",
                "rotation_period": "24h"
            }))
            .send()
            .await?;

        // 3. Create OIDC client for Silo CLI
        let client_secret: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let _ = client
            .post(format!(
                "{}/v1/identity/oidc/client/silo-cli",
                vault_address
            ))
            .header("X-Vault-Token", vault_token)
            .json(&serde_json::json!({
                "redirect_uris": [silo_redirect_uri],
                "assignments": ["silo-users"],
                "key": "silo-key",
                "id_token_ttl": "30m",
                "access_token_ttl": "1h",
                "client_secret": client_secret
            }))
            .send()
            .await?;

        // 4. Create OIDC provider
        let _ = client
            .post(format!("{}/v1/identity/oidc/provider/silo", vault_address))
            .header("X-Vault-Token", vault_token)
            .json(&serde_json::json!({
                "allowed_client_ids": ["silo-cli"],
                "scopes_supported": ["openid", "email", "profile"]
            }))
            .send()
            .await?;

        info!("Vault OIDC Provider configured successfully");
        Ok(client_secret)
    }

    /// Check if etcd is installed in PATH
    pub fn check_etcd_installed(&self) -> bool {
        Command::new("etcd")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Start etcd in dev mode (single node, in-memory)
    pub async fn start_etcd_dev(&self) -> Result<std::process::Child, Box<dyn std::error::Error>> {
        // Start etcd with default settings for local development
        let child = Command::new("etcd")
            .args([
                "--data-dir",
                "/tmp/silo-etcd-data",
                "--listen-client-urls",
                "http://127.0.0.1:2379",
                "--advertise-client-urls",
                "http://127.0.0.1:2379",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child.id();
        self.write_pid("etcd.pid", pid)?;

        // Wait for etcd to be ready
        let client = reqwest::Client::new();
        for _ in 0..10 {
            if client
                .get("http://127.0.0.1:2379/health")
                .send()
                .await
                .is_ok()
            {
                return Ok(child);
            }
            sleep(Duration::from_millis(500)).await;
        }

        Err("etcd failed to start or respond in time".into())
    }

    pub fn start_silo_server(
        &self,
        detach: bool,
    ) -> Result<std::process::Child, Box<dyn std::error::Error>> {
        let mut server_path = "silo-server".to_string();

        // Try local build if not in path - prefer release over debug
        if Command::new("silo-server")
            .arg("--version")
            .status()
            .is_err()
        {
            if let Ok(abs) = fs::canonicalize("./target/release/silo-server") {
                server_path = abs.to_string_lossy().to_string();
            } else if let Ok(abs) = fs::canonicalize("../target/release/silo-server") {
                server_path = abs.to_string_lossy().to_string();
            } else if let Ok(abs) = fs::canonicalize("./target/debug/silo-server") {
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

    /// Kill any orphan silo-server or Vault processes that may be holding ports
    pub fn cleanup_orphan_ports(&self) {
        let ports = ["50051", "8443", "6192", "8200"];
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

    /// Wait for the Silo server to become healthy
    pub async fn wait_for_healthy(&self, endpoint: &str, timeout_secs: u64) -> bool {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_millis(500);

        while start.elapsed() < timeout {
            match client.get(format!("{}/health", endpoint)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return true;
                }
                _ => {}
            }
            sleep(poll_interval).await;
        }
        false
    }

    /// Wait for a process to terminate
    pub fn wait_for_stopped(&self, pid_file: &str, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_millis(200);

        while start.elapsed() < timeout {
            if let Some(pid) = self.read_pid(pid_file) {
                // Check if process is still running
                let running = Command::new("kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if !running {
                    return true; // Process terminated
                }
            } else {
                return true; // PID file gone
            }
            std::thread::sleep(poll_interval);
        }
        false
    }
}
