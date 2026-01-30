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
        Ok(child)
    }
}
