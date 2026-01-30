use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub gateway: GatewayConfig,
    pub control_plane: ControlPlaneConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Optional custom path for certificates. Defaults to ~/.silo/certs/
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certs_dir: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub native: NativeAuthConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NativeAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub users: Vec<NativeUser>,
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
}

fn default_jwt_secret() -> String {
    "silo-default-secret-change-me".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NativeUser {
    pub username: String,
    pub password_hash: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GatewayConfig {
    pub address: String,
    pub metrics_address: String,
    pub tls: GatewayTlsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GatewayTlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ControlPlaneConfig {
    pub address: String,
    pub tls: ControlPlaneTlsConfig,
    pub allowed_identities: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ControlPlaneTlsConfig {
    pub ca_cert: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StorageConfig {
    #[serde(rename = "type")]
    pub storage_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultConfig>,
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etcd: Option<EtcdConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EtcdConfig {
    pub endpoints: Vec<String>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_yaml::to_string(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
