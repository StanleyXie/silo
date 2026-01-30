use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use reqwest::Client;
use serde_json::{json, Value};
use std::error::Error;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get(&self, path: &str) -> Result<Option<Vec<u8>>, Box<dyn Error + Send + Sync>> {
        self.get_versioned(path, 0)
            .await
            .map(|opt| opt.map(|(data, _)| data))
    }
    async fn get_versioned(
        &self,
        path: &str,
        version: u32,
    ) -> Result<Option<(Vec<u8>, u32)>, Box<dyn Error + Send + Sync>>;
    async fn put(
        &self,
        path: &str,
        data: &[u8],
        base_version: u32,
    ) -> Result<u32, Box<dyn Error + Send + Sync>>;
    async fn delete(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn list(&self, path: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>>;
    async fn health(&self) -> Result<(), Box<dyn Error + Send + Sync>>;
}

pub struct VaultClient {
    client: Client,
    addr: String,
    token: String,
}

impl VaultClient {
    pub fn new(addr: String, token: String) -> Self {
        VaultClient {
            client: Client::new(),
            addr,
            token,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.addr, path)
    }
}

#[async_trait]
impl StorageBackend for VaultClient {
    // KV v2 Read
    async fn get_versioned(
        &self,
        path: &str,
        version: u32,
    ) -> Result<Option<(Vec<u8>, u32)>, Box<dyn Error + Send + Sync>> {
        let mount = "secret";
        let relative_path = path.trim_start_matches("secret/");
        let mut api_path = format!("{}/data/{}", mount, relative_path);

        if version > 0 {
            api_path = format!("{}?version={}", api_path, version);
        }

        let resp = self
            .client
            .get(self.url(&api_path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if resp.status() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let text = resp.text().await?;
            return Err(format!("Vault Error: {}", text).into());
        }

        let json: Value = resp.json().await?;

        // Extract version from metadata
        let ver_id = json
            .get("data")
            .and_then(|d| d.get("metadata"))
            .and_then(|m| m.get("version"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Extract data.data.value
        if let Some(data) = json.get("data").and_then(|d| d.get("data")) {
            if let Some(val_str) = data.get("value").and_then(|v| v.as_str()) {
                let bytes = general_purpose::STANDARD.decode(val_str)?;
                return Ok(Some((bytes, ver_id)));
            }
        }

        Ok(None)
    }

    // KV v2 Write
    async fn put(
        &self,
        path: &str,
        data: &[u8],
        base_version: u32,
    ) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let mount = "secret";
        let relative_path = path.trim_start_matches("secret/");
        let api_path = format!("{}/data/{}", mount, relative_path);

        let data_b64 = general_purpose::STANDARD.encode(data);
        let mut payload = json!({
            "data": {
                "value": data_b64
            }
        });

        // Add CAS (Check-And-Set) if base_version > 0
        if base_version > 0 {
            payload["options"] = json!({ "cas": base_version });
        }

        let resp = self
            .client
            .put(self.url(&api_path))
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            return Err(format!("Vault Put Error (CAS={}): {}", base_version, text).into());
        }

        let json: Value = resp.json().await?;
        let version = json
            .get("data")
            .and_then(|d| d.get("version"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        Ok(version)
    }

    // Delete
    async fn delete(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mount = "secret";
        let relative_path = path.trim_start_matches("secret/");
        let api_path = format!("{}/metadata/{}", mount, relative_path);

        let resp = self
            .client
            .delete(self.url(&api_path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if resp.status() == 404 {
            return Ok(());
        }
        if !resp.status().is_success() {
            let text = resp.text().await?;
            return Err(format!("Vault Delete Error: {}", text).into());
        }
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let mount = "secret";
        let relative_path = path.trim_start_matches("secret/").trim_end_matches("/");
        let api_path = format!("{}/metadata/{}", mount, relative_path);

        let resp = self
            .client
            .request(
                reqwest::Method::from_bytes(b"LIST").unwrap(),
                self.url(&api_path),
            )
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if resp.status() == 404 {
            return Ok(vec![]);
        }
        if !resp.status().is_success() {
            let text = resp.text().await?;
            return Err(format!("Vault List Error: {}", text).into());
        }

        let json: Value = resp.json().await?;
        let keys = json
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(keys)
    }

    async fn health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let resp = self
            .client
            .get(self.url("sys/health"))
            .header("X-Vault-Token", &self.token)
            .send()
            .await?;

        if resp.status().is_success() || resp.status() == 429 {
            // 429 means active/standby but healthy in Vault terms
            Ok(())
        } else {
            Err(format!("Vault Unhealthy: {}", resp.status()).into())
        }
    }
}

#[cfg(feature = "etcd")]
pub mod etcd;
pub mod grpc;
#[cfg(test)]
mod tests;
