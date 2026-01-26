use crate::backend::StorageBackend;
use crate::proto::v1::control_service_client::ControlServiceClient;
use crate::proto::v1::{AuthorizeRequest, AuthorizeResponse};
use bytes::Bytes;
use log::{error, info};
use pingora_core::Result;
use pingora_proxy::Session;
use serde::Deserialize;
use std::sync::Arc;
use tonic::transport::Channel;

#[derive(Deserialize, serde::Serialize)]
#[allow(non_snake_case)]
struct LockInfo {
    ID: String,
    Operation: String,
    Who: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SessionMetadata {
    pub session_id: String,
    pub identity: String,
    pub start_time: String,
    pub last_heartbeat: String,
    pub client_ip: String,
    pub device_id: String,
    pub workspace: String,
    pub project_instance: String,
    pub config_version: u32,
    pub lock_path: Option<String>,
}

pub struct ApiHandler {
    client: Arc<dyn StorageBackend>,
    control: ControlServiceClient<Channel>,
}

impl ApiHandler {
    pub fn new(client: Arc<dyn StorageBackend>, control: ControlServiceClient<Channel>) -> Self {
        ApiHandler { client, control }
    }

    pub async fn handle(
        &self,
        session: &mut Session,
        request_id: &str,
        identity: &str,
        client_ip: &str,
    ) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.clone();

        if !path.starts_with("/v1/state/")
            && !path.starts_with("/v1/lock/")
            && !path.starts_with("/v1/config/")
        {
            return Ok(false);
        }

        // --- Autonomous Local Authorization (Shared-State) ---
        let auth_path = format!("secret/silo/policies/allowed_identities/{}", identity);
        let local_auth = match self.client.get(&auth_path).await {
            Ok(Some(_)) => {
                info!(
                    "[{}] Autonomous Auth: Identity '{}' verified via Shared-State (KV)",
                    request_id, identity
                );
                true
            }
            Ok(None) => false,
            Err(e) => {
                error!(
                    "[{}] Shared-State Lookup Error: {}. Falling back to Control Plane.",
                    request_id, e
                );
                false
            }
        };

        if !local_auth {
            let mut control = self.control.clone();
            let auth_req = AuthorizeRequest {
                request_id: request_id.to_string(),
                identity: identity.to_string(),
                method: method.to_string(),
                path: path.clone(),
            };

            match control.authorize(auth_req).await {
                Ok(resp) => {
                    let inner: AuthorizeResponse = resp.into_inner();
                    if !inner.authorized {
                        info!("[{}] Unauthorized: {}", request_id, inner.reason);
                        session
                            .respond_error_with_body(
                                403,
                                Bytes::from(format!("Forbidden: {}", inner.reason)),
                            )
                            .await?;
                        return Ok(true);
                    }
                }
                Err(e) => {
                    error!("[{}] CP Offline & Not in local KV: {}", request_id, e);
                    session
                        .respond_error_with_body(
                            403,
                            Bytes::from("Unauthorized: No policy found locally and CP is offline"),
                        )
                        .await?;
                    return Ok(true);
                }
            }
        }

        if path.starts_with("/v1/state/") {
            return self
                .handle_state(session, &method, &path, request_id, identity)
                .await;
        } else if path.starts_with("/v1/lock/") {
            return self
                .handle_lock(session, &method, &path, request_id, identity, client_ip)
                .await;
        } else if path.starts_with("/v1/config/") {
            return self
                .handle_config(session, &method, &path, request_id, identity)
                .await;
        }

        Ok(false)
    }

    async fn handle_state(
        &self,
        session: &mut Session,
        method: &http::Method,
        path: &str,
        request_id: &str,
        identity: &str,
    ) -> Result<bool> {
        let state_path = path.trim_start_matches("/v1/state/");
        let vault_path = format!("secret/{}", state_path);

        match *method {
            http::Method::GET => {
                info!("[{}] GET State: {}", request_id, vault_path);
                match self.client.get(&vault_path).await {
                    Ok(Some(data)) => {
                        session
                            .respond_error_with_body(200, Bytes::from(data))
                            .await?;
                    }
                    Ok(None) => {
                        let _ = session
                            .respond_error_with_body(404, Bytes::from_static(b"Not Found"))
                            .await;
                    }
                    Err(e) => {
                        error!("[{}] Storage Get Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            http::Method::POST => {
                info!("[{}] POST State: {}", request_id, vault_path);

                // --- Lock Guard ---
                let lock_session_path = format!("secret/{}/lock/session", state_path);
                if let Ok(Some(lock_session_bytes)) = self.client.get(&lock_session_path).await {
                    let locked_session_id =
                        String::from_utf8_lossy(&lock_session_bytes).to_string();

                    let device_id = session
                        .get_header("X-Silo-Device-ID")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown-device");
                    let current_session_id =
                        format!("{}-{}", identity.replace(".", "-"), device_id);

                    if locked_session_id != current_session_id {
                        error!("[{}] LOCK VIOLATION: State is locked by session {} but request is from session {}", 
                            request_id, locked_session_id, current_session_id);
                        session
                            .respond_error_with_body(
                                423,
                                Bytes::from(format!(
                                    "Locked: State is held by another session ({})",
                                    locked_session_id
                                )),
                            )
                            .await?;
                        return Ok(true);
                    }
                }

                // --- CAS & Version Lineage ---
                let config_version = session
                    .get_header("X-Silo-Config-Version")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u32>().ok());

                let base_version = session
                    .get_header("X-Silo-Base-Version")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);

                let body = match session.read_request_body().await? {
                    Some(b) => b,
                    None => Bytes::new(),
                };

                match self.client.put(&vault_path, &body, base_version).await {
                    Ok(state_version) => {
                        if let Some(cv) = config_version {
                            let lineage_path =
                                format!("secret/lineage/{}/v{}", state_path, state_version);
                            let lineage_data = serde_json::json!({
                                "config_version": cv,
                                "state_version": state_version,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                            });
                            let _ = self
                                .client
                                .put(&lineage_path, lineage_data.to_string().as_bytes(), 0)
                                .await;
                            info!(
                                "[{}] Lineage recorded: State v{} -> Config v{}",
                                request_id, state_version, cv
                            );
                        }
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("CAS") || err_str.contains("version") {
                            error!("[{}] CAS Conflict: {}", request_id, err_str);
                            session
                                .respond_error_with_body(
                                    409,
                                    Bytes::from(format!("Conflict: {}", err_str)),
                                )
                                .await?;
                        } else {
                            error!("[{}] Storage Put Error: {}", request_id, e);
                            session
                                .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                                .await?;
                        }
                    }
                }
            }
            http::Method::DELETE => {
                info!("[{}] DELETE State: {}", request_id, vault_path);
                match self.client.delete(&vault_path).await {
                    Ok(_) => {
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        error!("[{}] Storage Delete Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            _ => {
                return Ok(false);
            }
        }

        // --- Heartbeat Update ---
        let _ = self.update_session_heartbeat(state_path).await;

        Ok(true)
    }

    async fn handle_lock(
        &self,
        session: &mut Session,
        method: &http::Method,
        path: &str,
        request_id: &str,
        identity: &str,
        client_ip: &str,
    ) -> Result<bool> {
        let lock_path = format!("secret/{}/lock", path.trim_start_matches("/v1/lock/"));

        match *method {
            http::Method::POST | http::Method::PUT => {
                let body = match session.read_request_body().await? {
                    Some(b) => b,
                    None => Bytes::new(),
                };

                let lock_info: Option<LockInfo> = serde_json::from_slice(&body).ok();
                let caller = lock_info.as_ref().map(|li| li.Who.as_str()).unwrap_or("-");
                let op = lock_info
                    .as_ref()
                    .map(|li| li.Operation.as_str())
                    .unwrap_or("-");
                let id = lock_info.as_ref().map(|li| li.Who.as_str()).unwrap_or("-");

                info!(
                    "[{}] LOCK: {} (caller: {}, op: {}, id: {})",
                    request_id, lock_path, caller, op, id
                );

                let device_id = session
                    .get_header("X-Silo-Device-ID")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown-device");

                let session_id = format!("{}-{}", identity.replace(".", "-"), device_id);
                let session_path = format!("secret/silo/sessions/{}", session_id);

                let meta = SessionMetadata {
                    session_id: session_id.clone(),
                    identity: identity.to_string(),
                    start_time: chrono::Utc::now().to_rfc3339(),
                    last_heartbeat: chrono::Utc::now().to_rfc3339(),
                    client_ip: client_ip.to_string(),
                    device_id: device_id.to_string(),
                    workspace: op.to_string(),
                    project_instance: id.to_string(),
                    config_version: 0,
                    lock_path: Some(lock_path.clone()),
                };

                let session_json = serde_json::to_vec(&meta).unwrap_or_default();
                let _ = self.client.put(&session_path, &session_json, 0).await;

                let lock_meta_path = format!("{}/session", lock_path);
                let _ = self
                    .client
                    .put(&lock_meta_path, session_id.as_bytes(), 0)
                    .await;

                match self.client.put(&lock_path, &body, 0).await {
                    Ok(_) => {
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        error!("[{}] LOCK Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            http::Method::DELETE => {
                info!("[{}] UNLOCK: {}", request_id, lock_path);
                match self.client.delete(&lock_path).await {
                    Ok(_) => {
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        error!("[{}] UNLOCK Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            _ => {
                return Ok(false);
            }
        }

        // --- Heartbeat Update ---
        let state_path = path.trim_start_matches("/v1/lock/");
        let _ = self.update_session_heartbeat(state_path).await;

        Ok(true)
    }

    async fn handle_config(
        &self,
        session: &mut Session,
        method: &http::Method,
        path: &str,
        request_id: &str,
        _identity: &str,
    ) -> Result<bool> {
        let config_path = format!("secret/configs/{}", path.trim_start_matches("/v1/config/"));
        let query = session.req_header().uri.query().unwrap_or("");
        let version = query
            .split('&')
            .find(|pair| pair.starts_with("version="))
            .and_then(|pair| pair.strip_prefix("version="))
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        match *method {
            http::Method::GET => {
                info!(
                    "[{}] GET Config: {} (v{})",
                    request_id, config_path, version
                );
                match self.client.get_versioned(&config_path, version).await {
                    Ok(Some((data, _ver_id))) => {
                        session
                            .respond_error_with_body(200, Bytes::from(data))
                            .await?;
                    }
                    Ok(None) => {
                        let _ = session
                            .respond_error_with_body(404, Bytes::from_static(b"Config Not Found"))
                            .await;
                    }
                    Err(e) => {
                        error!("[{}] Config Get Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            http::Method::POST | http::Method::PUT => {
                info!("[{}] PUT Config: {}", request_id, config_path);
                let body = match session.read_request_body().await? {
                    Some(b) => b,
                    None => Bytes::new(),
                };

                match self.client.put(&config_path, &body, 0).await {
                    Ok(_ver) => {
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        error!("[{}] Config Put Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            http::Method::DELETE => {
                info!("[{}] DELETE Config: {}", request_id, config_path);
                match self.client.delete(&config_path).await {
                    Ok(_) => {
                        session
                            .respond_error_with_body(200, Bytes::from_static(b""))
                            .await?;
                    }
                    Err(e) => {
                        error!("[{}] Config Delete Error: {}", request_id, e);
                        session
                            .respond_error_with_body(500, Bytes::from(format!("Error: {}", e)))
                            .await?;
                    }
                }
            }
            _ => {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn update_session_heartbeat(&self, state_path: &str) -> Result<()> {
        let lock_session_path = format!("secret/{}/lock/session", state_path);

        if let Ok(Some(session_id_bytes)) = self.client.get(&lock_session_path).await {
            let session_id = String::from_utf8_lossy(&session_id_bytes).to_string();
            let session_path = format!("secret/silo/sessions/{}", session_id);

            if let Ok(Some(session_data)) = self.client.get(&session_path).await {
                if let Ok(mut meta) = serde_json::from_slice::<SessionMetadata>(&session_data) {
                    meta.last_heartbeat = chrono::Utc::now().to_rfc3339();
                    if let Ok(updated_data) = serde_json::to_vec(&meta) {
                        let _ = self.client.put(&session_path, &updated_data, 0).await;
                    }
                }
            }
        }
        Ok(())
    }
}
