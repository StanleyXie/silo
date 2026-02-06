use crate::backend::StorageBackend;
use crate::proto::v1::control_service_client::ControlServiceClient;
use crate::proto::v1::{AuthorizeRequest, AuthorizeResponse};
use bytes::Bytes;
use log::{error, info};
use pingora_core::Result;
use pingora_proxy::Session;
use serde_json::json;
// use serde::Deserialize; (Handled in grouped import)
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

use crate::auth::NativeIdentityService;
use askama::Template;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: usize,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    redirect_uri: &'a str,
    state: &'a str,
    response_type: &'a str,
    client_id: &'a str,
    error: Option<&'a str>,
}

use crate::config::OidcConfig;

pub struct ApiHandler {
    client: Arc<dyn StorageBackend>,
    control: ControlServiceClient<Channel>,
    native_auth: NativeIdentityService,
    certs_dir: PathBuf,
    oidc_config: Option<OidcConfig>,
}

impl ApiHandler {
    pub fn new(
        client: Arc<dyn StorageBackend>,
        control: ControlServiceClient<Channel>,
        native_auth: NativeIdentityService,
        certs_dir: PathBuf,
        oidc_config: Option<OidcConfig>,
    ) -> Self {
        ApiHandler {
            client,
            control,
            native_auth,
            certs_dir,
            oidc_config,
        }
    }


    /// Read the full request body by looping until EOF.
    /// This fixes the truncation bug where large bodies were only partially read.
    async fn read_full_body(session: &mut Session) -> Result<Bytes> {
        let mut full_body = bytes::BytesMut::new();
        loop {
            match session.read_request_body().await? {
                Some(chunk) => full_body.extend_from_slice(&chunk),
                None => break,
            }
        }
        Ok(full_body.freeze())
    }

    async fn handle_health(&self, session: &mut Session) -> Result<bool> {
        let mut storage_status = "UP";
        let mut control_status = "UP";
        let mut overall_healthy = true;

        if let Err(e) = self.client.health().await {
            storage_status = "DOWN";
            overall_healthy = false;
            error!("Health Check: Storage Backend is DOWN: {}", e);
        }

        // Check Control Plane (gRPC)
        let mut control_client = self.control.clone();
        if let Err(e) = control_client
            .heartbeat(crate::proto::v1::HeartbeatRequest {
                instance_id: "health-check".to_string(),
                lock_id: "health-check".to_string(),
                project: "health-check".to_string(),
            })
            .await
        {
            control_status = "DOWN";
            overall_healthy = false;
            error!("Health Check: Control Plane is DOWN: {}", e);
        }

        let health_report = json!({
            "status": if overall_healthy { "UP" } else { "DOWN" },
            "version": env!("CARGO_PKG_VERSION"),
            "components": {
                "gateway": "UP",
                "storage": storage_status,
                "control_plane": control_status,
            }
        });

        let status_code = if overall_healthy { 200 } else { 503 };
        let _ = session
            .respond_error_with_body(status_code, Bytes::from(health_report.to_string()))
            .await;
        Ok(true)
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

        if path.starts_with("/auth/") {
            return self
                .handle_auth(session, &method, &path, request_id, client_ip)
                .await;
        }

        if path == "/health" || path == "/" {
            return self.handle_health(session).await;
        }

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

                let body = Self::read_full_body(session).await?;


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
                let body = Self::read_full_body(session).await?;


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
                let body = Self::read_full_body(session).await?;


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

    async fn handle_auth(
        &self,
        session: &mut Session,
        method: &http::Method,
        path: &str,
        _request_id: &str,
        _client_ip: &str,
    ) -> Result<bool> {
        if path == "/auth/login" {
            match *method {
                http::Method::GET => {
                    let query = session.req_header().uri.query().unwrap_or("");
                    let params: std::collections::HashMap<String, String> =
                        url::form_urlencoded::parse(query.as_bytes())
                            .into_owned()
                            .collect();

                    let cli_redirect_uri = params
                        .get("redirect_uri")
                        .map(|s| s.as_str())
                        .unwrap_or("/");
                    let state = params.get("state").map(|s| s.as_str()).unwrap_or("");

                    // Check if OIDC with Google OAuth is configured
                    if let Some(ref oidc) = self.oidc_config {
                        if let (Some(client_id), Some(redirect_uri)) = (&oidc.client_id, &oidc.redirect_uri) {
                            // Store the CLI's redirect_uri and state in a session cookie or encode in state
                            // For simplicity, we'll encode both in the state parameter
                            let combined_state = format!("{}|{}", state, cli_redirect_uri);
                            let encoded_state = base64::Engine::encode(
                                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                                combined_state.as_bytes(),
                            );
                            
                            // Use configurable authorization endpoint, default to Google
                            let default_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
                            let auth_endpoint = oidc.authorization_endpoint.as_ref().unwrap_or(&default_auth_endpoint);
                            
                            // Build OAuth authorization URL (works with Vault, Google, etc.)
                            let auth_url = format!(
                                "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                                auth_endpoint,
                                urlencoding::encode(client_id),
                                urlencoding::encode(redirect_uri),
                                urlencoding::encode(&encoded_state),
                            );

                            info!("Redirecting to OIDC Provider: {}", auth_url);

                            let mut resp_header =
                                Box::new(pingora_http::ResponseHeader::build(302, Some(1)).unwrap());
                            resp_header.insert_header("Location", auth_url).unwrap();
                            session.write_response_header(resp_header, true).await?;
                            return Ok(true);
                        }
                    }

                    // Fall back to native login form
                    let response_type = params
                        .get("response_type")
                        .map(|s| s.as_str())
                        .unwrap_or("code");
                    let client_id = params.get("client_id").map(|s| s.as_str()).unwrap_or("");

                    let template = LoginTemplate {
                        redirect_uri: cli_redirect_uri,
                        state,
                        response_type,
                        client_id,
                        error: None,
                    };

                    let html = template
                        .render()
                        .unwrap_or_else(|_| "Error rendering template".into());

                    let mut resp_header =
                        Box::new(pingora_http::ResponseHeader::build(200, Some(3)).unwrap());
                    resp_header
                        .insert_header("Content-Type", "text/html")
                        .unwrap();
                    resp_header
                        .insert_header("Content-Length", html.len())
                        .unwrap();

                    session.write_response_header(resp_header, false).await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(html)), true)
                        .await?;
                    return Ok(true);
                }

                http::Method::POST => {
                    let body = Self::read_full_body(session).await?;
                    let params: std::collections::HashMap<String, String> =
                        url::form_urlencoded::parse(&body).into_owned().collect();

                    let username = params.get("username").map(|s| s.as_str()).unwrap_or("");
                    let password = params.get("password").map(|s| s.as_str()).unwrap_or("");
                    let redirect_uri = params
                        .get("redirect_uri")
                        .map(|s| s.as_str())
                        .unwrap_or("/");
                    let state = params.get("state").map(|s| s.as_str()).unwrap_or("");

                    if let Some(_roles) = self.native_auth.validate(username, password) {
                        let code: String = rand::thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(16)
                            .map(char::from)
                            .collect();

                        let code_path = format!("secret/silo/codes/{}", code);
                        let code_data = serde_json::json!({
                           "username": username,
                           "roles": _roles,
                           "ttl": chrono::Utc::now().to_rfc3339()
                        });
                        if let Err(e) = self
                            .client
                            .put(&code_path, code_data.to_string().as_bytes(), 0)
                            .await
                        {
                            error!("Failed to store auth code: {}", e);
                        } else {
                            info!("Stored auth code at {}", code_path);
                        }

                        let location = format!("{}?code={}&state={}", redirect_uri, code, state);

                        let mut resp_header =
                            Box::new(pingora_http::ResponseHeader::build(302, Some(0)).unwrap());
                        resp_header.insert_header("Location", location).unwrap();
                        session.write_response_header(resp_header, true).await?;
                        // session.write_response_body(None, true).await?; // Header implicitly ends stream if true?
                        return Ok(true);
                    } else {
                        let template = LoginTemplate {
                            redirect_uri,
                            state,
                            response_type: "code",
                            client_id: "silo",
                            error: Some("Invalid Username or Password"),
                        };
                        let html = template.render().unwrap();
                        let mut resp_header =
                            Box::new(pingora_http::ResponseHeader::build(401, Some(3)).unwrap());
                        resp_header
                            .insert_header("Content-Type", "text/html")
                            .unwrap();
                        session.write_response_header(resp_header, false).await?;
                        session
                            .write_response_body(Some(Bytes::from(html)), true)
                            .await?;
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        // Handle /auth/token (Exchange Code for Token)
        if path == "/auth/token" && *method == http::Method::POST {
            let body = Self::read_full_body(session).await?;
            let params: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(&body).into_owned().collect();
            let code = params.get("code").map(|s| s.as_str()).unwrap_or("");

            let code_path = format!("secret/silo/codes/{}", code);
            match self.client.get(&code_path).await {
                Ok(Some(data)) => {
                    let code_info: serde_json::Value = serde_json::from_slice(&data).unwrap();
                    let username = code_info
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("anonymous");
                    let roles: Vec<String> = code_info
                        .get("roles")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    // Mint real JWT
                    let expiration =
                        (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize;
                    let claims = Claims {
                        sub: username.to_string(),
                        roles: roles.clone(),
                        exp: expiration,
                    };

                    let token = match encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(self.native_auth.config.jwt_secret.as_bytes()),
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            error!("JWT Encoding Error: {}", e);
                            session
                                .respond_error_with_body(
                                    500,
                                    Bytes::from("Token generation failed"),
                                )
                                .await?;
                            return Ok(true);
                        }
                    };

                    let token_resp = serde_json::json!({
                        "access_token": token,
                        "id_token": token, // For OIDC compatibility
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "identity": {
                            "username": username,
                            "roles": roles
                        }
                    });

                    // Burn the code (One-time use)
                    let _ = self.client.delete(&code_path).await;

                    session
                        .respond_error_with_body(200, Bytes::from(token_resp.to_string()))
                        .await?;
                    return Ok(true);
                }
                _ => {
                    session
                        .respond_error_with_body(400, Bytes::from("Invalid Code"))
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Handle /auth/callback (OIDC Provider callback - Vault, Google, etc.)
        if path == "/auth/callback" && *method == http::Method::GET {
            let query = session.req_header().uri.query().unwrap_or("");
            let params: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();

            let code = params.get("code").map(|s| s.as_str()).unwrap_or("");
            let encoded_state = params.get("state").map(|s| s.as_str()).unwrap_or("");

            // Decode state to get original state and CLI redirect_uri
            let state_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                encoded_state,
            ).unwrap_or_default();
            let combined_state = String::from_utf8_lossy(&state_bytes);
            let parts: Vec<&str> = combined_state.splitn(2, '|').collect();
            let (original_state, cli_redirect_uri) = if parts.len() == 2 {
                (parts[0], parts[1])
            } else {
                ("", "/")
            };

            if code.is_empty() {
                // Handle error case
                let error = params.get("error").map(|s| s.as_str()).unwrap_or("unknown_error");
                let location = format!("{}?error={}&state={}", cli_redirect_uri, error, original_state);
                let mut resp_header =
                    Box::new(pingora_http::ResponseHeader::build(302, Some(1)).unwrap());
                resp_header.insert_header("Location", location).unwrap();
                session.write_response_header(resp_header, true).await?;
                return Ok(true);
            }

            // Exchange code for tokens with OIDC provider
            if let Some(ref oidc) = self.oidc_config {
                if let (Some(client_id), Some(client_secret), Some(redirect_uri)) =
                    (&oidc.client_id, &oidc.client_secret, &oidc.redirect_uri)
                {
                    // Use configurable token endpoint, default to Google
                    let default_token_endpoint = "https://oauth2.googleapis.com/token".to_string();
                    let token_url = oidc.token_endpoint.as_ref().unwrap_or(&default_token_endpoint);
                    
                    let client = reqwest::Client::new();
                    
                    let token_response = client
                        .post(token_url)
                        .form(&[
                            ("code", code),
                            ("client_id", client_id.as_str()),
                            ("client_secret", client_secret.as_str()),
                            ("redirect_uri", redirect_uri.as_str()),
                            ("grant_type", "authorization_code"),
                        ])
                        .send()
                        .await;

                    match token_response {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                let body = resp.text().await.unwrap_or_default();
                                let token_data: serde_json::Value =
                                    serde_json::from_str(&body).unwrap_or_default();

                                // Extract id_token (contains user info)
                                let id_token = token_data
                                    .get("id_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                // Generate a code for the CLI to exchange
                                let auth_code: String = rand::thread_rng()
                                    .sample_iter(&Alphanumeric)
                                    .take(32)
                                    .map(char::from)
                                    .collect();

                                // Determine the source based on configuration
                                let source = if oidc.authorization_endpoint.is_some() { "oidc_provider" } else { "google_oauth" };

                                // Store the OIDC tokens temporarily
                                let code_path = format!("secret/silo/codes/{}", auth_code);
                                let code_data = serde_json::json!({
                                    "id_token": id_token,
                                    "access_token": token_data.get("access_token").and_then(|v| v.as_str()).unwrap_or(""),
                                    "source": source,
                                    "ttl": chrono::Utc::now().to_rfc3339()
                                });
                                
                                if let Err(e) = self.client.put(&code_path, code_data.to_string().as_bytes(), 0).await {
                                    error!("Failed to store OAuth code: {}", e);
                                }

                                // Redirect to CLI with the code
                                let location = format!("{}?code={}&state={}", cli_redirect_uri, auth_code, original_state);
                                info!("OAuth callback successful, redirecting to CLI: {}", location);
                                
                                let mut resp_header =
                                    Box::new(pingora_http::ResponseHeader::build(302, Some(1)).unwrap());
                                resp_header.insert_header("Location", location).unwrap();
                                session.write_response_header(resp_header, true).await?;
                                return Ok(true);
                            } else {
                                error!("Google token exchange failed: {}", resp.status());
                            }
                        }
                        Err(e) => {
                            error!("Failed to exchange code with Google: {}", e);
                        }
                    }
                }
            }

            // Fallback: error
            session
                .respond_error_with_body(500, Bytes::from("OAuth callback failed"))
                .await?;
            return Ok(true);
        }

        // Handle /auth/exchange (Exchange JWT for mTLS Certs)
        if path == "/auth/exchange" && *method == http::Method::POST {
            let auth_header = session
                .req_header()
                .headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !auth_header.starts_with("Bearer ") {
                session
                    .respond_error_with_body(401, Bytes::from("Missing Bearer Token"))
                    .await?;
                return Ok(true);
            }

            let jwt = &auth_header[7..];
            let token_data = match decode::<Claims>(
                jwt,
                &DecodingKey::from_secret(self.native_auth.config.jwt_secret.as_bytes()),
                &Validation::default(),
            ) {
                Ok(data) => data,
                Err(e) => {
                    info!("JWT Validation Failed: {}", e);
                    session
                        .respond_error_with_body(401, Bytes::from(format!("Invalid Token: {}", e)))
                        .await?;
                    return Ok(true);
                }
            };

            let username = token_data.claims.sub;
            info!("Generating mTLS certificate for user: {}", username);

            match crate::certs::generate_dynamic_user_cert(&self.certs_dir, &username) {
                Ok((crt, key)) => {
                    let ca_pem = std::fs::read_to_string(self.certs_dir.join("internal/ca.crt"))
                        .unwrap_or_default();
                    let resp = serde_json::json!({
                        "certificate": crt,
                        "private_key": key,
                        "ca": ca_pem,
                        "identity": username
                    });
                    session
                        .respond_error_with_body(200, Bytes::from(resp.to_string()))
                        .await?;
                }
                Err(e) => {
                    error!("Cert Generation failed: {}", e);
                    session
                        .respond_error_with_body(500, Bytes::from("Certificate generation failure"))
                        .await?;
                }
            }
            return Ok(true);
        }

        Ok(false)
    }
}
