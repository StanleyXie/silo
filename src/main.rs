use async_trait::async_trait;
use log::{error, info};
use std::env;
use std::sync::Arc;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};

mod api;
mod auth;
mod backend;
mod certs;
mod config;
mod proto;

// Identity-Based Authorization Imports
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
#[cfg(feature = "openssl")]
use pingora_openssl::{nid::Nid, ssl::SslVerifyMode};

use proto::v1::control_service_client::ControlServiceClient;
use proto::v1::control_service_server::{ControlService, ControlServiceServer};
use proto::v1::storage_service_server::{StorageService, StorageServiceServer};
use proto::v1::{AuthorizeRequest, AuthorizeResponse, HeartbeatRequest, HeartbeatResponse};
use proto::v1::{DeleteRequest, DeleteResponse, GetRequest, GetResponse, PutRequest, PutResponse};
use tonic::transport::{
    Certificate, ClientTlsConfig, Identity, Server as TonicServer, ServerTlsConfig,
};
use tonic::{Request, Response, Status};

use api::ApiHandler;
#[cfg(feature = "etcd")]
use backend::etcd::EtcdBackend;
use backend::{StorageBackend, VaultClient};

pub struct ControlPlane {
    storage: Arc<dyn StorageBackend>,
    allowed_identities: Vec<String>,
}

#[tonic::async_trait]
impl ControlService for ControlPlane {
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let req = request.into_inner();
        info!(
            "[gRPC] Authorize request: {} from {}",
            req.path, req.identity
        );

        let authorized = self.allowed_identities.contains(&req.identity);
        let reason = if authorized {
            "Allowed".to_string()
        } else {
            format!("Identity '{}' not authorized", req.identity)
        };

        if !authorized {
            error!("[gRPC] DENIED: {} for {}", req.identity, req.path);
        }

        Ok(Response::new(AuthorizeResponse {
            authorized,
            reason,
            metadata: std::collections::HashMap::new(),
        }))
    }

    async fn heartbeat(
        &self,
        _request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        Ok(Response::new(HeartbeatResponse {}))
    }
}

#[tonic::async_trait]
impl StorageService for ControlPlane {
    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let req = request.into_inner();
        match self.storage.get_versioned(&req.path, req.version).await {
            Ok(Some((data, version))) => Ok(Response::new(GetResponse {
                found: true,
                data,
                version,
            })),
            Ok(None) => Ok(Response::new(GetResponse {
                found: false,
                data: vec![],
                version: 0,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        let req = request.into_inner();
        match self
            .storage
            .put(&req.path, &req.data, req.base_version)
            .await
        {
            Ok(version) => Ok(Response::new(PutResponse {
                success: true,
                version,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let req = request.into_inner();
        match self.storage.delete(&req.path).await {
            Ok(_) => Ok(Response::new(DeleteResponse { success: true })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list(
        &self,
        request: Request<proto::v1::ListRequest>,
    ) -> Result<Response<proto::v1::ListResponse>, Status> {
        let req = request.into_inner();
        match self.storage.list(&req.path).await {
            Ok(keys) => Ok(Response::new(proto::v1::ListResponse { keys })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

pub struct RequestCtx {
    start_time: std::time::Instant,
    request_id: String,
}

pub struct Gateway {
    handler: ApiHandler,
    req_metric: prometheus::IntCounter,
    oidc_auth: Option<Arc<auth::OidcAuthenticator>>,
}

// Custom structure to hold extracted TLS information
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub common_name: Option<String>,
}

pub struct GatewayTlsCallbacks;

#[async_trait]
impl TlsAccept for GatewayTlsCallbacks {
    #[cfg(feature = "openssl")]
    async fn certificate_callback(&self, _ssl: &mut TlsRef) -> () {
        // certificate_callback is used for certificate selection/SNI
        // mTLS extraction is now done in request_filter
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestCtx;
    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            start_time: std::time::Instant::now(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        self.req_metric.inc();

        // Identity Extraction Priority:
        // 1. Bearer token (OIDC/JWT)
        // 2. mTLS client certificate
        // 3. X-Forwarded-User header
        // 4. Anonymous fallback

        // 1. Check for Bearer token
        let bearer_identity = if let Some(ref oidc) = self.oidc_auth {
            if let Some(auth_header) = session.get_header("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        match oidc.validate_token(token).await {
                            Ok(identity) => Some(identity),
                            Err(e) => {
                                error!("[{}] JWT validation failed: {}", ctx.request_id, e);
                                None
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // 2. mTLS identity
        let mtls_identity = session
            .stream()
            .and_then(|s| s.get_ssl())
            .and_then(|ssl| ssl.peer_certificate())
            .and_then(|cert| {
                let cn = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next()?;
                cn.data().as_utf8().ok().map(|s| s.to_string())
            });

        // 3. Header fallback
        let identity = bearer_identity
            .or(mtls_identity)
            .or_else(|| {
                session
                    .get_header("X-Forwarded-User")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "anonymous".to_string());

        let client_ip = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string());

        let ua = session
            .get_header("User-Agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());

        match self
            .handler
            .handle(session, &ctx.request_id, &identity, &client_ip)
            .await
        {
            Ok(handled) => {
                let latency = ctx.start_time.elapsed();
                let status = session
                    .response_written()
                    .map(|h| h.status.as_u16())
                    .unwrap_or(0);
                if handled {
                    info!(
                        "[{}] {} {} -> status:{} latency:{:?} identity:{} ua:\"{}\"",
                        ctx.request_id,
                        session.req_header().method,
                        session.req_header().uri.path(),
                        status,
                        latency,
                        identity,
                        ua
                    );
                }
                Ok(handled)
            }
            Err(e) => {
                let latency = ctx.start_time.elapsed();
                error!(
                    "[{}] Request Filter Error: {} (latency: {:?})",
                    ctx.request_id, e, latency
                );
                match session
                    .respond_error_with_body(
                        500,
                        bytes::Bytes::from(format!("Internal Error: {}", e)),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(send_err) => error!("Failed to send error response: {}", send_err),
                }
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        error!("Upstream peer requested for unhandled path");
        Ok(Box::new(HttpPeer::new(
            "127.0.0.1:1",
            false,
            "".to_string(),
        )))
    }
}

fn main() {
    env_logger::init();

    // 1. Parse args first
    // Handle --version manually because Pingora's Opt doesn't support it
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--version".to_string()) || args.contains(&"-v".to_string()) {
        println!("silo {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // This allows --help to work
    let opt = Opt::parse_args();

    // 2. Load Configuration
    // Search in priority:
    // 1. SILO_CONFIG env var
    // 2. Local directory
    // 3. /etc/silo/
    // 4. /usr/local/etc/silo/ (Intel Homebrew)
    // 5. /opt/homebrew/etc/silo/ (Apple Silicon Homebrew)
    let config_path = env::var("SILO_CONFIG").unwrap_or_else(|_| {
        let paths = vec![
            "silo.yaml",
            "/etc/silo/silo.yaml",
            "/usr/local/etc/silo/silo.yaml",
            "/opt/homebrew/etc/silo/silo.yaml",
        ];
        for path in paths {
            if std::path::Path::new(path).exists() {
                return path.to_string();
            }
        }
        "silo.yaml".to_string() // Fallback to for error message
    });

    let silo_cfg = config::Config::load(&config_path).unwrap_or_else(|e| {
        error!("Failed to load configuration from {}: {}", config_path, e);
        std::process::exit(1);
    });
    info!("Configuration loaded from {}", config_path);

    // 3. Ensure certificates exist, generate if missing
    let certs_dir = certs::resolve_cert_paths(silo_cfg.certs_dir.as_deref()).unwrap_or_else(|e| {
        error!("Failed to resolve/generate certificates: {}", e);
        std::process::exit(1);
    });
    info!("Using certificates from {:?}", certs_dir);

    // Update config paths to absolute paths if they are missing at current location
    let mut silo_cfg = silo_cfg;
    if !std::path::Path::new(&silo_cfg.gateway.tls.cert_path).exists() {
        silo_cfg.gateway.tls.cert_path = certs_dir.join("server.crt").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.gateway.tls.key_path).exists() {
        silo_cfg.gateway.tls.key_path = certs_dir.join("server.key").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.control_plane.tls.ca_cert).exists() {
        silo_cfg.control_plane.tls.ca_cert = certs_dir.join("internal/ca.crt").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.control_plane.tls.server_cert).exists() {
        silo_cfg.control_plane.tls.server_cert = certs_dir.join("internal/control.crt").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.control_plane.tls.server_key).exists() {
        silo_cfg.control_plane.tls.server_key = certs_dir.join("internal/control.key").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.control_plane.tls.client_cert).exists() {
        silo_cfg.control_plane.tls.client_cert = certs_dir.join("internal/gateway.crt").to_string_lossy().to_string();
    }
    if !std::path::Path::new(&silo_cfg.control_plane.tls.client_key).exists() {
        silo_cfg.control_plane.tls.client_key = certs_dir.join("internal/gateway.key").to_string_lossy().to_string();
    }

    let mut server = Server::new(Some(opt)).expect("Failed to initialize server");
    server.bootstrap();

    // We need a runtime for async backend connections
    let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

    // 2. Initialize Backend
    let storage: Arc<dyn StorageBackend> = match silo_cfg.storage.storage_type.as_str() {
        #[cfg(feature = "etcd")]
        "etcd" => {
            let etcd_cfg = silo_cfg.storage.etcd.expect("etcd configuration missing");
            info!("Initializing Etcd backend at {:?}", etcd_cfg.endpoints);

            let endpoints: Vec<&str> = etcd_cfg.endpoints.iter().map(|s| s.as_str()).collect();
            let backend = rt
                .block_on(async { EtcdBackend::new(&endpoints).await })
                .expect("Failed to connect to Etcd");
            Arc::new(backend)
        }
        #[cfg(not(feature = "etcd"))]
        "etcd" => {
            error!("Etcd disabled. Compile with --features etcd");
            std::process::exit(1);
        }
        _ => {
            let vault_cfg = silo_cfg.storage.vault.expect("vault configuration missing");
            info!("Initializing Vault backend at {}", vault_cfg.address);
            Arc::new(VaultClient::new(vault_cfg.address, vault_cfg.token))
        }
    };

    // 3. Start gRPC Controller Service (mTLS)
    let cp_storage = storage.clone();
    let cp_addr: std::net::SocketAddr = silo_cfg
        .control_plane
        .address
        .parse()
        .expect("Invalid control plane address");
    let cp_tls_cfg = silo_cfg.control_plane.tls.clone();

    // Synchronize policies to KV for Autonomous Data Plane
    let cp_allowed_sync = silo_cfg.control_plane.allowed_identities.clone();
    let sync_storage = storage.clone();
    rt.spawn(async move {
        for identity in cp_allowed_sync {
            let path = format!("secret/silo/policies/allowed_identities/{}", identity);
            let _ = sync_storage.put(&path, b"allowed", 0).await;
        }
        info!("Synchronized policies to Shared-State (KV)");
    });

    // 2b. Start Background Lock Reaper (Reclaim orphan locks)
    let reaper_storage = storage.clone();
    rt.spawn(async move {
        info!("Background Lock Reaper started (Interval: 30s)");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

            match reaper_storage.list("secret/silo/sessions/").await {
                Ok(keys) => {
                    for key in keys {
                        let path = format!("secret/silo/sessions/{}", key);
                        if let Ok(Some(data)) = reaper_storage.get(&path).await {
                             if let Ok(meta) = serde_json::from_slice::<api::SessionMetadata>(&data) {
                                 if let Ok(last_heartbeat) = chrono::DateTime::parse_from_rfc3339(&meta.last_heartbeat) {
                                     let now = chrono::Utc::now();
                                     let diff = now.signed_duration_since(last_heartbeat.with_timezone(&chrono::Utc));

                                     if diff.num_minutes() > 2 { // Shorter for demo/testing
                                         info!("[Reaper] Session {} is stale (last heartbeat: {} min ago)", meta.session_id, diff.num_minutes());

                                         // Cleanup lock
                                         if let Some(lock_path) = meta.lock_path {
                                             let _ = reaper_storage.delete(&lock_path).await;
                                             let session_mapping_path = format!("{}/session", lock_path);
                                             let _ = reaper_storage.delete(&session_mapping_path).await;
                                             info!("[Reaper] Cleaned up lock: {}", lock_path);
                                         }

                                         // Delete session
                                         let _ = reaper_storage.delete(&path).await;
                                     }
                                 }
                             }
                        }
                    }
                },
                Err(e) => error!("[Reaper] Failed to list sessions: {}", e),
            }
        }
    });

    rt.spawn(async move {
        let cert = tokio::fs::read(&cp_tls_cfg.server_cert)
            .await
            .expect("server cert missing");
        let key = tokio::fs::read(&cp_tls_cfg.server_key)
            .await
            .expect("server key missing");
        let ca_cert = tokio::fs::read(&cp_tls_cfg.ca_cert)
            .await
            .expect("ca cert missing");

        let identity = Identity::from_pem(cert, key);
        let ca = Certificate::from_pem(ca_cert);

        let tls = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

        let cp_allowed = silo_cfg.control_plane.allowed_identities.clone();
        let cp_c = ControlPlane {
            storage: cp_storage.clone(),
            allowed_identities: cp_allowed.clone(),
        };
        let cp_s = ControlPlane {
            storage: cp_storage,
            allowed_identities: cp_allowed,
        };

        info!(
            "Internal gRPC Control Plane starting on {} (mTLS ENFORCED)",
            cp_addr
        );

        TonicServer::builder()
            .tls_config(tls)
            .expect("failed to config gRPC TLS")
            .add_service(ControlServiceServer::new(cp_s))
            .add_service(StorageServiceServer::new(cp_c))
            .serve(cp_addr)
            .await
            .expect("gRPC server failed");
    });

    // Wait for internal gRPC and connect clients
    std::thread::sleep(std::time::Duration::from_secs(1));

    let cp_tls_cfg = silo_cfg.control_plane.tls.clone();
    let control_client = rt.block_on(async {
        let cert = tokio::fs::read(&cp_tls_cfg.client_cert)
            .await
            .expect("client cert missing");
        let key = tokio::fs::read(&cp_tls_cfg.client_key)
            .await
            .expect("client key missing");
        let ca_cert = tokio::fs::read(&cp_tls_cfg.ca_cert)
            .await
            .expect("ca cert missing");

        let identity = Identity::from_pem(cert, key);
        let ca = Certificate::from_pem(ca_cert);

        let tls = ClientTlsConfig::new()
            .domain_name("control-plane.silo.internal")
            .identity(identity)
            .ca_certificate(ca);

        let channel = tonic::transport::Endpoint::from_shared(format!(
            "https://{}",
            silo_cfg.control_plane.address
        ))
        .expect("Invalid channel URL")
        .tls_config(tls)
        .expect("failed to config client TLS")
        .connect()
        .await
        .expect("failed to connect to gRPC Control Plane");

        ControlServiceClient::new(channel)
    });

    let grpc_storage = rt
        .block_on(async {
            backend::grpc::GrpcStorageClient::new_mtls(&format!(
                "https://{}",
                silo_cfg.control_plane.address
            ))
            .await
        })
        .expect("Failed to connect to internal gRPC Storage");

    let handler = ApiHandler::new(Arc::new(grpc_storage), control_client);
    let req_metric = prometheus::register_int_counter!("req_counter", "Number of requests")
        .expect("Failed to register metric");

    // Initialize OIDC authenticator if enabled
    let oidc_auth = if silo_cfg.auth.oidc.enabled {
        info!(
            "OIDC authentication enabled (issuer: {})",
            silo_cfg.auth.oidc.issuer
        );
        Some(Arc::new(auth::OidcAuthenticator::new(
            silo_cfg.auth.oidc.issuer.clone(),
            silo_cfg.auth.oidc.jwks_uri.clone(),
            silo_cfg.auth.oidc.audience.clone(),
        )))
    } else {
        None
    };

    // 4. Create Proxy Service
    let mut lb = pingora_proxy::http_proxy_service(
        &server.configuration,
        Gateway {
            handler,
            req_metric,
            oidc_auth,
        },
    );

    // Configure TLS Listener
    if silo_cfg.gateway.tls.enabled {
        let cert_path = &silo_cfg.gateway.tls.cert_path;
        let key_path = &silo_cfg.gateway.tls.key_path;

        if std::path::Path::new(cert_path).exists() {
            // Use callbacks for identity extraction
            let callbacks = Box::new(GatewayTlsCallbacks);
            let mut tls_settings =
                pingora_core::listeners::tls::TlsSettings::with_callbacks(callbacks)
                    .expect("Failed to load TLS settings");

            tls_settings
                .set_certificate_chain_file(cert_path)
                .expect("Failed to load cert chain");
            tls_settings
                .set_private_key_file(key_path, pingora_openssl::ssl::SslFiletype::PEM)
                .expect("Failed to load private key");

            // Enable Client Certificate Verification if CA is provided
            if let Some(ca_path) = &silo_cfg.control_plane.tls.ca_cert.clone().into() {
                let ca_path: &String = ca_path; // type hint
                if std::path::Path::new(ca_path).exists() {
                    info!(
                        "mTLS enabled: Verifying client certificates against {}",
                        ca_path
                    );
                    // We use the same internal CA for simplicity in this demo,
                    // but in prod this might be a dedicated client CA.
                    tls_settings.set_verify(SslVerifyMode::PEER);
                    tls_settings
                        .set_ca_file(ca_path)
                        .expect("Failed to load client CA");
                }
            }

            tls_settings.enable_h2();
            lb.add_tls_with_settings(&silo_cfg.gateway.address, None, tls_settings);
            info!(
                "Gateway starting: HTTPS {} (Backend: {})",
                silo_cfg.gateway.address, silo_cfg.storage.storage_type
            );
        } else {
            error!(
                "TLS certificates not found at {}, starting without TLS",
                cert_path
            );
            lb.add_tcp(&silo_cfg.gateway.address);
        }
    } else {
        info!(
            "Gateway starting: HTTP {} (Backend: {})",
            silo_cfg.gateway.address, silo_cfg.storage.storage_type
        );
        lb.add_tcp(&silo_cfg.gateway.address);
    }

    server.add_service(lb);

    // 5. Prometheus Metrics Service
    let mut prometheus_service_http =
        pingora_core::services::listening::Service::prometheus_http_service();
    prometheus_service_http.add_tcp(&silo_cfg.gateway.metrics_address);
    info!(
        "Metrics endpoint starting: {}",
        silo_cfg.gateway.metrics_address
    );
    server.add_service(prometheus_service_http);

    server.run_forever();
}
