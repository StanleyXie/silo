use super::StorageBackend;
use crate::proto::v1::control_service_client::ControlServiceClient;
use crate::proto::v1::storage_service_client::StorageServiceClient;
use crate::proto::v1::{DeleteRequest, GetRequest, ListRequest, PutRequest};
use async_trait::async_trait;
use std::error::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

pub struct GrpcStorageClient {
    client: StorageServiceClient<Channel>,
}

impl GrpcStorageClient {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = StorageServiceClient::connect(addr.to_string()).await?;
        Ok(GrpcStorageClient { client })
    }

    pub async fn new_mtls(addr: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let cert = tokio::fs::read("certs/internal/gateway.crt").await?;
        let key = tokio::fs::read("certs/internal/gateway.key").await?;
        let ca_cert = tokio::fs::read("certs/internal/ca.crt").await?;

        let identity = Identity::from_pem(cert, key);
        let ca = Certificate::from_pem(ca_cert);

        let tls = ClientTlsConfig::new()
            .domain_name("control-plane.silo.internal")
            .identity(identity)
            .ca_certificate(ca);

        let channel = tonic::transport::Endpoint::from_shared(addr.to_string())?
            .tls_config(tls)?
            .connect()
            .await?;

        let client = StorageServiceClient::new(channel);
        Ok(GrpcStorageClient { client })
    }
}

#[async_trait]
impl StorageBackend for GrpcStorageClient {
    async fn get_versioned(
        &self,
        path: &str,
        version: u32,
    ) -> Result<Option<(Vec<u8>, u32)>, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        let request = GetRequest {
            path: path.to_string(),
            session_token: "".to_string(),
            version,
        };
        let response = client.get(request).await?;
        let inner = response.into_inner();
        if inner.found {
            Ok(Some((inner.data.to_vec(), inner.version)))
        } else {
            Ok(None)
        }
    }

    async fn put(
        &self,
        path: &str,
        data: &[u8],
        base_version: u32,
    ) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        let request = PutRequest {
            path: path.to_string(),
            data: data.to_vec(),
            session_token: "".to_string(),
            base_version,
        };
        let response = client.put(request).await?;
        Ok(response.into_inner().version)
    }

    async fn delete(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        let request = DeleteRequest {
            path: path.to_string(),
            session_token: "".to_string(),
        };
        client.delete(request).await?;
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        let request = ListRequest {
            path: path.to_string(),
        };
        let response = client.list(request).await?;
        Ok(response.into_inner().keys)
    }
}

pub struct GrpcControlClient {
    client: ControlServiceClient<Channel>,
}

impl GrpcControlClient {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = ControlServiceClient::connect(addr.to_string()).await?;
        Ok(GrpcControlClient { client })
    }

    pub fn inner(&self) -> ControlServiceClient<Channel> {
        self.client.clone()
    }
}
