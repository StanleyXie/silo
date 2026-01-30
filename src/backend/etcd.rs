use crate::backend::StorageBackend;
use async_trait::async_trait;
use etcd_client::{Client, Error as EtcdError};
use std::error::Error;

pub struct EtcdBackend {
    client: Client,
}

impl EtcdBackend {
    pub async fn new(endpoints: &[&str]) -> Result<Self, EtcdError> {
        let client = Client::connect(endpoints, None).await?;
        Ok(EtcdBackend { client })
    }
}

#[async_trait]
impl StorageBackend for EtcdBackend {
    async fn get_versioned(
        &self,
        path: &str,
        _version: u32,
    ) -> Result<Option<(Vec<u8>, u32)>, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        let resp = client.get(path, None).await?;

        if let Some(kv) = resp.kvs().first() {
            return Ok(Some((kv.value().to_vec(), kv.mod_revision() as u32)));
        }

        Ok(None)
    }

    async fn put(
        &self,
        path: &str,
        data: &[u8],
        base_version: u32,
    ) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();

        if base_version > 0 {
            // Etcd CAS using transaction: check if mod_revision equals base_version
            use etcd_client::{Compare, CompareOp, Txn, TxnOp};
            let txn = Txn::new()
                .when(vec![Compare::mod_revision(
                    path,
                    CompareOp::Equal,
                    base_version as i64,
                )])
                .and_then(vec![TxnOp::put(path, data, None)]);

            let resp = client.txn(txn).await?;
            if !resp.succeeded() {
                return Err(
                    format!("Etcd CAS Failure: version {} has changed", base_version).into(),
                );
            }
            Ok(resp.header().map(|h| h.revision() as u32).unwrap_or(0))
        } else {
            let resp = client.put(path, data, None).await?;
            Ok(resp.header().map(|h| h.revision() as u32).unwrap_or(0))
        }
    }

    async fn delete(&self, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        client.delete(path, None).await?;
        Ok(())
    }

    async fn list(&self, path: &str) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        // Etcd list using prefix search
        let options = etcd_client::GetOptions::new().with_prefix();
        let resp = client.get(path, Some(options)).await?;

        let keys = resp
            .kvs()
            .iter()
            .map(|kv| kv.key_str().unwrap_or("").to_string())
            .filter(|k| !k.is_empty())
            .collect();
        Ok(keys)
    }

    async fn health(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut client = self.client.clone();
        client.status().await?;
        Ok(())
    }
}
