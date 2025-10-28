//! Types for integrating with a Key Management Server to use with Parquet Modular Encryption
//! in an asynchronous context.

use crate::kms::KmsConnectionConfig;
use futures::future::BoxFuture;
use parquet::errors::Result;
use std::ops::Deref;
use std::sync::Arc;

/// API for interacting with a KMS.
/// This should be implemented by user code for integration with your KMS.
#[async_trait::async_trait]
pub trait KmsClient: Send + Sync {
    /// Wrap encryption key bytes using the KMS with the specified master key
    async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String>;

    /// Unwrap a wrapped encryption key using the KMS with the specified master key
    async fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>>;
}

/// A reference-counted reference to a generic [`KmsClient`]
pub type KmsClientRef = Arc<dyn KmsClient>;

/// Trait for factories that create KMS clients
#[async_trait::async_trait]
pub trait KmsClientFactory: Send + Sync {
    /// Create a new [`KmsClient`] instance using the provided configuration
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<KmsClientRef>;
}

#[async_trait::async_trait]
impl<T> KmsClientFactory for Arc<T>
where
    T: KmsClientFactory,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<KmsClientRef> {
        self.deref().create_client(kms_connection_config).await
    }
}

#[async_trait::async_trait]
impl<T> KmsClientFactory for T
where
    T: Fn(&KmsConnectionConfig) -> BoxFuture<Result<KmsClientRef>> + Send + Sync + 'static,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<KmsClientRef> {
        self(kms_connection_config).await
    }
}
