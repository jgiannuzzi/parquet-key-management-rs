//! The key-management tools API for building file encryption and decryption properties
//! that work with a Key Management Server.

use crate::async_kms::key_unwrapper::KeyUnwrapper;
use crate::async_kms::key_wrapper::KeyWrapper;
use crate::async_kms::kms_manager::KmsManager;
use crate::async_kms::{KmsClientFactory, KmsConnectionConfig};
use crate::config::{DecryptionConfiguration, EncryptionConfiguration};
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::{ParquetError, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;

/// A factory that produces file decryption and encryption properties using
/// configuration options and a KMS client
///
/// Creating a `CryptoFactory` requires providing a [`KmsClientFactory`]
/// to create clients for your Key Management Server:
/// ```no_run
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::KmsConnectionConfig;
/// # let kms_client_factory = |config: &KmsConnectionConfig| todo!();
/// let crypto_factory = CryptoFactory::new(kms_client_factory);
/// ```
///
/// The `CryptoFactory` can then be used to generate file encryption properties
/// when writing an encrypted Parquet file:
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::config::EncryptionConfiguration;
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::KmsConnectionConfig;
/// # futures::executor::block_on(async {
/// # let crypto_factory: CryptoFactory = todo!();
/// let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let encryption_config = EncryptionConfiguration::builder("master_key_id".into()).build()?;
/// let encryption_properties = crypto_factory.file_encryption_properties(
///     kms_connection_config, &encryption_config).await?;
/// # Ok::<(), parquet::errors::ParquetError>(())
/// # });
/// ```
///
/// And file decryption properties can be constructed for reading an encrypted file:
/// ```no_run
/// # use std::sync::Arc;
/// # use parquet_key_management::config::DecryptionConfiguration;
/// # use parquet_key_management::async_crypto_factory::CryptoFactory;
/// # use parquet_key_management::async_kms::KmsConnectionConfig;
/// # futures::executor::block_on(async {
/// # let crypto_factory: CryptoFactory = todo!();
/// # let kms_connection_config = Arc::new(KmsConnectionConfig::default());
/// let decryption_config = DecryptionConfiguration::default();
/// let decryption_properties = crypto_factory.file_decryption_properties(
///     kms_connection_config, decryption_config).await?;
/// # Ok::<(), parquet::errors::ParquetError>(())
/// # });
/// ```
///
/// A `CryptoFactory` can be reused multiple times to encrypt or decrypt many files,
/// but the same encryption properties should not be reused between different files.
///
/// The `KmsClientFactory` will be used to create KMS clients as required,
/// and these will be internally cached based on the KMS instance ID and the key access token.
/// This means that if the key access token is changed using
/// [`KmsConnectionConfig::refresh_key_access_token`],
/// new `KmsClient` instances will be created using the new token rather than reusing
/// a cached client.
pub struct CryptoFactory {
    kms_manager: Arc<KmsManager>,
}

impl CryptoFactory {
    /// Create a new [`CryptoFactory`], providing a factory function for creating KMS clients
    pub fn new<T>(kms_client_factory: T) -> Self
    where
        T: KmsClientFactory + 'static,
    {
        CryptoFactory {
            kms_manager: Arc::new(KmsManager::new(kms_client_factory)),
        }
    }

    /// Create file decryption properties for a Parquet file
    pub async fn file_decryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        decryption_configuration: DecryptionConfiguration,
    ) -> Result<FileDecryptionProperties> {
        let key_retriever = Arc::new(
            KeyUnwrapper::new(
                self.kms_manager.clone(),
                kms_connection_config,
                decryption_configuration,
            )
            .await,
        );
        FileDecryptionProperties::with_async_key_retriever(key_retriever).build()
    }

    /// Create file encryption properties for a Parquet file
    pub async fn file_encryption_properties(
        &self,
        kms_connection_config: Arc<KmsConnectionConfig>,
        encryption_configuration: &EncryptionConfiguration,
    ) -> Result<FileEncryptionProperties> {
        if !encryption_configuration.internal_key_material() {
            return Err(ParquetError::NYI(
                "External key material is not yet implemented".to_owned(),
            ));
        }
        if encryption_configuration.data_key_length_bits() != 128 {
            return Err(ParquetError::NYI(
                "Only 128 bit data keys are currently implemented".to_owned(),
            ));
        }

        let mut key_wrapper = KeyWrapper::new(
            &self.kms_manager,
            kms_connection_config,
            encryption_configuration,
        )
        .await;

        let footer_key = self
            .generate_key(
                encryption_configuration.footer_key_id(),
                true,
                &mut key_wrapper,
            )
            .await?;

        let mut builder = FileEncryptionProperties::builder(footer_key.key)
            .with_footer_key_metadata(footer_key.metadata)
            .with_plaintext_footer(encryption_configuration.plaintext_footer());

        for (master_key_id, column_paths) in encryption_configuration.column_key_ids() {
            for column_path in column_paths {
                let column_key = self
                    .generate_key(master_key_id, false, &mut key_wrapper)
                    .await?;
                builder = builder.with_column_key_and_metadata(
                    column_path,
                    column_key.key,
                    column_key.metadata,
                );
            }
        }

        builder.build()
    }

    async fn generate_key(
        &self,
        master_key_identifier: &str,
        is_footer_key: bool,
        key_wrapper: &mut KeyWrapper<'_>,
    ) -> Result<EncryptionKey> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 16];
        rng.fill(&mut key)?;

        let key_metadata = key_wrapper
            .get_key_metadata(&key, master_key_identifier, is_footer_key)
            .await?;

        Ok(EncryptionKey::new(key, key_metadata))
    }

    #[cfg(test)]
    pub(crate) async fn cache_stats(&self) -> crate::async_kms::kms_manager::CacheStats {
        self.kms_manager.cache_stats().await
    }
}

struct EncryptionKey {
    key: Vec<u8>,
    metadata: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(key: Vec<u8>, metadata: Vec<u8>) -> Self {
        Self { key, metadata }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_kms::test::{KmsConnectionConfigDetails, TestKmsClientFactory};
    use crate::config::EncryptionConfigurationBuilder;
    use crate::key_material::KeyMaterialBuilder;
    use parquet::data_type::AsBytes;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn test_file_decryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = Default::default();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config, config)
            .await
            .unwrap();

        let expected_dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&expected_dek, "kc1").await.unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        let dek = decryption_props
            .footer_key_async(Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();

        assert_eq!(dek, expected_dek);
    }

    #[tokio::test]
    async fn test_kms_client_caching_with_lifetime() {
        test_kms_client_caching(Some(Duration::from_secs(6000))).await;
    }

    #[tokio::test]
    async fn test_kms_client_caching_no_lifetime() {
        test_kms_client_caching(None).await;
    }

    async fn test_kms_client_caching(cache_lifetime: Option<Duration>) {
        let _time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(cache_lifetime)
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
            .await
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").await.unwrap();

        let footer_key_material =
            KeyMaterialBuilder::for_footer_key("123".to_owned(), "https://example.com".to_owned())
                .with_single_wrapped_key("kc1".to_owned(), wrapped_key.clone())
                .build()
                .unwrap();
        let serialized_footer_key_material = footer_key_material.serialize().unwrap();

        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        // Default config with ID and URL set from the footer key material
        let default_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "https://example.com".to_string(),
            key_access_token: "DEFAULT".to_string(),
            custom_kms_conf: Default::default(),
        };

        // Expected config after the access token refresh
        let refreshed_config = KmsConnectionConfigDetails {
            kms_instance_id: "123".to_string(),
            kms_instance_url: "https://example.com".to_string(),
            key_access_token: "super_secret".to_string(),
            custom_kms_conf: Default::default(),
        };

        assert_eq!(0, kms_factory.invocations().await.len());

        decryption_props
            .footer_key_async(Some(serialized_footer_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            vec![default_config.clone()],
            kms_factory.invocations().await
        );

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        // Same client should have been reused
        assert_eq!(
            vec![default_config.clone()],
            kms_factory.invocations().await
        );

        kms_config
            .refresh_key_access_token("super_secret".to_owned())
            .await;

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        // New key access token should have been used
        assert_eq!(
            vec![default_config.clone(), refreshed_config.clone()],
            kms_factory.invocations().await
        );

        decryption_props
            .column_key_async("x", Some(serialized_key_material.as_bytes()))
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            vec![default_config, refreshed_config],
            kms_factory.invocations().await
        );
    }

    #[tokio::test]
    async fn test_kms_client_expiration() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let config = DecryptionConfiguration::builder()
            .set_cache_lifetime(Some(Duration::from_secs(600)))
            .build();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());
        let decryption_props = crypto_factory
            .file_decryption_properties(kms_config.clone(), config)
            .await
            .unwrap();

        let dek = "1234567890123450".as_bytes().to_vec();
        let kms = TestKmsClientFactory::with_default_keys()
            .create_client(&Default::default())
            .await
            .unwrap();

        let wrapped_key = kms.wrap_key(&dek, "kc1").await.unwrap();
        let key_material = KeyMaterialBuilder::for_column_key()
            .with_single_wrapped_key("kc1".to_owned(), wrapped_key)
            .build()
            .unwrap();
        let serialized_key_material = key_material.serialize().unwrap();

        assert_eq!(0, kms_factory.invocations().await.len());

        let do_key_retrieval = async || {
            decryption_props
                .footer_key_async(Some(serialized_key_material.as_bytes()))
                .await
                .unwrap()
                .into_owned();
        };

        do_key_retrieval().await;
        assert_eq!(1, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval().await;
        assert_eq!(1, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval().await;
        assert_eq!(2, kms_factory.invocations().await.len());
        // The old KMS client is expired so has been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(599));

        do_key_retrieval().await;
        assert_eq!(2, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);

        time_controller.advance(Duration::from_secs(1));

        do_key_retrieval().await;
        assert_eq!(3, kms_factory.invocations().await.len());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kms_clients);
    }

    #[tokio::test]
    async fn test_uniform_encryption_properties() {
        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let crypto_factory = CryptoFactory::new(TestKmsClientFactory::with_default_keys());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let (column_names, column_keys, _) = file_encryption_properties.column_keys();
        assert!(column_names.is_empty());
        assert!(column_keys.is_empty());
    }

    #[tokio::test]
    async fn test_round_trip_double_wrapping_properties() {
        round_trip_encryption_properties(true).await;
    }

    #[tokio::test]
    async fn test_round_trip_single_wrapping_properties() {
        round_trip_encryption_properties(false).await;
    }

    async fn round_trip_encryption_properties(double_wrapping: bool) {
        let _time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(
            KmsConnectionConfig::builder()
                .set_kms_instance_id("DEFAULT".to_owned())
                .build(),
        );
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(double_wrapping)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let decryption_properties = crypto_factory
            .file_decryption_properties(kms_config.clone(), Default::default())
            .await
            .unwrap();

        assert!(file_encryption_properties.encrypt_footer());
        assert!(file_encryption_properties.aad_prefix().is_none());
        assert_eq!(16, file_encryption_properties.footer_key().len());

        let retrieved_footer_key = decryption_properties
            .footer_key_async(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
            .await
            .unwrap();
        assert_eq!(
            file_encryption_properties.footer_key(),
            retrieved_footer_key.as_slice()
        );

        let (column_names, column_keys, key_metadata) = file_encryption_properties.column_keys();
        let mut all_columns: Vec<String> = column_names.clone();
        all_columns.sort();
        assert_eq!(vec!["x0", "x1", "x2", "x3"], all_columns);
        for col_idx in 0..column_keys.len() {
            let column_name = &column_names[col_idx];
            let column_key = &column_keys[col_idx];
            let key_metadata = &key_metadata[col_idx];

            assert_eq!(16, column_key.len());
            let retrieved_key = decryption_properties
                .column_key_async(column_name, Some(key_metadata))
                .await
                .unwrap();
            assert_eq!(column_key, retrieved_key.as_slice());
        }

        assert_eq!(1, kms_factory.invocations().await.len());
        if double_wrapping {
            // With double wrapping, only need to wrap one KEK per master key id used
            assert_eq!(3, kms_factory.keys_wrapped());
            assert_eq!(3, kms_factory.keys_unwrapped());
        } else {
            // With single wrapping, need to wrap the footer key and a DEK per column
            assert_eq!(5, kms_factory.keys_wrapped());
            assert_eq!(5, kms_factory.keys_unwrapped());
        }
    }

    /// Test caching of key encryption keys when decrypting files
    #[tokio::test]
    async fn test_decryption_key_encryption_key_caching() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let file_encryption_properties = crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .await
            .unwrap();

        let footer_key_metadata = file_encryption_properties.footer_key_metadata().cloned();

        // Key-encryption keys are cached for the lifetime of file decryption properties,
        // and when creating new file decryption properties, a previous key-encryption key cache
        // may be reused if the cache lifetime hasn't expired and the KMS access token is the same.

        let get_new_decryption_properties = async || {
            let decryption_config = DecryptionConfiguration::builder()
                .set_cache_lifetime(Some(Duration::from_secs(600)))
                .build();
            crypto_factory
                .file_decryption_properties(kms_config.clone(), decryption_config)
                .await
                .unwrap()
        };

        let retrieve_key = async |props: &FileDecryptionProperties| {
            props
                .footer_key_async(footer_key_metadata.as_deref())
                .await
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_unwrapped());

        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            time_controller.advance(Duration::from_secs(599));
            retrieve_key(&props).await;
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            assert_eq!(1, kms_factory.keys_unwrapped());
            time_controller.advance(Duration::from_secs(1));
            retrieve_key(&props).await;
            // Cache lifetime has expired but the key unwrapper still holds the
            // key encryption key cache.
            assert_eq!(1, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            let props = get_new_decryption_properties().await;
            retrieve_key(&props).await;
            // Newly created decryption properties use a new key encryption key cache
            assert_eq!(2, kms_factory.keys_unwrapped());
            // Old KEKs have been removed from the cache
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);
        }
        {
            time_controller.advance(Duration::from_secs(599));
            // Creating new decryption properties should re-use the more recent cache
            let props1 = get_new_decryption_properties().await;
            retrieve_key(&props1).await;
            assert_eq!(2, kms_factory.keys_unwrapped());
            assert_eq!(1, crypto_factory.cache_stats().await.num_kek_read_caches);

            kms_config
                .refresh_key_access_token("new_secret".to_owned())
                .await;
            // Creating decryption properties with a different access key should require
            // creating a new key encryption key cache.
            let props2 = get_new_decryption_properties().await;
            retrieve_key(&props2).await;
            assert_eq!(3, kms_factory.keys_unwrapped());
            // KEKs for old access token are still cached as they haven't expired
            assert_eq!(2, crypto_factory.cache_stats().await.num_kek_read_caches);

            // But the cache used by older file encryption properties is still usable.
            retrieve_key(&props1).await;
            assert_eq!(3, kms_factory.keys_unwrapped());
        }
    }

    /// Test caching of key encryption keys when encrypting files
    #[tokio::test]
    async fn test_encryption_key_encryption_key_caching() {
        let time_controller = crate::async_kms::kms_manager::mock_time::time_controller();

        let kms_config = Arc::new(KmsConnectionConfig::default());
        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .add_column_key("kc1".to_owned(), vec!["x0".to_owned(), "x1".to_owned()])
            .add_column_key("kc2".to_owned(), vec!["x2".to_owned(), "x3".to_owned()])
            .set_cache_lifetime(Some(Duration::from_secs(600)))
            .build()
            .unwrap();

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let generate_encryption_props = async || {
            let _ = crypto_factory
                .file_encryption_properties(kms_config.clone(), &encryption_config)
                .await
                .unwrap();
        };

        assert_eq!(0, kms_factory.keys_wrapped());

        generate_encryption_props().await;
        // We generate 1 KEK for each master key used and wrap it with the KMS
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props().await;
        // KEK cache hasn't yet expired, we reused it to generate new props
        assert_eq!(3, kms_factory.keys_wrapped());
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(1));
        generate_encryption_props().await;
        // The KEK cache has now expired, so we generated 3 new KEKs and wrapped them with the KMS
        assert_eq!(6, kms_factory.keys_wrapped());
        // Old KEKs have been removed from the cache
        assert_eq!(1, crypto_factory.cache_stats().await.num_kek_write_caches);

        // Refreshing the access token should invalidate the KEK write cache,
        // requiring us to again generate new KEKs and wrap them with the KMS
        kms_config
            .refresh_key_access_token("new_secret".to_owned())
            .await;
        generate_encryption_props().await;
        assert_eq!(9, kms_factory.keys_wrapped());
        // KEKs for old access token are still cached as they haven't expired
        assert_eq!(2, crypto_factory.cache_stats().await.num_kek_write_caches);

        time_controller.advance(Duration::from_secs(599));
        generate_encryption_props().await;
        // The KEK cache for the refreshed token is still valid, no new KEKs were generated
        assert_eq!(9, kms_factory.keys_wrapped());
        assert_eq!(2, crypto_factory.cache_stats().await.num_kek_write_caches);
    }

    #[tokio::test]
    async fn test_get_kms_client_using_provided_config() {
        // Connection configuration options provided at read time should take precedence over
        // the KMS URL and ID in the footer key material.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_kms_instance_id("456".to_owned())
            .set_kms_instance_url("https://example.com/kms2/".to_owned())
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(decryption_kms_config).await;

        assert_eq!(details.kms_instance_id, "456");
        assert_eq!(details.kms_instance_url, "https://example.com/kms2/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    #[tokio::test]
    async fn test_get_kms_client_using_config_from_file() {
        // When KMS config doesn't have the instance ID and URL,
        // they should be retrieved from the file metadata.
        // Other properties like the access key and custom configuration can only be provided
        // at decryption time.
        let decryption_kms_config = KmsConnectionConfig::builder()
            .set_key_access_token("secret_2".to_owned())
            .set_custom_kms_conf_option("test_key".to_owned(), "test_value_2".to_owned())
            .build();

        let details = get_kms_connection_config_for_decryption(decryption_kms_config).await;

        assert_eq!(details.kms_instance_id, "123");
        assert_eq!(details.kms_instance_url, "https://example.com/kms1/");
        assert_eq!(details.key_access_token, "secret_2");
        let expected_conf = HashMap::from([("test_key".to_owned(), "test_value_2".to_owned())]);
        assert_eq!(details.custom_kms_conf, expected_conf);
    }

    async fn get_kms_connection_config_for_decryption(
        decryption_kms_config: KmsConnectionConfig,
    ) -> KmsConnectionConfigDetails {
        let encryption_kms_config = Arc::new(
            KmsConnectionConfig::builder()
                .set_kms_instance_id("123".to_owned())
                .set_kms_instance_url("https://example.com/kms1/".to_owned())
                .set_key_access_token("secret_1".to_owned())
                .set_custom_kms_conf_option("test_key".to_owned(), "test_value_1".to_owned())
                .build(),
        );

        let encryption_config = EncryptionConfigurationBuilder::new("kf".to_owned())
            .set_double_wrapping(true)
            .build()
            .unwrap();

        let file_encryption_properties = {
            let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
            let crypto_factory = CryptoFactory::new(kms_factory.clone());

            crypto_factory
                .file_encryption_properties(encryption_kms_config, &encryption_config)
                .await
                .unwrap()
        };

        let kms_factory = Arc::new(TestKmsClientFactory::with_default_keys());
        let crypto_factory = CryptoFactory::new(kms_factory.clone());

        let decryption_kms_config = Arc::new(decryption_kms_config);
        let decryption_properties = crypto_factory
            .file_decryption_properties(decryption_kms_config, Default::default())
            .await
            .unwrap();

        let _ = decryption_properties
            .footer_key_async(
                file_encryption_properties
                    .footer_key_metadata()
                    .map(|k| k.as_bytes()),
            )
            .await
            .unwrap();

        let mut invocations = kms_factory.invocations().await;
        assert_eq!(invocations.len(), 1);
        invocations.pop().unwrap()
    }
}
