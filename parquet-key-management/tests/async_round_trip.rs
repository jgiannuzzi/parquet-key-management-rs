use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use futures::task::{Spawn, SpawnExt};
use futures::TryStreamExt;
use parquet::arrow::arrow_reader::ArrowReaderOptions;
use parquet::arrow::{AsyncArrowWriter, ParquetRecordBatchStreamBuilder};
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::encryption::encrypt::FileEncryptionProperties;
use parquet::errors::Result;
use parquet::file::properties::WriterProperties;
use parquet_key_management::crypto_factory::{
    CryptoFactory, DecryptionConfiguration, EncryptionConfiguration,
};
use parquet_key_management::kms::{KmsClient, KmsClientFactory, KmsClientRef, KmsConnectionConfig};
use parquet_key_management::test_kms::TestKmsClientFactory;
use std::marker::PhantomData;
use std::sync::mpsc as oneshot;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::sleep;

enum KmsClientCommand {
    WrapKey {
        key_bytes: Vec<u8>,
        master_key_identifier: String,
        respond_to: oneshot::Sender<Result<String>>,
    },
    UnwrapKey {
        wrapped_key: String,
        master_key_identifier: String,
        respond_to: oneshot::Sender<Result<Vec<u8>>>,
    },
}

struct TokioTestKmsClient<S: Spawn> {
    sender: mpsc::UnboundedSender<KmsClientCommand>,
    _marker: PhantomData<S>,
}

impl<S> TokioTestKmsClient<S>
where
    S: Spawn,
{
    fn new(spawner: S, inner: KmsClientRef) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel::<KmsClientCommand>();

        spawner
            .spawn(async move {
                while let Some(cmd) = receiver.recv().await {
                    match cmd {
                        KmsClientCommand::WrapKey {
                            key_bytes,
                            master_key_identifier,
                            respond_to,
                        } => {
                            println!(
                                "TokioTestKmsClient: wrapping key for master key identifier '{}'",
                                master_key_identifier
                            );
                            let result = inner.wrap_key(&key_bytes, &master_key_identifier);
                            sleep(Duration::from_millis(1)).await;
                            let _ = respond_to.send(result);
                            println!("TokioTestKmsClient: finished wrapping key");
                        }
                        KmsClientCommand::UnwrapKey {
                            wrapped_key,
                            master_key_identifier,
                            respond_to,
                        } => {
                            println!(
                                "TokioTestKmsClient: unwrapping key for master key identifier '{}'",
                                master_key_identifier
                            );
                            let result = inner.unwrap_key(&wrapped_key, &master_key_identifier);
                            sleep(Duration::from_millis(1)).await;
                            let _ = respond_to.send(result);
                            println!("TokioTestKmsClient: finished unwrapping key");
                        }
                    }
                }
            })
            .expect("Failed to spawn KMS client task");

        Self {
            sender,
            _marker: PhantomData,
        }
    }
}

impl<S> KmsClient for TokioTestKmsClient<S>
where
    S: Spawn + Sync + Send,
{
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        let (send, recv) = oneshot::channel();

        let cmd = KmsClientCommand::WrapKey {
            key_bytes: key_bytes.to_vec(),
            master_key_identifier: master_key_identifier.to_string(),
            respond_to: send,
        };

        println!("TokioTestKmsClient: sending wrap key command");
        let _ = self.sender.send(cmd);
        println!("TokioTestKmsClient: waiting for wrap key response");
        let res = recv.recv().map_err(|e| {
            parquet::errors::ParquetError::General(format!(
                "Failed to receive response from KMS client: {e}"
            ))
        })?;
        println!("TokioTestKmsClient: received wrap key response");
        res
    }

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        let (send, recv) = oneshot::channel();

        let cmd = KmsClientCommand::UnwrapKey {
            wrapped_key: wrapped_key.to_string(),
            master_key_identifier: master_key_identifier.to_string(),
            respond_to: send,
        };

        println!("TokioTestKmsClient: sending unwrap key command");
        let _ = self.sender.send(cmd);
        println!("TokioTestKmsClient: waiting for unwrap key response");
        let res = recv.recv().map_err(|e| {
            parquet::errors::ParquetError::General(format!(
                "Failed to receive response from KMS client: {e}"
            ))
        })?;
        println!("TokioTestKmsClient: received unwrap key response");
        res
    }
}

pub struct TokioTestKmsClientFactory<S>
where
    S: Spawn + Clone + Send + Sync + 'static,
{
    spawner: S,
    inner: TestKmsClientFactory,
}

impl<S> TokioTestKmsClientFactory<S>
where
    S: Spawn + Clone + Send + Sync + 'static,
{
    fn with_default_keys(s: S) -> Self {
        Self {
            spawner: s,
            inner: TestKmsClientFactory::with_default_keys(),
        }
    }

    fn keys_wrapped(&self) -> usize {
        self.inner.keys_wrapped()
    }

    fn keys_unwrapped(&self) -> usize {
        self.inner.keys_unwrapped()
    }
}

impl<S> KmsClientFactory for TokioTestKmsClientFactory<S>
where
    S: Spawn + Clone + Send + Sync + 'static,
{
    fn create_client(&self, config: &KmsConnectionConfig) -> Result<KmsClientRef> {
        let inner_client = self.inner.create_client(config)?;
        Ok(Arc::new(TokioTestKmsClient::new(
            self.spawner.clone(),
            inner_client,
        )))
    }
}

#[derive(Clone)]
struct TokioSpawner;
impl Spawn for TokioSpawner {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> std::result::Result<(), futures::task::SpawnError> {
        tokio::task::spawn(future);
        Ok(())
    }
}

#[tokio::test]
async fn write_with_keys_and_read_with_async_kms() {
    let footer_key = b"0123456789012345";
    let encryption_properties = FileEncryptionProperties::builder(footer_key.to_vec())
        .build()
        .unwrap();

    let crypto_factory =
        CryptoFactory::new(TokioTestKmsClientFactory::with_default_keys(TokioSpawner));
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config, decryption_config)
        .unwrap();

    let result =
        round_trip_parquet_with_properties(encryption_properties, decryption_properties).await;

    match result {
        Ok(_) => panic!("Expected an error when reading encrypted Parquet that doesn't use a KMS"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains(". Perhaps this file was encrypted without using a KMS"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn multi_file_round_trip_with_async_kms() {
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .set_cache_lifetime(None)
        .build()
        .unwrap();

    let write_client_factory = Arc::new(TokioTestKmsClientFactory::with_default_keys(TokioSpawner));
    let read_client_factory = Arc::new(TokioTestKmsClientFactory::with_default_keys(TokioSpawner));

    let write_crypto_factory = CryptoFactory::new(write_client_factory.clone());
    let read_crypto_factory = CryptoFactory::new(read_client_factory.clone());

    let kms_config = Arc::new(KmsConnectionConfig::default());

    for _ in 0..5 {
        let encryption_properties = write_crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let decryption_config = DecryptionConfiguration::builder().build();
        let decryption_properties = read_crypto_factory
            .file_decryption_properties(kms_config.clone(), decryption_config)
            .unwrap();

        round_trip_parquet_with_properties(encryption_properties, decryption_properties)
            .await
            .unwrap()
    }

    assert_eq!(write_client_factory.keys_wrapped(), 3);
    assert_eq!(read_client_factory.keys_unwrapped(), 3);
}

async fn round_trip_parquet_with_properties(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_file.parquet");

    let ids = Int32Array::from(vec![0, 1, 2, 3, 4, 5]);
    let x_vals = Float32Array::from(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5]);
    let y_vals = Float32Array::from(vec![1.0, 1.1, 1.2, 1.3, 1.4, 1.5]);
    let z_vals = Float32Array::from(vec![2.0, 2.1, 2.2, 2.3, 2.4, 2.5]);
    let write_batch = RecordBatch::try_from_iter(vec![
        ("id", Arc::new(ids) as ArrayRef),
        ("x", Arc::new(x_vals) as ArrayRef),
        ("y", Arc::new(y_vals) as ArrayRef),
        ("z", Arc::new(z_vals) as ArrayRef),
    ])?;

    {
        let file = tokio::fs::File::create(&file_path).await?;

        let writer_properties = WriterProperties::builder()
            .with_file_encryption_properties(encryption_properties)
            .build();

        let mut writer =
            AsyncArrowWriter::try_new(file, write_batch.schema(), Some(writer_properties))?;

        writer.write(&write_batch).await?;
        writer.close().await?;
    }

    let reader_options =
        ArrowReaderOptions::new().with_file_decryption_properties(decryption_properties);

    let file = tokio::fs::File::open(&file_path).await?;

    let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
    let stream = builder.build()?;
    let results = stream.try_collect::<Vec<_>>().await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], write_batch);

    Ok(())
}
