use arrow_array::{ArrayRef, Float32Array, Int32Array, RecordBatch};
use futures::future::BoxFuture;
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
use std::future::Future;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

/*
 * traits
 */

#[async_trait::async_trait]
pub trait AsyncKmsClient: Send + Sync {
    /// Wrap encryption key bytes using the KMS with the specified master key
    async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String>;

    /// Unwrap a wrapped encryption key using the KMS with the specified master key
    async fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>>;
}

pub type AsyncKmsClientRef = Arc<dyn AsyncKmsClient>;

/// Trait for factories that create KMS clients
#[async_trait::async_trait]
pub trait AsyncKmsClientFactory: Send + Sync {
    /// Create a new [`KmsClient`] instance using the provided configuration
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef>;
}

#[async_trait::async_trait]
impl<T> AsyncKmsClientFactory for Arc<T>
where
    T: AsyncKmsClientFactory,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef> {
        self.deref().create_client(kms_connection_config).await
    }
}

#[async_trait::async_trait]
impl<T> AsyncKmsClientFactory for T
where
    T: Fn(&KmsConnectionConfig) -> BoxFuture<Result<AsyncKmsClientRef>> + Send + Sync + 'static,
{
    async fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> Result<AsyncKmsClientRef> {
        self(kms_connection_config).await
    }
}

/*
 * Bridge KMS client implementation
 */

enum AsyncKmsClientCommand {
    WrapKey {
        key_bytes: Vec<u8>,
        master_key_identifier: String,
        respond_to: mpsc::Sender<Result<String>>,
    },
    UnwrapKey {
        wrapped_key: String,
        master_key_identifier: String,
        respond_to: mpsc::Sender<Result<Vec<u8>>>,
    },
}

struct BridgeKmsClient<S: Spawn> {
    sender: tokio::sync::mpsc::UnboundedSender<AsyncKmsClientCommand>,
    _marker: PhantomData<S>,
}

impl<S> BridgeKmsClient<S>
where
    S: Spawn + Clone + Send + Sync + 'static,
{
    fn new(spawner: S, inner: AsyncKmsClientRef) -> Self {
        let (sender, mut receiver) =
            tokio::sync::mpsc::unbounded_channel::<AsyncKmsClientCommand>();

        spawner
            .clone()
            .spawn(async move {
                while let Some(cmd) = receiver.recv().await {
                    let inner = inner.clone();
                    spawner
                        .spawn(async move {
                            match cmd {
                                AsyncKmsClientCommand::WrapKey {
                                    key_bytes,
                                    master_key_identifier,
                                    respond_to,
                                } => {
                                    let result =
                                        inner.wrap_key(&key_bytes, &master_key_identifier).await;
                                    let _ = respond_to.send(result);
                                }
                                AsyncKmsClientCommand::UnwrapKey {
                                    wrapped_key,
                                    master_key_identifier,
                                    respond_to,
                                } => {
                                    let result = inner
                                        .unwrap_key(&wrapped_key, &master_key_identifier)
                                        .await;
                                    let _ = respond_to.send(result);
                                }
                            }
                        })
                        .expect("Failed to spawn KMS command task");
                }
            })
            .expect("Failed to spawn KMS client task");

        Self {
            sender,
            _marker: PhantomData,
        }
    }
}

impl<S> KmsClient for BridgeKmsClient<S>
where
    S: Spawn + Sync + Send,
{
    fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        let (send, recv) = mpsc::channel();

        let _ = self.sender.send(AsyncKmsClientCommand::WrapKey {
            key_bytes: key_bytes.to_vec(),
            master_key_identifier: master_key_identifier.to_string(),
            respond_to: send,
        });
        recv.recv().map_err(|e| {
            parquet::errors::ParquetError::General(format!(
                "Failed to receive response from KMS client: {e}"
            ))
        })?
    }

    fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        let (send, recv) = mpsc::channel();

        let _ = self.sender.send(AsyncKmsClientCommand::UnwrapKey {
            wrapped_key: wrapped_key.to_string(),
            master_key_identifier: master_key_identifier.to_string(),
            respond_to: send,
        });
        recv.recv().map_err(|e| {
            parquet::errors::ParquetError::General(format!(
                "Failed to receive response from KMS client: {e}"
            ))
        })?
    }
}

/*
 * Bridge KMS client factory implementation
 */

enum AsyncKmsClientFactoryCommand {
    CreateClient {
        config: KmsConnectionConfig,
        respond_to: mpsc::Sender<Result<KmsClientRef>>,
    },
}

struct BridgeKmsClientFactory<S: Spawn, T: AsyncKmsClientFactory> {
    sender: tokio::sync::mpsc::UnboundedSender<AsyncKmsClientFactoryCommand>,
    _marker_s: PhantomData<S>,
    _marker_t: PhantomData<T>,
}

impl<S, T> BridgeKmsClientFactory<S, T>
where
    S: Spawn + Clone + Send + Sync + 'static,
    T: AsyncKmsClientFactory + 'static,
{
    fn new(spawner: S, inner: T) -> Self {
        let (sender, mut receiver) =
            tokio::sync::mpsc::unbounded_channel::<AsyncKmsClientFactoryCommand>();

        let inner = Arc::new(inner);

        spawner
            .clone()
            .spawn(async move {
                while let Some(cmd) = receiver.recv().await {
                    let inner = inner.clone();
                    let spawner = spawner.clone();
                    spawner
                        .clone()
                        .spawn(async move {
                            match cmd {
                                AsyncKmsClientFactoryCommand::CreateClient {
                                    config,
                                    respond_to,
                                } => {
                                    let result = async {
                                        let client = inner.create_client(&config).await?;
                                        let bridge_client = BridgeKmsClient::new(spawner, client);
                                        Ok(Arc::new(bridge_client) as KmsClientRef)
                                    }
                                    .await;
                                    let _ = respond_to.send(result);
                                }
                            }
                        })
                        .expect("Failed to spawn KMS factory command task");
                }
            })
            .expect("Failed to spawn KMS client factory task");

        Self {
            sender,
            _marker_s: PhantomData,
            _marker_t: PhantomData,
        }
    }
}

impl<S, T> KmsClientFactory for BridgeKmsClientFactory<S, T>
where
    S: Spawn + Sync + Send,
    T: AsyncKmsClientFactory,
{
    fn create_client(&self, kms_connection_config: &KmsConnectionConfig) -> Result<KmsClientRef> {
        let (send, recv) = mpsc::channel();

        let _ = self
            .sender
            .send(AsyncKmsClientFactoryCommand::CreateClient {
                config: kms_connection_config.clone(),
                respond_to: send,
            });
        recv.recv().map_err(|e| {
            parquet::errors::ParquetError::General(format!(
                "Failed to receive response from KMS client factory: {e}"
            ))
        })?
    }
}

/*
 * Test KMS client implementation
 */

struct TestAsyncKmsClient {
    inner: KmsClientRef,
}

impl TestAsyncKmsClient {
    fn new(inner: KmsClientRef) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl AsyncKmsClient for TestAsyncKmsClient {
    async fn wrap_key(&self, key_bytes: &[u8], master_key_identifier: &str) -> Result<String> {
        self.inner.wrap_key(key_bytes, master_key_identifier)
    }

    async fn unwrap_key(&self, wrapped_key: &str, master_key_identifier: &str) -> Result<Vec<u8>> {
        self.inner.unwrap_key(wrapped_key, master_key_identifier)
    }
}

/*
 * Test async KMS client factory implementation
 */
pub struct TestAsyncKmsClientFactory {
    inner: TestKmsClientFactory,
}

impl TestAsyncKmsClientFactory {
    fn with_default_keys() -> Self {
        Self {
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

#[async_trait::async_trait]
impl AsyncKmsClientFactory for TestAsyncKmsClientFactory {
    async fn create_client(&self, config: &KmsConnectionConfig) -> Result<AsyncKmsClientRef> {
        Ok(Arc::new(TestAsyncKmsClient::new(
            self.inner.create_client(config)?,
        )))
    }
}

/*
 * Test functions
 */

async fn write_with_keys_and_read_with_async_kms<S, F, Fut>(spawner: S, round_trip_fn: F)
where
    S: Spawn + Clone + Send + Sync + 'static,
    F: Fn(FileEncryptionProperties, FileDecryptionProperties) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let footer_key = b"0123456789012345";
    let encryption_properties = FileEncryptionProperties::builder(footer_key.to_vec())
        .build()
        .unwrap();

    let crypto_factory = CryptoFactory::new(BridgeKmsClientFactory::new(
        spawner,
        TestAsyncKmsClientFactory::with_default_keys(),
    ));
    let kms_config = Arc::new(KmsConnectionConfig::default());
    let decryption_config = DecryptionConfiguration::builder().build();
    let decryption_properties = crypto_factory
        .file_decryption_properties(kms_config, decryption_config)
        .unwrap();

    let result = round_trip_fn(encryption_properties, decryption_properties).await;

    match result {
        Ok(_) => panic!("Expected an error when reading encrypted Parquet that doesn't use a KMS"),
        Err(err) => {
            let message = err.to_string();
            assert!(message.contains(". Perhaps this file was encrypted without using a KMS"));
        }
    }
}

async fn multi_file_round_trip_with_async_kms<S, F, Fut>(spawner: S, round_trip_fn: F)
where
    S: Spawn + Clone + Send + Sync + 'static,
    F: Fn(FileEncryptionProperties, FileDecryptionProperties) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let encryption_config = EncryptionConfiguration::builder("kf".into())
        .set_double_wrapping(true)
        .add_column_key("kc1".into(), vec!["x".into()])
        .add_column_key("kc2".into(), vec!["y".into(), "z".into()])
        .set_cache_lifetime(None)
        .build()
        .unwrap();

    let write_client_factory = Arc::new(TestAsyncKmsClientFactory::with_default_keys());
    let read_client_factory = Arc::new(TestAsyncKmsClientFactory::with_default_keys());

    let write_crypto_factory = CryptoFactory::new(BridgeKmsClientFactory::new(
        spawner.clone(),
        write_client_factory.clone(),
    ));
    let read_crypto_factory = CryptoFactory::new(BridgeKmsClientFactory::new(
        spawner.clone(),
        read_client_factory.clone(),
    ));

    let kms_config = Arc::new(KmsConnectionConfig::default());

    for _ in 0..5 {
        let encryption_properties = write_crypto_factory
            .file_encryption_properties(kms_config.clone(), &encryption_config)
            .unwrap();

        let decryption_config = DecryptionConfiguration::builder().build();
        let decryption_properties = read_crypto_factory
            .file_decryption_properties(kms_config.clone(), decryption_config)
            .unwrap();

        round_trip_fn(encryption_properties, decryption_properties)
            .await
            .unwrap()
    }

    assert_eq!(write_client_factory.keys_wrapped(), 3);
    assert_eq!(read_client_factory.keys_unwrapped(), 3);
}

async fn round_trip_parquet_with_properties<W, R, CFut, OFut, CFn, OFn>(
    create_fn: CFn,
    open_fn: OFn,
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()>
where
    W: AsyncWrite + Send + Unpin,
    R: AsyncRead + AsyncSeek + Send + Unpin + 'static,
    CFn: Fn(&Path) -> CFut,
    OFn: Fn(&Path) -> OFut,
    CFut: Future<Output = Result<W>>,
    OFut: Future<Output = Result<R>>,
{
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
        let file = create_fn(&file_path).await?;

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

    let file = open_fn(&file_path).await?;

    let builder = ParquetRecordBatchStreamBuilder::new_with_options(file, reader_options).await?;
    let stream = builder.build()?;
    let results = stream.try_collect::<Vec<_>>().await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], write_batch);

    Ok(())
}

/*
 * tokio tests
 */

#[derive(Clone)]
struct TokioSpawner;
impl Spawn for TokioSpawner {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> std::result::Result<(), futures::task::SpawnError> {
        assert_eq!(
            tokio::runtime::RuntimeFlavor::MultiThread,
            tokio::runtime::Handle::current().runtime_flavor()
        );
        tokio::task::spawn(future);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn write_with_keys_and_read_with_async_kms_tokio() {
    write_with_keys_and_read_with_async_kms(TokioSpawner, round_trip_parquet_with_properties_tokio)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn multi_file_round_trip_with_async_kms_tokio() {
    multi_file_round_trip_with_async_kms(TokioSpawner, round_trip_parquet_with_properties_tokio)
        .await
}

async fn round_trip_parquet_with_properties_tokio(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(tokio::fs::File::create(path).await?) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(tokio::fs::File::open(path).await?) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}

/*
 * async-std tests
 */

#[derive(Clone)]
struct AsyncStdSpawner;
impl Spawn for AsyncStdSpawner {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> std::result::Result<(), futures::task::SpawnError> {
        async_std::task::spawn(future);
        Ok(())
    }
}

#[test]
fn write_with_keys_and_read_with_async_kms_async_std() {
    async_std::task::block_on(async {
        write_with_keys_and_read_with_async_kms(
            AsyncStdSpawner,
            round_trip_parquet_with_properties_async_std,
        )
        .await
    })
}

#[test]
fn multi_file_round_trip_with_async_kms_async_std() {
    async_std::task::block_on(async {
        multi_file_round_trip_with_async_kms(
            AsyncStdSpawner,
            round_trip_parquet_with_properties_async_std,
        )
        .await
    })
}

async fn round_trip_parquet_with_properties_async_std(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(async_std::fs::File::create(path).await?.compat()) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(async_std::fs::File::open(path).await?.compat_write()) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}

/*
 * smol tests
 */

#[derive(Clone)]
struct SmolSpawner;
impl Spawn for SmolSpawner {
    fn spawn_obj(
        &self,
        future: futures::task::FutureObj<'static, ()>,
    ) -> std::result::Result<(), futures::task::SpawnError> {
        smol::spawn(future).detach();
        Ok(())
    }
}

#[test]
fn write_with_keys_and_read_with_async_kms_smol() {
    smol::block_on(async {
        write_with_keys_and_read_with_async_kms(
            SmolSpawner,
            round_trip_parquet_with_properties_smol,
        )
        .await
    })
}

#[test]
fn wmulti_file_round_trip_with_async_kms_smol() {
    smol::block_on(async {
        multi_file_round_trip_with_async_kms(SmolSpawner, round_trip_parquet_with_properties_smol)
            .await
    })
}

async fn round_trip_parquet_with_properties_smol(
    encryption_properties: FileEncryptionProperties,
    decryption_properties: FileDecryptionProperties,
) -> Result<()> {
    round_trip_parquet_with_properties(
        |path| {
            let path = path.to_owned();
            async move { Ok(async_fs::File::create(path).await?.compat()) }
        },
        |path| {
            let path = path.to_owned();
            async move { Ok(async_fs::File::open(path).await?.compat_write()) }
        },
        encryption_properties,
        decryption_properties,
    )
    .await
}
