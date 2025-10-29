use crate::{
    async_kms::{KmsClientFactory as AsyncKmsClientFactory, KmsClientRef as AsyncKmsClientRef},
    kms::{KmsClient, KmsClientFactory, KmsClientRef, KmsConnectionConfig},
};
use futures::task::{Spawn, SpawnExt};
use parquet::errors::Result;
use std::sync::mpsc;
use std::{marker::PhantomData, sync::Arc};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

// TODO documentation

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
    sender: UnboundedSender<AsyncKmsClientCommand>,
    _marker: PhantomData<S>,
}

impl<S> BridgeKmsClient<S>
where
    S: Spawn + Clone + Send + Sync + 'static,
{
    fn new(spawner: S, inner: AsyncKmsClientRef) -> Self {
        let (sender, mut receiver) = unbounded_channel::<AsyncKmsClientCommand>();

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

pub(crate) struct BridgeKmsClientFactory<S: Spawn, T: AsyncKmsClientFactory> {
    sender: UnboundedSender<AsyncKmsClientFactoryCommand>,
    _marker_s: PhantomData<S>,
    _marker_t: PhantomData<T>,
}

impl<S, T> BridgeKmsClientFactory<S, T>
where
    S: Spawn + Clone + Send + Sync + 'static,
    T: AsyncKmsClientFactory + 'static,
{
    pub(crate) fn new(spawner: S, inner: T) -> Self {
        let (sender, mut receiver) = unbounded_channel::<AsyncKmsClientFactoryCommand>();

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
