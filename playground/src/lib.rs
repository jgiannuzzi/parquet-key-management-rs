use arrow::record_batch::RecordBatchReader;
use parquet::arrow::arrow_reader::{
    ArrowReaderOptions, ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder,
};
use parquet::errors::ParquetError;
use parquet_key_management::crypto_factory::{CryptoFactory, DecryptionConfiguration};
use parquet_key_management::kms::{KmsClient, KmsClientFactory, KmsClientRef, KmsConnectionConfig};
use pyo3::exceptions::{PyException, PyRuntimeError};
use pyo3::{intern, prelude::*};
use pyo3_arrow::error::PyArrowResult;
use pyo3_arrow::PyRecordBatchReader;
use std::fs::File;
use std::sync::Arc;

/// Read an encrypted Parquet file to a PyArrow RecordBatchReader
#[pyfunction]
fn read_encrypted_parquet(
    py: Python,
    path: std::path::PathBuf,
    crypto_factory: Py<PyAny>,
) -> PyResult<Bound<PyAny>> {
    let crypto_factory = CryptoFactory::new(PythonKmsClientFactory::new(crypto_factory));
    let reader: ParquetRecordBatchReader =
        py.detach(|| get_encrypted_parquet_reader(&path, crypto_factory))?;
    let reader: Box<dyn RecordBatchReader + Send> = Box::new(reader);
    PyRecordBatchReader::from(reader).into_pyarrow(py)
}

fn get_encrypted_parquet_reader(
    path: &std::path::PathBuf,
    crypto_factory: CryptoFactory,
) -> PyArrowResult<ParquetRecordBatchReader> {
    let file = File::open(path).map_err(|e| PyErr::from(e))?;

    let file_decryption_properties = crypto_factory
        .file_decryption_properties(
            Arc::new(KmsConnectionConfig::default()),
            DecryptionConfiguration::default(),
        )
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let options =
        ArrowReaderOptions::default().with_file_decryption_properties(file_decryption_properties);

    let reader_builder = ParquetRecordBatchReaderBuilder::try_new_with_options(file, options)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let reader = reader_builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    Ok(reader)
}

#[pyfunction]
fn wrap_key(
    py: Python,
    crypto_factory: Py<PyAny>,
    key_bytes: &[u8],
    master_key_identifier: &str,
) -> PyResult<String> {
    let client = PythonKmsClientFactory::new(crypto_factory)
        .create_client(&KmsConnectionConfig::default())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    client
        .wrap_key(key_bytes, master_key_identifier)
        .map_err(|e| PyException::new_err(format!("ParquetError: {}", e)))
}

/// A Python module implemented in Rust.
#[pymodule]
fn playground(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(read_encrypted_parquet, m)?)?;
    m.add_function(wrap_pyfunction!(wrap_key, m)?)?;
    Ok(())
}

struct PythonKmsClientFactory {
    inner: Py<PyAny>,
}

impl PythonKmsClientFactory {
    fn new(inner: Py<PyAny>) -> Self {
        Self { inner }
    }
}

impl KmsClientFactory for PythonKmsClientFactory {
    fn create_client(
        &self,
        kms_connection_config: &KmsConnectionConfig,
    ) -> parquet::errors::Result<KmsClientRef> {
        Python::attach(|py| {
            let pe_mod = py
                .import(intern!(py, "pyarrow.parquet.encryption"))
                .map_err(|e| ParquetError::General(e.to_string()))?;
            let kms_connection_config_class = pe_mod
                .getattr(intern!(py, "KmsConnectionConfig"))
                .map_err(|e| ParquetError::General(e.to_string()))?;
            let kms_connection_config = kms_connection_config_class
                .call0()
                .map_err(|e| ParquetError::General(e.to_string()))?;
            let client = self
                .inner
                .call1(py, (kms_connection_config,))
                .map_err(|e| ParquetError::General(e.to_string()))?;
            Ok(Arc::new(PythonKmsClient::new(client)) as KmsClientRef)
        })
    }
}

struct PythonKmsClient {
    inner: Py<PyAny>,
}

impl PythonKmsClient {
    fn new(inner: Py<PyAny>) -> Self {
        Self { inner }
    }
}

impl KmsClient for PythonKmsClient {
    fn wrap_key(
        &self,
        key_bytes: &[u8],
        master_key_identifier: &str,
    ) -> parquet::errors::Result<String> {
        Python::attach(|py| {
            Ok(self
                .inner
                .call_method1(
                    py,
                    intern!(py, "wrap_key"),
                    (key_bytes, master_key_identifier),
                )
                .map_err(|e| {
                    ParquetError::General(format!("Python implementation returned {}", e))
                })?
                .to_string())
        })
    }

    fn unwrap_key(
        &self,
        wrapped_key: &str,
        master_key_identifier: &str,
    ) -> parquet::errors::Result<Vec<u8>> {
        Python::attach(|py| {
            self.inner
                .call_method1(
                    py,
                    intern!(py, "unwrap_key"),
                    (wrapped_key, master_key_identifier),
                )
                .map_err(|e| {
                    ParquetError::General(format!("Python implementation returned {}", e))
                })?
                .extract::<Vec<u8>>(py)
                .map_err(|_| {
                    ParquetError::General("Python implementation did not return bytes".into())
                })
        })
    }
}
