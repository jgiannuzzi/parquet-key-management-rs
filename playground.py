# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "numpy==2.3.3",
#     "pandas==2.3.3",
#     "pyarrow==21.0.0",
# ]
# ///

import marimo

__generated_with = "0.16.3"
app = marimo.App()


@app.cell
def _():
    import base64
    import json
    import pyarrow as pa
    import pyarrow.parquet as pq
    import pyarrow.parquet.encryption as pe
    import pandas as pd
    import numpy as np
    return base64, json, np, pa, pd, pe, pq


@app.cell
def _(np, pa, pd):
    df = pd.DataFrame({'one': [-1, np.nan, 2.5],
                       'two': ['foo', 'bar', 'baz']},
                       index=list('abc'))
    table = pa.Table.from_pandas(df)
    return (table,)


@app.cell
def _(base64, json, pa, pe):
    class MyKmsClient(pe.KmsClient):
       def __init__(self, kms_connection_configuration):
          pe.KmsClient.__init__(self)

       def wrap_key(self, key_bytes, master_key_identifier):
          wrapped_key = json.dumps({"key_bytes": base64.encodebytes(key_bytes).decode("ascii").rstrip('\n'), "master_key_identifier": master_key_identifier})
          return wrapped_key

       def unwrap_key(self, wrapped_key, master_key_identifier):
          metadata = json.loads(wrapped_key)
          if metadata["master_key_identifier"] != master_key_identifier:
               raise pa.ArrowException("boo")
          key_bytes = base64.decodebytes(metadata["key_bytes"].encode("ascii"))
          return key_bytes

    def kms_client_factory(kms_connection_configuration):
        return MyKmsClient(kms_connection_configuration)

    crypto_factory = pe.CryptoFactory(kms_client_factory)
    return (crypto_factory,)


@app.cell
def _(pq, table):
    pq.write_table(table, 'test.parquet')
    return


@app.cell
def _(crypto_factory, pe, pq, table):
    encryption_properties = crypto_factory.file_encryption_properties(pe.KmsConnectionConfig(), pe.EncryptionConfiguration("foo", column_keys={"bar": ["two"]}))

    pq.write_table(table, 'encrypted.parquet', encryption_properties=encryption_properties)
    return


@app.cell
def _(crypto_factory, pe, pq):
    pq.read_table("encrypted.parquet", decryption_properties=crypto_factory.file_decryption_properties(pe.KmsConnectionConfig()))
    return


app._unparsable_cell(
    r"""
    config = pe.KmsConnectionConfig()
    config.
    """,
    name="_"
)


if __name__ == "__main__":
    app.run()
