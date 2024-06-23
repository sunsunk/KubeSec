#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2020-2023 Alibaba Group Holding Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import base64
import json
import logging
import sys

import cloudpickle
import fsspec

import vineyard
from vineyard.io.dataframe import DataframeStream
from vineyard.io.utils import expand_full_path

logger = logging.getLogger('vineyard')

try:
    from vineyard.drivers.io import fsspec_adaptors
except Exception:  # pylint: disable=broad-except
    logger.warning("Failed to import fsspec adaptors for hdfs, oss, etc.")
from vineyard.drivers.io.fsspec_adaptors import infer_fsspec_paths  # noqa: E402


def write_parquet(
    vineyard_socket,
    path,
    stream_id,
    storage_options,
    write_options,
    proc_num,
    proc_index,
):
    client = vineyard.connect(vineyard_socket)
    streams = client.get(stream_id)
    if len(streams) != proc_num or streams[proc_index] is None:
        raise ValueError(
            f"Fetch stream error with proc_num={proc_num},proc_index={proc_index}"
        )
    instream: DataframeStream = streams[proc_index]
    reader = instream.open_reader(client)

    chunk_hook = write_options.get('chunk_hook', None)

    writer = None
    fs, _, _ = infer_fsspec_paths(
        f"{path}_{proc_index}", storage_options=storage_options
    )
    if hasattr(fs, 'auto_mkdir'):
        fs.auto_mkdir = True
    with fs.open(f"{path}_{proc_index}", "wb", **storage_options) as fp:
        while True:
            try:
                batch = reader.next()
            except (StopIteration, vineyard.StreamDrainedException):
                writer.close()
                break
            if chunk_hook is not None:
                batch = chunk_hook(batch)
            if writer is None:
                import pyarrow.parquet

                kwargs = dict()
                if "version" in write_options:
                    kwargs["version"] = write_options["version"]
                if "data_page_size" in write_options:
                    kwargs["data_page_size"] = write_options["data_page_size"]
                if "data_page_version" in write_options:
                    kwargs["data_page_version"] = write_options["data_page_version"]
                if "write_batch_size" in write_options:
                    kwargs["write_batch_size"] = write_options["write_batch_size"]
                if "compression" in write_options:
                    kwargs["compression"] = write_options["compression"]
                if "compression_level" in write_options:
                    kwargs["compression_level"] = write_options["compression_level"]

                writer = pyarrow.parquet.ParquetWriter(fp, batch.schema, **kwargs)

            if hasattr(writer, 'write_batch'):
                writer.write_batch(batch)  # pylint: disable=no-member
            else:
                writer.write_table(pyarrow.Table.from_batches([batch], batch.schema))

        if writer is not None:
            writer.close()


def main():
    if len(sys.argv) < 7:
        print(
            "usage: ./write_parquet <ipc_socket> <path> <stream id> "
            "<storage_options> <write_options> <proc_num> <proc_index>"
        )
        sys.exit(1)
    ipc_socket = sys.argv[1]
    path = expand_full_path(sys.argv[2])
    stream_id = sys.argv[3]
    storage_options = json.loads(
        base64.b64decode(sys.argv[4].encode("utf-8")).decode("utf-8")
    )
    write_options = json.loads(
        base64.b64decode(sys.argv[5].encode("utf-8")).decode("utf-8")
    )
    if 'chunk_hook' in write_options:
        write_options['chunk_hook'] = cloudpickle.loads(
            base64.b64decode(write_options['chunk_hook'].encode('ascii'))
        )
    proc_num = int(sys.argv[6])
    proc_index = int(sys.argv[7])
    write_parquet(
        ipc_socket,
        path,
        stream_id,
        storage_options,
        write_options,
        proc_num,
        proc_index,
    )


if __name__ == "__main__":
    main()
