#! /usr/bin/env python
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

import json
import re
from typing import List
from typing import Union

import pyarrow as pa

try:
    import polars
except ImportError:
    polars = None

from vineyard._C import Blob
from vineyard._C import IPCClient
from vineyard._C import Object
from vineyard._C import ObjectMeta
from vineyard._C import RemoteBlob
from vineyard.core.builder import BuilderContext
from vineyard.core.resolver import ResolverContext
from vineyard.data.utils import build_buffer
from vineyard.data.utils import normalize_dtype


def buffer_builder(client, buffer: Union[bytes, memoryview], builder: BuilderContext):
    if buffer is None:
        address = None
        size = 0
    else:
        address = buffer.address
        size = len(buffer)
    return build_buffer(client, address, size, builder)


def as_arrow_buffer(blob: Union[Blob, RemoteBlob]):
    if isinstance(blob, (Blob, RemoteBlob)) and not blob.is_empty:
        buffer = memoryview(blob)
    else:
        buffer = memoryview(b'')
    return pa.py_buffer(buffer)


def json_to_arrow_buffer(value: str):
    assert isinstance(value, str)
    value = json.loads(value)
    assert 'bytes' in value
    return pa.py_buffer(bytearray(value['bytes']))


def json_from_arrow_buffer(buffer: pa.Buffer):
    return {"bytes": list(bytearray(buffer))}


def numeric_array_builder(
    client: IPCClient, array: pa.NumericArray, builder: BuilderContext
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::NumericArray<%s>' % array.type
    meta['length_'] = len(array)
    meta['null_count_'] = array.null_count
    meta['offset_'] = array.offset

    null_bitmap = buffer_builder(client, array.buffers()[0], builder)
    buffer = buffer_builder(client, array.buffers()[1], builder)

    meta.add_member('buffer_', buffer)
    meta.add_member('null_bitmap_', null_bitmap)
    meta['nbytes'] = array.nbytes
    return client.create_metadata(meta)


def fixed_size_binary_array_builder(
    client: IPCClient, array: pa.FixedSizeBinaryArray, builder: BuilderContext
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::FixedSizeBinaryArray'
    meta['length_'] = len(array)
    meta['null_count_'] = array.null_count
    meta['offset_'] = array.offset
    meta['byte_width_'] = array.byte_width

    null_bitmap = buffer_builder(client, array.buffers()[0], builder)
    buffer = buffer_builder(client, array.buffers()[1], builder)

    meta.add_member('buffer_', buffer)
    meta.add_member('null_bitmap_', null_bitmap)
    meta['nbytes'] = array.nbytes
    return client.create_metadata(meta)


def binary_or_string_array_builder(
    client: IPCClient, array: pa.StringArray, typename: str, builder: BuilderContext
):
    meta = ObjectMeta()
    meta['typename'] = typename
    meta['length_'] = len(array)
    meta['null_count_'] = array.null_count
    meta['offset_'] = array.offset

    null_bitmap = buffer_builder(client, array.buffers()[0], builder)
    if isinstance(array, pa.StringArray):
        buffer = array.buffers()[1]
        length = len(buffer) // (pa.uint32().bit_width // 8)
        offset_array = pa.Array.from_buffers(pa.uint32(), length, [None, buffer])
        offset_array = offset_array.cast(pa.uint64())
        offset_buffer = offset_array.buffers()[1]
    else:  # is pa.LargeStringArray
        offset_buffer = array.buffers()[1]
    buffer_offsets = buffer_builder(client, offset_buffer, builder)
    buffer_data = buffer_builder(client, array.buffers()[2], builder)

    meta.add_member('buffer_offsets_', buffer_offsets)
    meta.add_member('buffer_data_', buffer_data)
    meta.add_member('null_bitmap_', null_bitmap)
    meta['nbytes'] = array.nbytes
    return client.create_metadata(meta)


def binary_array_builder(
    client: IPCClient, array: pa.StringArray, builder: BuilderContext
):
    return binary_or_string_array_builder(
        client, array, 'vineyard::BaseBinaryArray<arrow::LargeBinaryArray>', builder
    )


def string_array_builder(
    client: IPCClient, array: pa.StringArray, builder: BuilderContext
):
    return binary_or_string_array_builder(
        client, array, 'vineyard::BaseBinaryArray<arrow::LargeStringArray>', builder
    )


def list_array_builder(client: IPCClient, array: pa.ListArray, builder: BuilderContext):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::LargeListArray'
    meta['length_'] = len(array)
    meta['null_count_'] = array.null_count
    meta['offset_'] = array.offset

    if isinstance(array, pa.ListArray):
        buffer = array.buffers()[1]
        length = len(buffer) // (pa.uint32().bit_width // 8)
        offset_array = pa.Array.from_buffers(pa.uint32(), length, [None, buffer])
        offset_array = offset_array.cast(pa.uint64())
        offset_buffer = offset_array.buffers()[1]
    else:  # is pa.LargeListArray
        offset_buffer = array.buffers()[1]

    meta.add_member('null_bitmap_', buffer_builder(client, array.buffers()[0], builder))
    meta.add_member('buffer_offsets_', buffer_builder(client, offset_buffer, builder))
    meta.add_member('values_', builder.run(client, array.values))
    meta['nbytes'] = array.nbytes
    return client.create_metadata(meta)


def null_array_builder(client: IPCClient, array: pa.NullArray):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::NullArray'
    meta['length_'] = len(array)
    meta['nbytes'] = 0
    return client.create_metadata(meta)


def boolean_array_builder(
    client: IPCClient, array: pa.BooleanArray, builder: BuilderContext
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::BooleanArray'
    meta['length_'] = len(array)
    meta['null_count_'] = array.null_count
    meta['offset_'] = array.offset

    null_bitmap = buffer_builder(client, array.buffers()[0], builder)
    buffer = buffer_builder(client, array.buffers()[1], builder)

    meta.add_member('buffer_', buffer)
    meta.add_member('null_bitmap_', null_bitmap)
    meta['nbytes'] = array.nbytes
    return client.create_metadata(meta)


def _resize_arrow_type(t: pa.DataType):
    if t == pa.string():
        return pa.large_string()
    if t == pa.utf8():
        return pa.large_utf8()
    if t == pa.binary():
        return pa.large_binary()
    if isinstance(t, pa.lib.ListType):
        return pa.large_list(t.value_type)
    return t


def schema_proxy_builder(client: IPCClient, schema: pa.Schema, builder: BuilderContext):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::SchemaProxy'

    # translate pa.StringArray, pa.ListArray, etc.
    names = schema.names
    types = [_resize_arrow_type(t) for t in schema.types]
    fields = [pa.field(name, t) for name, t in zip(names, types)]
    resized_schema = pa.schema(fields, schema.metadata)

    serialized = resized_schema.serialize()
    meta['schema_binary_'] = json.dumps(json_from_arrow_buffer(serialized))
    meta['nbytes'] = len(serialized)
    return client.create_metadata(meta)


def record_batch_builder(
    client: IPCClient, batch: pa.RecordBatch, builder: BuilderContext
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::RecordBatch'
    meta['row_num_'] = batch.num_rows
    meta['column_num_'] = batch.num_columns
    meta['__columns_-size'] = batch.num_columns

    meta.add_member('schema_', schema_proxy_builder(client, batch.schema, builder))
    for idx in range(batch.num_columns):
        meta.add_member('__columns_-%d' % idx, builder.run(client, batch[idx]))
    meta['nbytes'] = batch.nbytes
    return client.create_metadata(meta)


def table_builder(client: IPCClient, table: pa.Table, builder: BuilderContext, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::Table'
    meta['num_rows_'] = table.num_rows
    meta['num_columns_'] = table.num_columns
    batches = table.to_batches()
    meta['batch_num_'] = len(batches)
    meta['partitions_-size'] = len(batches)

    # apply extra metadata, e.g., from_polars=True
    for k, v in kw.items():
        meta[k] = v

    meta.add_member('schema_', schema_proxy_builder(client, table.schema, builder))
    for idx, batch in enumerate(batches):
        meta.add_member(
            'partitions_-%d' % idx, record_batch_builder(client, batch, builder)
        )
    meta['nbytes'] = table.nbytes
    return client.create_metadata(meta)


def polars_dataframe_builder(
    client: IPCClient, dataframe: "polars.DataFrame", builder: BuilderContext
):
    return table_builder(client, dataframe.to_arrow(), builder, from_polars=True)


def table_from_recordbatches(
    client: IPCClient,
    schema: pa.Schema,
    batches: List[pa.RecordBatch],
    num_rows: int,
    num_columns: int,
    builder: BuilderContext,
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::Table'
    meta['num_rows_'] = num_rows
    meta['num_columns_'] = num_columns
    meta['batch_num_'] = len(batches)
    meta['partitions_-size'] = len(batches)

    meta.add_member('schema_', schema_proxy_builder(client, schema, builder))
    for idx, batch in enumerate(batches):
        meta.add_member('partitions_-%d' % idx, batch)
    meta['nbytes'] = 0
    return client.create_metadata(meta)


def numeric_array_resolver(obj: Union[Object, ObjectMeta]):
    meta = obj.meta
    typename = obj.typename
    value_type = normalize_dtype(
        re.match(r'vineyard::NumericArray<([^>]+)>', typename).groups()[0]
    )
    dtype = pa.from_numpy_dtype(value_type)
    buffer = as_arrow_buffer(obj.member('buffer_'))
    null_bitmap = as_arrow_buffer(obj.member('null_bitmap_'))
    length = int(meta['length_'])
    null_count = int(meta['null_count_'])
    offset = int(meta['offset_'])
    return pa.lib.Array.from_buffers(
        dtype, length, [null_bitmap, buffer], null_count, offset
    )


def fixed_size_binary_array_resolver(obj: Union[Object, ObjectMeta]):
    meta = obj.meta
    buffer = as_arrow_buffer(obj.member('buffer_'))
    null_bitmap = as_arrow_buffer(obj.member('null_bitmap_'))
    length = int(meta['length_'])
    null_count = int(meta['null_count_'])
    offset = int(meta['offset_'])
    byte_width = int(meta['byte_width_'])
    return pa.lib.Array.from_buffers(
        pa.binary(byte_width), length, [null_bitmap, buffer], null_count, offset
    )


def binary_or_string_array_resolver(obj: Union[Object, ObjectMeta], dtype: pa.DataType):
    meta = obj.meta
    buffer_data = as_arrow_buffer(obj.member('buffer_data_'))
    buffer_offsets = as_arrow_buffer(obj.member('buffer_offsets_'))
    null_bitmap = as_arrow_buffer(obj.member('null_bitmap_'))
    length = int(meta['length_'])
    null_count = int(meta['null_count_'])
    offset = int(meta['offset_'])
    return pa.lib.Array.from_buffers(
        dtype,
        length,
        [null_bitmap, buffer_offsets, buffer_data],
        null_count,
        offset,
    )


def binary_array_resolver(obj: Union[Object, ObjectMeta]):
    return binary_or_string_array_resolver(obj, pa.large_binary())


def string_array_resolver(obj: Union[Object, ObjectMeta]):
    return binary_or_string_array_resolver(obj, pa.large_string())


def null_array_resolver(obj: Union[Object, ObjectMeta]):
    length = int(obj.meta['length_'])
    return pa.lib.Array.from_buffers(
        pa.null(),
        length,
        [
            None,
        ],
        length,
        0,
    )


def boolean_array_resolver(obj: Union[Object, ObjectMeta]):
    meta = obj.meta
    buffer = as_arrow_buffer(obj.member('buffer_'))
    null_bitmap = as_arrow_buffer(obj.member('null_bitmap_'))
    length = int(meta['length_'])
    null_count = int(meta['null_count_'])
    offset = int(meta['offset_'])
    return pa.lib.Array.from_buffers(
        pa.bool_(), length, [null_bitmap, buffer], null_count, offset
    )


def list_array_resolver(obj: Union[Object, ObjectMeta], resolver: ResolverContext):
    meta = obj.meta
    buffer_offsets = as_arrow_buffer(obj.member('buffer_offsets_'))
    length = int(meta['length_'])
    null_count = int(meta['null_count_'])
    offset = int(meta['offset_'])
    null_bitmap = as_arrow_buffer(obj.member('null_bitmap_'))
    values = resolver.run(obj.member('values_'))
    return pa.lib.Array.from_buffers(
        pa.large_list(values.type),
        length,
        [null_bitmap, buffer_offsets],
        null_count,
        offset,
        [values],
    )


def schema_proxy_resolver(obj: Union[Object, ObjectMeta]):
    meta = obj.meta
    if 'buffer_' in meta:
        buffer = as_arrow_buffer(meta.member('buffer_'))
    elif 'schema_binary_' in meta:
        buffer = json_to_arrow_buffer(meta['schema_binary_'])
    else:
        raise ValueError("not a valid schema: %s" % meta)
    return pa.ipc.read_schema(buffer)


def record_batch_resolver(obj: Union[Object, ObjectMeta], resolver: ResolverContext):
    meta = obj.meta
    schema = resolver.run(obj.member('schema_'))
    columns = []
    for idx in range(int(meta['__columns_-size'])):
        columns.append(resolver.run(obj.member('__columns_-%d' % idx)))
    return pa.RecordBatch.from_arrays(columns, schema=schema)


def table_resolver(obj: Union[Object, ObjectMeta], resolver: ResolverContext):
    meta = obj.meta
    batch_num = int(meta['batch_num_'])
    batches = []
    for idx in range(batch_num):
        batches.append(resolver.run(obj.member('partitions_-%d' % idx)))
    return pa.Table.from_batches(batches)


def polars_dataframe_resolver(
    obj: Union[Object, ObjectMeta], resolver: ResolverContext
):
    meta = obj.meta
    table = table_resolver(obj, resolver)
    if polars is not None and meta.get('from_polars', False):
        return polars.DataFrame(table)
    return table


def register_arrow_types(
    builder_ctx: BuilderContext = None, resolver_ctx: ResolverContext = None
):
    if builder_ctx is not None:
        builder_ctx.register(pa.Buffer, buffer_builder)
        builder_ctx.register(pa.NumericArray, numeric_array_builder)
        builder_ctx.register(pa.FixedSizeBinaryArray, fixed_size_binary_array_builder)
        builder_ctx.register(pa.StringArray, string_array_builder)
        builder_ctx.register(pa.LargeBinaryArray, binary_array_builder)
        builder_ctx.register(pa.LargeStringArray, string_array_builder)
        builder_ctx.register(pa.NullArray, null_array_builder)
        builder_ctx.register(pa.BooleanArray, boolean_array_builder)
        builder_ctx.register(pa.Schema, schema_proxy_builder)
        builder_ctx.register(pa.RecordBatch, record_batch_builder)
        builder_ctx.register(pa.Table, table_builder)
        builder_ctx.register(pa.ListArray, list_array_builder)

        if polars is not None:
            builder_ctx.register(polars.DataFrame, polars_dataframe_builder)

    if resolver_ctx is not None:
        resolver_ctx.register('vineyard::NumericArray', numeric_array_resolver)
        resolver_ctx.register(
            'vineyard::FixedSizeBinaryArray', fixed_size_binary_array_resolver
        )
        resolver_ctx.register('vineyard::LargeBinaryArray', binary_array_resolver)
        resolver_ctx.register('vineyard::LargeStringArray', string_array_resolver)
        resolver_ctx.register(
            'vineyard::BaseBinaryArray<arrow::LargeStringArray>', string_array_resolver
        )
        resolver_ctx.register('vineyard::NullArray', null_array_resolver)
        resolver_ctx.register('vineyard::BooleanArray', boolean_array_resolver)
        resolver_ctx.register('vineyard::SchemaProxy', schema_proxy_resolver)
        resolver_ctx.register('vineyard::RecordBatch', record_batch_resolver)
        resolver_ctx.register('vineyard::Table', table_resolver)
        resolver_ctx.register('vineyard::LargeListArray', list_array_resolver)

        if polars is not None:
            resolver_ctx.register('vineyard::Table', polars_dataframe_resolver)
