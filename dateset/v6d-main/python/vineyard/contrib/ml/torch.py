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

import contextlib
import time
import warnings
from collections import OrderedDict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Union

import numpy as np
import pandas as pd
import pyarrow as pa

import lazy_import

import vineyard
from vineyard._C import ObjectID
from vineyard._C import ObjectMeta
from vineyard._C import RemoteBlobBuilder
from vineyard.core import Client
from vineyard.core import context
from vineyard.data.utils import from_json
from vineyard.data.utils import normalize_cpptype
from vineyard.data.utils import to_json

torch = lazy_import.lazy_module("torch")


class WholeBatchSampler(torch.utils.data.Sampler[List[int]]):
    r"""Wraps another sampler to yield a single batch of all indices.

    Args:
        sampler (Dataset, Sampler or Iterable): Dataset, or the base sampler (can be any
                                                iterable object).

    Example:
        >>> list(WholeBatchSampler(SequentialSampler(range(10))))
        [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]]
    """

    def __init__(
        self,
        sampler: Union[
            torch.utils.data.Dataset, torch.utils.data.Sampler[int], Iterable[int]
        ],
    ) -> None:
        if isinstance(sampler, torch.utils.data.Dataset):
            sampler = torch.utils.data.SequentialSampler(sampler)
        self.sampler = sampler

    def __iter__(self) -> Iterator[List[int]]:
        return iter([list(self.sampler)])

    def __len__(self) -> int:
        return 1


def torch_tensor_builder(client, value, builder, **kw):
    return builder.run(client, value.numpy(), **kw)


def torch_dataset_builder(client, value, builder, **kw):
    dsl = torch.utils.data.DataLoader(value, batch_sampler=WholeBatchSampler(value))

    # the dataloader will contains only one batch
    columns = next(iter(dsl))

    # build as a dataframe
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::DataFrame'
    meta['columns_'] = to_json(list(range(len(columns))))
    meta.add_member('index_', builder.run(client, pd.RangeIndex(columns[0].shape[0])))

    for index, column in enumerate(columns):
        meta['__values_-key-%d' % index] = to_json(index)
        meta.add_member(
            '__values_-value-%d' % index, builder.run(client, column.numpy(), **kw)
        )
    meta['nbytes'] = 0  # FIXME
    meta['__values_-size'] = len(columns)
    meta['partition_index_row_'] = kw.get('partition_index', [-1, -1])[0]
    meta['partition_index_column_'] = kw.get('partition_index', [-1, -1])[1]
    meta['row_batch_index_'] = kw.get('row_batch_index', 0)
    return client.create_metadata(meta)


def torch_tensor_resolver(obj, resolver, **kw):
    value = resolver.parent_context.run(obj, **kw)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return torch.from_numpy(value)


def torch_dataset_resolver(obj, resolver, **kw):
    value = resolver.parent_context.run(obj, **kw)
    if isinstance(value, pd.DataFrame):
        return torch.utils.data.TensorDataset(
            *[
                torch.from_numpy(np.array(value[column].values))
                for column in value.columns
            ]
        )
    elif isinstance(value, (pa.Table, pa.RecordBatch)):
        return torch.utils.data.TensorDataset(
            *[torch.from_numpy(column.to_numpy()) for column in value.columns]
        )
    else:
        raise TypeError(f'torch dataset: unsupported type {type(value)}')


def torch_global_tensor_resolver(obj, resolver, **_kw):
    meta = obj.meta
    num = int(meta['partitions_-size'])
    data = []
    for i in range(num):
        if meta[f'partitions_{i}'].islocal:
            data.append(
                torch.utils.data.TensorDataset(
                    resolver.run(obj.member(f'partitions_{i}'))
                )
            )
    return torch.utils.data.ConcatDataset(data)


def torch_global_dataframe_resolver(obj, resolver, **_kw):
    meta = obj.meta
    num = int(meta['partitions_-size'])
    data = []
    for i in range(num):
        if meta[f'partitions_{i}'].islocal:
            data.append(resolver.run(obj.member(f'partitions_{i}')))
    return torch.utils.data.ConcatDataset(data)


def datapipe(
    dataset: torch.utils.data.Dataset,
):  # -> "torchdata.datapipes.iter.IterableWrapper":
    '''Convert a torch.utils.data.Dataset to a torchdata.datapipes.iter.IterableWrapper.

        e.g.,

        .. code:: python

            with torch_context():
                # using existing vineyard object as the dataset
                ds = client.get(object_id)

                # convert to datapipes
                ds = datapipe(ds)

                # do some transformation
                ds2 = ds.map(lambda x: x + 1)

                # iterator
                for index, record in enumerate(ds2):
                    print(record)

    Args:
        dataset: The torch.utils.data.Dataset to be converted.

    Returns:
        A torchdata.datapipes.iter.IterableWrapper.
    '''
    import torchdata

    return torchdata.datapipes.iter.IterableWrapper(dataset)


def put_torch_tensors(client, tensors) -> List[Union[ObjectID, ObjectMeta]]:
    pointers, sizes = [], []
    tensors = [tensor.contiguous() for tensor in tensors]
    for tensor in tensors:
        pointers.append(tensor.data_ptr())
        sizes.append(tensor.numel() * tensor.element_size())

    if client.is_ipc:
        blobs = client.create_blob(sizes)
        for pointer, size, blob in zip(pointers, sizes, blobs):
            vineyard.memory_copy(blob.address, size, pointer, size)
        blobs = [blob.seal(client) for blob in blobs]
    else:
        blob_writers = []
        for pointer, size in zip(pointers, sizes):
            blob_writers.append(RemoteBlobBuilder.wrap(pointer, size))
        blobs = client.create_remote_blob(blob_writers)

    metadatas = []
    for tensor, size, blob in zip(tensors, sizes, blobs):
        value = tensor.numpy()
        meta = ObjectMeta()
        meta['typename'] = 'vineyard::Tensor<%s>' % normalize_cpptype(value.dtype)
        meta['value_type_'] = value.dtype.name
        meta['value_type_meta_'] = value.dtype.str
        meta['shape_'] = to_json(value.shape)
        meta['partition_index_'] = to_json([])
        meta['nbytes'] = size
        meta['order_'] = to_json(('C' if value.flags['C_CONTIGUOUS'] else 'F'))
        meta.add_member('buffer_', blob)
        metadatas.append(meta)

    return client.create_metadata(metadatas)


def torch_module_builder(client, value, builder, **kw):
    def go(state_dict, key_prefix, tensors):
        if isinstance(state_dict, torch.Tensor):
            tensors[key_prefix] = state_dict
        elif isinstance(state_dict, dict):
            keys = list(state_dict.keys())
            for key in keys:
                state_dict[key] = go(state_dict[key], f'{key_prefix}.{key}', tensors)
            return state_dict
        elif isinstance(state_dict, (tuple, list)):
            return [
                go(element, f'{key_prefix}.{i}', tensors)
                for i, element in enumerate(state_dict)
            ]
        else:
            return state_dict

    def assign(state_dict, key_prefix, tensors):
        if isinstance(state_dict, torch.Tensor):
            r = tensors[key_prefix]
            if isinstance(r, ObjectMeta):
                r = r.id
            return r
        elif isinstance(state_dict, dict):
            keys = list(state_dict.keys())
            for key in keys:
                state_dict[key] = go(state_dict[key], f'{key_prefix}.{key}', tensors)
            return state_dict
        elif isinstance(state_dict, (tuple, list)):
            return [
                go(element, f'{key_prefix}.{i}', tensors)
                for i, element in enumerate(state_dict)
            ]
        else:
            return state_dict

    if isinstance(value, torch.nn.Module):
        value = value.state_dict()

    tensors = dict()
    go(value, 'tensor', tensors)

    tensor_keys, tensor_values = list(tensors.keys()), list(tensors.values())
    tensor_objects = put_torch_tensors(client, tensor_values)

    tensors = dict(zip(tensor_keys, tensor_objects))
    value = assign(value, 'tensor', tensors)

    meta = ObjectMeta()
    meta['typename'] = 'vineyard::torch::Module'
    meta['state_dict'] = to_json(value)
    for key, tensor in tensors.items():
        meta.add_member(key, tensor)
    return client.create_metadata(meta)


def torch_module_resolver(obj, resolver, **kw):
    def go(state_dict, key_prefix, tensors):
        if key_prefix in tensors:
            return tensors[key_prefix]
        elif isinstance(state_dict, dict):
            keys = list(state_dict.keys())
            for key in keys:
                state_dict[key] = go(state_dict[key], f'{key_prefix}.{key}', tensors)
            return state_dict
        elif isinstance(state_dict, (tuple, list)):
            return [
                go(element, f'{key_prefix}.{i}', tensors)
                for i, element in enumerate(state_dict)
            ]
        else:
            return state_dict

    meta = obj.meta
    state_dict = from_json(meta['state_dict'])
    tensors = dict()
    for key, value in meta.items():
        if key.startswith('tensor.'):
            tensors[key] = resolver.run(value, **kw)
    state_dict = go(state_dict, 'tensor', tensors)
    return state_dict


def register_torch_types(builder_ctx, resolver_ctx):
    if builder_ctx is not None:
        builder_ctx.register(torch.Tensor, torch_tensor_builder)
        builder_ctx.register(torch.utils.data.Dataset, torch_dataset_builder)
        builder_ctx.register(torch.nn.Module, torch_module_builder)
        builder_ctx.register(dict, torch_module_builder)
        builder_ctx.register(OrderedDict, torch_module_builder)

    if resolver_ctx is not None:
        resolver_ctx.register('vineyard::Tensor', torch_tensor_resolver)
        resolver_ctx.register('vineyard::DataFrame', torch_dataset_resolver)
        resolver_ctx.register('vineyard::RecordBatch', torch_dataset_resolver)
        resolver_ctx.register('vineyard::Table', torch_dataset_resolver)
        resolver_ctx.register('vineyard::GlobalTensor', torch_global_tensor_resolver)
        resolver_ctx.register(
            'vineyard::GlobalDataFrame', torch_global_dataframe_resolver
        )
        resolver_ctx.register('vineyard::torch::Module', torch_module_resolver)


@contextlib.contextmanager
def torch_context(client: Client = None):
    if client is not None:
        with client.with_compression(False):
            with context() as (builder_ctx, resolver_ctx):
                with contextlib.suppress(ImportError):
                    register_torch_types(builder_ctx, resolver_ctx)
                yield builder_ctx, resolver_ctx
    else:
        with context() as (builder_ctx, resolver_ctx):
            with contextlib.suppress(ImportError):
                register_torch_types(builder_ctx, resolver_ctx)
            yield builder_ctx, resolver_ctx
