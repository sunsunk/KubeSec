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

import pickle

import numpy as np
import pyarrow as pa

from vineyard._C import Object
from vineyard._C import ObjectID
from vineyard._C import ObjectMeta
from vineyard.data.utils import build_numpy_buffer
from vineyard.data.utils import from_json
from vineyard.data.utils import normalize_cpptype
from vineyard.data.utils import normalize_dtype
from vineyard.data.utils import to_json

try:
    import scipy as sp
    import scipy.sparse  # pylint: disable=unused-import
except ImportError:
    sp = None

if pickle.HIGHEST_PROTOCOL < 5:
    import pickle5 as pickle  # pylint: disable=import-error


# Enable dynamic attribute on numpy.ndarray.
class ndarray(np.ndarray):
    pass


# n.b. don't wrap `__module__` otherwise `pickle` on such values will fail.
#
# ndarray.__module__ = np.ndarray.__module__
ndarray.__name__ = np.ndarray.__name__
ndarray.__qualname__ = np.ndarray.__qualname__
ndarray.__doc__ = np.ndarray.__doc__


def numpy_ndarray_builder(client, value, **kw):
    meta = ObjectMeta()
    meta['shape_'] = to_json(value.shape)
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nbytes
    meta['order_'] = to_json(('C' if value.flags['C_CONTIGUOUS'] else 'F'))

    if value.dtype.name == 'object' or value.dtype.name.startswith('str'):
        # check if it can be used as a string array
        try:
            from vineyard.core.builder import get_current_builders
            from vineyard.data.arrow import string_array_builder

            # string tensors in numpy like np.array(['a', 'b']) cannot be
            # converted to pa.large_string_array directly.
            try:
                array = pa.array(value, type=pa.large_string())
            except:  # noqa: E722, pylint: disable=bare-except
                array = pa.array(value, type=pa.string())
            meta['typename'] = 'vineyard::Tensor<std::string>'
            meta['value_type_'] = 'string'
            meta['value_type_meta_'] = 'str'
            meta.add_member(
                'buffer_', string_array_builder(client, array, get_current_builders())
            )
        except:  # noqa: E722, pylint: disable=bare-except
            meta['typename'] = 'vineyard::Tensor<%s>' % normalize_cpptype(value.dtype)
            meta['value_type_'] = value.dtype.name
            meta['value_type_meta_'] = value.dtype.str
            meta.add_member('buffer_', build_numpy_buffer(client, value))
    else:
        meta['typename'] = 'vineyard::Tensor<%s>' % normalize_cpptype(value.dtype)
        meta['value_type_'] = value.dtype.name
        meta['value_type_meta_'] = value.dtype.str
        meta.add_member('buffer_', build_numpy_buffer(client, value))
    return client.create_metadata(meta)


def numpy_ndarray_resolver(obj):
    meta = obj.meta
    value_type_name = meta['value_type_']
    if value_type_name == 'object':
        view = memoryview(obj.member('buffer_'))
        return pickle.loads(view, fix_imports=True)

    value_type = normalize_dtype(value_type_name, meta.get('value_type_meta_', None))
    # process string ndarray from c++
    if value_type_name in ['str', 'string', 'std::string', 'std::__1::string']:
        from vineyard.data.arrow import binary_array_resolver
        from vineyard.data.arrow import string_array_resolver

        try:
            return string_array_resolver(obj.member('buffer_')).to_numpy(
                zero_copy_only=False
            )
        except:  # noqa: E722, pylint: disable=bare-except
            return binary_array_resolver(obj.member('buffer_')).to_numpy(
                zero_copy_only=False
            )

    shape = from_json(meta['shape_'])
    if 'order_' in meta:
        order = from_json(meta['order_'])
    else:
        order = 'C'
    if np.prod(shape) == 0:
        return np.zeros(shape, dtype=value_type)
    mem = memoryview(obj.member('buffer_'))[
        0 : int(np.prod(shape)) * np.dtype(value_type).itemsize
    ]
    c_array = np.frombuffer(mem, dtype=value_type).reshape(shape)
    # TODO: revise the memory copy of asfortranarray
    array = c_array if order == 'C' else np.asfortranarray(c_array)
    return array.view(ndarray)


def bsr_matrix_builder(client, value, builder, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::BSRMatrix<%s>' % value.dtype.name
    meta['value_type_'] = value.dtype.name
    meta['shape_'] = to_json(value.shape)
    meta['ndim'] = value.ndim
    meta['nnz'] = value.nnz
    meta.add_member('data', builder.run(client, value.data, **kw))
    meta.add_member('indices', builder.run(client, value.indices, **kw))
    meta.add_member('indptr', builder.run(client, value.indptr, **kw))
    meta['blocksize'] = value.blocksize
    meta['has_sorted_indices'] = value.has_sorted_indices
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nnz * value.dtype.itemsize
    return client.create_metadata(meta)


def bsr_matrix_resolver(obj, resolver):
    meta = obj.meta
    shape = from_json(meta['shape_'])
    value_type = normalize_dtype(meta['value_type_'])
    data = resolver.run(obj.member('data'))
    indices = resolver.run(obj.member('indices'))
    indptr = resolver.run(obj.member('indptr'))
    return sp.sparse.bsr_matrix((data, indices, indptr), shape=shape, dtype=value_type)


def coo_matrix_builder(client, value, builder, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::COOMatrix<%s>' % value.dtype.name
    meta['value_type_'] = value.dtype.name
    meta['shape_'] = to_json(value.shape)
    meta['ndim'] = value.ndim
    meta['nnz'] = value.nnz
    meta.add_member('data', builder.run(client, value.data, **kw))
    meta.add_member('row', builder.run(client, value.row, **kw))
    meta.add_member('col', builder.run(client, value.col, **kw))
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nnz * value.dtype.itemsize
    return client.create_metadata(meta)


def coo_matrix_resolver(obj, resolver):
    meta = obj.meta
    shape = from_json(meta['shape_'])
    value_type = normalize_dtype(meta['value_type_'])
    data = resolver.run(obj.member('data'))
    row = resolver.run(obj.member('row'))
    col = resolver.run(obj.member('col'))
    return sp.sparse.coo_matrix((data, (row, col)), shape=shape, dtype=value_type)


def csc_matrix_builder(client, value, builder, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::CSCMatrix<%s>' % value.dtype.name
    meta['value_type_'] = value.dtype.name
    meta['shape_'] = to_json(value.shape)
    meta['ndim'] = value.ndim
    meta['nnz'] = value.nnz
    meta.add_member('data', builder.run(client, value.data, **kw))
    meta.add_member('indices', builder.run(client, value.indices, **kw))
    meta.add_member('indptr', builder.run(client, value.indptr, **kw))
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nnz * value.dtype.itemsize
    return client.create_metadata(meta)


def csc_matrix_resolver(obj, resolver):
    meta = obj.meta
    shape = from_json(meta['shape_'])
    value_type = normalize_dtype(meta['value_type_'])
    data = resolver.run(obj.member('data'))
    indices = resolver.run(obj.member('indices'))
    indptr = resolver.run(obj.member('indptr'))
    return sp.sparse.csc_matrix((data, indices, indptr), shape=shape, dtype=value_type)


def csr_matrix_builder(client, value, builder, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::CSRMatrix<%s>' % value.dtype.name
    meta['value_type_'] = value.dtype.name
    meta['shape_'] = to_json(value.shape)
    meta['ndim'] = value.ndim
    meta['nnz'] = value.nnz
    meta.add_member('data', builder.run(client, value.data, **kw))
    meta.add_member('indices', builder.run(client, value.indices, **kw))
    meta.add_member('indptr', builder.run(client, value.indptr, **kw))
    meta['has_sorted_indices'] = value.has_sorted_indices
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nnz * value.dtype.itemsize
    return client.create_metadata(meta)


def csr_matrix_resolver(obj, resolver):
    meta = obj.meta
    shape = from_json(meta['shape_'])
    value_type = normalize_dtype(meta['value_type_'])
    data = resolver.run(obj.member('data'))
    indices = resolver.run(obj.member('indices'))
    indptr = resolver.run(obj.member('indptr'))
    return sp.sparse.csr_matrix((data, indices, indptr), shape=shape, dtype=value_type)


def dia_matrix_builder(client, value, builder, **kw):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::DIAMatrix<%s>' % value.dtype.name
    meta['value_type_'] = value.dtype.name
    meta['shape_'] = to_json(value.shape)
    meta['ndim'] = value.ndim
    meta['nnz'] = value.nnz
    meta.add_member('data', builder.run(client, value.data, **kw))
    meta.add_member('offsets', builder.run(client, value.offsets, **kw))
    meta['partition_index_'] = to_json(kw.get('partition_index', []))
    meta['nbytes'] = value.nnz * value.dtype.itemsize
    return client.create_metadata(meta)


def dia_matrix_resolver(obj, resolver):
    meta = obj.meta
    shape = from_json(meta['shape_'])
    value_type = normalize_dtype(meta['value_type_'])
    data = resolver.run(obj.member('data'))
    offsets = resolver.run(obj.member('offsets'))
    return sp.sparse.dia_matrix((data, offsets), shape=shape, dtype=value_type)


def dok_matrix_builder(client, value, **kw):
    # FIXME
    raise NotImplementedError('sp.sparse.dok_matrix is not supported')


def dok_matrix_resolver(obj):
    # FIXME
    raise NotImplementedError('sp.sparse.dok_matrix is not supported')


def lil_matrix_builder(client, value, builder, **kw):
    # FIXME
    raise NotImplementedError('sp.sparse.lil_matrix is not supported')


def lil_matrix_resolver(obj):
    # FIXME
    raise NotImplementedError('sp.sparse.lil_matrix is not supported')


def make_global_tensor(
    client, blocks, extra_meta=None, shape=None, partition_shape=None
):
    meta = ObjectMeta()
    meta['typename'] = 'vineyard::GlobalTensor'
    meta.set_global(True)
    meta['partitions_-size'] = len(blocks)
    if extra_meta:
        for k, v in extra_meta.items():
            meta[k] = v

    if 'shape_' not in meta:
        if shape is not None:
            meta['shape_'] = to_json(tuple(shape))
        else:
            meta['shape_'] = to_json(())
    if 'partition_shape_' not in meta:
        if partition_shape is not None:
            meta['partition_shape_'] = to_json(tuple(partition_shape))
        else:
            meta['partition_shape_'] = to_json(())

    for idx, block in enumerate(blocks):
        if not isinstance(block, (ObjectMeta, ObjectID, Object)):
            block = ObjectID(block)
        meta.add_member('partitions_-%d' % idx, block)

    gtensor_meta = client.create_metadata(meta)
    client.persist(gtensor_meta)
    return gtensor_meta


def register_tensor_types(builder_ctx, resolver_ctx):
    if builder_ctx is not None:
        builder_ctx.register(np.ndarray, numpy_ndarray_builder)

        if sp is not None:
            builder_ctx.register(sp.sparse.bsr_matrix, bsr_matrix_builder)
            builder_ctx.register(sp.sparse.coo_matrix, coo_matrix_builder)
            builder_ctx.register(sp.sparse.csc_matrix, csc_matrix_builder)
            builder_ctx.register(sp.sparse.csr_matrix, csr_matrix_builder)
            builder_ctx.register(sp.sparse.dia_matrix, dia_matrix_builder)
            builder_ctx.register(sp.sparse.dok_matrix, dok_matrix_builder)
            builder_ctx.register(sp.sparse.lil_matrix, lil_matrix_builder)

    if resolver_ctx is not None:
        resolver_ctx.register('vineyard::Tensor', numpy_ndarray_resolver)

        if sp is not None:
            resolver_ctx.register('vineyard::BSRMatrix', bsr_matrix_resolver)
            resolver_ctx.register('vineyard::COOMatrix', coo_matrix_resolver)
            resolver_ctx.register('vineyard::CSCMatrix', csc_matrix_resolver)
            resolver_ctx.register('vineyard::CSRMatrix', csr_matrix_resolver)
            resolver_ctx.register('vineyard::DIAMatrix', dia_matrix_resolver)
            resolver_ctx.register('vineyard::DOKMatrix', dok_matrix_resolver)
            resolver_ctx.register('vineyard::LILMatrix', lil_matrix_resolver)
