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

import numpy as np
import pandas as pd

import pytest
import pytest_cases

from vineyard.conftest import vineyard_client
from vineyard.conftest import vineyard_rpc_client
from vineyard.core import default_builder_context
from vineyard.core import default_resolver_context
from vineyard.data import register_builtin_types
from vineyard.data.dataframe import NDArrayArray

register_builtin_types(default_builder_context, default_resolver_context)


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe(vineyard_client):
    df = pd.DataFrame({'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8]})
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe_string(vineyard_client):
    # see gh#533
    df = pd.DataFrame({'a': ['1', '2', '3', '4'], 'b': ['5', '6', '7', '8']})
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe_empty(vineyard_client):
    # see gh#533
    df = pd.DataFrame({'a': [1, 2, 3, 4], 'b': ['5', '6', '7', '8']})
    df = df.iloc[0:0]
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe_complex_columns(vineyard_client):
    # see gh#533
    df = pd.DataFrame([1, 2, 3, 4], columns=[['x']])
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe_int_columns(vineyard_client):
    df = pd.DataFrame({1: [1, 2, 3, 4], 2: [5, 6, 7, 8]})
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_pandas_dataframe_mixed_columns(vineyard_client):
    df = pd.DataFrame(
        {'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8], 1: [9, 10, 11, 12], 2: [13, 14, 15, 16]}
    )
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_reindex(vineyard_client):
    df = pd.DataFrame(np.random.rand(10, 5), columns=['c1', 'c2', 'c3', 'c4', 'c5'])
    expected = df.reindex(index=np.arange(10, 1, -1))
    object_id = vineyard_client.put(expected)
    pd.testing.assert_frame_equal(expected, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_set_index(vineyard_client):
    df1 = pd.DataFrame(
        [[1, 3, 3], [4, 2, 6], [7, 8, 9]],
        index=['a1', 'a2', 'a3'],
        columns=['x', 'y', 'z'],
    )
    expected = df1.set_index('y', drop=True)
    object_id = vineyard_client.put(expected)
    pd.testing.assert_frame_equal(expected, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_sparse_array(vineyard_client):
    arr = np.random.randn(10)
    arr[2:5] = np.nan
    arr[7:8] = np.nan
    sparr = pd.arrays.SparseArray(arr)
    object_id = vineyard_client.put(sparr)
    pd.testing.assert_extension_array_equal(sparr, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_with_sparse_array(vineyard_client):
    df = pd.DataFrame(np.random.randn(100, 4), columns=['x', 'y', 'z', 'a'])
    df.iloc[:98] = np.nan
    sdf = df.astype(pd.SparseDtype("float", np.nan))
    object_id = vineyard_client.put(sdf)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_with_sparse_array_int_columns(vineyard_client):
    df = pd.DataFrame(np.random.randn(100, 4), columns=[1, 2, 3, 4])
    df.iloc[:98] = np.nan
    sdf = df.astype(pd.SparseDtype("float", np.nan))
    object_id = vineyard_client.put(sdf)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_with_sparse_array_mixed_columns(vineyard_client):
    df = pd.DataFrame(np.random.randn(100, 4), columns=['x', 'y', 'z', 0])
    df.iloc[:98] = np.nan
    sdf = df.astype(pd.SparseDtype("float", np.nan))
    object_id = vineyard_client.put(sdf)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_with_datetime(vineyard_client):
    # GH-575
    dates = [
        pd.Timestamp("2012-05-01"),
        pd.Timestamp("2012-05-02"),
        pd.Timestamp("2012-05-03"),
    ]
    pd.DataFrame(pd.Series(dates))
    df = pd.DataFrame(pd.Series(dates))
    object_id = vineyard_client.put(df)
    pd.testing.assert_frame_equal(df, vineyard_client.get(object_id))


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_dataframe_with_multidimensional(vineyard_client):
    df = pd.DataFrame(
        {
            'data': NDArrayArray(np.random.rand(1000, 10)),
            'label': np.random.randint(0, 2, size=(1000,)),
        }
    )
    object_id = vineyard_client.put(df)
    value = vineyard_client.get(object_id)

    assert value.shape == df.shape


def test_dataframe_reusing(vineyard_client):
    nparr = np.ones(1000)
    df = pd.DataFrame({"x": nparr})
    df_id = vineyard_client.put(df)
    df = vineyard_client.get(df_id)

    df2 = pd.DataFrame(df)
    df2["y"] = nparr
    df2_id = vineyard_client.put(df2)
    df2 = vineyard_client.get(df2_id)

    meta1 = vineyard_client.get_meta(df_id)
    meta2 = vineyard_client.get_meta(df2_id)

    # share the same blob
    assert (
        meta1['__values_-value-0']['buffer_'].id
        == meta2['__values_-value-0']['buffer_'].id
    )


@pytest.mark.parametrize(
    "value",
    [
        pd.DataFrame({'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8]}),
        pd.DataFrame({'a': ['1', '2', '3', '4'], 'b': ['5', '6', '7', '8']}),
        pd.DataFrame([1, 2, 3, 4], columns=[['x']]),
        pd.DataFrame({1: [1, 2, 3, 4], 2: [5, 6, 7, 8]}),
        pd.DataFrame(
            {
                'a': [1, 2, 3, 4],
                'b': [5, 6, 7, 8],
                1: [9, 10, 11, 12],
                2: [13, 14, 15, 16],
            }
        ),
        pd.DataFrame(np.random.rand(10, 5), columns=['c1', 'c2', 'c3', 'c4', 'c5']),
        pd.DataFrame(
            [[1, 3, 3], [4, 2, 6], [7, 8, 9]],
            index=['a1', 'a2', 'a3'],
            columns=['x', 'y', 'z'],
        ),
        pd.arrays.SparseArray(np.random.randn(10)),
        pd.DataFrame(np.random.randn(100, 4), columns=['x', 'y', 'z', 'a']).astype(
            pd.SparseDtype("float", np.nan)
        ),
        pd.DataFrame(np.random.randn(100, 4), columns=[1, 2, 3, 4]).astype(
            pd.SparseDtype("float", np.nan)
        ),
        pd.DataFrame(np.random.randn(100, 4), columns=['x', 'y', 'z', 0]).astype(
            pd.SparseDtype("float", np.nan)
        ),
        pd.DataFrame(
            pd.Series(
                [
                    pd.Timestamp("2012-05-01"),
                    pd.Timestamp("2012-05-02"),
                    pd.Timestamp("2012-05-03"),
                ]
            )
        ),
    ],
)
def test_data_consistency_between_ipc_and_rpc(
    value, vineyard_client, vineyard_rpc_client
):
    if isinstance(value, pd.arrays.SparseArray):
        value = pd.DataFrame(value)
    object_id = vineyard_client.put(value)
    pd.testing.assert_frame_equal(
        vineyard_client.get(object_id), vineyard_rpc_client.get(object_id)
    )
    object_id = vineyard_rpc_client.put(value)
    pd.testing.assert_frame_equal(
        vineyard_client.get(object_id), vineyard_rpc_client.get(object_id)
    )
