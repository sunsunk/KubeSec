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

import copy
import itertools
from typing import Any
from typing import Dict

import numpy as np
import pandas as pd
import pyarrow as pa

import lazy_import
import pytest
import pytest_cases

from vineyard.conftest import vineyard_client
from vineyard.conftest import vineyard_rpc_client
from vineyard.contrib.ml.torch import torch_context
from vineyard.data.dataframe import NDArrayArray

torch = lazy_import.lazy_module("torch")
nn = lazy_import.lazy_module("torch.nn")
F = lazy_import.lazy_module("torch.nn.functional")
torchdata = lazy_import.lazy_module("torchdata")


@pytest.fixture(scope="module", autouse=True)
def vineyard_for_torch():
    with torch_context():
        yield


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_tensor(vineyard_client):
    tensor = torch.ones(5, 2)
    object_id = vineyard_client.put(tensor)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.Tensor)
    assert value.shape == tensor.shape
    assert value.dtype == tensor.dtype
    assert torch.equal(value, tensor)


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_dataset(vineyard_client):
    dataset = torch.utils.data.TensorDataset(
        *[
            torch.from_numpy(np.random.rand(2, 3)),
            torch.from_numpy(np.random.rand(2, 3)),
        ],
    )
    object_id = vineyard_client.put(dataset)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.utils.data.TensorDataset)
    assert len(value.tensors) == len(dataset.tensors)
    for t1, t2 in zip(value.tensors, dataset.tensors):
        assert t1.shape == t2.shape
        assert t1.dtype == t2.dtype
        assert torch.isclose(t1, t2).all()


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_dataset_dataframe(vineyard_client):
    df = pd.DataFrame({'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8], 'c': [1.0, 2.0, 3.0, 4.0]})
    object_id = vineyard_client.put(df)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.utils.data.TensorDataset)
    assert len(df.columns) == len(value.tensors)

    assert torch.isclose(value.tensors[0], torch.from_numpy([1, 2, 3, 4])).all()
    assert torch.isclose(value.tensors[1], torch.from_numpy([5, 6, 7, 8])).all()
    assert torch.isclose(
        value.tensors[2], torch.from_numpy([1.0, 2.0, 3.0, 4.0], dtype=torch.float64)
    ).all()


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_dataset_dataframe_multidimensional(vineyard_client):
    df = pd.DataFrame(
        {
            'data': NDArrayArray(np.random.rand(1000, 10)),
            'label': np.random.randint(0, 2, size=(1000,)),
        }
    )
    object_id = vineyard_client.put(df)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.utils.data.TensorDataset)
    assert len(df.columns) == len(value.tensors)


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_dataset_recordbatch(vineyard_client):
    df = pd.DataFrame({'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8], 'c': [1.0, 2.0, 3.0, 4.0]})
    batch = pa.RecordBatch.from_pandas(df)
    object_id = vineyard_client.put(batch)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.utils.data.TensorDataset)
    assert len(df.columns) == len(value.tensors)

    assert torch.isclose(value.tensors[0], torch.from_numpy([1, 2, 3, 4])).all()
    assert torch.isclose(value.tensors[1], torch.from_numpy([5, 6, 7, 8])).all()
    assert torch.isclose(
        value.tensors[2], torch.from_numpy([1.0, 2.0, 3.0, 4.0], dtype=torch.float64)
    ).all()


@pytest_cases.parametrize("vineyard_client", [vineyard_client, vineyard_rpc_client])
def test_torch_dataset_table(vineyard_client):
    df = pd.DataFrame({'a': [1, 2, 3, 4], 'b': [5, 6, 7, 8], 'c': [1.0, 2.0, 3.0, 4.0]})
    table = pa.Table.from_pandas(df)
    object_id = vineyard_client.put(table)
    value = vineyard_client.get(object_id)

    assert isinstance(value, torch.utils.data.TensorDataset)
    assert len(df.columns) == len(value.tensors)

    assert torch.isclose(value.tensors[0], torch.from_numpy([1, 2, 3, 4])).all()
    assert torch.isclose(value.tensors[1], torch.from_numpy([5, 6, 7, 8])).all()
    assert torch.isclose(
        value.tensors[2], torch.from_numpy([1.0, 2.0, 3.0, 4.0], dtype=torch.float64)
    ).all()


class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(1, 20, 5)
        self.conv2 = nn.Conv2d(20, 20, 5)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        return F.relu(self.conv2(x))


def assert_torch_module_equal(model1, model2):
    assert isinstance(model1, nn.Module)
    assert isinstance(model2, nn.Module)
    assert len(list(model1.parameters())) == len(list(model2.parameters()))
    for p1, p2 in zip(model1.parameters(), model2.parameters()):
        assert torch.allclose(p1, p2), f'{p1} != {p2}'


@pytest_cases.parametrize(
    "vineyard_client,model",
    itertools.product(
        [vineyard_client, vineyard_rpc_client],
        [nn.Linear(5, 2), nn.Conv2d(1, 20, 5), Model()],
    ),
)
def test_torch_module(vineyard_client, model):
    object_id = vineyard_client.put(model)
    value: Dict[str, Any] = vineyard_client.get(object_id)

    result = copy.deepcopy(model)
    result.to(torch.device('meta'))
    result.load_state_dict(value, assign=True)

    # check the module's equality
    assert_torch_module_equal(model, result)
