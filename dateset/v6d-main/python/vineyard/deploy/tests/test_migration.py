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

import itertools
import json
import logging

import numpy as np
import pandas as pd

import pytest

import vineyard
from vineyard.core import default_builder_context
from vineyard.core import default_resolver_context
from vineyard.data import register_builtin_types

register_builtin_types(default_builder_context, default_resolver_context)

logger = logging.getLogger('vineyard')


@pytest.mark.skip_without_migration()
def test_migration(vineyard_ipc_sockets):
    vineyard_ipc_sockets = list(
        itertools.islice(itertools.cycle(vineyard_ipc_sockets), 2)
    )

    client1 = vineyard.connect(vineyard_ipc_sockets[0])
    client2 = vineyard.connect(vineyard_ipc_sockets[1])

    # test on scalars

    # test if metadata of remote object available
    data = "abcdefgh"
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)

    # migrate local to local: do nothing.
    o1 = client1.migrate(o)
    assert o == o1
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    o2 = client2.migrate(o)
    assert o != o2
    assert client1.get(o1) == client2.get(o2)
    logger.info('------- finish migrate remote --------')

    # test on numpy ndarray

    # test if metadata of remote object available
    data = np.ones((1, 2, 3, 4, 5))
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)
    assert data.shape == tuple(json.loads(meta['shape_']))

    # migrate local to local: do nothing.
    o1 = client1.migrate(o)
    assert o == o1
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    o2 = client2.migrate(o)
    assert o != o2
    np.testing.assert_allclose(client1.get(o1), client2.get(o2))
    logger.info('------- finish migrate remote --------')

    # test on pandas dataframe

    # test if metadata of remote object available
    data = pd.DataFrame(np.ones((1, 2)))
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)

    # migrate local to local: do nothing.
    o1 = client1.migrate(o)
    assert o == o1
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    o2 = client2.migrate(o)
    assert o != o2
    pd.testing.assert_frame_equal(client1.get(o1), client2.get(o2))
    logger.info('------- finish migrate remote --------')


@pytest.mark.skip_without_migration()
def test_fetch_and_get(vineyard_ipc_sockets):
    vineyard_ipc_sockets = list(
        itertools.islice(itertools.cycle(vineyard_ipc_sockets), 2)
    )

    client1 = vineyard.connect(vineyard_ipc_sockets[0])
    client2 = vineyard.connect(vineyard_ipc_sockets[1])

    # test on scalars

    # test if metadata of remote object available
    data = "abcdefgh"
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)

    # migrate local to local: do nothing.
    assert client1.get(o) == client1.get(o, fetch=True)
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    assert client1.get(o) == client2.get(o, fetch=True)
    logger.info('------- finish migrate remote --------')

    # test on numpy ndarray

    # test if metadata of remote object available
    data = np.ones((1, 2, 3, 4, 5))
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)
    assert data.shape == tuple(json.loads(meta['shape_']))

    # migrate local to local: do nothing.
    np.testing.assert_allclose(client1.get(o), client1.get(o, fetch=True))
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    np.testing.assert_allclose(client1.get(o), client2.get(o, fetch=True))
    logger.info('------- finish migrate remote --------')

    # test on pandas dataframe

    # test if metadata of remote object available
    data = pd.DataFrame(np.ones((33, 44)))
    o = client1.put(data)
    client1.persist(o)
    meta = client2.get_meta(o, sync_remote=True)

    # migrate local to local: do nothing.
    pd.testing.assert_frame_equal(client1.get(o), client1.get(o, fetch=True))
    logger.info('------- finish migrate local --------')

    # migrate remote to local: do nothing.
    pd.testing.assert_frame_equal(client1.get(o), client2.get(o, fetch=True))
    logger.info('------- finish migrate remote --------')


@pytest.mark.skip_without_migration()
def test_migration_and_deletion(
    vineyard_ipc_sockets,
):  # pylint: disable=too-many-statements
    vineyard_ipc_sockets = list(
        itertools.islice(itertools.cycle(vineyard_ipc_sockets), 2)
    )

    client1 = vineyard.connect(vineyard_ipc_sockets[0])
    client2 = vineyard.connect(vineyard_ipc_sockets[1])

    data1 = np.ones((1, 2, 3, 4, 5))
    o1 = client1.put(data1)
    client1.persist(o1)
    meta1 = client2.get_meta(o1, sync_remote=True)
    assert data1.shape == tuple(json.loads(meta1['shape_']))

    data2 = np.zeros((1, 2, 3, 4, 5))
    o2 = client2.put(data2)
    client2.persist(o2)
    meta2 = client1.get_meta(o2, sync_remote=True)
    assert data2.shape == tuple(json.loads(meta2['shape_']))

    # make the global object
    o = client1.put((o1, o2), global_=True)
    gmeta = client1.get_meta(o, sync_remote=True)
    client1.persist(o)
    assert not gmeta.islocal
    assert gmeta.isglobal

    # migrate o2 to h1, as o3
    o3 = client1.migrate(o2)
    assert o3 != o1
    assert o3 != o2
    logger.info('------- finish migrate remote --------')

    # delete the o2
    client1.sync_meta()
    client1.delete(o2, force=False, deep=True)
    logger.info('------- finish delete original chunk --------')

    client1.sync_meta()
    assert client1.exists(o)
    assert client1.exists(o1)
    assert client1.exists(o3)
    assert not client1.exists(o2)

    with pytest.raises(vineyard.ObjectNotExistsException):
        print(client1.get_meta(o2))

    client2.sync_meta()
    assert client2.exists(o)
    assert client2.exists(o1)
    assert client2.exists(o3)
    assert not client2.exists(o2)

    with pytest.raises(vineyard.ObjectNotExistsException):
        print(client2.get_meta(o2))

    # delete the o3
    client2.sync_meta()
    client2.delete(o3, force=False, deep=True)
    logger.info('------- finish delete migrated chunk --------')

    client1.sync_meta()
    assert client1.exists(o)
    assert client1.exists(o1)
    assert client1.exists(o3)
    assert not client1.exists(o2)

    with pytest.raises(vineyard.ObjectNotExistsException):
        print(client1.get_meta(o2))

    client2.sync_meta()
    assert client2.exists(o)
    assert client2.exists(o1)
    assert client2.exists(o3)
    assert not client2.exists(o2)

    with pytest.raises(vineyard.ObjectNotExistsException):
        print(client2.get_meta(o2))


@pytest.mark.skip_without_migration()
def test_migration_large_object(
    vineyard_ipc_sockets,
):  # pylint: disable=too-many-statements
    vineyard_ipc_sockets = list(
        itertools.islice(itertools.cycle(vineyard_ipc_sockets), 2)
    )

    client1 = vineyard.connect(vineyard_ipc_sockets[0])
    client2 = vineyard.connect(vineyard_ipc_sockets[1])

    client1.clear()
    client2.clear()
    data1 = np.ones((1024, 102400))
    o1 = client1.put(data1)
    client1.persist(o1)
    meta1 = client2.get_meta(o1, sync_remote=True)
    assert data1.shape == tuple(json.loads(meta1['shape_']))

    # migrate o1 to h2
    o2 = client2.migrate(o1)
    assert o1 != o2
    np.testing.assert_allclose(client1.get(o1), client2.get(o2))
    logger.info('------- finish migrate remote large object --------')
