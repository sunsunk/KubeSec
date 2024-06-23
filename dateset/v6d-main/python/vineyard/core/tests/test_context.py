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

from vineyard.core import default_builder_context
from vineyard.core import default_resolver_context
from vineyard.core.resolver import resolver_context
from vineyard.data import register_builtin_types

register_builtin_types(default_builder_context, default_resolver_context)


def fake_sequence_resolver(obj, resolver):  # pylint: disable=unused-argument
    return 'faked sequence'


def test_resolver_context(vineyard_client):
    value = (1, 2, 3, 4)
    o = vineyard_client.put(value)
    result = vineyard_client.get(o)
    assert result == value
    assert result != 'faked sequence'

    with resolver_context() as ctx:
        ctx.register('vineyard::Sequence', fake_sequence_resolver)

        result = vineyard_client.get(o)
        assert result != value
        assert result == 'faked sequence'

    result = vineyard_client.get(o)
    assert result == value
    assert result != 'faked sequence'

    with resolver_context({'vineyard::Sequence': fake_sequence_resolver}) as ctx:
        result = vineyard_client.get(o)
        assert result != value
        assert result == 'faked sequence'

    result = vineyard_client.get(o)
    assert result == value
    assert result != 'faked sequence'
