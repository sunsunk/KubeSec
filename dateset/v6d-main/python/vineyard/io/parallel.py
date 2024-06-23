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
import logging

from vineyard.core import context
from vineyard.core import resolver_context

logger = logging.getLogger("vineyard")


def parallel_stream_resolver(obj):
    """Return a list of *local* partial streams."""
    meta = obj.meta
    partition_size = int(meta["__streams_-size"])
    logger.debug('parallel stream: partitions = %d', partition_size)
    with resolver_context() as ctx:
        return [
            ctx(meta.get_member("__streams_-%d" % i)) for i in range(partition_size)
        ]


def register_parallel_stream_types(_builder_ctx, resolver_ctx):
    if resolver_ctx is not None:
        resolver_ctx.register('vineyard::ParallelStream', parallel_stream_resolver)


@contextlib.contextmanager
def parallel_stream_context():
    with context() as (builder_ctx, resolver_ctx):
        register_parallel_stream_types(builder_ctx, resolver_ctx)
        yield builder_ctx, resolver_ctx
