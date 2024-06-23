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

import os
import subprocess
import sys

from vineyard.deploy._cobra import click
from vineyard.deploy.utils import find_vineyardctl_path

_vineyardctl = find_vineyardctl_path()


def _register():
    if hasattr(sys.modules[__name__], 'vineyardctl'):
        return
    if _vineyardctl is None:

        def cmd(*args, **kwargs):
            raise RuntimeError("vineyardctl is not bundled")

    else:
        try:
            cmd = click(
                _vineyardctl,
                exclude_args=['dump_usage', 'gen_doc', 'x_version', 'help'],
            )
        except Exception:  # noqa: E722, pylint: disable=bare-except,broad-except

            def cmd(*args, **kwargs):
                raise RuntimeError("Bundled vineyardctl binary doesn't work")

    setattr(sys.modules[__name__], 'vineyardctl', cmd)


def _main(args):
    if _vineyardctl is None:
        raise RuntimeError("vineyardctl is not bundled")
    if os.name == 'nt':
        try:
            return subprocess.call([_vineyardctl] + args)
        except KeyboardInterrupt:
            return 0
    else:
        return os.execvp(_vineyardctl, [_vineyardctl] + args)


__all__ = [  # noqa: F822
    'vineyardctl',  # pylint: disable=undefined-all-variable
]
