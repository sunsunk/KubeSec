#!/usr/bin/env python3
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

from argparse import ArgumentParser
from distutils.util import strtobool

from .cpp import codegen as cppgen
from .java import codegen as javagen
from .parsing import parse_deps
from .parsing import parse_module
from .python import codegen as pythongen


def codegen(
    root_directory,
    language,
    source,
    target=None,
    package=None,
    system_includes=None,
    includes=None,
    extra_flags=None,
    build_directory=None,
    delayed=True,
    verbose=False,
    **kwargs,
):
    if language == 'java':
        javagen(
            root_directory,
            source,
            target,
            package,
            system_includes,
            includes,
            extra_flags,
            build_directory,
            verbose,
            **kwargs,
        )
        return

    content, to_reflect, _, _ = parse_module(  # pylint: disable=too-many-function-args
        root_directory=root_directory,
        source=source,
        target=target,
        system_includes=system_includes,
        includes=includes,
        extra_flags=extra_flags,
        build_directory=build_directory,
        delayed=delayed,
        parse_only=False,
        verbose=verbose,
    )
    if language == 'cpp':
        cppgen(root_directory, content, to_reflect, source, target, verbose)
    elif language == 'python':
        pythongen(  # pylint: disable=too-many-function-args
            root_directory, content, to_reflect, source, target, verbose
        )
    else:
        raise ValueError('Not supported language: %s' % language)


def parse_sys_args():
    arg_parser = ArgumentParser()

    arg_parser.add_argument(
        '-d',
        '--dump-dependencies',
        type=lambda x: bool(strtobool(x)),
        nargs='?',
        const=True,
        default=False,
        help='Just dump module dependencies, without code generation',
    )
    arg_parser.add_argument(
        '-r',
        '--root-directory',
        type=str,
        default='.',
        help='Root directory for code generation.',
    )
    arg_parser.add_argument(
        '-isystem',
        '--system-includes',
        type=str,
        default='',
        help='Directories that will been included in CMakeLists.txt',
    )
    arg_parser.add_argument(
        '-I',
        '--includes',
        type=str,
        default='',
        help='Directories that will been included in CMakeLists.txt',
    )
    arg_parser.add_argument(
        '-l',
        '--language',
        type=str,
        default='cpp',
        help="Language interfaces to generate",
    )
    arg_parser.add_argument(
        '-s',
        '--source',
        type=str,
        required=True,
        help='Data structure source file to parse',
    )
    arg_parser.add_argument(
        '-t', '--target', type=str, default=None, help='Output path to be generated'
    )
    arg_parser.add_argument(
        '-b',
        '--build-directory',
        type=str,
        default=None,
        help='Build directory that contains compilation database '
        '(compile_commands.json)',
    )
    arg_parser.add_argument(
        '-p',
        '--package',
        type=str,
        default=None,
        help='Package directory for Java/Python bindings',
    )
    arg_parser.add_argument(
        '-pkg',
        '--package-name',
        type=str,
        default=None,
        help="Package name for Java/Python bindings",
    )
    arg_parser.add_argument(
        '-lib',
        '--ffilibrary-name',
        type=str,
        default=None,
        help="FFI library name for Java/Python bindings",
    )
    arg_parser.add_argument(
        '-e',
        '--excludes',
        type=str,
        default=None,
        help="Excluded declarations for Java/Python bindings",
    )
    arg_parser.add_argument(
        '-fwd',
        '--forwards',
        type=str,
        default=None,
        help="Forward declrations for Java/Python bindings",
    )
    arg_parser.add_argument(
        '-f',
        '--extra-flags',
        type=str,
        action='append',
        default=list(),
        help='Extra flags that will be passed to libclang',
    )
    arg_parser.add_argument(
        '--delayed', action='store_true', help='Delayed the template parsing'
    )
    arg_parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Run codegen script with verbose output',
    )
    return arg_parser.parse_args()


def main():
    args = parse_sys_args()
    if args.dump_dependencies:
        parse_deps(
            args.root_directory,
            args.source,
            args.target,
            args.system_includes,
            args.includes,
            args.extra_flags,
            args.build_directory,
            args.delayed,
            args.verbose,
        )
    else:
        codegen(
            args.root_directory,
            args.language,
            args.source,
            args.target,
            args.package,
            args.system_includes,
            args.includes,
            args.extra_flags,
            args.build_directory,
            args.delayed,
            args.verbose,
            package_name=args.package_name,
            ffilibrary_name=args.ffilibrary_name,
            excludes=args.excludes,
            forwards=args.forwards,
        )


if __name__ == '__main__':
    main()
