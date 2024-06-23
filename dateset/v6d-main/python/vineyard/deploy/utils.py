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

import contextlib
import logging
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import time

import pkg_resources
import psutil

try:
    import kubernetes
except ImportError:
    kubernetes = None

logger = logging.getLogger('vineyard')


def ssh_base_cmd(host):
    return [
        'ssh',
        host,
        '--',
        'shopt',
        '-s',
        'huponexit',
        '2>/dev/null',
        '||',
        'setopt',
        'HUP',
        '2>/dev/null',
        '||',
        'true;',
    ]


def find_executable(name, search_paths=None):
    '''Use executable in local build directory first.'''
    if search_paths:
        for path in search_paths:
            exe = os.path.join(path, name)
            if os.path.isfile(exe) and os.access(exe, os.R_OK):
                return exe
    exe = shutil.which(name)
    if exe is not None:
        return exe
    raise RuntimeError('Unable to find program %s' % name)


@contextlib.contextmanager
def start_program(
    name, *args, verbose=False, nowait=False, search_paths=None, shell=False, **kwargs
):
    # actually start a new program that will be running forever
    env, cmdargs = os.environ.copy(), list(args)
    for k, v in kwargs.items():
        if k[0].isupper():
            env[k] = str(v)
        else:
            cmdargs.append('--%s' % k)
            cmdargs.append(str(v))

    proc = None
    try:
        prog = find_executable(name, search_paths=search_paths)
        print('Starting %s... with %s' % (prog, ' '.join(cmdargs)), flush=True)
        if verbose:
            out, err = sys.stdout, sys.stderr
        else:
            out, err = subprocess.PIPE, subprocess.PIPE
        proc = subprocess.Popen(
            [prog] + cmdargs, env=env, stdout=out, stderr=err, shell=shell
        )
        if not nowait:
            time.sleep(1)
        rc = proc.poll()
        if rc is not None:
            raise RuntimeError('Failed to launch program %s' % name)
        yield proc
    finally:
        print('Terminating %s' % prog, flush=True)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(60)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def port_is_inuse(port):
    try:
        if port not in [conn.laddr.port for conn in psutil.net_connections()]:
            return False
    except (psutil.AccessDenied, RuntimeError):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return False
    return True


def find_port_probe(start=2048, end=20480):
    '''Find an available port in range [start, end)'''
    for port in range(start, end):
        if not port_is_inuse(port):
            yield port


ipc_port_finder = find_port_probe()


def find_port():
    return next(ipc_port_finder)


def check_socket(address):
    if isinstance(address, tuple):
        socket_type = socket.AF_INET
    else:
        socket_type = socket.AF_UNIX
    with contextlib.closing(socket.socket(socket_type, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(address) == 0


def _check_executable(path):
    if path and os.path.isfile(path) and os.access(path, os.R_OK | os.X_OK):
        return path
    return None


__vineyardd_path = None


def find_vineyardd_path():
    global __vineyardd_path

    if __vineyardd_path is not None:
        return __vineyardd_path

    current_dir = os.path.dirname(__file__)

    # find vineyard in the package
    resource_path = None
    vineyardd_path = None
    try:
        # `pkg_resources.resource_filename` may causing `TypeError`
        resource_path = pkg_resources.resource_filename('vineyard.bdist', 'vineyardd')
    except:  # noqa: E722, pylint: disable=bare-except
        resource_path = None
    if resource_path is not None:
        vineyardd_path = _check_executable(resource_path)
    if vineyardd_path is None:
        vineyardd_path = _check_executable(
            os.path.join(current_dir, '..', 'bdist', 'vineyardd')
        )
    if vineyardd_path is None:
        vineyardd_path = _check_executable(os.path.join(current_dir, '..', 'vineyardd'))

    if vineyardd_path is None:
        vineyardd_path = _check_executable(
            os.path.join(current_dir, '..', '..', '..', 'build', 'bin', 'vineyardd')
        )

    if vineyardd_path is None:
        vineyardd_path = _check_executable(shutil.which('vineyardd'))

    __vineyardd_path = vineyardd_path
    return vineyardd_path


__vineyardctl_path = None


def find_vineyardctl_path():
    global __vineyardctl_path

    if __vineyardctl_path is not None:
        return __vineyardctl_path

    current_dir = os.path.dirname(__file__)

    # find vineyardctl in the package
    resource_path = None
    vineyardctl_path = None
    try:
        # `pkg_resources.resource_filename` may causing `TypeError`
        resource_path = pkg_resources.resource_filename('vineyard.bdist', 'vineyardctl')
    except:  # noqa: E722, pylint: disable=bare-except
        resource_path = None
    if resource_path is not None:
        vineyardctl_path = _check_executable(resource_path)
    if vineyardctl_path is None:
        vineyardctl_path = _check_executable(
            os.path.join(current_dir, '..', 'bdist', 'vineyardctl')
        )
    if vineyardctl_path is None:
        vineyardctl_path = _check_executable(
            os.path.join(current_dir, '..', 'vineyardctl')
        )

    if vineyardctl_path is None:
        vineyardctl_path = _check_executable(
            os.path.join(current_dir, '..', '..', '..', 'k8s', 'vineyardctl')
        )

    if vineyardctl_path is None:
        vineyardctl_path = _check_executable(shutil.which('vineyardctl'))

    __vineyardctl_path = vineyardctl_path
    return vineyardctl_path


@contextlib.contextmanager
def start_etcd(host=None, etcd_executable=None):
    if etcd_executable is None:
        etcd_executable = '/usr/local/bin/etcd'
    if host is None:
        srv_host = '127.0.0.1'
        client_port = find_port()
        peer_port = find_port()
    else:
        srv_host = host
        client_port = 2379
        peer_port = 2380

    prog_args = [
        etcd_executable,
        '--max-txn-ops=102400',
        '--listen-peer-urls',
        'http://0.0.0.0:%d' % peer_port,
        '--listen-client-urls',
        'http://0.0.0.0:%d' % client_port,
        '--advertise-client-urls',
        'http://%s:%d' % (srv_host, client_port),
        '--initial-cluster',
        'default=http://%s:%d' % (srv_host, peer_port),
        '--initial-advertise-peer-urls',
        'http://%s:%d' % (srv_host, peer_port),
    ]

    proc = None
    try:
        if host is None:
            commands = []
        else:
            commands = ssh_base_cmd(host)
        proc = subprocess.Popen(
            commands + prog_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            encoding='utf-8',
        )

        rc = proc.poll()
        while rc is None:
            if check_socket(('0.0.0.0', client_port)):
                break
            time.sleep(1)
            rc = proc.poll()

        if rc is not None:
            err = textwrap.indent(proc.stdout.read(), ' ' * 4)
            raise RuntimeError(
                'Failed to launch program etcd on %s, error:\n%s' % (srv_host, err)
            )
        yield proc, 'http://%s:%d' % (srv_host, client_port)
    finally:
        logging.info('Etcd being killed...')
        if proc is not None and proc.poll() is None:
            proc.terminate()


def ensure_kubernetes_namespace(namespace, k8s_client=None):
    if kubernetes is None:
        raise RuntimeError('Please install the package python "kubernetes" first')
    if k8s_client is None:
        kubernetes.config.load_kube_config()
        k8s_client = kubernetes.client.ApiClient()
    corev1 = kubernetes.client.CoreV1Api(k8s_client)
    try:
        corev1.read_namespace(namespace)
    except kubernetes.client.rest.ApiException:
        corev1.create_namespace(
            kubernetes.client.V1Namespace(metadata={'name': namespace})
        )
