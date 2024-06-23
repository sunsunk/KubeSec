#!/usr/bin/env python

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_in_toto_run.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test in_toto_run command line tool.

"""

import glob
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import securesystemslib.interface  # pylint: disable=unused-import

from in_toto.in_toto_run import main as in_toto_run_main
from in_toto.models.link import FILENAME_FORMAT
from in_toto.models.metadata import Metablock, Metadata
from tests.common import CliTestCase, GenKeysMixin, GPGKeysMixin, TmpDirMixin


class TestInTotoRunTool(CliTestCase, TmpDirMixin, GPGKeysMixin, GenKeysMixin):
    """Test in_toto_run's main() - requires sys.argv patching; and
    in_toto_run- calls runlib and error logs/exits on Exception."""

    cli_main_func = staticmethod(in_toto_run_main)

    @classmethod
    def setUpClass(cls):
        """Create and change into temporary directory,
        generate key pair, dummy artifact and base arguments."""
        cls.set_up_test_dir()
        cls.set_up_gpg_keys()
        cls.set_up_keys()

        cls.test_step = "test_step"
        cls.test_link_rsa = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.rsa_key_id
        )
        cls.test_link_ed25519 = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ed25519_key_id
        )
        cls.test_link_ecdsa = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ecdsa_key_id
        )
        cls.test_link_rsa_enc = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.rsa_key_enc_id
        )
        cls.test_link_ed25519_enc = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ed25519_key_enc_id
        )
        cls.test_link_ecdsa_enc = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ecdsa_key_enc_id
        )

        cls.test_artifact = "test_artifact"
        Path(cls.test_artifact).touch()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def tearDown(self):
        for link in glob.glob("*.link"):
            os.remove(link)

    def test_main_required_args(self):
        """Test CLI command with required arguments."""

        args = [
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 0)
        self.assertTrue(os.path.exists(self.test_link_rsa))

    def test_main_optional_args(self):
        """Test CLI command with optional arguments."""

        named_args = [
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--materials",
            self.test_artifact,
            "--products",
            self.test_artifact,
            "--record-streams",
        ]
        positional_args = ["--", "python", "--version"]

        # Test and assert recorded artifacts
        args1 = named_args + positional_args
        self.assert_cli_sys_exit(args1, 0)
        link_metadata = Metablock.load(self.test_link_rsa)
        self.assertTrue(
            self.test_artifact in list(link_metadata.signed.materials.keys())
        )
        self.assertTrue(
            self.test_artifact in list(link_metadata.signed.products.keys())
        )

        # Test and assert exlcuded artifacts
        args2 = named_args + ["--exclude", "*test*"] + positional_args
        self.assert_cli_sys_exit(args2, 0)
        link_metadata = Metablock.load(self.test_link_rsa)
        self.assertFalse(link_metadata.signed.materials)
        self.assertFalse(link_metadata.signed.products)

        # Test with base path
        args3 = named_args + ["--base-path", self.test_dir] + positional_args
        self.assert_cli_sys_exit(args3, 0)
        link_metadata = Metablock.load(self.test_link_rsa)
        self.assertListEqual(
            list(link_metadata.signed.materials.keys()), [self.test_artifact]
        )
        self.assertListEqual(
            list(link_metadata.signed.products.keys()), [self.test_artifact]
        )

        # Test with bogus base path
        args4 = named_args + ["--base-path", "bogus/path"] + positional_args
        self.assert_cli_sys_exit(args4, 1)

        # Test with lstrip path
        strip_prefix = self.test_artifact[:-1]
        args5 = named_args + ["--lstrip-paths", strip_prefix] + positional_args
        self.assert_cli_sys_exit(args5, 0)
        link_metadata = Metablock.load(self.test_link_rsa)
        self.assertListEqual(
            list(link_metadata.signed.materials.keys()),
            [self.test_artifact[len(strip_prefix) :]],
        )
        self.assertListEqual(
            list(link_metadata.signed.products.keys()),
            [self.test_artifact[len(strip_prefix) :]],
        )

    def test_main_with_metadata_directory(self):
        """Test CLI command with metadata directory."""
        tmp_dir = os.path.realpath(tempfile.mkdtemp(dir=os.getcwd()))
        args = [
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--metadata-directory",
            tmp_dir,
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 0)

        linkpath = os.path.join(tmp_dir, self.test_link_rsa)

        self.assertTrue(os.path.exists(linkpath))

    def test_main_with_unencrypted_ed25519_key(self):
        """Test CLI command with ed25519 key."""
        args = [
            "-n",
            self.test_step,
            "--key",
            self.ed25519_key_path,
            "--key-type",
            "ed25519",
            "--",
            "ls",
        ]

        self.assert_cli_sys_exit(args, 0)
        self.assertTrue(os.path.exists(self.test_link_ed25519))

    def test_main_with_unencrypted_ecdsa_key(self):
        """Test CLI command with ecdsa key."""
        args = [
            "-n",
            self.test_step,
            "--key",
            self.ecdsa_key_path,
            "--key-type",
            "ecdsa",
            "--",
            "ls",
        ]

        self.assert_cli_sys_exit(args, 0)
        self.assertTrue(os.path.exists(self.test_link_ecdsa))

    def test_main_with_encrypted_keys(self):
        """Test CLI command with encrypted ed25519 key."""

        for key_type, key_path, link_path in [
            ("rsa", self.rsa_key_enc_path, self.test_link_rsa_enc),
            ("ed25519", self.ed25519_key_enc_path, self.test_link_ed25519_enc),
            ("ecdsa", self.ecdsa_key_enc_path, self.test_link_ecdsa_enc),
        ]:
            # Define common arguments passed to in in-toto-run below
            args = [
                "-n",
                self.test_step,
                "--key",
                key_path,
                "--key-type",
                key_type,
            ]
            cmd = ["--", "python", "--version"]

            # Make sure the link file to be generated doesn't already exist
            self.assertFalse(os.path.exists(link_path))

            # Test 1: Call in-toto-run entering signing key password on prompt
            with mock.patch(
                "securesystemslib.interface.get_password",
                return_value=self.key_pw,
            ):
                self.assert_cli_sys_exit(args + ["--password"] + cmd, 0)

            self.assertTrue(os.path.exists(link_path))
            os.remove(link_path)

            # Test 2: Call in-toto-run passing signing key password
            self.assert_cli_sys_exit(
                args + ["--password", self.key_pw] + cmd, 0
            )
            self.assertTrue(os.path.exists(link_path))
            os.remove(link_path)

    def test_main_with_specified_gpg_key(self):
        """Test CLI command with specified gpg key."""
        args = [
            "-n",
            self.test_step,
            "--gpg",
            self.gpg_key_85da58,
            "--gpg-home",
            self.gnupg_home,
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 0)
        link_filename = FILENAME_FORMAT.format(
            step_name=self.test_step, keyid=self.gpg_key_85da58
        )

        self.assertTrue(os.path.exists(link_filename))

    def test_main_with_default_gpg_key(self):
        """Test CLI command with default gpg key."""
        args = [
            "-n",
            self.test_step,
            "--gpg",
            "--gpg-home",
            self.gnupg_home,
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 0)

        link_filename = FILENAME_FORMAT.format(
            step_name=self.test_step, keyid=self.gpg_key_d92439
        )

        self.assertTrue(os.path.exists(link_filename))

    def test_main_no_command_arg(self):
        """Test CLI command with --no-command argument."""

        args = [
            "in_toto_run.py",
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--no-command",
        ]

        self.assert_cli_sys_exit(args, 0)

        self.assertTrue(os.path.exists(self.test_link_rsa))

    def test_main_wrong_args(self):
        """Test CLI command with missing arguments."""

        wrong_args_list = [
            [],
            ["--step-name", "some"],
            ["--key", self.rsa_key_path],
            ["--", "echo", "blub"],
            ["--step-name", "test-step", "--key", self.rsa_key_path],
            ["--step-name", "--", "echo", "blub"],
            ["--key", self.rsa_key_path, "--", "echo", "blub"],
            ["--step-name", "test-step", "--key", self.rsa_key_path, "--"],
            [
                "--step-name",
                "test-step",
                "--key",
                self.rsa_key_path,
                "--gpg",
                "--",
                "echo",
                "blub",
            ],
        ]

        for wrong_args in wrong_args_list:
            self.assert_cli_sys_exit(wrong_args, 2)
            self.assertFalse(os.path.exists(self.test_link_rsa))

    def test_main_wrong_key_exits(self):
        """Test CLI command with wrong key argument, exits and logs error"""

        args = [
            "--step-name",
            self.test_step,
            "--key",
            "non-existing-key",
            "--",
            "echo",
            "test",
        ]

        self.assert_cli_sys_exit(args, 1)
        self.assertFalse(os.path.exists(self.test_link_rsa))

    def test_main_encrypted_key_but_no_pw(self):
        """Test CLI command exits 1 with encrypted key but no pw."""
        args = ["-n", self.test_step, "--key", self.rsa_key_enc_path, "-x"]
        self.assert_cli_sys_exit(args, 1)
        self.assertFalse(os.path.exists(self.test_link_rsa_enc))

        args = ["-n", self.test_step, "--key", self.ed25519_key_enc_path, "-x"]
        self.assert_cli_sys_exit(args, 1)
        self.assertFalse(os.path.exists(self.test_link_ed25519_enc))

    def test_pkcs8_signing_key(self):
        """Test in-toto-run, sign link with pkcs8 key file for each algo."""
        pems_dir = Path(__file__).parent / "pems"
        args = ["-n", "foo", "-x", "--signing-key"]
        for algo, short_keyid in [
            ("rsa", "2f685fa7"),
            ("ecdsa", "50d7e110"),
            ("ed25519", "c6d8bf2e"),
        ]:
            link_path = Path(f"foo.{short_keyid}.link")

            # Use unencrypted key
            pem_path = pems_dir / f"{algo}_private_unencrypted.pem"
            self.assert_cli_sys_exit(args + [str(pem_path)], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()

            # Fail with encrypted key, but no pw
            pem_path = pems_dir / f"{algo}_private_encrypted.pem"
            self.assert_cli_sys_exit(args + [str(pem_path)], 1)
            self.assertFalse(link_path.exists())

            # Use encrypted key, passing pw
            self.assert_cli_sys_exit(args + [str(pem_path), "-P", "hunter2"], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()

            # Use encrypted key, mocking pw enter on prompt
            with mock.patch(
                "in_toto.in_toto_run.getpass", return_value="hunter2"
            ):
                self.assert_cli_sys_exit(args + [str(pem_path), "-P"], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()


class TestInTotoRunToolWithDSSE(
    CliTestCase, TmpDirMixin, GPGKeysMixin, GenKeysMixin
):
    """Test in_toto_run's main() with --use-dsse argument - requires sys.argv
    patching; and in_toto_run- calls runlib and error logs/exits on Exception.
    """

    cli_main_func = staticmethod(in_toto_run_main)

    @classmethod
    def setUpClass(cls):
        """Create and change into temporary directory,
        generate key pair, dummy artifact and base arguments."""
        cls.set_up_test_dir()
        cls.set_up_gpg_keys()
        cls.set_up_keys()

        cls.test_step = "test_step"
        cls.test_link_rsa = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.rsa_key_id
        )
        cls.test_link_ed25519 = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ed25519_key_id
        )
        cls.test_link_rsa_enc = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.rsa_key_enc_id
        )
        cls.test_link_ed25519_enc = FILENAME_FORMAT.format(
            step_name=cls.test_step, keyid=cls.ed25519_key_enc_id
        )

        cls.test_artifact = "test_artifact"
        Path(cls.test_artifact).touch()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def tearDown(self):
        for link in glob.glob("*.link"):
            os.remove(link)

    def test_main_required_args(self):
        """Test CLI command with required arguments."""

        args = [
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--use-dsse",
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 0)
        self.assertTrue(os.path.exists(self.test_link_rsa))

    def test_main_optional_args(self):
        """Test CLI command with optional arguments."""

        named_args = [
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--materials",
            self.test_artifact,
            "--products",
            self.test_artifact,
            "--record-streams",
            "--use-dsse",
        ]
        positional_args = ["--", "python", "--version"]

        # Test and assert recorded artifacts
        args1 = named_args + positional_args
        self.assert_cli_sys_exit(args1, 0)
        metadata = Metadata.load(self.test_link_rsa)
        link = metadata.get_payload()
        self.assertTrue(self.test_artifact in list(link.materials.keys()))
        self.assertTrue(self.test_artifact in list(link.products.keys()))

        # Test and assert exlcuded artifacts
        args2 = named_args + ["--exclude", "*test*"] + positional_args
        self.assert_cli_sys_exit(args2, 0)
        link = Metadata.load(self.test_link_rsa).get_payload()
        self.assertFalse(link.materials)
        self.assertFalse(link.products)

        # Test with base path
        args3 = named_args + ["--base-path", self.test_dir] + positional_args
        self.assert_cli_sys_exit(args3, 0)
        link = Metadata.load(self.test_link_rsa).get_payload()
        self.assertListEqual(list(link.materials.keys()), [self.test_artifact])
        self.assertListEqual(list(link.products.keys()), [self.test_artifact])

        # Test with bogus base path
        args4 = named_args + ["--base-path", "bogus/path"] + positional_args
        self.assert_cli_sys_exit(args4, 1)

        # Test with lstrip path
        strip_prefix = self.test_artifact[:-1]
        args5 = named_args + ["--lstrip-paths", strip_prefix] + positional_args
        self.assert_cli_sys_exit(args5, 0)
        link = Metadata.load(self.test_link_rsa).get_payload()
        self.assertListEqual(
            list(link.materials.keys()),
            [self.test_artifact[len(strip_prefix) :]],
        )
        self.assertListEqual(
            list(link.products.keys()),
            [self.test_artifact[len(strip_prefix) :]],
        )

    def test_main_with_default_gpg_key(self):
        """Test CLI command with default gpg key."""
        args = [
            "-n",
            self.test_step,
            "--gpg",
            "--gpg-home",
            self.gnupg_home,
            "--use-dsse",
            "--",
            "python",
            "--version",
        ]

        self.assert_cli_sys_exit(args, 1)

    def test_main_no_command_arg(self):
        """Test CLI command with --no-command argument."""

        args = [
            "in_toto_run.py",
            "--step-name",
            self.test_step,
            "--key",
            self.rsa_key_path,
            "--no-command",
            "--use-dsse",
        ]

        self.assert_cli_sys_exit(args, 0)

        self.assertTrue(os.path.exists(self.test_link_rsa))

    def test_pkcs8_signing_key(self):
        """Test in-toto-run, sign link with pkcs8 key file for each algo."""
        pems_dir = Path(__file__).parent / "pems"
        args = ["-n", "foo", "-x", "--use-dsse", "--signing-key"]
        for algo, short_keyid in [
            ("rsa", "2f685fa7"),
            ("ecdsa", "50d7e110"),
            ("ed25519", "c6d8bf2e"),
        ]:
            link_path = Path(f"foo.{short_keyid}.link")

            # Use unencrypted key
            pem_path = pems_dir / f"{algo}_private_unencrypted.pem"
            self.assert_cli_sys_exit(args + [str(pem_path)], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()

            # Fail with encrypted key, but no pw
            pem_path = pems_dir / f"{algo}_private_encrypted.pem"
            self.assert_cli_sys_exit(args + [str(pem_path)], 1)
            self.assertFalse(link_path.exists())

            # Use encrypted key, passing pw
            self.assert_cli_sys_exit(args + [str(pem_path), "-P", "hunter2"], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()

            # Use encrypted key, mocking pw enter on prompt
            with mock.patch(
                "in_toto.in_toto_run.getpass", return_value="hunter2"
            ):
                self.assert_cli_sys_exit(args + [str(pem_path), "-P"], 0)
            self.assertTrue(link_path.exists())
            link_path.unlink()


if __name__ == "__main__":
    unittest.main()
