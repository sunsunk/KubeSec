#!/usr/bin/env python3
# Used for e2e tests to set configuration

import argparse
import subprocess
import logging
import time
import json

parser = argparse.ArgumentParser()
parser.add_argument(
    "-u", "--base-url", help="Base url for API", default="http://localhost:5000/api/v3/"
)
parser.add_argument(
    "CONFIGNAME", choices=["denyall", "defaultconfig", "contentfilter-and-acl"]
)
args = parser.parse_args()


TEST_CONFIG_NAME = "prod"


class CliHelper:
    def __init__(self, base_url):
        self._base_url = base_url
        self._initial_version_cache = None

    def call(self, args, inputjson=None):
        logging.info("Calling CLI with arguments: %s", args)
        cmd = ["curieconfctl", "-u", self._base_url, "-o", "json"]
        cmd += args.split(" ")
        indata = None
        if inputjson:
            indata = json.dumps(inputjson).encode("utf-8")

        process = subprocess.run(
            cmd,
            shell=False,
            input=indata,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout:
            logging.debug("CLI output: %s", process.stdout)

            try:
                return json.loads(process.stdout.decode("utf-8"))
            except json.JSONDecodeError:
                return process.stdout.decode("utf-8")
        else:
            return []

    def delete_test_config(self):
        self.call("conf delete test")

    def initial_version(self):
        if not self._initial_version_cache:
            versions = self.call("conf list-versions prod")
            if "version" not in versions[-3]:
                print("Unsupported curieconfctl output", versions)
                raise TypeError("Unsupported curieconfctl output")
            self._initial_version_cache = versions[-3]["version"]
        return self._initial_version_cache

    def empty_acl(self):
        version = self.initial_version()
        return self.call(f"doc get prod aclprofiles --version {version}")

    def revert_and_enable(self, acl=True, content_filter=True):
        version = self.initial_version()
        self.call(f"conf revert {TEST_CONFIG_NAME} {version}")
        securitypolicy = self.call(f"doc get {TEST_CONFIG_NAME} securitypolicies")
        securitypolicy[0]["map"][0]["acl_active"] = acl
        securitypolicy[0]["map"][0]["content_filter_active"] = content_filter
        self.call(
            f"doc update {TEST_CONFIG_NAME} securitypolicies /dev/stdin",
            inputjson=securitypolicy,
        )

    def publish_and_apply(self):
        buckets = self.call("key get system publishinfo")

        for bucket in buckets["buckets"]:
            if bucket["name"] == "prod":
                url = bucket["url"]
        self.call(f"tool publish prod {url}")
        time.sleep(20)


class ACLHelper:
    def __init__(self, cli):
        self._cli = cli

    def set_acl(self, updates: dict):
        acl = self._cli.empty_acl()
        # update acl
        for key, value in updates.items():
            acl[0][key].append(value)
        self._cli.call(
            f"doc update {TEST_CONFIG_NAME} aclprofiles /dev/stdin", inputjson=acl
        )

    def reset_and_set_acl(self, updates: dict):
        self._cli.revert_and_enable()
        self.set_acl(updates)
        self._cli.publish_and_apply()


cli = CliHelper(args.base_url)
acl = ACLHelper(cli)

if args.CONFIGNAME == "denyall":
    acl.reset_and_set_acl({"force_deny": "all"})
elif args.CONFIGNAME == "defaultconfig":
    cli.revert_and_enable(False, False)
    cli.publish_and_apply()
elif args.CONFIGNAME == "contentfilter-and-acl":
    cli.revert_and_enable(True, True)
    cli.publish_and_apply()
