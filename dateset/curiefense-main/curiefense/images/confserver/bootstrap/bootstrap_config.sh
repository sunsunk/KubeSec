#!/bin/bash

set -e

# to be run in an initContainer
# Will deploy specified configuration as a bootstrap config, if there is no config in /cf-persistent-config/confdb
TARGETDIR="/cf-persistent-config/confdb"

if [ -e "$TARGETDIR" ]; then
	echo "Config already present in $TARGETDIR, exiting"
	exit 0
fi
echo "Config directory $TARGETDIR is empty"

if [ -n "$IF_NO_CONFIG_PULL_FROM" ]; then
	if [ -n "$CURIECONF_GIT_SSH_KEY_PATH" ]; then
		export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -i $CURIECONF_GIT_SSH_KEY_PATH"
	fi
	echo "Cloning configuration from $IF_NO_CONFIG_PULL_FROM"
	git clone --mirror "$IF_NO_CONFIG_PULL_FROM" "$TARGETDIR"
	exit 0
fi

if [ -n "$IF_NO_CONFIG_INIT_FROM" ]; then
  git config --global --add safe.directory $TARGETDIR
  git config --global --add safe.directory /cf-persistent-config/bootstrap-repo
	mkdir -p "$TARGETDIR"
	cd "$TARGETDIR"
	git init --bare
	cd "$TARGETDIR/../"
	git clone confdb/ bootstrap-repo
	cd bootstrap-repo
	git config --global user.email "curiefense-bootstrap@reblaze.com"
	git config --global user.name "Curiefense Bootstrap Script"
	git checkout -b _internal_db
	git commit --allow-empty -am "Initial empty content"
	cp -R "$IF_NO_CONFIG_INIT_FROM/_internal_db/." .
	git add .
	git commit -m "Added namespace [system]"
	git checkout -b _internal_base
	git reset --hard "HEAD~1"
	cp -R "$IF_NO_CONFIG_INIT_FROM/_internal_base/." .
	git add .
	git commit -m "Initial empty config"
	git checkout -b prod
	rm -rf config
	cp -R "$IF_NO_CONFIG_INIT_FROM/prod/." .
	sed -i -e 's/TARGET_BRANCH/prod/g' config/json/globalfilter-lists.json
	git add .
	git commit -m "Create config [prod]"
	git checkout -b stage
	cp -R "$IF_NO_CONFIG_INIT_FROM/prod/." .
	sed -i -e 's/TARGET_BRANCH/stage/g' config/json/globalfilter-lists.json
	git add .
	git commit -m "Override config [stage]"
	git remote add db "$TARGETDIR"
	git push --all db
	cd ..
	rm -rf bootstrap-repo
	exit 0
fi

echo "No configuration found in $TARGETDIR, IF_NO_CONFIG_PULL_FROM and IF_NO_CONFIG_INIT_FROM are not defined: exiting"
exit 1
