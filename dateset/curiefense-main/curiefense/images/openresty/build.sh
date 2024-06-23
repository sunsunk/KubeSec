#! /bin/bash
docker build --build-arg UBUNTU_VERSION="bionic" -t "curiefense/openresty:1.21.4.1-bionic" .
docker login
docker push curiefense/openresty:1.21.4.1-bionic
