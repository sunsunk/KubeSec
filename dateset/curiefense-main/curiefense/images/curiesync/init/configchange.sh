#!/bin/sh

# K8s mode, notify localhost
CONFIG_URL_NGINX="${CF_URL_NGINX:-http://localhost:8998}"

curl -X POST "$CONFIG_URL_NGINX" -H "Content-Type: application/json" -d "$1"
