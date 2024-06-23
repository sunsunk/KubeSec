#!/bin/sh

CONFIG_URL_1="${CF_CONFIG_URL_1:-http://curieproxyngx:8998}"
CONFIG_URL_2="${CF_CONFIG_URL_2:-http://curieproxyenvoy:8998}"

curl -X POST "$CONFIG_URL_1" -H "Content-Type: application/json" -d "$1"
curl -X POST "$CONFIG_URL_2" -H "Content-Type: application/json" -d "$1"