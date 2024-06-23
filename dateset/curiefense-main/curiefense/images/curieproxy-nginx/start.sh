#!/bin/bash

# shellcheck disable=SC2016
envsubst '${TARGET_ADDRESS_A},${TARGET_PORT_A},${TARGET_ADDRESS_B},${TARGET_PORT_B},${AGGREGATED_STATS_LOG_FILE},${NGINX_ACCESS_LOG},${NGINX_ERROR_LOG},${CF_LOG_LEVEL},${NGINX_LOG_LEVEL}' < /usr/local/openresty/nginx/conf/nginx.conf > /usr/local/openresty/nginx/conf/nginx.conf.1
mv /usr/local/openresty/nginx/conf/nginx.conf.1 /usr/local/openresty/nginx/conf/nginx.conf


if [ "$NGINX_CONFIGURATION_TEMPLATE" = "yes" ]
then
  envsubst '${TARGET_ADDRESS_A},${TARGET_PORT_A},${TARGET_ADDRESS_B},${TARGET_PORT_B},${AGGREGATED_STATS_LOG_FILE},${NGINX_ACCESS_LOG},${NGINX_ERROR_LOG},${CF_LOG_LEVEL},${NGINX_LOG_LEVEL}' < /etc/nginx/conf.d/default.template > /etc/nginx/conf.d/default.conf
else
  /usr/local/bin/nginx-conf-watch.sh &
fi

if [ "$FILEBEAT" = "yes" ]
then
  /usr/local/openresty/bin/openresty -g "daemon off;" | grep -v '^.$' | /usr/bin/filebeat --path.config /etc
else
  rm /etc/nginx/conf.d/default.template 
  /usr/local/openresty/bin/openresty -g "daemon off;"
fi
