#!/bin/bash -e

PERIOD=10

echo "Run mode is [${RUN_MODE}]"
QUIET="${CURIESYNC_QUIET:-false}"
CONFIGCHANGE="${CONFIGCHANGE:-/init/configchange.sh}"

info () {
    if [ "$QUIET" = "true" ]; then
        echo "$*"
    fi
}

if [ -f /etc/curiefense/curiesync.env ]; then
	# shellcheck disable=SC1091
	source /etc/curiefense/curiesync.env
fi

if [ "$RUN_MODE" = "SYNC_ONCE" ]; then
    info "Synchronizing once"
    curieconfctl sync pull "${CURIE_BUCKET_LINK}" /cf-config
    if [ "$USE_IPINFO" = "true" ]
    then
      curieconfctl sync pullipinfo "${IPINFO_PROJECT}" "${IPINFO_REMOTE_BUCKET}" "${IPINFO_REMOTE_DIR}" /cf-config/ipinfo/
    fi
    exit 0
fi

if [ "$RUN_MODE" = "COPY_BOOTSTRAP" ]; then
    info "Copying bootstrap config"
    if [ ! -e /cf-config/bootstrap ]
    then
        mkdir -p /cf-config
        cp -va /bootstrap-config /cf-config/bootstrap
    fi

    if [ ! -e /cf-config/current ]
    then
        ln -s bootstrap /cf-config/current
    fi
    exit 0
fi


if [ "$RUN_MODE" = "PERIODIC_SYNC" ] || [ -z "$RUN_MODE" ]; then
    info "Synchronizing conf every $PERIOD seconds"
    info "Initial configuration loading after $PERIOD seconds ..."
    sleep $PERIOD
    $CONFIGCHANGE '[]'
    while :;
    do
        info "Pulling ${CURIE_BUCKET_LINK}"
        curieconfctl sync pull "${CURIE_BUCKET_LINK}" /cf-config --on-conf-change "$CONFIGCHANGE"
        if [ "$USE_IPINFO" = "true" ]
        then
          curieconfctl sync pullipinfo "${IPINFO_PROJECT}" "${IPINFO_REMOTE_BUCKET}" "${IPINFO_REMOTE_DIR}" /cf-config/ipinfo/
        fi
        info "Sleeping"
        sleep $PERIOD
    done
fi

