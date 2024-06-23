#!/usr/bin/env bash

set -o errexit # Exit script when a command exits with a non-zero status
set -o nounset # Exit script when trying to use undeclared variables
set -o pipefail # Exit script when any command in a pipeline exits with a non-zero status

# Enable debugging if TRACE variable is set to 1
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

# The file that we are going to monitor
confarchive=/cf-config/current/config/customconf.tar.gz

# Hashsum for the config file, empty to invoke initial loading
original_md5=""

while true; do
if [ -f "$confarchive" ]; then
    # Compare the current md5sum with the original
    current_md5=$(md5sum "$confarchive" | awk '{print $1}')
    if [ "$current_md5" != "$original_md5" ]; then
        echo "watch-customconf: New copy of $confarchive found, reloading..."
        # If the md5sums are different, it means that the file has been modified, so call the reload script
        /usr/local/bin/nginx-conf-reload.sh &
        # Update the original md5sum
        original_md5=$current_md5
    fi
    sleep 10; # Sleep for 10 seconds before checking the file again
else
    echo "watch-customconf: ${confarchive} is missing" >&2
    sleep 1; # Sleep for 1 second before checking the file again
fi
done
