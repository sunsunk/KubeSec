#! /bin/bash

# Change directory to this script's location
cd "${0%/*}" || exit 1

# Parameters should be passed as environment variables.
# By default, builds and tags images locally, without pushing
# To push, set `PUSH=1`
# To specify a different repo, set `REPO=my.repo.tld`

REPO=${REPO:-curiefense}
BUILD_OPT=${BUILD_OPT:-}
BUILD_RUST=${BUILD_RUST:-yes}

declare -A status

GLOBALSTATUS=0

if [ -z "$DOCKER_TAG" ]
then
    GITTAG="$(git describe --tag --long --dirty)"
    DOCKER_DIR_HASH="$(git rev-parse --short=12 HEAD:curiefense)"
    DOCKER_TAG="${DOCKER_TAG:-$GITTAG-$DOCKER_DIR_HASH}"
fi

STOP_ON_FAIL=${STOP_ON_FAIL:-yes}

IFS=' ' read -ra RUST_DISTROS <<< "${RUST_DISTROS:-bionic focal jammy}"

if [ -n "$TESTIMG" ]; then
    IMAGES=("$TESTIMG")
    OTHER_IMAGES_DOCKER_TAG="$DOCKER_TAG"
    DOCKER_TAG="main"
    echo "Building only image $TESTIMG"
else
    IMAGES=(confserver curieproxy-istio curieproxy-envoy \
        curieproxy-nginx curiesync grafana prometheus extproc \
        redis traffic-metrics-exporter)
fi

if [ "$BUILD_RUST" = "yes" ]
then
    echo "-------"
    echo "Building : Rust"
    echo "with tag : $DOCKER_TAG"
    echo "-------"

    for distro in "${RUST_DISTROS[@]}"
    do
            image="curiefense-rustbuild-${distro}"
            IMG=${REPO}/${image}
            echo "=================== $IMG:$DOCKER_TAG ====================="
            if tar -C curiefense-rustbuild -ch --exclude='.*/target' --exclude='.*/ctarget' . \
                    | docker build --build-arg UBUNTU_VERSION="${distro}" -t "$IMG:$DOCKER_TAG" -; then
                STB="ok"
                if [ -n "$PUSH" ]; then
                    if docker push "$IMG:$DOCKER_TAG"; then
                        STP="ok"
                    else
                        STP="KO"
                        GLOBALSTATUS=1
                    fi
                else
                    STP="SKIP"
                fi
            else

                if [ "$STOP_ON_FAIL" = "yes" ];
                then
                    exit 1
                fi
                STB="KO"
                STP="SKIP"
                GLOBALSTATUS=1
            fi
            status[$image]="build=$STB  push=$STP"
    done
fi

echo "-------"
echo "Building images: " "${IMAGES[@]}"
echo "with tag       : $DOCKER_TAG"
echo "-------"


for image in "${IMAGES[@]}"
do
        IMG=${REPO}/$image
        echo "=================== $IMG:$DOCKER_TAG ====================="
        # shellcheck disable=SC2086
        # a temporary file is needed on macos -- docker complains otherwise
        TMPFILE=$(mktemp)
        tar -czhf "$TMPFILE" --exclude='.*/target' --exclude='.*/ctarget' -C "$image" .
        if docker build --build-arg RUSTBIN_TAG=${DOCKER_TAG} -t "$IMG:$DOCKER_TAG" "$@" - < "$TMPFILE"; then
            STB="ok"
            if [ -n "$PUSH" ]; then
                if docker push "$IMG:$DOCKER_TAG"; then
                    STP="ok"
                else
                    STP="KO"
                    GLOBALSTATUS=1
                fi
            else
                STP="SKIP"
            fi
        else
            if [ "$STOP_ON_FAIL" = "yes" ];
            then
                exit 1
            fi
            STB="KO"
            STP="SKIP"
            GLOBALSTATUS=1
        fi
        rm "$TMPFILE"
        status[$image]="build=$STB  push=$STP"
done

for s in "${!status[@]}"
do
        printf "%-25s %s\n" "$s" "${status[$s]}"
done


if [ -n "$TESTIMG" ]; then
    echo "To deploy this test image, export \"TESTIMG=$TESTIMG\" before running deploy.sh or docker-compose up"
    echo "To choose a docker tag for all other images, also export DOCKER_TAG"
    echo "Docker tag of the current working directory is:"
    echo "export DOCKER_TAG=$OTHER_IMAGES_DOCKER_TAG"
else
    echo "To deploy this set of images later, export \"DOCKER_TAG=$DOCKER_TAG\" before running deploy.sh or docker-compose up"
fi

exit $GLOBALSTATUS
