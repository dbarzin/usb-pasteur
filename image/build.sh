#!/bin/sh
# Build the USB-Pasteur image with mkosi, in a Debian 13 container.
#   image/build.sh                 production image
#   image/build.sh --profile test  test image (test signatures, root shell on hvc0)
# Other arguments are passed to mkosi. An existing image is replaced. The
# image is written to image/mkosi.output/.
set -eu

cd "$(dirname "$0")"
docker build -q -t usb-pasteur-builder . >/dev/null
mkdir -p mkosi.output
# Privileged: mkosi creates namespaces and mounts to build the image. Its
# workspace and caches (packages, incremental build) are in a volume:
# overlayfs cannot use the container overlay filesystem. The image is given
# back to the calling user.
exec docker run --rm --privileged \
    -v "$PWD/..:/src" -w /src/image \
    -v usb-pasteur-mkosi:/var/tmp \
    -e HOST_IDS="$(id -u):$(id -g)" \
    usb-pasteur-builder sh -c '
        mkdir -p /var/tmp/cache/images /var/tmp/cache/packages
        status=0
        mkosi --force --cache-directory=/var/tmp/cache/images \
            --package-cache-dir=/var/tmp/cache/packages "$@" build || status=$?
        chown -R "$HOST_IDS" mkosi.output
        exit $status' \
    mkosi "$@"
