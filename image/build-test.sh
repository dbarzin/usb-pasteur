#!/bin/sh
# Build the images of the virtual machine test (image/vm.sh test):
#   image/mkosi.output/usb-pasteur-test.raw   the test image, version 1
#   image/mkosi.output/updates/2, 3           signed image updates to the
#                                             versions 2 and 3 (A/B update test)
# Arguments are passed to image/build.sh.
set -eu

cd "$(dirname "$0")"
./build.sh --profile test "$@"
for version in 2 3; do
    ./build.sh --profile test --image-version="$version" \
        --output-directory="mkosi.output/v$version" "$@"
done
for version in 2 3; do
    ./package-update.sh "mkosi.output/v$version/usb-pasteur-test.raw" \
        "mkosi.output/updates/$version" update.key
done
