#!/bin/sh
# Run a USB-Pasteur image in a QEMU/KVM virtual machine, in the build container.
#   image/vm.sh test [--workdir DIR]  automated end-to-end test of the test image
#   image/vm.sh run [IMAGE]           interactive machine (default: the test image)
# Build the test image first: image/build.sh --profile test
set -eu

cd "$(dirname "$0")/.."
docker build -q -t usb-pasteur-builder image >/dev/null
# Run as the calling user, so that the files written in the repository
# (work folder) belong to them
user="--user $(id -u):$(id -g) -e PYTHONDONTWRITEBYTECODE=1"
# KVM when available, otherwise QEMU emulation (much slower)
kvm=""
if [ -w /dev/kvm ]; then
    kvm="--device /dev/kvm --group-add $(stat -c %g /dev/kvm)"
fi

command="${1:-}"
[ $# -gt 0 ] && shift
case "$command" in
test)
    # shellcheck disable=SC2086
    exec docker run --rm $user $kvm -v "$PWD:/src" -w /src \
        usb-pasteur-builder python3 image/vm/run_tests.py "$@"
    ;;
run)
    image="${1:-image/mkosi.output/usb-pasteur-test.raw}"
    # shellcheck disable=SC2086
    exec docker run --rm -it $user $kvm -v "$PWD:/src" -w /src -p 127.0.0.1:5900:5900 \
        usb-pasteur-builder python3 image/vm/machine.py run "$image"
    ;;
*)
    sed -n '2,5p' "$0" >&2
    exit 2
    ;;
esac
