# Image build and test environment: mkosi, QEMU/KVM and OVMF from Debian 13
# (trixie), so that the developer only needs Docker. Used by image/build.sh
# and image/vm.sh.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        mkosi systemd-container systemd-ukify systemd-boot-efi systemd-repart \
        apt debian-archive-keyring dpkg-dev \
        dosfstools e2fsprogs erofs-utils exfatprogs mtools cpio zstd \
        python3 python3-venv python3-pip git ca-certificates \
        qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools \
        openssl sbsigntool python3-virt-firmware \
    && rm -rf /var/lib/apt/lists/*
