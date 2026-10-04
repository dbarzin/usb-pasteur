"""Updates of the system image: A/B slots written by systemd-sysupdate.

An image update is a folder usb-pasteur-image/ holding the partitions of a
system slot and the unified kernel image (UKI) of a newer image version, with
a manifest signed with an update key (sigsets, content "image", serial = the
image version):

    files/usb-pasteur_<version>_<uuid>.root.raw.xz        root filesystem
    files/usb-pasteur_<version>_<uuid>.verity.raw.xz      its dm-verity hash tree
    files/usb-pasteur_<version>_<uuid>.verity-sig.raw.xz  signature of the root hash
    files/usb-pasteur_<version>.efi                        UKI

The partition UUIDs are those of the built image: systemd finds the root
filesystem of a version from its root hash, which they encode.

The kiosk installs an update found on a device: it verifies the manifest
(signature, newer version than the running image), copies the files to
/var/lib/usb-pasteur-image with their size and SHA-256 checked, then
systemd-sysupdate (/usr/lib/sysupdate.d) writes them to the free slot and
the UKI to the ESP with 3 boot tries, and the kiosk restarts. The new version
is kept once the kiosk has started (boot-complete.target); otherwise
systemd-boot goes back to the previous one.

Two keys protect the kiosk: the update key decides what is installed, the
Secure Boot key of the image (UKI, root hash) decides what can boot.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from usb_pasteur import sigsets

UPDATE_FOLDER = "usb-pasteur-image"
STAGING = Path("/var/lib/usb-pasteur-image")
FILES = "files"
SYSUPDATE_SERVICE = "systemd-sysupdate.service"
SYSTEMCTL = "/usr/bin/systemctl"
SFDISK = "/usr/sbin/sfdisk"
XZ = "/usr/bin/xz"
NAME = "usb-pasteur"
# Partitions of a slot: suffix of the split artifact (mkosi), suffix of the
# partition label, suffix of the update file
PARTITIONS = (
    ("root-x86-64", "", "root"),
    ("root-x86-64-verity", "_verity", "verity"),
    ("root-x86-64-verity-sig", "_verity_sig", "verity-sig"),
)
_FILE = re.compile(
    rf"{FILES}/{NAME}_(?P<version>\d+)"
    r"(_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"\.(root|verity|verity-sig)\.raw\.xz|\.efi)"
)


class ImageUpdateError(Exception):
    pass


def running_version(os_release: Path = Path("/etc/os-release")) -> int | None:
    """IMAGE_VERSION of the running system, or None (not an image, development)."""
    try:
        lines = os_release.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        key, _, value = line.partition("=")
        if key == "IMAGE_VERSION":
            value = value.strip().strip("\"'")
            return int(value) if value.isdigit() else None
    return None


# -- kiosk side --------------------------------------------------------------------


def stage(
    source: Path,
    keys: Sequence[Path],
    staging: Path = STAGING,
    running: int | None = None,
) -> sigsets.Manifest:
    """Verify an image update and copy its files to staging.

    Raise sigsets.NotNewerError when it is not newer than the running image,
    sigsets.SignatureSetError when it is not valid.
    """
    manifest, _, _ = sigsets.read_set(source, keys, sigsets.CONTENT_IMAGE)
    if running is not None and manifest.serial <= running:
        raise sigsets.NotNewerError(
            f"image version {manifest.serial} is not newer than the running {running}"
        )
    kinds = []
    for entry in manifest.files:
        match = _FILE.fullmatch(entry.path)
        if match is None or int(match["version"]) != manifest.serial:
            raise sigsets.SignatureSetError(f"unexpected file in the image update: {entry.path}")
        kinds.append(entry.path.rsplit(".", 3)[1] if entry.path.endswith(".xz") else "efi")
    if sorted(kinds) != ["efi", "root", "verity", "verity-sig"]:
        raise sigsets.SignatureSetError(f"incomplete image update: {', '.join(sorted(kinds))}")
    clear(staging)
    sigsets.copy_files(source, manifest, staging)
    return manifest


def apply(staging: Path = STAGING) -> None:
    """Write the staged update to the free slot (systemd-sysupdate), then clear it."""
    try:
        result = subprocess.run(  # noqa: S603  (fixed command, no shell)
            [SYSTEMCTL, "--no-ask-password", "start", "--wait", SYSUPDATE_SERVICE],
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
        )
    finally:
        clear(staging)
    if result.returncode != 0:
        raise ImageUpdateError(
            f"systemd-sysupdate failed ({result.returncode}): {result.stderr.strip()[-500:]}"
        )


def clear(staging: Path) -> None:
    staging.mkdir(parents=True, exist_ok=True)
    staging.chmod(0o755)
    for path in staging.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def reboot() -> None:
    subprocess.run(  # noqa: S603  (fixed command, no shell)
        [SYSTEMCTL, "--no-ask-password", "reboot"], check=False, timeout=60
    )


# -- publisher side ----------------------------------------------------------------


def slot_partitions(image: Path) -> tuple[int, dict[str, str]]:
    """Version and partition UUIDs (by label suffix) of slot A of a disk image."""
    table = json.loads(
        subprocess.run(  # noqa: S603  (fixed command, no shell)
            [SFDISK, "--json", str(image)], check=True, capture_output=True, text=True
        ).stdout
    )["partitiontable"]["partitions"]
    labels = {p.get("name", ""): p["uuid"].lower() for p in table}
    versions = [int(m[1]) for label in labels if (m := re.fullmatch(rf"{NAME}_(\d+)", label))]
    if len(versions) != 1:
        raise ImageUpdateError(f"{image}: expected one {NAME}_<version> root partition")
    version = versions[0]
    uuids = {}
    for _, suffix, _ in PARTITIONS:
        label = f"{NAME}_{version}{suffix}"
        if label not in labels:
            raise ImageUpdateError(f"{image}: no partition {label}")
        uuids[suffix] = labels[label]
    return version, uuids


def package(image: Path, output: Path, key: Path) -> sigsets.Manifest:
    """Build a signed image update from a built image and its split artifacts.

    image: the disk image (<name>.raw), next to <name>.root-x86-64.raw... and
    <name>.efi, as written by image/build.sh (SplitArtifacts=uki,partitions).
    """
    version, uuids = slot_partitions(image)
    prefix = image.with_suffix("")
    shutil.rmtree(output, ignore_errors=True)
    files = output / FILES
    files.mkdir(parents=True)
    for artifact, suffix, kind in PARTITIONS:
        source = Path(f"{prefix}.{artifact}.raw")
        target = files / f"{NAME}_{version}_{uuids[suffix]}.{kind}.raw.xz"
        # The partitions are mostly empty: compressed, they are small. xz, as
        # systemd-sysupdate of Debian 13 decompresses xz and gzip, not zstd.
        with target.open("wb") as out:
            subprocess.run(  # noqa: S603  (fixed command, no shell)
                [XZ, "-q", "-T0", "-2", "-c", str(source)], stdout=out, check=True
            )
    shutil.copyfile(f"{prefix}.efi", files / f"{NAME}_{version}.efi")
    manifest = sigsets.build(output, version, content=sigsets.CONTENT_IMAGE)
    sigsets.sign(output, key)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="usb-pasteur-image", description="Build a signed update of the system image"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_package = sub.add_parser("package", help="build an image update from a built image")
    p_package.add_argument("image", type=Path, help="disk image built by image/build.sh")
    p_package.add_argument("output", type=Path, help="folder of the update (replaced)")
    p_package.add_argument("--key", type=Path, required=True, help="update key (PEM)")
    args = parser.parse_args(argv)
    try:
        manifest = package(args.image, args.output, args.key)
    except (ImageUpdateError, sigsets.SignatureSetError, OSError) as ex:
        print(f"usb-pasteur-image: {ex}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as ex:
        print(f"usb-pasteur-image: {ex}", file=sys.stderr)
        return 1
    size = sum(f.size for f in manifest.files)
    print(f"image version {manifest.serial}: {len(manifest.files)} files, {size} bytes")
    return 0


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main())
