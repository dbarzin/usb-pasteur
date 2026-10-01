"""End-to-end test: a disk image attached to a loop device simulates a USB key.

Requires root, loop devices and mkfs tools: run it with tests/e2e/run.sh.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from usb_pasteur.config import parse_config
from usb_pasteur.device import Mounter, UsbDevice
from usb_pasteur.engines.fake import EICAR
from usb_pasteur.kiosk import Kiosk, build_engines
from usb_pasteur.monitor import Action, DeviceEvent

from ..conftest import ListSource, RecordingDisplay

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.geteuid() != 0, reason="needs root to use loop devices"),
]

MKFS = {
    "vfat": ["mkfs.vfat", "-n", "USBKEY"],
    "exfat": ["mkfs.exfat", "-L", "USBKEY"],
    "ext4": ["mkfs.ext4", "-q", "-L", "USBKEY"],
}


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout.strip()


def attach(image: Path) -> str:
    """Attach the image to a free loop device, creating the node if missing.

    Containers have a static /dev: the node of a new loop device must be created.
    """
    # losetup prints "/dev/loopN (lost)" when the node does not exist
    node = run("losetup", "--find").split()[0]
    if not Path(node).exists():
        os.mknod(node, 0o660 | 0o060000, os.makedev(7, int(node.removeprefix("/dev/loop"))))
    run("losetup", node, str(image))
    return node


def mount_options(node: str) -> list[str]:
    for line in Path("/proc/self/mounts").read_text().splitlines():
        fields = line.split()
        if fields[0] == node:
            return fields[3].split(",")
    return []


@pytest.fixture(params=sorted(MKFS))
def usb_key(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[UsbDevice]:
    fs_type: str = request.param
    if shutil.which(MKFS[fs_type][0]) is None:
        pytest.skip(f"{MKFS[fs_type][0]} not installed")
    image = tmp_path / f"{fs_type}.img"
    with image.open("wb") as f:
        f.truncate(64 * 1024 * 1024)
    run(*MKFS[fs_type], str(image))
    node = attach(image)
    try:
        # Populate the key
        populate = tmp_path / "populate"
        populate.mkdir()
        run("mount", "-t", fs_type, node, str(populate))
        (populate / "docs").mkdir()
        (populate / "readme.txt").write_text("hello")
        (populate / "docs" / "report.pdf").write_bytes(b"%PDF-1.4 harmless")
        (populate / "docs" / "eicar.com").write_bytes(EICAR)
        (populate / "eicar copy.txt").write_bytes(EICAR + b"\n")
        run("umount", str(populate))
        yield UsbDevice(node=node, fs_type=fs_type, label="USBKEY", model="Loop")
    finally:
        subprocess.run(["umount", str(tmp_path / "populate")], capture_output=True)
        subprocess.run(["losetup", "-d", node], capture_output=True)


def test_scan_and_clean(usb_key: UsbDevice, tmp_path: Path) -> None:
    mount_point = tmp_path / "media"
    mount_point.mkdir()
    config = parse_config(
        {
            "kiosk": {"name": "e2e", "fake_scan": True, "interface": "console"},
            "device": {"mount_point": str(mount_point)},
            "quarantine": {"folder": str(tmp_path / "quarantine")},
            "logging": {"file": str(tmp_path / "usb-pasteur.log")},
        }
    )
    display = RecordingDisplay()
    options_during_scan: list[list[str]] = []
    original_progress = display.progress

    def record(percent: int) -> None:
        options_during_scan.append(mount_options(usb_key.node))
        original_progress(percent)

    display.progress = record  # type: ignore[method-assign]
    mounter = Mounter(mount_point, config.device.allowed_filesystems)
    source = ListSource([DeviceEvent(Action.ADD, usb_key)])
    Kiosk(config, display, source, build_engines(config), mounter).run()

    # The device was scanned read-only with hardened options, then unmounted
    assert options_during_scan
    for options in options_during_scan:
        assert {"ro", "noexec", "nosuid", "nodev"} <= set(options)
    assert not os.path.ismount(mount_point)
    assert "Device cleaned! You can remove the device." in display.messages

    # Infected files are quarantined
    manifests = list((tmp_path / "quarantine").glob("*/manifest.json"))
    assert len(manifests) == 1
    quarantined = {e["original_path"] for e in json.loads(manifests[0].read_text())}
    assert quarantined == {"docs/eicar.com", "eicar copy.txt"}

    # Infected files are removed from the key, clean files are kept
    check = tmp_path / "check"
    check.mkdir()
    run("mount", "-o", "ro", usb_key.node, str(check))
    try:
        files = sorted(str(p.relative_to(check)) for p in check.rglob("*") if p.is_file())
    finally:
        run("umount", str(check))
    assert [f for f in files if not f.startswith("lost+found")] == [
        "docs/report.pdf",
        "readme.txt",
    ]
