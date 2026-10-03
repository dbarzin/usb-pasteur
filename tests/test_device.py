from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from usb_pasteur.device import (
    DeviceError,
    Mounter,
    SystemMountWatcher,
    UsbDevice,
    find_mount,
    mount_options,
)


def test_mount_options_vfat() -> None:
    options = mount_options("vfat", read_only=True, uid=1000, gid=1000)
    assert options[:4] == ["ro", "noexec", "nosuid", "nodev"]
    assert "uid=1000" in options
    assert "utf8" in options


def test_mount_options_ext4() -> None:
    assert mount_options("ext4", read_only=False, uid=0, gid=0) == [
        "rw",
        "noexec",
        "nosuid",
        "nodev",
    ]


def test_from_udev() -> None:
    device = UsbDevice.from_udev(
        {"ID_FS_TYPE": "vfat", "ID_FS_LABEL": "KEY", "ID_MODEL": "Flash", "ID_SERIAL_SHORT": "42"},
        "/dev/sdb1",
    )
    assert device == UsbDevice("/dev/sdb1", "vfat", "KEY", "Flash", "42", "")


def test_rejects_filesystem(tmp_path: Path) -> None:
    mounter = Mounter(tmp_path, ["vfat"])
    with pytest.raises(DeviceError, match="filesystem not allowed: ntfs"):
        mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))


def test_mount_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)

    monkeypatch.setattr(subprocess, "run", fake_run)
    mounter = Mounter(tmp_path, ["ntfs"], use_sudo=True)
    mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))
    argv = calls[0]
    assert argv[:5] == ["/usr/bin/sudo", "-n", "/usr/bin/mount", "-t", "ntfs3"]
    assert argv[5] == "-o"
    assert argv[6].startswith("ro,noexec,nosuid,nodev,")
    assert argv[7:] == ["/dev/sdb1", str(tmp_path)]


def test_mount_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(32, argv, stderr="wrong fs type")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DeviceError, match="wrong fs type"):
        Mounter(tmp_path, ["vfat"]).mount(UsbDevice("/dev/sdb1", "vfat"))


def test_missing_mount_point(tmp_path: Path) -> None:
    with pytest.raises(DeviceError, match="does not exist"):
        Mounter(tmp_path / "missing", ["vfat"]).mount(UsbDevice("/dev/sdb1", "vfat"))


def mounts_file(tmp_path: Path, node: str, mount_point: Path, options: str = "rw,nosuid") -> Path:
    escaped = str(mount_point).replace(" ", "\\040")
    path = tmp_path / "mounts"
    path.write_text(f"proc /proc proc rw 0 0\n{node} {escaped} vfat {options} 0 0\n")
    return path


def test_find_mount(tmp_path: Path) -> None:
    mounts = mounts_file(tmp_path, "/dev/sdb1", Path("/media/didier/MY KEY"))
    assert find_mount("/dev/sdb1", mounts) == (Path("/media/didier/MY KEY"), ["rw", "nosuid"])
    assert find_mount("/dev/sdc1", mounts) is None
    assert find_mount("/dev/sdb1", tmp_path / "missing") is None


def test_system_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_command(argv: list[str], **kwargs: Any) -> None:
        raise AssertionError("no mount command in auto-mount mode")

    monkeypatch.setattr(subprocess, "run", no_command)
    key = tmp_path / "key"
    key.mkdir()
    watcher = SystemMountWatcher(["vfat"], mounts=mounts_file(tmp_path, "/dev/sdb1", key))
    watcher.mount(UsbDevice("/dev/sdb1", "vfat"))
    assert watcher.mount_point == key
    assert watcher.is_mounted()
    watcher.remount_rw()
    watcher.unmount()
    assert watcher.device is None


def test_system_mount_timeout(tmp_path: Path) -> None:
    watcher = SystemMountWatcher(["vfat"], wait=0.2, mounts=tmp_path / "empty", poll=0.05)
    (tmp_path / "empty").write_text("")
    with pytest.raises(DeviceError, match=r"not mounted by the system after 0\.2s"):
        watcher.mount(UsbDevice("/dev/sdb1", "vfat"))


def test_system_mount_checks(tmp_path: Path) -> None:
    mounts = mounts_file(tmp_path, "/dev/sdb1", tmp_path, "ro,nosuid")
    watcher = SystemMountWatcher(["vfat"], mounts=mounts)
    with pytest.raises(DeviceError, match="filesystem not allowed: ntfs"):
        watcher.mount(UsbDevice("/dev/sdb1", "ntfs"))
    watcher.mount(UsbDevice("/dev/sdb1", "vfat"))
    with pytest.raises(DeviceError, match="read-only by the system"):
        watcher.remount_rw()
