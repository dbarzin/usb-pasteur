"""USB device description, mounting and unmounting."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from usb_pasteur.logs import get_logger, log_event

logger = get_logger("device")

# Kernel driver used for each filesystem type reported by udev
_FS_DRIVERS = {"vfat": "vfat", "exfat": "exfat", "ntfs": "ntfs3", "ext4": "ext4"}
# Filesystems without Unix permissions: files are owned by the scanning process
_NO_UNIX_PERMISSIONS = {"vfat", "exfat", "ntfs"}
# Absolute paths: commands are never looked up in PATH
MOUNT = "/usr/bin/mount"
UMOUNT = "/usr/bin/umount"
SUDO = "/usr/bin/sudo"


class DeviceError(Exception):
    """Raised when a device cannot be mounted or unmounted."""


@dataclass(frozen=True)
class UsbDevice:
    node: str
    fs_type: str = ""
    label: str = ""
    model: str = ""
    serial: str = ""
    vendor: str = ""

    @classmethod
    def from_udev(cls, properties: Mapping[str, Any], node: str) -> UsbDevice:
        def prop(name: str) -> str:
            return str(properties.get(name) or "")

        return cls(
            node=node,
            fs_type=prop("ID_FS_TYPE"),
            label=prop("ID_FS_LABEL"),
            model=prop("ID_MODEL"),
            serial=prop("ID_SERIAL_SHORT"),
            vendor=prop("ID_VENDOR"),
        )


def mount_options(fs_type: str, read_only: bool, uid: int, gid: int) -> list[str]:
    """Build hardened mount options: never execute, no setuid, no device files."""
    options = ["ro" if read_only else "rw", "noexec", "nosuid", "nodev"]
    if fs_type in _NO_UNIX_PERMISSIONS:
        options += [f"uid={uid}", f"gid={gid}", "fmask=0177", "dmask=0077"]
        options.append("utf8" if fs_type == "vfat" else "iocharset=utf8")
    return options


class Mounter:
    """Mount the inserted device on a fixed mount point."""

    def __init__(
        self,
        mount_point: Path,
        allowed_filesystems: Sequence[str],
        use_sudo: bool = False,
        timeout: float = 60.0,
    ) -> None:
        self.mount_point = mount_point
        self.allowed_filesystems = tuple(allowed_filesystems)
        self.use_sudo = use_sudo
        self.timeout = timeout
        self.device: UsbDevice | None = None

    def mount(self, device: UsbDevice, read_only: bool = True) -> None:
        if device.fs_type not in self.allowed_filesystems:
            raise DeviceError(f"filesystem not allowed: {device.fs_type or 'unknown'}")
        if not self.mount_point.is_dir():
            raise DeviceError(f"mount point does not exist: {self.mount_point}")
        if self.is_mounted():
            raise DeviceError(f"mount point already in use: {self.mount_point}")
        options = mount_options(device.fs_type, read_only, os.getuid(), os.getgid())
        self._run(
            MOUNT,
            "-t",
            _FS_DRIVERS[device.fs_type],
            "-o",
            ",".join(options),
            device.node,
            str(self.mount_point),
        )
        self.device = device
        log_event(logger, "device_mounted", node=device.node, options=",".join(options))

    def remount_rw(self) -> None:
        """Remount the device read-write, only to remove infected files."""
        if self.device is None:
            raise DeviceError("no device mounted")
        self._run(MOUNT, "-o", "remount,rw", str(self.mount_point))
        log_event(logger, "device_remounted_rw", node=self.device.node)

    def unmount(self) -> None:
        if not self.is_mounted():
            self.device = None
            return
        self._run(UMOUNT, str(self.mount_point))
        log_event(logger, "device_unmounted", mount_point=str(self.mount_point))
        self.device = None

    def is_mounted(self) -> bool:
        return os.path.ismount(self.mount_point)

    def is_present(self) -> bool:
        """Check that the mounted device is still plugged in."""
        return self.device is not None and Path(self.device.node).exists() and self.is_mounted()

    def _run(self, *command: str) -> None:
        argv = [SUDO, "-n", *command] if self.use_sudo else list(command)
        name = Path(command[0]).name
        try:
            subprocess.run(  # noqa: S603  (fixed command, no shell)
                argv, capture_output=True, text=True, check=True, timeout=self.timeout
            )
        except subprocess.CalledProcessError as ex:
            raise DeviceError(f"{name} failed: {ex.stderr.strip() or ex.returncode}") from ex
        except subprocess.TimeoutExpired as ex:
            raise DeviceError(f"{name} timed out") from ex
        except FileNotFoundError as ex:
            raise DeviceError(f"command not found: {argv[0]}") from ex
