"""Detection of USB storage devices with udev."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from usb_pasteur.device import UsbDevice


class Action(StrEnum):
    ADD = "add"
    REMOVE = "remove"


@dataclass(frozen=True)
class DeviceEvent:
    action: Action
    device: UsbDevice


class DeviceSource(Protocol):
    def wait_event(self) -> DeviceEvent | None:
        """Block until a USB filesystem is added or removed (None: stop)."""
        ...


class UdevSource:
    """Listen to udev block events for filesystems on USB devices."""

    def __init__(self) -> None:
        import pyudev

        self._monitor = pyudev.Monitor.from_netlink(pyudev.Context())
        self._monitor.filter_by("block")

    def wait_event(self) -> DeviceEvent | None:
        for dev in iter(self._monitor.poll, None):
            if dev.get("ID_FS_USAGE") != "filesystem" or dev.get("ID_BUS") != "usb":
                continue
            if dev.action in (Action.ADD, Action.REMOVE) and dev.device_node:
                return DeviceEvent(Action(dev.action), UsbDevice.from_udev(dev, dev.device_node))
        return None
