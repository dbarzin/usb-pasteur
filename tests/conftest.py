from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from usb_pasteur.config import Config, parse_config
from usb_pasteur.device import Mounter, UsbDevice
from usb_pasteur.engines.fake import EICAR
from usb_pasteur.monitor import DeviceEvent


@dataclass
class RecordingDisplay:
    """Display that records everything and confirms immediately."""

    messages: list[str] = field(default_factory=list)
    devices: list[UsbDevice | None] = field(default_factory=list)
    percents: list[int] = field(default_factory=list)
    confirmations: int = 0

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def message(self, text: str) -> None:
        self.messages.append(text)

    def show_device(self, device: UsbDevice | None) -> None:
        self.devices.append(device)

    def show_usage(self, size: int, used: int) -> None:
        pass

    def progress(self, percent: int) -> None:
        self.percents.append(percent)

    def confirm(self, prompt: str) -> None:
        self.confirmations += 1
        self.messages.append(prompt)


class ListSource:
    """Device source replaying a fixed list of events, then stopping."""

    def __init__(self, events: list[DeviceEvent]) -> None:
        self.events = list(events)

    def wait_event(self) -> DeviceEvent | None:
        return self.events.pop(0) if self.events else None


class DirectoryMounter(Mounter):
    """Mounter that 'mounts' a directory already populated by the test."""

    def __init__(self, mount_point: Path) -> None:
        super().__init__(mount_point, ["vfat"])
        self.mounted = False
        self.read_only: bool | None = None
        self.present = True

    def mount(self, device: UsbDevice, read_only: bool = True) -> None:
        self.device = device
        self.mounted = True
        self.read_only = read_only

    def remount_rw(self) -> None:
        self.read_only = False

    def unmount(self) -> None:
        self.mounted = False
        self.device = None

    def is_mounted(self) -> bool:
        return self.mounted

    def is_present(self) -> bool:
        return self.present and self.mounted


@pytest.fixture
def display() -> RecordingDisplay:
    return RecordingDisplay()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return parse_config(
        {
            "kiosk": {"name": "test", "fake_scan": True, "interface": "console"},
            "device": {"mount_point": str(tmp_path / "media")},
            "scan": {"workers": 2},
            "quarantine": {"folder": str(tmp_path / "quarantine")},
            "logging": {"file": ""},
        }
    )


@pytest.fixture
def usb_tree(tmp_path: Path) -> Path:
    """A fake device content: two clean files and an EICAR file in a sub folder."""
    root = tmp_path / "media"
    (root / "docs").mkdir(parents=True)
    (root / "readme.txt").write_text("hello")
    (root / "docs" / "report.pdf").write_bytes(b"%PDF-1.4 harmless")
    (root / "docs" / "eicar.com").write_bytes(EICAR)
    return root
