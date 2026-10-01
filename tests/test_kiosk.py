from __future__ import annotations

import json
from pathlib import Path

import pytest

from usb_pasteur.config import Config, parse_config
from usb_pasteur.device import UsbDevice
from usb_pasteur.kiosk import Kiosk, NoEngineError, build_engines
from usb_pasteur.monitor import Action, DeviceEvent

from .conftest import DirectoryMounter, ListSource, RecordingDisplay

DEVICE = UsbDevice("/dev/sdb1", "vfat", "KEY")


def make_kiosk(
    config: Config, display: RecordingDisplay, mounter: DirectoryMounter, events: list[DeviceEvent]
) -> Kiosk:
    return Kiosk(config, display, ListSource(events), build_engines(config), mounter)


def test_infected_device_is_cleaned(
    config: Config, display: RecordingDisplay, usb_tree: Path, tmp_path: Path
) -> None:
    mounter = DirectoryMounter(usb_tree)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)]).run()

    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert (usb_tree / "readme.txt").exists()
    assert display.confirmations == 1
    assert "Device cleaned! You can remove the device." in display.messages
    assert display.percents[-1] == 100
    assert not mounter.mounted
    manifests = list((tmp_path / "quarantine").glob("*/manifest.json"))
    assert json.loads(manifests[0].read_text())[0]["original_path"] == "docs/eicar.com"


def test_clean_device(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "file.txt").write_text("hello")
    make_kiosk(config, display, DirectoryMounter(root), [DeviceEvent(Action.ADD, DEVICE)]).run()

    assert display.confirmations == 0
    assert "No infected file found. You can remove the device." in display.messages
    assert not (tmp_path / "quarantine").exists()


def test_device_removed_before_clean(
    config: Config, display: RecordingDisplay, usb_tree: Path
) -> None:
    mounter = DirectoryMounter(usb_tree)
    kiosk = make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)])
    original_confirm = display.confirm

    def remove_device(prompt: str) -> None:
        original_confirm(prompt)
        mounter.present = False

    display.confirm = remove_device  # type: ignore[method-assign]
    kiosk.run()

    assert (usb_tree / "docs" / "eicar.com").exists()
    assert "Device removed before cleaning: NOT CLEANED" in display.messages


def test_scan_is_read_only(config: Config, display: RecordingDisplay, usb_tree: Path) -> None:
    mounter = DirectoryMounter(usb_tree)
    modes: list[bool | None] = []
    original_progress = display.progress

    def record(percent: int) -> None:
        modes.append(mounter.read_only)
        original_progress(percent)

    display.progress = record  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)]).run()
    assert modes and all(modes)
    assert mounter.read_only is False  # remounted read-write to clean


def test_rejected_filesystem(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    from usb_pasteur.device import Mounter

    (tmp_path / "media").mkdir()
    mounter = Mounter(tmp_path / "media", ["vfat"])
    event = DeviceEvent(Action.ADD, UsbDevice("/dev/sdb1", "ntfs"))
    Kiosk(config, display, ListSource([event]), build_engines(config), mounter).run()
    assert "Cannot mount device: filesystem not allowed: ntfs" in display.messages
    assert "Error: please remove the device." in display.messages


def test_device_removed(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    mounter = DirectoryMounter(tmp_path)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.REMOVE, DEVICE)]).run()
    assert display.devices == [None]
    assert "Device removed" in display.messages


def test_fake_scan_banner(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    make_kiosk(config, display, DirectoryMounter(tmp_path), []).run()
    assert display.messages[0].startswith("FAKE SCAN MODE")


def test_no_engine_without_fake_scan() -> None:
    with pytest.raises(NoEngineError):
        build_engines(parse_config({"kiosk": {"fake_scan": False}}))
