"""The kiosk: wait for a device, scan it, then remove infected files."""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from pathlib import Path

from usb_pasteur.config import Config
from usb_pasteur.device import DeviceError, Mounter, UsbDevice
from usb_pasteur.engines import Engine, FakeEngine
from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.monitor import Action, DeviceSource
from usb_pasteur.quarantine import Quarantine
from usb_pasteur.scanner import FileResult, Scanner, ScanSummary, describe
from usb_pasteur.statemachine import State, StateMachine
from usb_pasteur.ui import Display

logger = get_logger("kiosk")

# Number of infected files listed on screen before asking to clean
_MAX_LISTED = 10


class NoEngineError(Exception):
    pass


def build_engines(config: Config) -> list[Engine]:
    if config.kiosk.fake_scan:
        return [FakeEngine(delay=config.scan.fake_delay)]
    # Real engines (Hashlookup, MalwareBazaar, ClamAV, YARA-X) come in phase 1
    raise NoEngineError(
        "no detection engine is available yet: set kiosk.fake_scan = true for development"
    )


class Kiosk:
    def __init__(
        self,
        config: Config,
        display: Display,
        source: DeviceSource,
        engines: Sequence[Engine],
        mounter: Mounter | None = None,
    ) -> None:
        self.config = config
        self.display = display
        self.source = source
        self.scanner = Scanner(engines, config.scan.workers, config.limits)
        self.mounter = mounter or Mounter(
            config.device.mount_point,
            config.device.allowed_filesystems,
            use_sudo=config.device.use_sudo,
            timeout=config.device.command_timeout,
        )
        self.quarantine = (
            Quarantine(config.quarantine.folder) if config.quarantine.enabled else None
        )
        self.device: UsbDevice | None = None
        self.summary: ScanSummary | None = None
        # Files to quarantine and remove, depending on the suspicious policy
        self.to_remove: list[FileResult] = []
        self.machine = StateMachine(
            {
                State.START: self.on_start,
                State.WAIT: self.on_wait,
                State.INSERTED: self.on_inserted,
                State.SCAN: self.on_scan,
                State.CLEAN: self.on_clean,
                State.ERROR: self.on_error,
            }
        )

    def run(self) -> None:
        try:
            self.machine.run()
        finally:
            self._unmount()
            log_event(logger, "kiosk_stopped")

    # -- states ------------------------------------------------------------

    def on_start(self) -> State:
        log_event(
            logger,
            "kiosk_started",
            fake_scan=self.config.kiosk.fake_scan,
            engines=[e.name for e in self.scanner.engines],
        )
        if self.config.kiosk.fake_scan:
            self.display.message("FAKE SCAN MODE - for development only, no real detection")
        self.display.message("Ready. Insert a USB device.")
        return State.WAIT

    def on_wait(self) -> State:
        self._unmount()
        event = self.source.wait_event()
        if event is None:
            return State.STOP
        if event.action is Action.REMOVE:
            log_event(logger, "device_removed", node=event.device.node)
            self.device = None
            self.display.show_device(None)
            self.display.message("Device removed")
            return State.WAIT
        self.device = event.device
        d = event.device
        log_event(
            logger,
            "device_inserted",
            node=d.node,
            fs_type=d.fs_type,
            label=d.label,
            vendor=d.vendor,
            model=d.model,
            serial=d.serial,
        )
        self.display.show_device(d)
        self.display.message("Device inserted")
        return State.INSERTED

    def on_inserted(self) -> State:
        if self.device is None:
            return State.WAIT
        try:
            self.mounter.mount(self.device, read_only=True)
        except DeviceError as ex:
            log_event(logger, "mount_failed", logging.ERROR, node=self.device.node, error=str(ex))
            self.display.message(f"Cannot mount device: {ex}")
            return State.ERROR
        return State.SCAN

    def on_scan(self) -> State:
        root = self.mounter.mount_point
        try:
            st = os.statvfs(root)
        except OSError as ex:
            log_event(logger, "statvfs_failed", logging.ERROR, error=str(ex))
            self.display.message(f"Cannot read device: {ex}")
            return State.ERROR
        size = st.f_frsize * st.f_blocks
        used = max(1, st.f_frsize * (st.f_blocks - st.f_bfree))
        self.display.show_usage(size, used)
        log_event(logger, "scan_started", size=size, used=used)
        self.display.message("Scanning...")
        self.display.progress(0)

        def on_progress(result: FileResult, done: int, total: int) -> None:
            self.display.message(describe(result))
            self.display.progress(min(99, done * 100 // max(1, total)))

        self.summary = self.scanner.scan_tree(root, on_progress)
        self.display.progress(100)
        s = self.summary
        self.display.message(
            f"Scan done in {s.duration:.1f}s, {len(s.files)} files scanned, "
            f"{len(s.infected)} files infected, {len(s.suspicious)} files suspicious"
        )
        self.to_remove = s.infected
        if self.config.scan.suspicious == "block":
            self.to_remove = s.infected + s.suspicious
        if self.quarantine is not None:
            try:
                self.quarantine.store(self.to_remove, root)
            except OSError as ex:
                log_event(logger, "quarantine_failed", logging.ERROR, error=str(ex))
        return State.CLEAN

    def on_clean(self) -> State:
        if self.summary is None:
            return State.WAIT
        infected = self.to_remove
        if self.config.scan.suspicious == "warn" and self.summary.suspicious:
            suspicious = self.summary.suspicious
            log_event(logger, "suspicious_files", logging.WARNING, count=len(suspicious))
            self._list(
                f"WARNING: {len(suspicious)} suspicious files, use with caution:", suspicious
            )
        if not infected:
            self._unmount()
            self.display.message("No infected file found. You can remove the device.")
            return State.WAIT

        log_event(logger, "infected_files", count=len(infected))
        self._list(f"{len(infected)} infected files detected:", infected)
        self.display.confirm("PRESS A KEY OR TOUCH THE SCREEN TO CLEAN")

        if not self.mounter.is_present():
            log_event(logger, "device_removed_before_clean", logging.WARNING)
            self.display.message("Device removed before cleaning: NOT CLEANED")
            return State.ERROR
        try:
            self.mounter.remount_rw()
        except DeviceError as ex:
            log_event(logger, "remount_failed", logging.ERROR, error=str(ex))
            self.display.message(f"Cannot clean device: {ex}")
            return State.ERROR

        removed = sum(self._remove(result.path) for result in infected)
        self._unmount()
        log_event(logger, "device_cleaned", removed=removed, infected=len(infected))
        if removed == len(infected):
            self.display.message("Device cleaned! You can remove the device.")
        else:
            self.display.message(f"Device NOT cleaned: {len(infected) - removed} files remain")
        return State.WAIT

    def on_error(self) -> State:
        self._unmount()
        self.display.message("Error: please remove the device.")
        return State.WAIT

    # -- helpers -----------------------------------------------------------

    def _list(self, title: str, results: list[FileResult]) -> None:
        self.display.message(title)
        for result in results[:_MAX_LISTED]:
            self.display.message(result.rel_path)
        if len(results) > _MAX_LISTED:
            self.display.message("...")

    def _remove(self, path: Path) -> bool:
        root = self.mounter.mount_point
        # Never follow a link out of the device
        if not Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root)):
            log_event(logger, "remove_refused", logging.ERROR, path=str(path))
            return False
        try:
            path.unlink()
        except OSError as ex:
            log_event(logger, "remove_failed", logging.ERROR, path=str(path), error=ex.strerror)
            self.display.message(f"Could not remove {path.name}: {ex.strerror}")
            return False
        log_event(logger, "file_removed", path=str(path))
        self.display.message(f"{path.relative_to(root)} removed")
        return True

    def _unmount(self) -> None:
        try:
            self.mounter.unmount()
        except DeviceError as ex:
            log_event(logger, "unmount_failed", logging.ERROR, error=str(ex))
