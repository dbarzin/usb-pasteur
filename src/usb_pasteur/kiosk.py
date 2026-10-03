"""The kiosk: wait for a device, scan it, then remove infected files."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path

from usb_pasteur.config import Config
from usb_pasteur.device import DeviceError, Mounter, SystemMountWatcher, UsbDevice
from usb_pasteur.engines import Engine
from usb_pasteur.engines.registry import NoEngineError, engine_specs, load_engines
from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.monitor import Action, DeviceSource
from usb_pasteur.policy import device_verdict
from usb_pasteur.quarantine import Quarantine
from usb_pasteur.report import (
    Actions,
    DeviceUsage,
    ScanReport,
    build_report,
    set_actions,
    write_report,
)
from usb_pasteur.scanner import FileResult, Scanner, ScanSummary, describe, pipeline_options
from usb_pasteur.signatures import find_stale
from usb_pasteur.statemachine import State, StateMachine
from usb_pasteur.text import escape
from usb_pasteur.ui import Display
from usb_pasteur.workers import EngineInfo, WorkerPool

logger = get_logger("kiosk")

# Number of infected files listed on screen before asking to clean
_MAX_LISTED = 10


__all__ = ["Kiosk", "NoEngineError", "build_engines", "build_pool", "stale_signatures"]


def build_engines(config: Config) -> list[Engine]:
    """Load the enabled engines in this process (configuration check).

    Raise NoEngineError or EngineError on failure.
    """
    return load_engines(engine_specs(config))


def build_pool(config: Config) -> WorkerPool:
    """The scan worker pool (not started); raise NoEngineError without engine."""
    return WorkerPool(
        engine_specs(config),
        pipeline_options(config),
        config.scan.workers,
        config.scan.file_timeout,
    )


def make_mounter(config: Config) -> Mounter:
    device = config.device
    if device.auto_mount:
        return SystemMountWatcher(device.allowed_filesystems, device.auto_mount_wait)
    return Mounter(
        device.mount_point,
        device.allowed_filesystems,
        use_sudo=device.use_sudo,
        timeout=device.command_timeout,
    )


def stale_signatures(config: Config, engines: list[EngineInfo]) -> list[str]:
    """Warnings for signature databases older than their maximum age."""
    engine_configs = {
        "malwarebazaar": config.engines.malwarebazaar.max_age_days,
        "hashlookup": config.engines.hashlookup.max_age_days,
        "clamav": config.engines.clamav.max_age_days,
        "yara": config.engines.yara.max_age_days,
    }
    warnings = []
    for engine in engines:
        if engine.name not in engine_configs:
            continue
        max_age = engine_configs[engine.name] or config.signatures.max_age_days
        for stale in find_stale(engine.name, engine.signatures, max_age):
            age = "unknown age" if stale.age_days == float("inf") else f"{stale.age_days:.0f} days"
            warnings.append(f"{engine.name}: signatures {stale.signature.name} are old ({age})")
    return warnings


class Kiosk:
    def __init__(
        self,
        config: Config,
        display: Display,
        source: DeviceSource,
        pool: WorkerPool,
        mounter: Mounter | None = None,
    ) -> None:
        """pool must be started; it is stopped by its owner."""
        self.config = config
        self.display = display
        self.source = source
        self.scanner = Scanner(pool, config.limits)
        self.mounter = mounter or make_mounter(config)
        self.quarantine = (
            Quarantine(config.quarantine.folder) if config.quarantine.enabled else None
        )
        self.device: UsbDevice | None = None
        self.summary: ScanSummary | None = None
        # Files to quarantine and remove, depending on the suspicious policy
        self.to_remove: list[FileResult] = []
        self.report: ScanReport | None = None
        self.actions = Actions()
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
            engines={e.name: e.version for e in self.scanner.engines},
            signatures={
                e.name: [
                    [s.name, s.version, s.date.isoformat() if s.date else None]
                    for s in e.signatures
                ]
                for e in self.scanner.engines
            },
        )
        if self.config.kiosk.fake_scan:
            self.display.message("FAKE SCAN MODE - for development only, no real detection")
        if self.config.device.auto_mount:
            self.display.message(
                "AUTO-MOUNT MODE - for development only, devices are not mounted read-only"
            )
        for warning in stale_signatures(self.config, self.scanner.engines):
            log_event(logger, "signatures_stale", logging.WARNING, warning=warning)
            self.display.message(f"WARNING: {warning}")
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
        started = datetime.now(UTC)
        # Signature versions as they are at the start of the scan
        engines = self.scanner.pool.engine_info()
        self.display.show_usage(size, used)
        log_event(logger, "scan_started", size=size, used=used)
        self.display.message("Scanning...")
        self.display.progress(0)

        def on_progress(result: FileResult, done: int, total: int) -> None:
            self.display.message(f"[{done}/{total}] {describe(result)}")
            self.display.progress(min(99, done * 100 // max(1, total)))

        self.summary = self.scanner.scan_tree(root, on_progress)
        self.display.progress(100)
        s = self.summary
        self.display.message(
            f"Scan done in {s.duration:.1f}s, {len(s.files)} files scanned, "
            f"{len(s.infected)} files infected, {len(s.suspicious)} files suspicious, "
            f"{len(s.unscanned)} files not fully scanned"
        )
        log_event(logger, "device_verdict", verdict=device_verdict(s).value, complete=s.complete)
        self.to_remove = s.infected
        if self.config.scan.suspicious == "block":
            self.to_remove = s.infected + s.suspicious
        self.report = build_report(
            self.config,
            self.device,
            DeviceUsage(size, used),
            engines,
            s,
            started,
            datetime.now(UTC),
        )
        self.actions = Actions()
        self._save_report()
        if self.quarantine is not None:
            try:
                self.actions.quarantine_folder = self.quarantine.store(
                    self.to_remove,
                    root,
                    self.report.report_id,
                    self.report.path,
                )
                if self.actions.quarantine_folder is not None:
                    self.actions.quarantined = list(self.to_remove)
            except OSError as ex:
                log_event(logger, "quarantine_failed", logging.ERROR, error=str(ex))
            self._save_report()
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
        not_verified = self._check_complete(self.summary)
        if not infected:
            self._unmount()
            if not_verified:
                self.display.message("DEVICE NOT VERIFIED: do not use it. Remove the device.")
            else:
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

        for result in infected:
            if self._remove(result.path):
                self.actions.removed.append(result)
            else:
                self.actions.remove_failed.append(result)
        removed = len(self.actions.removed)
        self.actions.cleaned = removed == len(infected)
        self._save_report()
        self._unmount()
        log_event(logger, "device_cleaned", removed=removed, infected=len(infected))
        if removed == len(infected) and not_verified:
            self.display.message(
                "Device cleaned, but NOT VERIFIED: do not use it. Remove the device."
            )
        elif removed == len(infected):
            self.display.message("Device cleaned! You can remove the device.")
        else:
            self.display.message(f"Device NOT cleaned: {len(infected) - removed} files remain")
        return State.WAIT

    def on_error(self) -> State:
        self._unmount()
        self.display.message("Error: please remove the device.")
        return State.WAIT

    # -- helpers -----------------------------------------------------------

    def _save_report(self) -> None:
        """Write the scan report; a failure is logged and shown, not fatal."""
        if self.report is None:
            return
        set_actions(self.report, self.actions)
        try:
            path = write_report(self.report, self.config.report.folder)
        except OSError as ex:
            log_event(logger, "report_failed", logging.ERROR, error=str(ex))
            self.display.message(f"WARNING: cannot write the scan report: {ex.strerror}")
            return
        log_event(logger, "report_written", report_id=self.report.report_id, path=str(path))

    def _check_complete(self, summary: ScanSummary) -> bool:
        """Report files that were not fully scanned.

        Return True when the device must be rejected (scan.on_error = "block").
        Unscanned files are never removed: they are not known to be malicious.
        """
        if summary.complete:
            return False
        unscanned = summary.unscanned
        block = self.config.scan.on_error == "block"
        log_event(
            logger,
            "device_not_verified" if block else "device_incomplete",
            logging.WARNING,
            files=len(unscanned),
            reasons=summary.incomplete_reasons,
        )
        if block:
            title = f"{len(unscanned)} files could not be fully scanned:"
        else:
            title = f"WARNING: {len(unscanned)} files could not be fully scanned, use with caution:"
        self._list(title, unscanned)
        for reason in summary.incomplete_reasons:
            self.display.message(f"Not scanned: {reason}")
        return block

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
            log_event(logger, "remove_refused", logging.ERROR, path=escape(str(path)))
            return False
        try:
            path.unlink()
        except OSError as ex:
            log_event(
                logger, "remove_failed", logging.ERROR, path=escape(str(path)), error=ex.strerror
            )
            self.display.message(f"Could not remove {path.name}: {ex.strerror}")
            return False
        log_event(logger, "file_removed", path=escape(str(path)))
        self.display.message(f"{path.relative_to(root)} removed")
        return True

    def _unmount(self) -> None:
        try:
            self.mounter.unmount()
        except DeviceError as ex:
            log_event(logger, "unmount_failed", logging.ERROR, error=str(ex))
