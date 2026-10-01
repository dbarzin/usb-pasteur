"""TOML configuration, loaded and validated at startup."""

from __future__ import annotations

import socket
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("/etc/usb-pasteur/usb-pasteur.toml")

INTERFACES = ("curses", "console")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
SUSPICIOUS_POLICIES = ("block", "warn")
SUPPORTED_FILESYSTEMS = ("vfat", "exfat", "ntfs", "ext4")


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


@dataclass(frozen=True)
class KioskConfig:
    name: str = field(default_factory=socket.gethostname)
    fake_scan: bool = False
    interface: str = "curses"


@dataclass(frozen=True)
class DeviceConfig:
    mount_point: Path = Path("/media/usb-pasteur")
    use_sudo: bool = False
    allowed_filesystems: tuple[str, ...] = SUPPORTED_FILESYSTEMS
    command_timeout: float = 60.0


@dataclass(frozen=True)
class ScanConfig:
    workers: int = 4
    max_file_size: int = 1024**3
    # "block": suspicious files are quarantined and removed like malicious ones
    # "warn": they are only reported to the user
    suspicious: str = "block"
    fake_delay: float = 0.0


@dataclass(frozen=True)
class QuarantineConfig:
    enabled: bool = True
    folder: Path = Path("/var/lib/usb-pasteur/quarantine")


@dataclass(frozen=True)
class LoggingConfig:
    file: Path | None = Path("/var/log/usb-pasteur/usb-pasteur.log")
    level: str = "INFO"


@dataclass(frozen=True)
class Config:
    kiosk: KioskConfig = field(default_factory=KioskConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    quarantine: QuarantineConfig = field(default_factory=QuarantineConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(path: Path) -> Config:
    """Read and validate the configuration file."""
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError as ex:
        raise ConfigError(f"configuration file not found: {path}") from ex
    except tomllib.TOMLDecodeError as ex:
        raise ConfigError(f"{path}: invalid TOML: {ex}") from ex
    except OSError as ex:
        raise ConfigError(f"{path}: {ex.strerror}") from ex
    return parse_config(data)


def parse_config(data: dict[str, Any]) -> Config:
    """Build a validated Config from a parsed TOML document."""
    _reject_unknown(data, {f.name for f in fields(Config)}, "")
    for name, value in data.items():
        if not isinstance(value, dict):
            raise ConfigError(f"[{name}] must be a table")

    kiosk = data.get("kiosk", {})
    _reject_unknown(kiosk, {"name", "fake_scan", "interface"}, "kiosk")
    kiosk_cfg = KioskConfig(
        name=_get(kiosk, "kiosk", "name", str, KioskConfig().name),
        fake_scan=_get(kiosk, "kiosk", "fake_scan", bool, False),
        interface=_choice(kiosk, "kiosk", "interface", INTERFACES, "curses"),
    )
    if not kiosk_cfg.name.strip():
        raise ConfigError("kiosk.name must not be empty")

    device = data.get("device", {})
    _reject_unknown(
        device, {"mount_point", "use_sudo", "allowed_filesystems", "command_timeout"}, "device"
    )
    filesystems = _get(device, "device", "allowed_filesystems", list, list(SUPPORTED_FILESYSTEMS))
    for fs in filesystems:
        if fs not in SUPPORTED_FILESYSTEMS:
            raise ConfigError(
                f"device.allowed_filesystems: unsupported filesystem {fs!r} "
                f"(supported: {', '.join(SUPPORTED_FILESYSTEMS)})"
            )
    device_cfg = DeviceConfig(
        mount_point=_path(device, "device", "mount_point", DeviceConfig.mount_point),
        use_sudo=_get(device, "device", "use_sudo", bool, False),
        allowed_filesystems=tuple(filesystems),
        command_timeout=_positive(device, "device", "command_timeout", 60.0),
    )

    scan = data.get("scan", {})
    _reject_unknown(scan, {"workers", "max_file_size", "suspicious", "fake_delay"}, "scan")
    workers = _get(scan, "scan", "workers", int, 4)
    if not 1 <= workers <= 64:
        raise ConfigError("scan.workers must be between 1 and 64")
    max_file_size = _get(scan, "scan", "max_file_size", int, 1024**3)
    if max_file_size <= 0:
        raise ConfigError("scan.max_file_size must be a positive number of bytes")
    fake_delay = _number(scan, "scan", "fake_delay", 0.0)
    if fake_delay < 0:
        raise ConfigError("scan.fake_delay must not be negative")
    scan_cfg = ScanConfig(
        workers=workers,
        max_file_size=max_file_size,
        suspicious=_choice(scan, "scan", "suspicious", SUSPICIOUS_POLICIES, "block"),
        fake_delay=fake_delay,
    )

    quarantine = data.get("quarantine", {})
    _reject_unknown(quarantine, {"enabled", "folder"}, "quarantine")
    quarantine_cfg = QuarantineConfig(
        enabled=_get(quarantine, "quarantine", "enabled", bool, True),
        folder=_path(quarantine, "quarantine", "folder", QuarantineConfig.folder),
    )

    log = data.get("logging", {})
    _reject_unknown(log, {"file", "level"}, "logging")
    log_file: Path | None = _path(log, "logging", "file", LoggingConfig.file or Path())
    if "file" in log and log["file"] == "":
        log_file = None
    logging_cfg = LoggingConfig(
        file=log_file,
        level=_choice(log, "logging", "level", LOG_LEVELS, "INFO"),
    )

    return Config(
        kiosk=kiosk_cfg,
        device=device_cfg,
        scan=scan_cfg,
        quarantine=quarantine_cfg,
        logging=logging_cfg,
    )


def _reject_unknown(table: dict[str, Any], allowed: Any, section: str) -> None:
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        where = f"[{section}]" if section else "top level"
        raise ConfigError(f"unknown key(s) in {where}: {', '.join(unknown)}")


def _get[T](table: dict[str, Any], section: str, key: str, kind: type[T], default: T) -> T:
    if key not in table:
        return default
    value = table[key]
    # bool is a subclass of int: reject it explicitly for integer settings
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ConfigError(f"{section}.{key} must be of type {kind.__name__}")
    if kind is list and not all(isinstance(v, str) for v in value):  # type: ignore[attr-defined]
        raise ConfigError(f"{section}.{key} must be a list of strings")
    return value


def _number(table: dict[str, Any], section: str, key: str, default: float) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{section}.{key} must be a number")
    return float(value)


def _positive(table: dict[str, Any], section: str, key: str, default: float) -> float:
    value = _number(table, section, key, default)
    if value <= 0:
        raise ConfigError(f"{section}.{key} must be positive")
    return value


def _choice(
    table: dict[str, Any], section: str, key: str, choices: tuple[str, ...], default: str
) -> str:
    value = _get(table, section, key, str, default)
    if value not in choices:
        raise ConfigError(f"{section}.{key} must be one of: {', '.join(choices)}")
    return value


def _path(table: dict[str, Any], section: str, key: str, default: Path) -> Path:
    value = _get(table, section, key, str, str(default))
    path = Path(value)
    if value and not path.is_absolute():
        raise ConfigError(f"{section}.{key} must be an absolute path")
    return path
