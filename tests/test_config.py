from __future__ import annotations

from pathlib import Path

import pytest

from usb_pasteur.config import Config, ConfigError, load_config, parse_config

EXAMPLE = Path(__file__).parent.parent / "packaging" / "usb-pasteur.toml"


def test_defaults() -> None:
    config = parse_config({})
    assert config.kiosk.fake_scan is False
    assert config.kiosk.interface == "curses"
    assert config.device.mount_point == Path("/media/usb-pasteur")
    assert config.scan.workers == 4
    assert config.scan.suspicious == "block"
    assert config.quarantine.enabled is True
    assert config.logging.level == "INFO"


def test_example_file_matches_defaults() -> None:
    config = load_config(EXAMPLE)
    defaults = Config()
    assert config.device == defaults.device
    assert config.scan == defaults.scan
    assert config.quarantine == defaults.quarantine
    assert config.logging == defaults.logging
    assert config.kiosk.fake_scan is False


def test_full_config() -> None:
    config = parse_config(
        {
            "kiosk": {"name": "kiosk-01", "fake_scan": True, "interface": "console"},
            "device": {"allowed_filesystems": ["vfat"], "use_sudo": True},
            "scan": {"workers": 8, "max_file_size": 1000, "suspicious": "warn", "fake_delay": 1},
            "logging": {"file": "", "level": "DEBUG"},
        }
    )
    assert config.kiosk.name == "kiosk-01"
    assert config.device.allowed_filesystems == ("vfat",)
    assert config.scan.fake_delay == 1.0
    assert config.scan.suspicious == "warn"
    assert config.logging.file is None


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"unknown": {}}, "unknown key"),
        ({"kiosk": {"fake_scan": "yes"}}, "kiosk.fake_scan must be of type bool"),
        ({"kiosk": {"interface": "web"}}, "kiosk.interface must be one of"),
        ({"kiosk": {"name": " "}}, "kiosk.name must not be empty"),
        ({"kiosk": {"typo": 1}}, "unknown key(s) in [kiosk]: typo"),
        ({"kiosk": 1}, "[kiosk] must be a table"),
        ({"device": {"mount_point": "media"}}, "must be an absolute path"),
        ({"device": {"allowed_filesystems": ["btrfs"]}}, "unsupported filesystem"),
        ({"device": {"allowed_filesystems": [1]}}, "list of strings"),
        ({"device": {"command_timeout": 0}}, "must be positive"),
        ({"scan": {"workers": 0}}, "between 1 and 64"),
        ({"scan": {"workers": True}}, "must be of type int"),
        ({"scan": {"max_file_size": -1}}, "positive number of bytes"),
        ({"scan": {"fake_delay": -1}}, "must not be negative"),
        ({"scan": {"suspicious": "ignore"}}, "scan.suspicious must be one of: block, warn"),
        ({"logging": {"level": "TRACE"}}, "logging.level must be one of"),
    ],
)
def test_invalid(data: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=None) as info:
        parse_config(data)
    assert message in str(info.value)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")


def test_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[kiosk\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)
