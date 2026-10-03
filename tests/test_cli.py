from __future__ import annotations

from pathlib import Path

import pytest

from usb_pasteur.cli import apply_overrides, main, parse_args
from usb_pasteur.config import parse_config


def write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "usb-pasteur.toml"
    path.write_text(content)
    return path


def test_check_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "[kiosk]\nfake_scan = true\n")
    assert main(["--config", str(path), "--check-config"]) == 0
    assert "OK" in capsys.readouterr().out


def test_invalid_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, "[kiosk]\nfake_scan = 1\n")
    assert main(["--config", str(path), "--check-config"]) == 2
    assert "kiosk.fake_scan" in capsys.readouterr().err


def test_refuses_to_start_without_engine_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every engine is enabled by default: without signatures, the kiosk refuses to start
    path = write(tmp_path, "")
    assert main(["--config", str(path), "--check-config"]) == 2
    assert "cannot load an enabled engine: malwarebazaar" in capsys.readouterr().err
    assert main(["--config", str(path), "--check-config", "--fake-scan"]) == 0


def test_refuses_to_start_without_content_engine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(
        tmp_path,
        "[engines.clamav]\nenabled = false\n[engines.yara]\nenabled = false\n",
    )
    assert main(["--config", str(path), "--check-config"]) == 2
    assert "no content engine" in capsys.readouterr().err


def test_overrides() -> None:
    args = parse_args(["--fake-scan", "--interface", "console"])
    config = apply_overrides(parse_config({}), args)
    assert config.kiosk.fake_scan is True
    assert config.kiosk.interface == "console"
