from __future__ import annotations

import json
import stat
from pathlib import Path

from usb_pasteur.config import LimitsConfig
from usb_pasteur.engines.fake import EICAR
from usb_pasteur.quarantine import Quarantine
from usb_pasteur.scanner import Scanner
from usb_pasteur.workers import WorkerPool


def test_store(usb_tree: Path, tmp_path: Path, fake_pool: WorkerPool) -> None:
    summary = Scanner(fake_pool, LimitsConfig()).scan_tree(usb_tree)
    folder = Quarantine(tmp_path / "q").store(summary.infected, usb_tree)
    assert folder is not None
    stored = folder / "00001.bin"
    assert stored.read_bytes() == EICAR
    assert stat.S_IMODE(stored.stat().st_mode) == 0o400
    manifest = json.loads((folder / "manifest.json").read_text())
    assert manifest["report"] == {"id": None, "path": None}
    [entry] = manifest["files"]
    assert entry["original_path"] == "docs/eicar.com"
    assert entry["detections"] == {"fake": "EICAR-Test-File"}
    assert entry["verdict"] == "malicious"
    assert len(entry["sha256"]) == 64


def test_nothing_to_store(tmp_path: Path) -> None:
    assert Quarantine(tmp_path / "q").store([], tmp_path) is None
    assert not (tmp_path / "q").exists()
