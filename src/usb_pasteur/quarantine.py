"""Copy infected files to the kiosk quarantine folder."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.scanner import FileResult

logger = get_logger("quarantine")

_CHUNK = 1024 * 1024


class Quarantine:
    def __init__(self, folder: Path) -> None:
        self.folder = folder

    def store(self, infected: Sequence[FileResult], root: Path) -> Path | None:
        """Copy infected files into a new timestamped folder with a manifest.

        Files are renamed to a sequence number so that untrusted names never
        become paths on the kiosk; the original path is kept in manifest.json.
        """
        if not infected:
            return None
        target = self.folder / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        target.mkdir(mode=0o700, parents=True)
        manifest = []
        for index, result in enumerate(infected, start=1):
            name = f"{index:05d}.bin"
            entry: dict[str, object] = {
                "file": name,
                "original_path": str(result.path.relative_to(root)),
                "size": result.size,
                "detections": {r.engine: r.detail for r in result.results if r.detail},
            }
            try:
                entry["sha256"] = _copy(result.path, target / name)
            except OSError as ex:
                entry["error"] = ex.strerror
                log_event(logger, "quarantine_failed", path=str(result.path), error=ex.strerror)
            manifest.append(entry)
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        log_event(logger, "quarantine_stored", folder=str(target), files=len(infected))
        return target


def _copy(source: Path, target: Path) -> str:
    """Copy a file without following symbolic links and return its SHA-256."""
    digest = hashlib.sha256()
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as src, target.open("xb") as dst:
        while chunk := src.read(_CHUNK):
            digest.update(chunk)
            dst.write(chunk)
    target.chmod(0o400)
    return digest.hexdigest()
