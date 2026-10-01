"""Fake engine used in FAKE_SCAN mode, for development and tests only."""

from __future__ import annotations

import os
import time
from pathlib import Path

from usb_pasteur.engines.base import EngineResult, Verdict

# The EICAR test string is built at runtime so that this source file is not itself
# detected by antivirus software (keep the explicit concatenation)
_EICAR_HEAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
EICAR = _EICAR_HEAD + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_READ_SIZE = 4096


class FakeEngine:
    """Reports the EICAR test file as malicious and every other file as clean.

    It performs no real detection: it only lets the kiosk workflow (scan,
    quarantine, cleaning) be exercised without the real engines.
    """

    name = "fake"

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay

    def scan(self, path: Path) -> EngineResult:
        if self.delay:
            time.sleep(self.delay)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            head = f.read(_READ_SIZE)
        if EICAR in head:
            return EngineResult(self.name, Verdict.MALICIOUS, "EICAR-Test-File")
        return EngineResult(self.name, Verdict.CLEAN)
