"""Test engines, importable by the scan worker processes."""

from __future__ import annotations

import os
import time

from usb_pasteur.engines import Engine, EngineError, EngineResult, FakeEngine, FileInfo, Verdict


class SuspiciousEngine(FakeEngine):
    """Fake engine that also reports files named *.suspect as suspicious."""

    def scan(self, file: FileInfo) -> EngineResult:
        if file.rel_path.endswith(".suspect"):
            return EngineResult(self.name, Verdict.SUSPICIOUS, ("Heuristic",))
        return super().scan(file)


class MisbehavingEngine(Engine):
    """Clean, except for files whose name contains the trigger.

    behavior: "raise", "hang" (sleeps forever), "crash" (kills the worker),
    "slow" (answers clean after its timeout), "bad" (invalid result).
    """

    name = "misbehaving"

    def __init__(self, behavior: str, trigger: str = "", timeout: float = 60.0) -> None:
        self.behavior = behavior
        self.trigger = trigger
        self.timeout = timeout

    def scan(self, file: FileInfo) -> EngineResult:
        if self.trigger in file.rel_path:
            if self.behavior == "raise":
                raise RuntimeError("boom")
            if self.behavior == "hang":
                time.sleep(3600)
            if self.behavior == "crash":
                os._exit(3)
            if self.behavior == "slow":
                time.sleep(self.timeout + 0.2)
            if self.behavior == "bad":
                return "clean"  # type: ignore[return-value]
        return EngineResult(self.name, Verdict.CLEAN)


class FailingLoadEngine(Engine):
    name = "failing"

    def load(self) -> None:
        raise EngineError("failing: no signatures")

    def scan(self, file: FileInfo) -> EngineResult:
        return EngineResult(self.name, Verdict.CLEAN)
