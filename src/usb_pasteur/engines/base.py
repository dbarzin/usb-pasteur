"""Common interface implemented by every detection engine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    SKIPPED = "skipped"


# Highest priority first: the aggregated verdict is the most severe one
_SEVERITY = (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.ERROR, Verdict.CLEAN, Verdict.SKIPPED)


@dataclass(frozen=True)
class EngineResult:
    engine: str
    verdict: Verdict
    detail: str = ""


class Engine(Protocol):
    """A detection engine. Implementations must be thread-safe and work offline."""

    name: str

    def scan(self, path: Path) -> EngineResult: ...


def aggregate(results: Iterable[EngineResult]) -> Verdict:
    """Combine engine results: a single positive engine is enough."""
    verdicts = {r.verdict for r in results}
    for verdict in _SEVERITY:
        if verdict in verdicts:
            return verdict
    return Verdict.SKIPPED
