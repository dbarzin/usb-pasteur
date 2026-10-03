"""Signature databases: provenance, freshness, and the verification hook.

Each signature folder may contain a manifest.json describing its files, written
by the update tool (phase 2) or by scripts/fetch-dev-signatures.py:

    {"hashlookup-full.bloom": {"version": "...", "date": "2026-10-01T00:00:00Z",
                               "source": "https://...", "sha256": "..."}}

Without a manifest, the file modification time is used as the signature date.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from usb_pasteur.engines.base import SignatureInfo
from usb_pasteur.logs import get_logger, log_event

logger = get_logger("signatures")

MANIFEST = "manifest.json"


def describe_file(
    path: Path, source: str = "", version: str = "", date: datetime | None = None
) -> SignatureInfo:
    """Describe a signature file from its manifest entry.

    Without a manifest date, use the given date, or else the file mtime.
    """
    default_date = date
    entry = _manifest_entry(path)
    date = None
    raw_date = entry.get("date")
    if isinstance(raw_date, str):
        try:
            date = datetime.fromisoformat(raw_date)
        except ValueError:
            date = None
        if date is not None and date.tzinfo is None:
            date = date.replace(tzinfo=UTC)
    if date is None:
        date = default_date
    if date is None:
        try:
            date = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        except OSError:
            date = None
    return SignatureInfo(
        name=path.name,
        version=str(entry.get("version") or version),
        date=date,
        path=str(path),
        source=str(entry.get("source") or source),
    )


def _manifest_entry(path: Path) -> dict[str, object]:
    manifest = path.parent / MANIFEST
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entry = data.get(path.name) if isinstance(data, dict) else None
    return entry if isinstance(entry, dict) else {}


def verify_signatures(engine: str, paths: Sequence[Path]) -> None:
    """Verify the integrity and origin of signature files before loading them.

    Phase 2 hook: signed updates are not implemented yet, so nothing is
    verified. Implementations must raise EngineError when a file is not trusted.
    """
    log_event(
        logger,
        "signatures_not_verified",
        logging.DEBUG,
        engine=engine,
        files=[str(p) for p in paths],
    )


@dataclass(frozen=True)
class StaleSignature:
    engine: str
    signature: SignatureInfo
    age_days: float


def find_stale(
    engine: str, infos: Sequence[SignatureInfo], max_age_days: float, now: datetime | None = None
) -> list[StaleSignature]:
    """Signatures older than max_age_days, or without a known date."""
    now = now or datetime.now(UTC)
    stale = []
    for info in infos:
        if info.date is None:
            stale.append(StaleSignature(engine, info, float("inf")))
            continue
        age = (now - info.date).total_seconds() / 86400
        if age > max_age_days:
            stale.append(StaleSignature(engine, info, age))
    return stale
