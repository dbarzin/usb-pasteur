"""Scan of one file: open, hash, identify, then run the engines.

This code runs in the scan worker processes: it must not depend on the state
of the kiosk process.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from usb_pasteur.engines import Engine, EngineKind, EngineResult, FileInfo, Verdict, aggregate
from usb_pasteur.filetype import FileTypeDetector
from usb_pasteur.hashing import hash_fd
from usb_pasteur.inventory import Entry, UnsafeFileError, open_entry
from usb_pasteur.results import FileResult

KNOWN_FILE = "known file (hashlookup)"


@dataclass(frozen=True)
class PipelineOptions:
    # Skip the content engines for files known by a hash engine (hashlookup),
    # unless a hash engine reports them as malicious
    skip_content_for_known: bool = True


def scan_entry(
    root: Path,
    entry: Entry,
    engines: Sequence[Engine],
    detector: FileTypeDetector,
    options: PipelineOptions | None = None,
) -> FileResult:
    start = time.monotonic()
    path = root / entry.rel_path

    def error(detail: str) -> FileResult:
        return FileResult(
            path,
            entry.size,
            Verdict.ERROR,
            detail=detail,
            duration=time.monotonic() - start,
            rel_path=entry.rel_path,
        )

    try:
        with open_entry(root, entry) as fd:
            hashes = hash_fd(fd)
            if hashes.size != entry.size:
                return error("file size changed while reading")
            file_type = detector.identify(fd)
            info = FileInfo(
                rel_path=entry.rel_path,
                size=hashes.size,
                sha256=hashes.sha256,
                sha1=hashes.sha1,
                md5=hashes.md5,
                mime=file_type.mime,
                description=file_type.description,
                fd=fd,
            )
            results = run_engines(info, engines, options or PipelineOptions())
    except UnsafeFileError as ex:
        return error(str(ex))
    except OSError as ex:
        return error(f"cannot read: {ex.strerror or ex}")
    return FileResult(
        path=path,
        size=entry.size,
        verdict=aggregate(results),
        results=tuple(results),
        duration=time.monotonic() - start,
        info=info,
        rel_path=entry.rel_path,
    )


def run_engines(
    info: FileInfo, engines: Sequence[Engine], options: PipelineOptions
) -> list[EngineResult]:
    """Run the hash engines, then the content engines.

    A malicious hash always wins over a "known file" answer: the content
    engines are only skipped for known files that no engine reports.
    """
    results = [run_engine(e, info) for e in engines if e.kind is EngineKind.HASH]
    malicious = any(r.verdict is Verdict.MALICIOUS for r in results)
    known = any(r.facts.get("known") is True for r in results)
    for engine in engines:
        if engine.kind is EngineKind.HASH:
            continue
        if known and not malicious and options.skip_content_for_known:
            results.append(EngineResult(engine.name, Verdict.SKIPPED, reason=KNOWN_FILE))
        else:
            results.append(run_engine(engine, info))
    return results


def run_engine(engine: Engine, info: FileInfo) -> EngineResult:
    """Run one engine: an exception or an overrun of its timeout is an error."""
    start = time.monotonic()
    try:
        result = engine.scan(info)
    except Exception as ex:  # an engine failure must not stop the scan
        result = EngineResult(engine.name, Verdict.ERROR, error=f"{type(ex).__name__}: {ex}")
    duration = time.monotonic() - start
    if not isinstance(result, EngineResult) or result.engine != engine.name:
        result = EngineResult(engine.name, Verdict.ERROR, error="invalid engine result")
    elif duration > engine.timeout and result.verdict in (Verdict.CLEAN, Verdict.SKIPPED):
        # A late clean answer is not trusted; a late detection is kept
        result = EngineResult(
            engine.name, Verdict.ERROR, error=f"timeout ({engine.timeout:g}s) exceeded"
        )
    return dataclasses.replace(result, duration=duration)
