"""Scan every file of a mounted device with the detection engines."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path

from usb_pasteur.engines import Engine, EngineResult, Verdict, aggregate
from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.text import human_size

logger = get_logger("scanner")

ProgressCallback = Callable[["FileResult", int], None]


@dataclass(frozen=True)
class FileResult:
    path: Path
    size: int
    verdict: Verdict
    results: tuple[EngineResult, ...] = ()
    detail: str = ""
    duration: float = 0.0


@dataclass
class ScanSummary:
    files: list[FileResult] = field(default_factory=list)
    duration: float = 0.0

    @property
    def infected(self) -> list[FileResult]:
        return [f for f in self.files if f.verdict is Verdict.MALICIOUS]

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.files if f.verdict is verdict)


class Scanner:
    """Walk a directory tree and scan regular files in a thread pool."""

    def __init__(self, engines: Sequence[Engine], workers: int, max_file_size: int) -> None:
        self.engines = list(engines)
        self.workers = workers
        self.max_file_size = max_file_size

    def scan_tree(self, root: Path, on_progress: ProgressCallback | None = None) -> ScanSummary:
        """Scan all files under root.

        on_progress is called from the calling thread after each file, with the
        file result and the number of bytes scanned so far.
        """
        summary = ScanSummary()
        start = time.monotonic()
        scanned_bytes = 0
        # Bound the number of pending files so huge devices do not fill memory
        max_pending = self.workers * 4
        pending: set[Future[FileResult]] = set()

        def collect(done: set[Future[FileResult]]) -> None:
            nonlocal scanned_bytes
            for future in done:
                result = future.result()
                summary.files.append(result)
                scanned_bytes += result.size
                self._log_result(result)
                if on_progress is not None:
                    on_progress(result, scanned_bytes)

        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="scan") as pool:
            for path, size in self._walk(root):
                if size > self.max_file_size:
                    collect({_done(FileResult(path, size, Verdict.SKIPPED, detail="too big"))})
                    continue
                pending.add(pool.submit(self.scan_file, path, size))
                if len(pending) >= max_pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    collect(done)
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                collect(done)

        summary.duration = time.monotonic() - start
        log_event(
            logger,
            "scan_done",
            duration=round(summary.duration, 1),
            files_scanned=len(summary.files),
            files_infected=len(summary.infected),
            files_suspicious=summary.count(Verdict.SUSPICIOUS),
            files_error=summary.count(Verdict.ERROR),
            files_skipped=summary.count(Verdict.SKIPPED),
        )
        return summary

    def scan_file(self, path: Path, size: int) -> FileResult:
        start = time.monotonic()
        results: list[EngineResult] = []
        for engine in self.engines:
            try:
                results.append(engine.scan(path))
            except Exception as ex:  # an engine failure must not stop the scan
                results.append(EngineResult(engine.name, Verdict.ERROR, str(ex)))
        return FileResult(
            path=path,
            size=size,
            verdict=aggregate(results),
            results=tuple(results),
            duration=time.monotonic() - start,
        )

    def _walk(self, root: Path) -> Iterator[tuple[Path, int]]:
        """Yield regular files only: symbolic links, FIFOs and devices are ignored."""

        def on_error(ex: OSError) -> None:
            log_event(logger, "walk_error", path=ex.filename, error=ex.strerror)

        for dirpath, _dirs, files in os.walk(root, onerror=on_error, followlinks=False):
            for name in files:
                path = Path(dirpath, name)
                try:
                    st = path.lstat()
                except OSError as ex:
                    on_error(ex)
                    continue
                if stat.S_ISREG(st.st_mode):
                    yield path, st.st_size
                else:
                    log_event(logger, "file_ignored", path=str(path), reason="not a regular file")

    @staticmethod
    def _log_result(result: FileResult) -> None:
        log_event(
            logger,
            "file_scanned",
            path=str(result.path),
            size=result.size,
            verdict=result.verdict.value,
            detail=result.detail,
            engines={r.engine: [r.verdict.value, r.detail] for r in result.results},
            duration=round(result.duration, 3),
        )


def describe(result: FileResult) -> str:
    return f"{result.path.name} [{human_size(result.size)}] -> {result.verdict.value.upper()}"


def _done(result: FileResult) -> Future[FileResult]:
    future: Future[FileResult] = Future()
    future.set_result(result)
    return future
