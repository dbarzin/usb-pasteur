"""Scan worker processes, supervised by a watchdog.

Each worker is a long-lived process that builds and loads its own engines
once, then scans files one at a time. Engines therefore share no state, and a
crash only affects the file being scanned. In phase 2, workers will run in a
bubblewrap sandbox under a dedicated user.

concurrent.futures.ProcessPoolExecutor is not used: it cannot cancel a running
task, and a killed worker breaks the whole pool. Here, the supervisor (the
kiosk process) arms two deadlines for each file:

- the engine deadline: the timeout of the running engine plus a grace delay,
  re-armed when the worker reports that the next engine starts;
- the file deadline: scan.file_timeout, for the whole file.

When a deadline expires the worker is killed (SIGKILL), the file is reported as
an error and a new worker is started. A worker that dies (crash, out of
memory) is handled the same way. A timeout or a crash is never clean.
"""

from __future__ import annotations

import contextlib
import logging
import multiprocessing
import multiprocessing.connection
import signal
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any

from usb_pasteur.engines import (
    Engine,
    EngineError,
    EngineKind,
    EngineResult,
    EngineSpec,
    SignatureInfo,
    Verdict,
)
from usb_pasteur.engines.registry import load_engines
from usb_pasteur.filetype import FileTypeDetector
from usb_pasteur.inventory import Entry
from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.pipeline import PipelineOptions, scan_entry
from usb_pasteur.results import FileResult
from usb_pasteur.text import escape

logger = get_logger("workers")

# Added to the timeout of an engine before the watchdog kills the worker:
# engines with a native timeout (YARA-X, clamd socket) report it themselves
ENGINE_GRACE = 5.0
# Maximum time for a worker to load its engines
START_TIMEOUT = 600.0
# Modules imported once by the fork server, before the workers are forked
_PRELOAD = ["usb_pasteur.workers"]


@dataclass(frozen=True)
class EngineInfo:
    """Description of a loaded engine, for logs and scan reports."""

    name: str
    kind: EngineKind
    version: str
    timeout: float
    signatures: tuple[SignatureInfo, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)


def describe_engine(engine: Engine) -> EngineInfo:
    return EngineInfo(
        name=engine.name,
        kind=engine.kind,
        version=engine.version(),
        timeout=engine.timeout,
        signatures=tuple(engine.signature_info()),
        extra=engine.extra_info(),
    )


# -- worker side -----------------------------------------------------------------


def _worker_main(
    conn: multiprocessing.connection.Connection,
    specs: tuple[EngineSpec, ...],
    options: PipelineOptions,
) -> None:
    # Ctrl-C is handled by the kiosk process, which stops the workers
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        engines = load_engines(specs)
        detector = FileTypeDetector()
    except Exception as ex:
        conn.send(("load_failed", str(ex)))
        return
    conn.send(("ready", [describe_engine(e) for e in engines]))
    while True:
        try:
            message = conn.recv()
        except (EOFError, OSError):
            return
        if message[0] == "stop":
            return
        if message[0] == "info":
            conn.send(("info", [describe_engine(e) for e in engines]))
        elif message[0] == "scan":
            _, task_id, root, entry = message

            def on_engine(engine: Engine, task_id: int = task_id) -> None:
                conn.send(("engine", task_id, engine.name, engine.timeout))

            result = scan_entry(Path(root), entry, engines, detector, options, on_engine)
            conn.send(("result", task_id, result))


# -- supervisor side ---------------------------------------------------------------


class _State(Enum):
    STARTING = "starting"
    IDLE = "idle"
    BUSY = "busy"
    # The worker could not load its engines: it is not restarted
    FAILED = "failed"


@dataclass
class _Task:
    task_id: int
    entry: Entry
    file_deadline: float
    engine: str = ""
    engine_deadline: float = float("inf")


@dataclass
class _Worker:
    process: BaseProcess
    conn: multiprocessing.connection.Connection
    state: _State = _State.STARTING
    started: float = field(default_factory=time.monotonic)
    task: _Task | None = None


ResultCallback = Callable[[FileResult], None]


class WorkerPool:
    """A fixed number of scan worker processes, reused for every device."""

    def __init__(
        self,
        specs: Sequence[EngineSpec],
        options: PipelineOptions,
        workers: int,
        file_timeout: float,
        engine_grace: float = ENGINE_GRACE,
        start_timeout: float = START_TIMEOUT,
    ) -> None:
        self.specs = tuple(specs)
        self.options = options
        self.size = workers
        self.file_timeout = file_timeout
        self.engine_grace = engine_grace
        self.start_timeout = start_timeout
        self._context = multiprocessing.get_context("forkserver")
        self._context.set_forkserver_preload(_PRELOAD)
        self._workers: list[_Worker] = []
        self._next_task = 0
        self.engines: list[EngineInfo] = []
        # Number of workers restarted after a timeout or a crash
        self.restarts = 0

    # -- life cycle -------------------------------------------------------------

    def start(self) -> list[EngineInfo]:
        """Start the workers and wait until they have loaded their engines.

        Raise EngineError when an engine cannot be loaded.
        """
        self._workers = [self._spawn() for _ in range(self.size)]
        deadline = time.monotonic() + self.start_timeout
        while starting := [w for w in self._workers if w.state is _State.STARTING]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stop()
                raise EngineError("scan workers did not load their engines in time")
            for conn in multiprocessing.connection.wait([w.conn for w in starting], remaining):
                worker = next(w for w in starting if w.conn is conn)
                error = self._receive_ready(worker)
                if error is not None:
                    self.stop()
                    raise EngineError(error)
        log_event(
            logger, "workers_started", workers=self.size, engines=[e.name for e in self.engines]
        )
        return self.engines

    def stop(self) -> None:
        for worker in self._workers:
            with contextlib.suppress(OSError, ValueError):
                worker.conn.send(("stop",))
        for worker in self._workers:
            worker.process.join(timeout=2)
            self._kill(worker)
        self._workers = []

    def __enter__(self) -> WorkerPool:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def pids(self) -> list[int]:
        """Process ids of the running workers (diagnostics and tests)."""
        return [w.process.pid for w in self._workers if w.process.pid is not None]

    def _spawn(self) -> _Worker:
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=_worker_main,
            args=(child, self.specs, self.options),
            name="usb-pasteur-scan",
            daemon=True,
        )
        process.start()
        # Close our copy of the child end: EOF then signals a dead worker
        child.close()
        return _Worker(process, parent)

    def _receive_ready(self, worker: _Worker) -> str | None:
        """Handle the first message of a worker; return an error message."""
        try:
            message = worker.conn.recv()
        except (EOFError, OSError):
            return f"scan worker died while loading engines (exit code {self._exit(worker)})"
        if message[0] == "load_failed":
            return str(message[1])
        if message[0] != "ready":
            return f"unexpected message from a scan worker: {message[0]}"
        worker.state = _State.IDLE
        self.engines = list(message[1])
        return None

    # -- information ------------------------------------------------------------

    def engine_info(self) -> list[EngineInfo]:
        """Ask an idle worker for up to date engine information."""
        for worker in self._workers:
            if worker.state is not _State.IDLE:
                continue
            try:
                worker.conn.send(("info",))
                if worker.conn.poll(30):
                    message = worker.conn.recv()
                    if message[0] == "info":
                        self.engines = list(message[1])
                        break
            except (EOFError, OSError):
                continue
        return self.engines

    # -- scan ---------------------------------------------------------------------

    def scan(self, root: Path, entries: Iterable[Entry], on_result: ResultCallback) -> None:
        """Scan the entries; on_result is called in this thread for each file."""
        queue = deque(entries)
        while queue or any(w.state is _State.BUSY for w in self._workers):
            for worker in self._workers:
                if worker.state is _State.IDLE and not worker.process.is_alive():
                    self._kill(worker)
                    self._restart(worker)
                if worker.state is _State.IDLE and queue and self._assign(worker, root, queue[0]):
                    queue.popleft()
            if all(w.state is _State.FAILED for w in self._workers):
                # No worker can load its engines any more: fail closed
                for entry in queue:
                    on_result(self._error_result(root, entry, "no scan worker available"))
                return
            self._wait(root, on_result)

    def _assign(self, worker: _Worker, root: Path, entry: Entry) -> bool:
        self._next_task += 1
        task = _Task(self._next_task, entry, time.monotonic() + self.file_timeout)
        try:
            worker.conn.send(("scan", task.task_id, str(root), entry))
        except OSError:
            # The worker died while idle: the entry stays in the queue
            self._kill(worker)
            self._restart(worker)
            return False
        worker.state = _State.BUSY
        worker.task = task
        return True

    def _wait(self, root: Path, on_result: ResultCallback) -> None:
        active = [w for w in self._workers if w.state in (_State.STARTING, _State.BUSY)]
        if not active:
            return
        timeout = max(0.0, min(self._deadline(w) for w in active) - time.monotonic())
        ready = multiprocessing.connection.wait([w.conn for w in active], timeout)
        for conn in ready:
            worker = next(w for w in active if w.conn is conn)
            self._handle(worker, root, on_result)
        now = time.monotonic()
        for worker in active:
            if worker.state in (_State.STARTING, _State.BUSY) and now >= self._deadline(worker):
                self._expire(worker, root, on_result)

    def _deadline(self, worker: _Worker) -> float:
        if worker.state is _State.STARTING:
            return worker.started + self.start_timeout
        if worker.task is None:
            return float("inf")
        return min(worker.task.file_deadline, worker.task.engine_deadline)

    def _handle(self, worker: _Worker, root: Path, on_result: ResultCallback) -> None:
        if worker.state is _State.STARTING:
            error = self._receive_ready(worker)
            if error is not None:
                log_event(logger, "worker_load_failed", logging.ERROR, error=error)
                self._kill(worker)
                worker.state = _State.FAILED
            return
        try:
            message = worker.conn.recv()
        except (EOFError, OSError):
            self._crashed(worker, root, on_result)
            return
        task = worker.task
        if task is None or message[1] != task.task_id:
            return
        if message[0] == "engine":
            task.engine = message[2]
            task.engine_deadline = time.monotonic() + float(message[3]) + self.engine_grace
        elif message[0] == "result":
            worker.task = None
            worker.state = _State.IDLE
            on_result(message[2])

    def _expire(self, worker: _Worker, root: Path, on_result: ResultCallback) -> None:
        task = worker.task
        if worker.state is _State.STARTING or task is None:
            log_event(logger, "worker_start_timeout", logging.ERROR)
            self._kill(worker)
            worker.state = _State.FAILED
            return
        if time.monotonic() >= task.file_deadline:
            reason = f"file scan timeout ({self.file_timeout:g}s, scan.file_timeout)"
        else:
            reason = "engine timeout"
        if task.engine:
            reason += f" in engine {task.engine}"
        log_event(
            logger, "worker_killed", logging.ERROR, path=escape(task.entry.rel_path), reason=reason
        )
        self._kill(worker)
        on_result(self._error_result(root, task.entry, reason, task.engine))
        self._restart(worker)

    def _crashed(self, worker: _Worker, root: Path, on_result: ResultCallback) -> None:
        task = worker.task
        reason = f"scan worker crashed (exit code {self._exit(worker)})"
        if task is not None and task.engine:
            reason += f" in engine {task.engine}"
        log_event(logger, "worker_crashed", logging.ERROR, reason=reason)
        self._kill(worker)
        if task is not None:
            on_result(self._error_result(root, task.entry, reason, task.engine))
        self._restart(worker)

    def _restart(self, worker: _Worker) -> None:
        self.restarts += 1
        replacement = self._spawn()
        worker.process = replacement.process
        worker.conn = replacement.conn
        worker.state = _State.STARTING
        worker.started = replacement.started
        worker.task = None

    @staticmethod
    def _kill(worker: _Worker) -> None:
        with contextlib.suppress(OSError, ValueError):
            if worker.process.is_alive():
                worker.process.kill()
            worker.process.join(timeout=5)
        with contextlib.suppress(OSError):
            worker.conn.close()

    @staticmethod
    def _exit(worker: _Worker) -> int | None:
        with contextlib.suppress(OSError, ValueError):
            worker.process.join(timeout=1)
        return worker.process.exitcode

    @staticmethod
    def _error_result(root: Path, entry: Entry, reason: str, engine: str = "") -> FileResult:
        results = (EngineResult(engine, Verdict.ERROR, error=reason),) if engine else ()
        return FileResult(
            path=root / entry.rel_path,
            size=entry.size,
            verdict=Verdict.ERROR,
            results=results,
            detail=reason,
            rel_path=entry.rel_path,
        )
