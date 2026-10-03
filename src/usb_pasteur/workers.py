"""Scan worker processes, supervised by a watchdog.

Each worker is a long-lived process (usb_pasteur.worker) that builds and
loads its own engines once, then scans files one at a time. Engines therefore
share no state, and a crash only affects the file being scanned. With
scan.sandbox, workers run in a bubblewrap sandbox under a dedicated user
(usb_pasteur.sandbox).

The kiosk opens each file (usb_pasteur.inventory.open_entry) and passes its
descriptor to a worker, which never opens a file of the device. Workers are
assumed compromisable: their answers are validated JSON
(usb_pasteur.protocol); a malformed answer is handled like a crash.

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
import multiprocessing.connection
import os
import socket
import subprocess
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing.reduction import send_handle
from pathlib import Path
from typing import Any

from usb_pasteur.engines import EngineError, EngineResult, EngineSpec, Verdict
from usb_pasteur.inventory import Entry, UnsafeFileError, open_entry
from usb_pasteur.logs import get_logger, log_event
from usb_pasteur.pipeline import PipelineOptions
from usb_pasteur.protocol import (
    MAX_MESSAGE_SIZE,
    EngineInfo,
    ProtocolError,
    decode,
    decode_engines,
    decode_result,
    describe_engine,
)
from usb_pasteur.results import FileResult
from usb_pasteur.sandbox import Sandbox
from usb_pasteur.text import escape

__all__ = ["EngineInfo", "WorkerPool", "describe_engine"]

logger = get_logger("workers")

# Added to the timeout of an engine before the watchdog kills the worker:
# engines with a native timeout (YARA-X, clamd socket) report it themselves
ENGINE_GRACE = 5.0
# Maximum time for a worker to load its engines
START_TIMEOUT = 600.0


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
    process: subprocess.Popen[bytes]
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
        sandbox: Sandbox | None = None,
    ) -> None:
        self.specs = tuple(specs)
        self.options = options
        self.size = workers
        self.file_timeout = file_timeout
        self.engine_grace = engine_grace
        self.start_timeout = start_timeout
        self.sandbox = sandbox
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
        if self.sandbox is not None:
            self.sandbox.prepare()
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
        for engine in self.engines:
            excluded = engine.extra.get("excluded_rules") or []
            if excluded:
                log_event(
                    logger,
                    "rules_excluded",
                    logging.WARNING,
                    engine=engine.name,
                    count=len(excluded),
                    errors=excluded,
                )
        return self.engines

    def stop(self) -> None:
        for worker in self._workers:
            with contextlib.suppress(OSError, ValueError):
                worker.conn.send(("stop",))
        for worker in self._workers:
            with contextlib.suppress(subprocess.TimeoutExpired):
                worker.process.wait(timeout=2)
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
        return [w.process.pid for w in self._workers]

    def _spawn(self) -> _Worker:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        command = [sys.executable, "-m", "usb_pasteur.worker", str(child.fileno())]
        if self.sandbox is not None:
            command = self.sandbox.wrap(command)
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            # The modules of the engine factories (tests and development)
            "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        }
        with child:
            # stdout may be the kiosk screen. Workers never write, but errors
            # of bubblewrap or Python go to stderr: the journal of the service
            process = subprocess.Popen(  # noqa: S603  (fixed command)
                command,
                pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                env=env,
            )
        # Our copy of the child end is closed: EOF then signals a dead worker
        conn = multiprocessing.connection.Connection(parent.detach())
        worker = _Worker(process, conn)
        # A dead worker is reported when its first message is read
        with contextlib.suppress(OSError):
            conn.send(("init", self.specs, self.options, self.sandbox is not None))
        return worker

    def _receive(self, worker: _Worker) -> dict[str, Any]:
        """Read and decode a message: ProtocolError, EOFError or OSError."""
        return decode(worker.conn.recv_bytes(MAX_MESSAGE_SIZE))

    def _receive_ready(self, worker: _Worker) -> str | None:
        """Handle the first message of a worker; return an error message."""
        try:
            message = self._receive(worker)
            if message["type"] == "load_failed":
                return str(message.get("error"))[:1000]
            if message["type"] != "ready":
                return f"unexpected message from a scan worker: {message['type'][:100]}"
            engines = decode_engines(message.get("engines"))
        except (EOFError, OSError):
            return f"scan worker died while loading engines (exit code {self._exit(worker)})"
        except ProtocolError as ex:
            return f"invalid message from a scan worker: {ex}"
        worker.state = _State.IDLE
        self.engines = engines
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
                    message = self._receive(worker)
                    if message["type"] == "info":
                        self.engines = decode_engines(message.get("engines"))
                        break
            except (EOFError, OSError, ProtocolError):
                continue
        return self.engines

    # -- scan ---------------------------------------------------------------------

    def scan(self, root: Path, entries: Iterable[Entry], on_result: ResultCallback) -> None:
        """Scan the entries; on_result is called in this thread for each file."""
        queue = deque(entries)
        while queue or any(w.state is _State.BUSY for w in self._workers):
            for worker in self._workers:
                if worker.state is _State.IDLE and worker.process.poll() is not None:
                    self._kill(worker)
                    self._restart(worker)
                if (
                    worker.state is _State.IDLE
                    and queue
                    and self._assign(worker, root, queue[0], on_result)
                ):
                    queue.popleft()
            if all(w.state is _State.FAILED for w in self._workers):
                # No worker can load its engines any more: fail closed
                for entry in queue:
                    on_result(self._error_result(root, entry, "no scan worker available"))
                return
            self._wait(root, on_result)

    def _assign(self, worker: _Worker, root: Path, entry: Entry, on_result: ResultCallback) -> bool:
        """Open the file and pass it to the worker; return whether the entry is done."""
        self._next_task += 1
        task = _Task(self._next_task, entry, time.monotonic() + self.file_timeout)
        try:
            with open_entry(root, entry) as fd:
                try:
                    worker.conn.send(("scan", task.task_id, entry))
                    send_handle(worker.conn, fd, worker.process.pid)
                except OSError:
                    # The worker died while idle: the entry stays in the queue
                    self._kill(worker)
                    self._restart(worker)
                    return False
        except UnsafeFileError as ex:
            on_result(self._error_result(root, entry, str(ex)))
            return True
        except OSError as ex:
            on_result(self._error_result(root, entry, f"cannot read: {ex.strerror or ex}"))
            return True
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
        task = worker.task
        try:
            message = self._receive(worker)
            if task is None or message.get("task") != task.task_id:
                raise ProtocolError("message for another task")
            if message["type"] == "engine":
                # The timeout is the one reported at startup, never a new one
                engine = self._engine(message.get("engine"))
                task.engine = engine.name
                task.engine_deadline = time.monotonic() + engine.timeout + self.engine_grace
            elif message["type"] == "result":
                names = {e.name for e in self.engines}
                result = decode_result(message.get("result"), root, task.entry, names)
                worker.task = None
                worker.state = _State.IDLE
                on_result(result)
            else:
                raise ProtocolError(f"unexpected message: {message['type'][:100]}")
        except (EOFError, OSError):
            self._crashed(worker, root, on_result)
        except ProtocolError as ex:
            self._crashed(worker, root, on_result, f"invalid message ({ex})")

    def _engine(self, name: object) -> EngineInfo:
        for engine in self.engines:
            if engine.name == name:
                return engine
        raise ProtocolError("unknown engine")

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

    def _crashed(
        self, worker: _Worker, root: Path, on_result: ResultCallback, error: str = ""
    ) -> None:
        task = worker.task
        if error:
            # A worker sending malformed messages may be compromised: killed
            self._kill(worker)
            reason = f"scan worker killed: {error}"
        else:
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
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            if worker.process.poll() is None:
                worker.process.kill()
            worker.process.wait(timeout=5)
        with contextlib.suppress(OSError):
            worker.conn.close()

    @staticmethod
    def _exit(worker: _Worker) -> int | None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            worker.process.wait(timeout=1)
        return worker.process.returncode

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
