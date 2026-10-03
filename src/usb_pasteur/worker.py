"""Scan worker process, started by the kiosk (usb_pasteur.workers).

    python -m usb_pasteur.worker FD

FD is one end of a Unix socket pair. The kiosk sends pickled messages (the
worker trusts the kiosk) and, for each file, the descriptor of the file
opened by the kiosk; the worker answers with JSON messages (the kiosk does
not trust the worker, see usb_pasteur.protocol):

    kiosk -> worker                     worker -> kiosk
    ("init", specs, options, seccomp)   {"type": "ready", "engines": [...]}
                                        {"type": "load_failed", "error": ...}
    ("info",)                           {"type": "info", "engines": [...]}
    ("scan", task_id, entry) + fd       {"type": "engine", "task": id, "engine": name}
                                        {"type": "result", "task": id, "result": {...}}
    ("stop",)
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from multiprocessing.connection import Connection
from multiprocessing.reduction import recv_handle
from typing import Any

from usb_pasteur.engines import Engine
from usb_pasteur.engines.registry import load_engines
from usb_pasteur.filetype import FileTypeDetector
from usb_pasteur.logs import LOGGER_NAME
from usb_pasteur.pipeline import scan_fd
from usb_pasteur.protocol import describe_engine, encode, engine_info_message, result_message


def serve(conn: Connection) -> int:
    def send(message: dict[str, Any]) -> None:
        conn.send_bytes(encode(message))

    _, specs, options, seccomp = conn.recv()
    try:
        engines = load_engines(specs)
        detector = FileTypeDetector()
        if seccomp:
            from usb_pasteur.seccomp import apply_filter

            apply_filter()
    except Exception as ex:
        send({"type": "load_failed", "error": str(ex)})
        return 1
    info = engine_info_message([describe_engine(e) for e in engines])
    send({"type": "ready", "engines": info})
    while True:
        try:
            message = conn.recv()
        except (EOFError, OSError):
            return 0
        if message[0] == "stop":
            return 0
        if message[0] == "info":
            info = engine_info_message([describe_engine(e) for e in engines])
            send({"type": "info", "engines": info})
        elif message[0] == "scan":
            _, task_id, entry = message
            fd = recv_handle(conn)

            def on_engine(engine: Engine, task_id: int = task_id) -> None:
                send({"type": "engine", "task": task_id, "engine": engine.name})

            try:
                result = scan_fd(fd, entry, engines, detector, options, on_engine)
            finally:
                os.close(fd)
            send({"type": "result", "task": task_id, "result": result_message(result)})


def main(argv: list[str]) -> int:
    # Ctrl-C is handled by the kiosk process, which stops the workers
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # Workers do not log: everything they find goes to the kiosk process
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False
    return serve(Connection(int(argv[0])))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
