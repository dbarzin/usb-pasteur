"""A fake clamd server on a Unix socket, for the ClamAV engine tests."""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import struct
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .samples import eicar

VERSION = "ClamAV 1.4.3/27791/Thu Oct  2 09:12:00 2026"


class FakeClamd:
    """Answer PING, VERSION, FILDES and INSTREAM like clamd.

    Detection depends on the content: EICAR, b"PUA-TEST", b"LIMITS-TEST" and
    b"MULTI-TEST" (two replies, as with AllMatchScan). mode changes the
    behavior: "normal", "hang", "garbage", "close", "reject_fd".
    """

    def __init__(self, path: Path, mode: str = "normal", stream_max: int = 1024**2) -> None:
        self.path = path
        self.mode = mode
        self.stream_max = stream_max
        self.commands: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        # shutdown() wakes up the thread blocked in accept(), close() does not
        self._server.shutdown(socket.SHUT_RDWR)
        self._server.close()
        self._thread.join(timeout=5)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        # The client may give up (timeout) and close the connection
        with conn, contextlib.suppress(OSError):
            command = b""
            while not command.endswith(b"\0"):
                data = conn.recv(1)
                if not data:
                    return
                command += data
            name = command.strip(b"z\0").decode()
            self.commands.append(name)
            if self.mode == "close":
                return
            if self.mode == "garbage":
                conn.sendall(b"hello world\0")
                return
            if name == "PING":
                conn.sendall(b"PONG\0")
            elif name == "VERSION":
                conn.sendall(VERSION.encode() + b"\0")
            elif name == "FILDES":
                self._fildes(conn)
            elif name == "INSTREAM":
                self._instream(conn)
            else:
                conn.sendall(b"UNKNOWN COMMAND\0")

    def _fildes(self, conn: socket.socket) -> None:
        _, fds, _, _ = socket.recv_fds(conn, 1, 1)
        if self.mode == "reject_fd" or not fds:
            for fd in fds:
                os.close(fd)
            conn.sendall(b"fd[-1]: lstat() failed: Permission denied. ERROR\0")
            return
        try:
            content = _read_all(fds[0])
        finally:
            os.close(fds[0])
        self._reply(conn, f"fd[{fds[0]}]", content)

    def _instream(self, conn: socket.socket) -> None:
        content = bytearray()
        while True:
            header = _recv_exactly(conn, 4)
            (size,) = struct.unpack("!I", header)
            if size == 0:
                break
            content += _recv_exactly(conn, size)
            if len(content) > self.stream_max:
                conn.sendall(b"INSTREAM size limit exceeded. ERROR\0")
                return
        self._reply(conn, "stream", bytes(content))

    def _reply(self, conn: socket.socket, subject: str, content: bytes) -> None:
        if self.mode == "hang":
            time.sleep(5)
        if eicar() in content:
            conn.sendall(f"{subject}: Eicar-Test-Signature FOUND\0".encode())
        elif b"MULTI-TEST" in content:
            conn.sendall(
                f"{subject}: PUA.Win.Test FOUND\0{subject}: Win.Trojan.Test FOUND\0".encode()
            )
        elif b"PUA-TEST" in content:
            conn.sendall(f"{subject}: PUA.Win.Test FOUND\0".encode())
        elif b"LIMITS-TEST" in content:
            conn.sendall(f"{subject}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0".encode())
        else:
            conn.sendall(f"{subject}: OK\0".encode())


def _read_all(fd: int) -> bytes:
    data = bytearray()
    while chunk := os.pread(fd, 65536, len(data)):
        data += chunk
    return bytes(data)


def _recv_exactly(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("client closed")
        data += chunk
    return bytes(data)


@contextmanager
def fake_clamd(mode: str = "normal", stream_max: int = 1024**2) -> Iterator[FakeClamd]:
    # Unix socket paths are limited to 108 bytes: pytest tmp_path may be too long
    folder = Path(tempfile.mkdtemp(prefix="clamd-"))
    server = FakeClamd(folder / "clamd.sock", mode, stream_max)
    try:
        yield server
    finally:
        server.close()
        shutil.rmtree(folder, ignore_errors=True)
