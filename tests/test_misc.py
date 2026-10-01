from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from usb_pasteur.lock import AlreadyRunningError, InstanceLock
from usb_pasteur.logs import get_logger, log_event, setup_logging
from usb_pasteur.statemachine import State, StateMachine
from usb_pasteur.text import human_size, printable


def test_human_size() -> None:
    assert human_size(512) == "512.0B"
    assert human_size(1536) == "1.5KB"
    assert human_size(1024**3) == "1.0GB"


def test_printable_strips_terminal_escapes() -> None:
    assert printable("evil\x1b[2Jname\n") == "evil?[2Jname?"
    assert printable("bad-\udcff.txt") == "bad-\\udcff.txt"
    assert printable(None) == ""


def test_state_machine() -> None:
    visited: list[State] = []

    def go(target: State) -> State:
        visited.append(target)
        return target

    machine = StateMachine(
        {State.START: lambda: go(State.WAIT), State.WAIT: lambda: go(State.STOP)}
    )
    machine.run()
    assert visited == [State.WAIT, State.STOP]


def test_unknown_state_stops() -> None:
    machine = StateMachine({State.START: lambda: State.SCAN})
    machine.run()
    assert machine.state is State.STOP


def test_lock() -> None:
    first = InstanceLock("usb-pasteur-test")
    first.acquire()
    try:
        with pytest.raises(AlreadyRunningError):
            InstanceLock("usb-pasteur-test").acquire()
    finally:
        first.release()
    second = InstanceLock("usb-pasteur-test")
    second.acquire()
    second.release()


def test_json_logs(tmp_path: Path) -> None:
    file = tmp_path / "logs" / "usb-pasteur.log"
    setup_logging("kiosk-01", "INFO", file)
    log_event(get_logger("test"), "file_scanned", path="bad-\udcff", size=3)
    log_event(get_logger("test"), "debug_only", logging.DEBUG)
    lines = file.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["kiosk"] == "kiosk-01"
    assert entry["event"] == "file_scanned"
    assert entry["path"] == "bad-\udcff"
    assert entry["level"] == "INFO"
    setup_logging("kiosk-01", "INFO", None)
