"""Full screen text interface (administrator mode)."""

from __future__ import annotations

import contextlib
import curses
import os
from collections import deque

from usb_pasteur.device import UsbDevice
from usb_pasteur.text import human_size, printable

LOGO = (
    "░█░█░█▀▀░█▀▄░░░░░█▀█░█▀█░█▀▀░▀█▀░█▀▀░█░█░█▀▄",
    "░█░█░▀▀█░█▀▄░▄▄▄░█▀▀░█▀█░▀▀█░░█░░█▀▀░█░█░█▀▄",
    "░▀▀▀░▀▀▀░▀▀░░░░░░▀░░░▀░▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀░▀",
)

_TITLE_HEIGHT = len(LOGO) + 2
_STATUS_HEIGHT = 5
_PROGRESS_HEIGHT = 3
_MICE = "/dev/input/mice"

_RED, _BLUE, _GREEN = 1, 2, 3


class CursesDisplay:
    def __init__(self) -> None:
        self.screen: curses.window | None = None
        self.status_win: curses.window | None = None
        self.progress_win: curses.window | None = None
        self.log_win: curses.window | None = None
        self.logs: deque[str] = deque()
        self._percent = -1

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self.screen = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.screen.keypad(True)
        curses.curs_set(0)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(_RED, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(_BLUE, curses.COLOR_BLUE, curses.COLOR_BLACK)
            curses.init_pair(_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        self._layout()

    def stop(self) -> None:
        if self.screen is not None:
            curses.flushinp()
            curses.nocbreak()
            self.screen.keypad(False)
            curses.echo()
            curses.endwin()
            self.screen = None

    def _layout(self) -> None:
        lines, cols = curses.LINES, curses.COLS
        title = curses.newwin(_TITLE_HEIGHT, cols, 0, 0)
        col = max(0, (cols - len(LOGO[0])) // 2)
        for i, line in enumerate(LOGO):
            _addstr(title, i + 1, col, line, curses.color_pair(_RED))
        title.refresh()

        self.status_win = curses.newwin(_STATUS_HEIGHT, cols, _TITLE_HEIGHT, 0)
        self.show_device(None)

        top = _TITLE_HEIGHT + _STATUS_HEIGHT
        self.progress_win = curses.newwin(_PROGRESS_HEIGHT, cols, top, 0)
        self.progress(0)

        top += _PROGRESS_HEIGHT
        self.log_win = curses.newwin(max(3, lines - top), cols, top, 0)
        self.logs = deque(maxlen=max(1, lines - top - 2))
        self._draw_logs()

    # -- Display protocol --------------------------------------------------

    def message(self, text: str) -> None:
        self.logs.append(printable(text))
        self._draw_logs()

    def show_device(self, device: UsbDevice | None) -> None:
        win = self.status_win
        if win is None:
            return
        d = device or UsbDevice(node="")
        win.erase()
        win.border(0)
        _addstr(win, 0, 1, " USB device ")
        half = curses.COLS // 2
        blue = curses.color_pair(_BLUE)
        _addstr(win, 1, 1, f"Label  : {printable(d.label)}", blue)
        _addstr(win, 2, 1, "Size   :", blue)
        _addstr(win, 3, 1, "Used   :", blue)
        _addstr(win, 1, half, f"Type   : {printable(d.fs_type)}", blue)
        _addstr(win, 2, half, f"Model  : {printable(d.vendor)} {printable(d.model)}", blue)
        _addstr(win, 3, half, f"Serial : {printable(d.serial)}", blue)
        win.refresh()
        if device is None:
            self.progress(0)

    def show_usage(self, size: int, used: int) -> None:
        win = self.status_win
        if win is None:
            return
        blue = curses.color_pair(_BLUE)
        _addstr(win, 2, 1, f"Size   : {human_size(size)}", blue)
        _addstr(win, 3, 1, f"Used   : {human_size(used)}", blue)
        win.refresh()

    def progress(self, percent: int) -> None:
        win = self.progress_win
        if win is None or percent == self._percent:
            return
        self._percent = percent
        width = curses.COLS - 2
        win.erase()
        win.border(0)
        _addstr(win, 0, 1, f" Progress: {percent}% ")
        _addstr(win, 1, 1, "#" * (width * percent // 100))
        win.refresh()

    def confirm(self, prompt: str) -> None:
        """Wait for a key, a curses mouse event or a touch on the screen."""
        self.message(prompt)
        if self.screen is None:
            return
        curses.flushinp()
        self.screen.timeout(200)
        mice = _Mice()
        try:
            # getch waits up to 200 ms, which paces the loop
            while self.screen.getch() == -1 and not mice.released():
                pass
        finally:
            self.screen.timeout(-1)
            mice.close()

    # -- helpers -----------------------------------------------------------

    def _draw_logs(self) -> None:
        win = self.log_win
        if win is None:
            return
        win.erase()
        win.border(0)
        green = curses.color_pair(_GREEN)
        for i, line in enumerate(self.logs):
            _addstr(win, i + 1, 1, line[: curses.COLS - 2], green)
        win.refresh()


def _addstr(win: curses.window, y: int, x: int, text: str, attr: int = 0) -> None:
    # Text that does not fit on a small screen is dropped
    with contextlib.suppress(curses.error):
        win.addstr(y, x, text, attr)


class _Mice:
    """Touchscreens are seen as a mouse: read raw events when allowed."""

    def __init__(self) -> None:
        self.fd: int | None
        try:
            self.fd = os.open(_MICE, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            self.fd = None
        self.pressed = False

    def released(self) -> bool:
        """Return True once a left button press has been followed by a release."""
        if self.fd is None:
            return False
        while True:
            try:
                buf = os.read(self.fd, 3)
            except BlockingIOError:
                return False
            if len(buf) < 3:
                return False
            if buf[0] & 0x1:
                self.pressed = True
            elif self.pressed:
                return True

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
