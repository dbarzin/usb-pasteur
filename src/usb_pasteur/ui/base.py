"""Interface between the kiosk state machine and its display."""

from __future__ import annotations

from typing import Protocol

from usb_pasteur.device import UsbDevice


class Display(Protocol):
    """All methods are called from the main thread."""

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def message(self, text: str) -> None:
        """Append a line to the message log."""
        ...

    def show_device(self, device: UsbDevice | None) -> None:
        """Show the inserted device, or clear the device panel."""
        ...

    def show_usage(self, size: int, used: int) -> None: ...

    def progress(self, percent: int) -> None: ...

    def confirm(self, prompt: str) -> None:
        """Wait for the user to acknowledge (key press or touch)."""
        ...
