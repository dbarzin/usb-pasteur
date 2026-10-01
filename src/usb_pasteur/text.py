"""Text helpers for untrusted strings (file names, device labels)."""

from __future__ import annotations

import unicodedata


def human_size(size: float, decimal_places: int = 1) -> str:
    """Convert a size in bytes to a human readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0:
            return f"{size:.{decimal_places}f}{unit}"
        size /= 1024.0
    return f"{size:.{decimal_places}f}PB"


def printable(value: object) -> str:
    """Make an untrusted string safe to display on a terminal.

    Control characters (including terminal escape sequences) are replaced and
    undecodable bytes in file names are shown as escapes.
    """
    text = "" if value is None else str(value)
    text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c for c in text)
