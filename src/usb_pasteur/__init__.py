"""USB-Pasteur: open source USB decontamination kiosk."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("usb-pasteur")
except PackageNotFoundError:  # used from a source tree (image tests)
    __version__ = "0+unknown"
