"""Command line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
from pathlib import Path

from usb_pasteur import __version__
from usb_pasteur.config import DEFAULT_CONFIG_PATH, INTERFACES, Config, ConfigError, load_config
from usb_pasteur.kiosk import Kiosk, NoEngineError, build_engines
from usb_pasteur.lock import AlreadyRunningError, InstanceLock
from usb_pasteur.logs import setup_logging
from usb_pasteur.ui import ConsoleDisplay, Display


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="usb-pasteur", description="USB decontamination kiosk")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(os.environ.get("USB_PASTEUR_CONFIG", DEFAULT_CONFIG_PATH)),
        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--check-config", action="store_true", help="validate the configuration and exit"
    )
    parser.add_argument(
        "--fake-scan", action="store_true", help="force FAKE_SCAN mode (development only)"
    )
    parser.add_argument("--interface", choices=INTERFACES, help="override kiosk.interface")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    kiosk = config.kiosk
    if args.fake_scan:
        kiosk = dataclasses.replace(kiosk, fake_scan=True)
    if args.interface:
        kiosk = dataclasses.replace(kiosk, interface=args.interface)
    return dataclasses.replace(config, kiosk=kiosk)


def make_display(interface: str) -> Display:
    if interface == "curses":
        from usb_pasteur.ui.curses_display import CursesDisplay

        return CursesDisplay()
    return ConsoleDisplay()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = apply_overrides(load_config(args.config), args)
        engines = build_engines(config)
    except (ConfigError, NoEngineError) as ex:
        print(f"usb-pasteur: {ex}", file=sys.stderr)
        return 2
    if args.check_config:
        print(f"{args.config}: OK")
        return 0

    lock = InstanceLock("usb-pasteur")
    try:
        lock.acquire()
    except AlreadyRunningError as ex:
        print(f"usb-pasteur: {ex}", file=sys.stderr)
        return 1

    try:
        setup_logging(config.kiosk.name, config.logging.level, config.logging.file)
    except OSError as ex:
        print(f"usb-pasteur: cannot open log file: {ex}", file=sys.stderr)
        return 1

    from usb_pasteur.monitor import UdevSource

    display = make_display(config.kiosk.interface)
    display.start()
    try:
        Kiosk(config, display, UdevSource(), engines).run()
    except KeyboardInterrupt:
        pass
    finally:
        display.stop()
        lock.release()
    return 0
