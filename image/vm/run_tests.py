"""End-to-end test of a USB-Pasteur image in a QEMU/KVM virtual machine.

Boots the test image (image/build.sh --profile test), then plays the whole
user workflow with an emulated USB key holding the corpus of corpus.py:
insertion, scan by the real engines, cleaning confirmed with a key press on
the kiosk screen, quarantine, report, eject and removal; then the cleaned key
is inserted again and must be reported clean. Run it with image/vm.sh test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import corpus
from machine import Machine, MachineError, make_key, read_key

LOG = "/var/log/usb-pasteur/usb-pasteur.log"
REPORTS = "/var/lib/usb-pasteur/reports"


class TestFailure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def step(message: str) -> None:
    print(f"--- {message}", flush=True)


def events(vm: Machine) -> list[dict[str, Any]]:
    output = vm.shell.run(f"cat {LOG} 2>/dev/null || true")
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def wait_event(
    vm: Machine,
    name: str,
    occurrence: int = 1,
    timeout: float = 120.0,
    action: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Wait for the nth kiosk log event of that name; run action while waiting."""
    deadline = time.monotonic() + timeout
    while True:
        found = [e for e in events(vm) if e.get("event") == name]
        if len(found) >= occurrence:
            return found[occurrence - 1]
        if time.monotonic() > deadline:
            raise TestFailure(f"kiosk event {name} (#{occurrence}) not logged")
        if action is not None:
            action()
        time.sleep(1.0)


def last_report(vm: Machine) -> dict[str, Any]:
    path = vm.shell.run(f"ls -t {REPORTS}/*.json | head -n 1").strip()
    report: dict[str, Any] = json.loads(vm.shell.run(f"cat {path}"))
    return report


def check_boot(vm: Machine, timeout: float) -> None:
    step("boot")
    vm.shell.login(timeout)
    started = wait_event(vm, "kiosk_started", timeout=timeout)
    check(not started["fake_scan"], "the kiosk runs in FAKE_SCAN mode")
    engines = sorted(started["engines"])
    check(
        engines == ["clamav", "hashlookup", "malwarebazaar", "yara"],
        f"unexpected engines: {engines}",
    )
    failed = vm.shell.run("systemctl --failed --no-legend --plain").strip()
    check(not failed, f"failed units:\n{failed}")
    print(f"kiosk started with engines {', '.join(engines)}")


def check_infected_key(vm: Machine, key: Path) -> None:
    step("insert the infected key")
    vm.insert_key(key)
    infected = wait_event(vm, "infected_files")
    expected = {path for path, (_, engine) in corpus.KEY.items() if engine}
    check(infected["count"] == len(expected), f"infected files: {infected['count']}")

    step("confirm the cleaning on the kiosk screen")
    # A key pressed before the kiosk waits for it may be discarded: press
    # again until the cleaning is done
    cleaned = wait_event(vm, "device_cleaned", action=vm.press_key, timeout=60)
    check(cleaned["removed"] == len(expected), f"removed files: {cleaned['removed']}")
    wait_event(vm, "device_ejected")

    step("check the report and the quarantine")
    report = last_report(vm)
    check(report["verdict"]["device"] == "malicious", f"device verdict: {report['verdict']}")
    check(report["verdict"]["complete"], "the device was not fully scanned")
    files = {f["path"]: f for f in report["files"]}
    check(sorted(files) == sorted(corpus.KEY), f"scanned files: {sorted(files)}")
    for path, (_, engine) in corpus.KEY.items():
        entry = files[path]
        detected_by = sorted(e["engine"] for e in entry["engines"] if e["detections"])
        if engine:
            check(entry["verdict"] == "malicious", f"{path}: verdict {entry['verdict']}")
            check(detected_by == [engine], f"{path}: detected by {detected_by}")
        else:
            check(entry["verdict"] == "clean", f"{path}: verdict {entry['verdict']}")
            check(not detected_by, f"{path}: detected by {detected_by}")
        print(f"{path}: {entry['verdict']} {' '.join(detected_by)}")

    stored = wait_event(vm, "quarantine_stored")
    manifest = json.loads(vm.shell.run(f"cat {stored['folder']}/manifest.json"))
    quarantined = {f["original_path"]: f["sha256"] for f in manifest["files"]}
    check(
        quarantined
        == {
            path: hashlib.sha256(content).hexdigest()
            for path, (content, engine) in corpus.KEY.items()
            if engine
        },
        f"quarantine: {quarantined}",
    )

    step("remove the key and check its content")
    vm.remove_key()
    wait_event(vm, "device_removed")
    remaining = read_key(key)
    clean = sorted(path for path, (_, engine) in corpus.KEY.items() if not engine)
    check(remaining == clean, f"files left on the key: {remaining}")
    print(f"files left on the key: {', '.join(remaining)}")


def check_clean_key(vm: Machine, key: Path) -> None:
    step("insert the cleaned key again")
    vm.insert_key(key)
    verdict = wait_event(vm, "device_verdict", occurrence=2)
    check(verdict["verdict"] == "clean", f"device verdict: {verdict}")
    wait_event(vm, "device_ejected", occurrence=2)
    vm.remove_key()
    wait_event(vm, "device_removed", occurrence=2)
    check(read_key(key) == sorted(p for p, (_, e) in corpus.KEY.items() if not e), "key changed")
    print("the cleaned key is reported clean")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--image", type=Path, default=Path("image/mkosi.output/usb-pasteur-test.raw")
    )
    parser.add_argument("--boot-timeout", type=float, default=300.0)
    parser.add_argument("--workdir", type=Path, help="keep the logs and key image in this folder")
    args = parser.parse_args(argv)
    if not args.image.exists():
        print(f"{args.image}: no such image, run image/build.sh --profile test", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        workdir = (args.workdir or Path(tmp)).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        key = workdir / "usbkey.img"
        make_key(key)
        try:
            with Machine(args.image.resolve(), workdir) as vm:
                check_boot(vm, args.boot_timeout)
                check_infected_key(vm, key)
                check_clean_key(vm, key)
        except (TestFailure, MachineError, TimeoutError) as ex:
            print(f"FAILED: {ex}", file=sys.stderr)
            serial = workdir / "serial.log"
            if serial.exists():
                tail = serial.read_text(errors="replace").splitlines()[-40:]
                print("--- serial console (last lines)", *tail, sep="\n", file=sys.stderr)
            return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
