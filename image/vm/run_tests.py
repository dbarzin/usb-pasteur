"""End-to-end test of a USB-Pasteur image in a QEMU/KVM virtual machine.

Boots the test image (image/build.sh --profile test) with Secure Boot and the
image signing certificate enrolled, checks its integrity protections, then
plays the whole user workflow with an emulated USB key holding the corpus of
corpus.py: insertion, scan by the real engines, cleaning confirmed with a key
press on the kiosk screen, quarantine, report, eject and removal; then the
cleaned key is inserted again and must be reported clean. Two more boots
check that a modified root filesystem cannot be read and that firmware
trusting another key refuses the image. Run it with image/vm.sh test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import corpus
from machine import SIGNING_CERTIFICATE, Machine, MachineError, make_key, read_key

LOG = "/var/log/usb-pasteur/usb-pasteur.log"
# Discoverable Partitions Specification: root partition of x86-64
ROOT_TYPE = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
SECURE_BOOT_VARIABLE = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
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


def wait_screen(vm: Machine, text: str, timeout: float = 30.0) -> str:
    """Wait until the kiosk screen (tty1) shows the text; return the screen."""
    deadline = time.monotonic() + timeout
    while True:
        screen = vm.shell.run("kiosk-screen")
        if text in screen:
            return screen
        if time.monotonic() > deadline:
            raise TestFailure(f"not on the kiosk screen: {text}\n{screen}")
        time.sleep(0.5)


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
    wait_screen(vm, "Ready. Insert a USB device.")
    print(f"kiosk started with engines {', '.join(engines)}")


def check_integrity(vm: Machine) -> None:
    step("check Secure Boot and dm-verity")
    # The variable holds 4 attribute bytes, then 1 when Secure Boot is enabled
    secure_boot = vm.shell.run(f"od -An -t u1 {SECURE_BOOT_VARIABLE}").split()
    check(secure_boot[-1:] == ["1"], f"Secure Boot is not enabled: {secure_boot}")
    lockdown = vm.shell.run("cat /sys/kernel/security/lockdown").strip()
    check("[none]" not in lockdown, f"kernel lockdown: {lockdown}")
    source = vm.shell.run("findmnt -n -o SOURCE /").strip()
    uuid = vm.shell.run("cat /sys/dev/block/$(mountpoint -d /)/dm/uuid 2>/dev/null || true").strip()
    check(uuid.startswith("CRYPT-VERITY-"), f"root filesystem is not dm-verity: {source} {uuid}")
    check(
        vm.shell.run(f"sha256sum < {corpus.VERITY_CANARY_PATH}").split()[0]
        == hashlib.sha256(corpus.VERITY_CANARY).hexdigest(),
        "cannot read the dm-verity canary",
    )
    print(f"Secure Boot enabled, kernel lockdown {lockdown}, root on dm-verity ({source})")


def root_partition(image: Path) -> tuple[int, int]:
    """Offset and size in bytes of the root partition of a disk image."""
    table = json.loads(
        subprocess.run(
            ["sfdisk", "--json", str(image)], check=True, capture_output=True, text=True
        ).stdout
    )["partitiontable"]
    sector = table.get("sectorsize", 512)
    for partition in table["partitions"]:
        if partition["type"].upper() == ROOT_TYPE:
            return partition["start"] * sector, partition["size"] * sector
    raise TestFailure(f"{image}: no root partition")


def find_canary(image: Path) -> int:
    """Offset in the disk image of the first block of the dm-verity canary file."""
    start, size = root_partition(image)
    chunk = 16 * 1024 * 1024
    overlap = len(corpus.VERITY_CANARY_MARKER)
    with image.open("rb") as disk:
        position = start
        while position < start + size:
            disk.seek(position)
            data = disk.read(chunk + overlap)
            index = data.find(corpus.VERITY_CANARY_MARKER)
            if index >= 0:
                return position + index
            position += chunk
    raise TestFailure(f"{image}: dm-verity canary not found in the root partition")


def check_modified_root(image: Path, workdir: Path, timeout: float) -> None:
    step("modified root filesystem: the modified block cannot be read")
    offset = find_canary(image)

    def modify(disk: Path) -> None:
        # Overwrite the canary on the disk of the machine (the image is unchanged)
        subprocess.run(
            ["qemu-io", "-f", "qcow2", "-c", f"write -P 0x41 {offset} 16", str(disk)],
            check=True,
            capture_output=True,
        )

    with Machine(image, workdir, SIGNING_CERTIFICATE, modify) as vm:
        vm.shell.login(timeout)
        check(
            not vm.shell.succeeds(f"cat {corpus.VERITY_CANARY_PATH}"),
            "the modified canary could be read",
        )
        errors = vm.shell.run("dmesg | grep -i 'verity' | grep -i 'corrupt' || true").strip()
        check(bool(errors), "no dm-verity corruption in the kernel log")
        print(errors.splitlines()[0])


def check_foreign_key(image: Path, workdir: Path, timeout: float) -> None:
    step("firmware trusting another key: the image does not boot")
    workdir.mkdir(parents=True, exist_ok=True)
    certificate = workdir / "foreign.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Foreign key", "-keyout", str(workdir / "foreign.key"),
         "-out", str(certificate)],
        check=True, capture_output=True,
    )  # fmt: skip
    serial = workdir / "serial.log"
    with Machine(image, workdir, certificate) as vm:
        deadline = time.monotonic() + timeout
        while "Access Denied" not in serial.read_text(errors="replace"):
            check(time.monotonic() < deadline, "the firmware did not report Access Denied")
            time.sleep(0.5)
        # Nothing else may start: no shell on the virtio console
        try:
            vm.shell.login(10.0)
        except MachineError:
            pass
        else:
            raise TestFailure("the image booted with firmware trusting another key")
    print("the firmware refused the bootloader: Access Denied")


def check_filesystems(vm: Machine) -> None:
    step("check the filesystems")
    fs_type, options = vm.shell.run("findmnt -n -o FSTYPE,OPTIONS /").split()
    check(fs_type == "erofs" and "ro" in options.split(","), f"root: {fs_type} {options}")
    for path in ("/etc/usb-pasteur/test", "/usr/test", "/media/test"):
        check(not vm.shell.succeeds(f"touch {path}"), f"{path} is writable")
    fs_type, options = vm.shell.run("findmnt -n -o FSTYPE,OPTIONS /var").split()
    check(fs_type == "ext4" and "rw" in options.split(","), f"/var: {fs_type} {options}")
    # The data partition and its filesystem grew to fill the disk (8 GB)
    size = int(vm.shell.run("findmnt -n -b -o SIZE /var"))
    check(size > 6 * 1024**3, f"/var was not grown: {size} bytes")
    print(f"root: read-only erofs, /var: ext4, {size / 1024**3:.1f} GiB")


def count_reports(vm: Machine) -> int:
    return int(vm.shell.run(f"ls {REPORTS} | wc -l"))


def check_reboot(vm: Machine, timeout: float) -> None:
    step("reboot: the data is kept, the system is unchanged")
    reports = count_reports(vm)
    vm.reboot(timeout)
    wait_event(vm, "kiosk_started", occurrence=2, timeout=timeout)
    check(count_reports(vm) == reports, "scan reports lost after a reboot")
    check(not vm.shell.succeeds("test -e /usr/test"), "the root filesystem changed")
    failed = vm.shell.run("systemctl --failed --no-legend --plain").strip()
    check(not failed, f"failed units:\n{failed}")
    print(f"{reports} scan reports kept")


def check_infected_key(vm: Machine, key: Path) -> None:
    step("insert the infected key")
    vm.insert_key(key)
    infected = wait_event(vm, "infected_files")
    expected = {path for path, (_, engine) in corpus.KEY.items() if engine}
    check(infected["count"] == len(expected), f"infected files: {infected['count']}")

    step("confirm the cleaning on the kiosk screen")
    # The screen must still show the scan while the kiosk waits for a key
    time.sleep(1.0)
    screen = wait_screen(vm, "PRESS A KEY OR TOUCH THE SCREEN TO CLEAN")
    for path in expected:
        check(path in screen, f"{path} not listed on the kiosk screen\n{screen}")
    # A key pressed before the kiosk waits for it may be discarded: press
    # again until the cleaning is done
    cleaned = wait_event(vm, "device_cleaned", action=vm.press_key, timeout=60)
    check(cleaned["removed"] == len(expected), f"removed files: {cleaned['removed']}")
    wait_event(vm, "device_ejected")
    wait_screen(vm, "Device cleaned! You can remove the device.")

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

    if not SIGNING_CERTIFICATE.exists():
        print(f"{SIGNING_CERTIFICATE}: no signing certificate", file=sys.stderr)
        return 2

    image = args.image.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = (args.workdir or Path(tmp)).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        key = workdir / "usbkey.img"
        make_key(key)
        current = workdir
        try:
            with Machine(image, workdir, SIGNING_CERTIFICATE) as vm:
                check_boot(vm, args.boot_timeout)
                check_integrity(vm)
                check_filesystems(vm)
                check_infected_key(vm, key)
                check_clean_key(vm, key)
                check_reboot(vm, args.boot_timeout)
            current = workdir / "modified-root"
            check_modified_root(image, current, args.boot_timeout)
            current = workdir / "foreign-key"
            check_foreign_key(image, current, 60.0)
        except (TestFailure, MachineError, TimeoutError) as ex:
            print(f"FAILED: {ex}", file=sys.stderr)
            serial = current / "serial.log"
            if serial.exists():
                tail = serial.read_text(errors="replace").splitlines()[-40:]
                print("--- serial console (last lines)", *tail, sep="\n", file=sys.stderr)
            return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
