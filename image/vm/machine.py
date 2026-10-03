"""QEMU/KVM virtual machine running a USB-Pasteur image.

The machine boots the image with UEFI (OVMF, Secure Boot capable firmware)
and has an empty USB 3 (xHCI) controller: emulated USB keys (disk images) are
inserted and removed while it runs, which triggers the same udev events as a
real device. It is driven through QMP (key insertion, key presses on the
kiosk screen) and a root shell on the virtio console (test profile only).

Interactive use (see docs/image.md):

    python3 machine.py run [IMAGE] [--workdir DIR] [--usb VENDOR:PRODUCT|BUS-PORT]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from types import TracebackType
from typing import Any

import corpus

OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
KEY_SIZE = 64 * 1024 * 1024
# Disk of the machine, bigger than the image: the data partition grows at boot
DISK_SIZE = "8G"
# VNC server address inside the container, which publishes it on localhost only
VNC_LISTEN = "0.0.0.0"  # noqa: S104


class MachineError(Exception):
    pass


def make_key(path: Path) -> None:
    """Create a vfat USB key image holding the corpus files."""
    with path.open("wb") as image:
        image.truncate(KEY_SIZE)
    subprocess.run(["mkfs.vfat", "-n", "USBKEY", str(path)], check=True, capture_output=True)
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        corpus.write_key(folder)
        entries = [str(p) for p in sorted(folder.iterdir())]
        subprocess.run(["mcopy", "-s", "-i", str(path), *entries, "::"], check=True)


def read_key(path: Path) -> list[str]:
    """Return the paths of the files left on a USB key image."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["mcopy", "-s", "-n", "-i", str(path), "::", tmp], check=True)
        root = Path(tmp)
        return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def usb_host_device(spec: str) -> list[str]:
    """QEMU device passing a host USB device through: VENDOR:PRODUCT or BUS-PORT.

    The device is attached when it is plugged into the host, and detached
    from the host kernel driver.
    """
    if match := re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{4})", spec):
        properties = f"vendorid=0x{match[1]},productid=0x{match[2]}"
    elif match := re.fullmatch(r"(\d+)-(\d+(?:\.\d+)*)", spec):
        properties = f"hostbus={match[1]},hostport={match[2]}"
    else:
        raise MachineError(f"not a USB device (VENDOR:PRODUCT) or port (BUS-PORT): {spec}")
    return ["-device", f"usb-host,bus=xhci.0,{properties}"]


def qemu_argv(
    image: Path,
    workdir: Path,
    interactive: bool = False,
    usb_host: Sequence[str] = (),
    vnc_listen: str = VNC_LISTEN,
) -> list[str]:
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    argv = [
        "qemu-system-x86_64",
        "-machine", "q35,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-accel", "kvm" if kvm else "tcg",
        "-cpu", "host" if kvm else "max",
        "-m", "2G",
        "-smp", "2",
        "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
        "-drive", f"if=pflash,format=raw,file={workdir / 'OVMF_VARS.fd'}",
        "-drive", f"if=none,id=system,format=qcow2,file={workdir / 'system.qcow2'}",
        "-device", "virtio-blk-pci,drive=system",
        # Empty USB 3 controller: keys are inserted while the machine runs
        "-device", "qemu-xhci,id=xhci",
        "-device", "virtio-serial-pci",
        "-nic", "none",
        "-qmp", f"unix:{workdir / 'qmp.sock'},server=on,wait=off",
    ]  # fmt: skip
    if interactive:
        # The shell (hvc0) and the QEMU monitor share the terminal (Ctrl-A C
        # switches between them); the kiosk screen (tty1) is shown over VNC.
        argv += [
            "-chardev", "stdio,id=console,mux=on,signal=off",
            "-device", "virtconsole,chardev=console",
            "-mon", "chardev=console",
            "-serial", f"file:{workdir / 'serial.log'}",
            "-vga", "std",
            "-display", f"vnc={vnc_listen}:0",
        ]  # fmt: skip
    else:
        argv += [
            "-chardev", f"socket,id=console,path={workdir / 'console.sock'},server=on,wait=off",
            "-device", "virtconsole,chardev=console",
            "-serial", f"file:{workdir / 'serial.log'}",
            "-vga", "std",
            "-display", "none",
        ]  # fmt: skip
    for spec in usb_host:
        argv += usb_host_device(spec)
    return argv


def prepare_workdir(image: Path, workdir: Path) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    # Sockets of a previous run: never connect to them
    for name in ("qmp.sock", "console.sock"):
        (workdir / name).unlink(missing_ok=True)
    # Firmware variables of this machine: no keys enrolled (Secure Boot setup mode)
    shutil.copyfile(OVMF_VARS, workdir / "OVMF_VARS.fd")
    # Disk of this machine: the built image is never modified, the writes go
    # to a new overlay (a new disk at every start)
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "raw", "-b", str(image),
         str(workdir / "system.qcow2"), DISK_SIZE],
        check=True,
    )  # fmt: skip


def connect(path: Path, timeout: float = 30.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            return sock
        except OSError:
            sock.close()
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


class Qmp:
    """Minimal QMP client: commands and events."""

    def __init__(self, path: Path) -> None:
        self.sock = connect(path)
        self.buffer = b""
        self.events: list[dict[str, Any]] = []
        self._read(30.0)  # greeting
        self.execute("qmp_capabilities")

    def _read(self, timeout: float) -> dict[str, Any]:
        self.sock.settimeout(timeout)
        while b"\n" not in self.buffer:
            data = self.sock.recv(65536)
            if not data:
                raise MachineError("QMP connection closed")
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        message: dict[str, Any] = json.loads(line)
        return message

    def execute(self, command: str, **arguments: Any) -> Any:
        request: dict[str, Any] = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        self.sock.sendall(json.dumps(request).encode() + b"\n")
        while True:
            message = self._read(60.0)
            if "event" in message:
                self.events.append(message)
            elif "error" in message:
                raise MachineError(f"QMP {command}: {message['error'].get('desc')}")
            elif "return" in message:
                return message["return"]

    def wait_event(self, name: str, timeout: float = 30.0, **data: Any) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self.events):
                fields = event.get("data", {})
                if event["event"] == name and all(fields.get(k) == v for k, v in data.items()):
                    del self.events[index]
                    return event
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MachineError(f"QMP event {name} not received")
            try:
                message = self._read(remaining)
            except TimeoutError:
                continue
            if "event" in message:
                self.events.append(message)

    def close(self) -> None:
        self.sock.close()


class Console:
    """Root shell on the virtio console (test profile autologin)."""

    def __init__(self, path: Path) -> None:
        self.sock = connect(path)
        self.buffer = b""
        self.count = 0

    def _read_until(self, pattern: re.Pattern[bytes], timeout: float) -> re.Match[bytes]:
        deadline = time.monotonic() + timeout
        while True:
            match = pattern.search(self.buffer)
            if match:
                return match
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.sock.settimeout(remaining)
            try:
                data = self.sock.recv(65536)
            except TimeoutError:
                continue
            if not data:
                raise MachineError("console connection closed")
            self.buffer += data

    def login(self, timeout: float) -> None:
        """Wait for the autologin shell and make its output easy to parse."""
        setup = (
            b"stty -echo; PS1=; export TERM=dumb SYSTEMD_COLORS=0 SYSTEMD_PAGER=;"
            b" echo READY-$((6*7))\n"
        )
        deadline = time.monotonic() + timeout
        while True:
            self.sock.sendall(setup)
            try:
                match = self._read_until(re.compile(rb"READY-42"), 5.0)
                self.buffer = self.buffer[match.end() :]
                return
            except TimeoutError:
                if time.monotonic() > deadline:
                    raise MachineError("no shell on the virtio console") from None

    def send(self, command: str) -> None:
        """Send a command without waiting for it (reboot)."""
        self.sock.sendall(f"{command}\n".encode())

    def reset(self) -> None:
        """Forget the output of the previous boot."""
        self.buffer = b""

    def succeeds(self, command: str, timeout: float = 60.0) -> bool:
        """Run a shell command, ignoring its output; return whether it succeeded."""
        output = self.run(f"if {command} >/dev/null 2>&1; then echo yes; else echo no; fi", timeout)
        return output.strip().endswith("yes")

    def run(self, command: str, timeout: float = 60.0, check: bool = True) -> str:
        """Run a shell command; return its output."""
        self.count += 1
        # The echoed command never matches the end marker (printf format)
        marker = re.compile(rb"\n?__rc=(\d+)__end%d__\r?\n" % self.count)
        self.sock.sendall(f"{command}\nprintf '\\n__rc=%s__end{self.count}__\\n' $?\n".encode())
        try:
            match = self._read_until(marker, timeout)
        except TimeoutError:
            raise MachineError(f"command timed out: {command}") from None
        output = self.buffer[: match.start()].decode(errors="replace").replace("\r", "")
        self.buffer = self.buffer[match.end() :]
        status = int(match.group(1))
        if check and status != 0:
            raise MachineError(f"command failed ({status}): {command}\n{output}")
        return output

    def close(self) -> None:
        self.sock.close()


class Machine:
    def __init__(self, image: Path, workdir: Path) -> None:
        self.image = image
        self.workdir = workdir
        self.process: subprocess.Popen[bytes] | None = None
        self.qmp: Qmp | None = None
        self.console: Console | None = None
        self.keys = 0
        self.nodes: dict[str, str] = {}

    def __enter__(self) -> Machine:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        prepare_workdir(self.image, self.workdir)
        with (self.workdir / "qemu.log").open("wb") as log:
            self.process = subprocess.Popen(
                qemu_argv(self.image, self.workdir), stdout=log, stderr=subprocess.STDOUT
            )
        self.qmp = Qmp(self.workdir / "qmp.sock")
        self.console = Console(self.workdir / "console.sock")

    def stop(self) -> None:
        if self.qmp is not None:
            with contextlib.suppress(OSError, MachineError):
                self.qmp.execute("quit")
            self.qmp.close()
        if self.console is not None:
            self.console.close()
        if self.process is not None:
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    @property
    def shell(self) -> Console:
        assert self.console is not None
        return self.console

    @property
    def monitor(self) -> Qmp:
        assert self.qmp is not None
        return self.qmp

    def insert_key(self, image: Path, device_id: str = "usbkey") -> None:
        self.keys += 1
        node = f"{device_id}-{self.keys}"
        self.monitor.execute(
            "blockdev-add",
            driver="raw",
            **{"node-name": node},
            file={"driver": "file", "filename": str(image)},
        )
        self.monitor.execute(
            "device_add", driver="usb-storage", bus="xhci.0", drive=node, id=device_id,
            removable=True,
        )  # fmt: skip
        self.nodes[device_id] = node

    def remove_key(self, device_id: str = "usbkey") -> None:
        self.monitor.execute("device_del", id=device_id)
        self.monitor.wait_event("DEVICE_DELETED", device=device_id)
        self.monitor.execute("blockdev-del", **{"node-name": self.nodes.pop(device_id)})

    def reboot(self, timeout: float) -> None:
        """Reboot the machine and wait for the shell."""
        self.shell.send("systemctl reboot")
        self.monitor.wait_event("RESET", timeout=120)
        self.shell.reset()
        self.shell.login(timeout)

    def press_key(self, qcode: str = "ret") -> None:
        """Press a key on the kiosk screen (active virtual terminal)."""
        self.monitor.execute("send-key", keys=[{"type": "qcode", "data": qcode}])


def run_interactive(
    image: Path, workdir: Path, usb_host: Sequence[str] = (), vnc_listen: str = VNC_LISTEN
) -> int:
    argv = qemu_argv(image, workdir, True, usb_host, vnc_listen)
    prepare_workdir(image, workdir)
    key = workdir / "usbkey.img"
    make_key(key)
    print(
        f"Kiosk screen: VNC display :0 (port 5900): gvncviewer localhost:0\n"
        f"Shell (test profile) on this terminal.\n"
        f"Ctrl-A C switches to the QEMU monitor; insert the test key with:\n"
        f"  drive_add 0 if=none,id=key,format=raw,file={key}\n"
        f"  device_add usb-storage,bus=xhci.0,drive=key,id=usbkey,removable=on\n"
        f"and remove it with: device_del usbkey\n"
        f"Ctrl-A X stops the machine.\n",
        flush=True,
    )
    for spec in usb_host:
        print(f"Host USB device {spec}: passed through to the machine when plugged in.")
    return subprocess.run(argv, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="start the machine interactively")
    run.add_argument(
        "image", type=Path, nargs="?", default=Path("image/mkosi.output/usb-pasteur-test.raw")
    )
    run.add_argument("--workdir", type=Path, default=Path("image/vm/work"))
    run.add_argument(
        "--usb",
        action="append",
        default=[],
        metavar="VENDOR:PRODUCT|BUS-PORT",
        help="pass a host USB device through (see image/vm.sh usb)",
    )
    run.add_argument("--vnc-listen", default=VNC_LISTEN, help="address of the VNC server")
    args = parser.parse_args(argv)
    try:
        return run_interactive(
            args.image.resolve(), args.workdir.resolve(), args.usb, args.vnc_listen
        )
    except MachineError as ex:
        parser.error(str(ex))


if __name__ == "__main__":
    sys.exit(main())
