# Kiosk image

The kiosk is distributed as a complete system image (phase 2), built with
[mkosi](https://github.com/systemd/mkosi) from Debian 13 (trixie) packages,
and tested in a QEMU/KVM virtual machine. Everything runs in a Debian 13
container (`image/Dockerfile`: mkosi, QEMU, OVMF), so the developer only needs
Docker.

> [!WARNING]
> The image is a first step: it is neither signed nor protected by dm-verity,
> and the production image has no signatures yet (the kiosk refuses to start until signature updates exist).
> See the phase 2 tasks in the [README](../README.md#phase-2--minimal-hardened-image).

## Layout

| Path | Role |
|---|---|
| `image/mkosi.conf` | Image definition: Debian 13, x86_64, systemd-boot, unified kernel image (UKI), packages |
| `image/mkosi.repart/` | Partitions: ESP, read-only root filesystem, data partition |
| `image/mkosi.prepare.chroot` | Runtime dependencies in a virtual environment (`/usr/lib/usb-pasteur`), from `image/requirements.txt` (pinned with their hashes) |
| `image/mkosi.build.chroot` | usb-pasteur wheel, built from the repository without network |
| `image/mkosi.postinst.chroot` | Installs usb-pasteur, its configuration, systemd service, tmpfiles and logrotate files (`packaging/`), and the clamd settings |
| `image/mkosi.extra/` | Files copied into the image: systemd presets (enabled and disabled units), `/etc/fstab`, growth of the data partition (`/usr/lib/repart.d/`) |
| `image/mkosi.profiles/test/` | Test profile, for the virtual machine tests only |
| `image/vm/` | Virtual machine tests: corpus, QEMU driver, automated test |
| `image/build.sh`, `image/vm.sh` | Build and run in the container |

## Build

Requirements: Docker, about 5 GB of disk space, network access (Debian
packages and Python wheels).

```sh
image/build.sh                  # production image
image/build.sh --profile test   # test image
```

The image is written to `image/mkosi.output/`: `usb-pasteur.raw` (or
`usb-pasteur-test.raw`, a GPT disk image), the UKI (`.efi`) and the list of
installed packages (`.manifest`). The first build takes a few minutes; the
following ones reuse the installed packages (mkosi incremental build, cached
in the `usb-pasteur-mkosi` Docker volume) and take less than a minute.

The cache is not rebuilt when `image/requirements.txt` or
`image/mkosi.prepare.chroot` change: rebuild it with `image/build.sh -f`
(`docker volume rm usb-pasteur-mkosi` removes it completely).

The disk image has three partitions:

| Partition | Filesystem | Content |
|---|---|---|
| ESP | vfat, 512 MB | systemd-boot and the UKI |
| root | EROFS, read-only | the whole system but `/var` (about 400 MB) |
| data (`usb-pasteur-data`) | ext4, 1 GB in the image | `/var`: scan reports, quarantine, logs, signatures, clamd database |

The root filesystem is read-only by design (EROFS cannot be written at all):
the system and its configuration only change with a new image. Everything
the kiosk writes is in `/var`. The data partition is the last one: at every
boot, `systemd-repart` grows it to fill the disk
(`/usr/lib/repart.d/20-var.conf`), then `systemd-growfs` grows its
filesystem (`x-systemd.growfs` in `/etc/fstab`), so the image can be written
to a disk of any size. As `/etc` is read-only, the machine ID is generated
again at every boot (a new journal folder per boot, within the journald
size limits).

The image contains:

- the kernel, systemd and udev, Python 3 and clamd (`clamav-daemon`), with no
  network service: `systemd-networkd`, `systemd-resolved`, freshclam and the
  ClamAV on-access scanner are disabled (`10-usb-pasteur.preset`);
- usb-pasteur in `/usr/lib/usb-pasteur` (`/usr/bin/usb-pasteur`), its
  configuration in `/etc/usb-pasteur/usb-pasteur.toml` and its service, which
  shows the curses interface on the first console;
- no `login` program and no root password: no interactive session is
  possible.

Runtime dependencies are pinned with their hashes in `image/requirements.txt`.
After a change of the dependencies in `pyproject.toml`, regenerate it with
`image/lock-requirements.sh`.

## Test profile

`--profile test` builds `usb-pasteur-test.raw`, for the virtual machine tests
only, never for a kiosk:

- test-only signatures, generated from `image/vm/corpus.py`: a ClamAV
  database that detects the EICAR test file, a MalwareBazaar database, a
  Hashlookup filter and a YARA rule, each detecting one file of the test key;
- the matching configuration, with every engine enabled;
- a root shell without password on the virtio console (`hvc0`), and kernel
  messages on the serial port;
- `kiosk-screen`, which prints the text of the kiosk screen in that shell.

## Automated test in a virtual machine

```sh
image/build.sh --profile test
image/vm.sh test
```

The test boots the test image in QEMU (KVM when `/dev/kvm` is writable,
otherwise much slower emulation), with UEFI firmware (OVMF) and an empty
USB 3 controller. It plays the whole user workflow, through QMP and the
shell on the virtio console:

1. the kiosk starts with its four engines and no systemd unit fails;
2. the root filesystem is read-only EROFS, and `/var` was grown to fill the
   8 GB disk of the machine;
3. an emulated USB key (a vfat disk image holding the corpus) is inserted,
   which triggers the same udev events as a real device;
4. each file gets the expected verdict from the expected engine;
5. the cleaning is confirmed with a key press on the kiosk screen; the
   infected files are quarantined (checked against their SHA-256) and
   removed from the key, which is ejected;
6. the key is removed: only the clean files are left on it;
7. the cleaned key is inserted again and reported clean;
8. after a reboot, the scan reports are still there and the root filesystem
   is unchanged.

The built image is never modified: the machine writes to a new disk overlay
(`system.qcow2`) at every start. It takes less than a minute with KVM. `image/vm.sh test --workdir DIR` keeps
the serial console log, the QEMU log and the key image in `DIR`.

## Interactive virtual machine

```sh
image/vm.sh run                              # test image
image/vm.sh run image/mkosi.output/usb-pasteur.raw
```

The kiosk screen (first console, `tty1`) is shown over VNC, display `:0`
(port 5900), for example with `gvncviewer localhost:0` (most viewers read
`host:N` as a display number, port 5900 + N); `kiosk-screen` also prints it in the shell of the test
image. The terminal shows this shell (virtio console), not the kiosk, and, after
`Ctrl-A C`, the QEMU monitor; `Ctrl-A X` stops the machine. A test key is
created in `image/vm/work/usbkey.img`; insert and remove it from the monitor:

```
(qemu) drive_add 0 if=none,id=key,format=raw,file=/src/image/vm/work/usbkey.img
(qemu) device_add usb-storage,bus=xhci.0,drive=key,id=usbkey,removable=on
(qemu) device_del usbkey
```

Paths are seen from the container, where the repository is mounted on `/src`.
Any disk image can be used as a key, but hostile samples should only ever be
copied into key images, never onto the development desktop.

### Real USB keys

A USB key plugged into this computer can be passed through to the machine.
List the USB storage devices of this computer, with their port (`BUS-PORT`)
and identifier (`VENDOR:PRODUCT`):

```sh
image/vm.sh usb
```
```
1-4  abcd:1234  General UDisk
    sda     3,8G
    └─sda1  3,7G vfat   /media/didier/6B20-F9DE
```

Then start the machine with `--usb`, followed by a port, which passes through
any key plugged into that port, like the USB port of a kiosk, or by an
identifier, which passes through that model of key on any port:

```sh
image/vm.sh run --usb 1-4
```

QEMU attaches the key to the machine as soon as it is plugged in (or at once
if it is already there) and takes it from this computer: its kernel driver is
detached. Before starting the machine, unmount the key
(`udisksctl unmount -b /dev/sda1`) and disable the automatic mounting of USB
devices of the desktop, so that this computer never mounts a key meant for
the kiosk. `--usb` can be given several times. On GNOME:

```sh
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false
# after the tests: the same commands with "true"
```

QEMU then runs as root in the container, with access to the USB devices of
this computer and its network (to receive the udev events of the keys
plugged in later); the kiosk screen is on `localhost:5900` as before.
