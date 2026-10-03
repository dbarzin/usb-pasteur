# Kiosk image

The kiosk is distributed as a complete system image (phase 2), built with
[mkosi](https://github.com/systemd/mkosi) from Debian 13 (trixie) packages,
and tested in a QEMU/KVM virtual machine. Everything runs in a Debian 13
container (`image/Dockerfile`: mkosi, QEMU, OVMF), so the developer only needs
Docker.

> [!WARNING]
> The image is not fully hardened yet (sandboxing, firewall), it is signed
> with development keys only, and the production image has no signatures yet
> (the kiosk refuses to start until signature updates exist).
> See the phase 2 tasks in the [README](../README.md#phase-2--minimal-hardened-image).

## Layout

| Path | Role |
|---|---|
| `image/mkosi.conf` | Image definition: Debian 13, x86_64, systemd-boot, unified kernel image (UKI), packages |
| `image/mkosi.repart/` | Partitions: ESP, read-only root filesystem and its dm-verity hash and signature, data partition |
| `image/mkosi.prepare.chroot` | Runtime dependencies in a virtual environment (`/usr/lib/usb-pasteur`), from `image/requirements.txt` (pinned with their hashes) |
| `image/mkosi.build.chroot` | usb-pasteur wheel, built from the repository without network |
| `image/mkosi.postinst.chroot` | Installs usb-pasteur, its configuration, systemd service, tmpfiles and logrotate files (`packaging/`), and the clamd settings |
| `image/mkosi.extra/` | Files copied into the image: systemd presets (enabled and disabled units), `/etc/fstab`, growth of the data partition (`/usr/lib/repart.d/`), USBGuard policy |
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

The disk image has five partitions:

| Partition | Filesystem | Content |
|---|---|---|
| ESP | vfat, 512 MB | systemd-boot and the UKI, both signed |
| root | EROFS, read-only | the whole system but `/var` (about 400 MB) |
| root-verity | | dm-verity hash tree of the root filesystem |
| root-verity-sig | | signature of the root hash |
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

## Signing, Secure Boot and dm-verity

The boot chain is verified from the firmware to every block of the system:

1. with Secure Boot, the firmware only starts systemd-boot if it is signed
   with a key of its `db`, and systemd-boot only starts a signed UKI;
2. the UKI holds the kernel, the initrd and the kernel command line, which
   contains the dm-verity root hash (`roothash=`): changing it breaks the
   signature;
3. the root filesystem is opened with dm-verity: every block read is checked
   against the hash tree, whose root is that hash. A modified block cannot
   be read (I/O error, "data block ... is corrupted" in the kernel log);
4. with Secure Boot, the Debian kernel enables its lockdown mode
   (`integrity`): even root cannot modify the running kernel.

`/var` is not protected by dm-verity: it holds the data of the kiosk, never
programs or configuration.

The image is signed with `image/mkosi.key` and `image/mkosi.crt` (systemd-boot,
UKI, root hash). When they do not exist, `image/build.sh` generates a
**development** key pair, valid 10 years, that never leaves the developer's
computer (ignored by git). A kiosk must only trust the release keys of the
project, which are not defined yet: they will be kept out of the repository,
and mkosi can sign with a key in a hardware token
(`--secure-boot-key-source=provider:pkcs11`).

On a kiosk, the certificate is enrolled in the firmware in place of the
Microsoft keys (PK, KEK and db), so that it starts nothing else. The ESP
contains the keys in the format expected by the firmware
(`loader/keys/auto/`): with the firmware in Secure Boot setup mode, the
systemd-boot menu offers to enroll them. The virtual machines enroll the
certificate with `virt-fw-vars` instead (`image/vm/machine.py`).

## USB devices

A kiosk must only use USB storage devices: a key that is also a keyboard
(BadUSB) could type commands, a network adapter could open a network.

- **USBGuard** (`/etc/usbguard/rules.conf`) allows hubs and the devices
  whose interfaces are all mass storage; it blocks every other device,
  including a key that has a storage interface and another one. Blocked
  devices are listed in `/var/log/usbguard/usbguard-audit.log`.
- **No device is authorized before USBGuard has started**: the kernel
  command line sets `usbcore.authorized_default=0`. If USBGuard does not
  start, no USB device is usable.
- **Drivers removed from the image** (`KernelModulesExclude=` in
  `image/mkosi.conf`): USB network adapters, wireless, Bluetooth, USB serial
  adapters and modems, plus the staging drivers and batman-adv, which would
  bring the wireless modules back as dependencies. Such devices have no
  driver even if they were authorized.
- **USB HID is kept**: the touchscreen of the kiosk is a USB HID device. It
  will be allowed by its own USBGuard rule once the reference hardware is
  chosen; until then, every keyboard, mouse and touchscreen is blocked. The
  virtual machines are not affected: their keyboard is not a USB device.

## Dependencies

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
otherwise much slower emulation), with UEFI firmware (OVMF) where the image
signing certificate is enrolled (Secure Boot enabled), and an empty USB 3
controller. It plays the whole user workflow, through QMP and the shell on
the virtio console:

1. the kiosk starts with its four engines and no systemd unit fails;
2. Secure Boot is enabled, the kernel is locked down and the root filesystem
   is on dm-verity;
3. the root filesystem is read-only EROFS, and `/var` was grown to fill the
   8 GB disk of the machine;
4. an emulated USB key (a vfat disk image holding the corpus) is inserted,
   which triggers the same udev events as a real device;
5. each file gets the expected verdict from the expected engine;
6. the cleaning is confirmed with a key press on the kiosk screen; the
   infected files are quarantined (checked against their SHA-256) and
   removed from the key, which is ejected;
7. the key is removed: only the clean files are left on it;
8. the cleaned key is inserted again and reported clean; an emulated USB
   keyboard and network adapter are blocked by USBGuard (no input device, no
   network interface) and the excluded drivers are not in the image;
9. after a reboot, the scan reports are still there and the root filesystem
   is unchanged.

Two more machines boot the same image:

- with a block of the root filesystem modified on the disk (a canary file of
  the test image): it cannot be read and the kernel reports the corruption;
- with firmware trusting another key: the firmware refuses systemd-boot
  ("Access Denied") and nothing starts.

The built image is never modified: the machine writes to a new disk overlay
(`system.qcow2`) at every start. It takes about a minute and a half with KVM.
`image/vm.sh test --workdir DIR` keeps the serial console logs, the QEMU logs
and the key image in `DIR`.

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
