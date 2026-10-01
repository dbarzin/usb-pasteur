# USB-Pasteur README

**USB-Pasteur** is an open source USB decontamination kiosk ("sheep-dip station") to detect and remove malware from USB storage devices.
Successor to [pandora-box](https://github.com/dbarzin/pandora-box), with no dependency on Pandora (CIRCL).

## Vision

Provide a **free, auditable and hardened** USB decontamination kiosk, a credible alternative to commercial solutions, suited to sensitive environments (healthcare, industry, public administration).

## Guiding principles

- **Minimal, hardened image**: the system contains only what is needed to scan.
- **Defense in depth**: the USB device is hostile, and analyzers are assumed to be compromisable.
- **Offline by default**: no network connection is required to scan; updates go through a signed channel.
- **Plugin engines**: every detection engine implements a common interface.
- **Traceability**: every scan produces a structured, timestamped report.
- **Language**: Python 3.12+ for the orchestrator (reuse of pandora-box code, analysis ecosystem).

---

## Phase 0 — Foundations

Goal: restart from a clean base while reusing what works in pandora-box.

### Code reused from pandora-box

| Component | Decision |
|---|---|
| State machine (START, WAIT, SCAN, CLEAN, STOP) | Kept, refactored into a dedicated module |
| USB detection with `pyudev` | Kept |
| Device mounting / unmounting | Kept, hardened (mount options, read-only) |
| Quarantine of infected files | Kept |
| Curses interface (administrator mode) | Kept |
| Logging, logrotate, systemd service | Kept, moved to structured JSON |
| Single-instance lock | Kept |
| `pypandora` calls | Removed, replaced by the engine pipeline |
| Comodo engine | Removed (no longer maintained on Linux) |

### Tasks

- [x] Project name: **USB-Pasteur** (repository `usb-pasteur`, Python module `usb_pasteur`)
- [x] New repository, GPL-3.0 license, `CONTRIBUTING.md`, `SECURITY.md`
- [ ] Python package structure (`pyproject.toml`), type hints, `ruff`, `mypy`
- [ ] TOML configuration (replaces the `.ini`), validated at startup
- [ ] Keep `FAKE_SCAN` mode for development
- [ ] Continuous integration: lint, unit tests, package build
- [ ] End-to-end tests in a container with a simulated USB disk image (loop device)

## Phase 1 — Scanning engine (MVP)

Goal: replace Pandora with an equivalent or better local pipeline.

- [ ] Common plugin interface: `scan(file) -> Verdict` (clean, suspicious, malicious, error, skipped)
- [ ] Device inventory and hash computation (SHA-256, SHA-1, MD5)
- [ ] **Hashlookup (CIRCL)** as an offline Bloom filter: skip files known to be clean
- [ ] **MalwareBazaar**: offline list of malicious hashes
- [ ] **ClamAV** through `clamd` (Unix socket) + third-party signatures
- [ ] **YARA-X** + YARA Forge and signature-base rules
- [ ] Real file type identification (`libmagic`)
- [ ] Parallel engine execution (process pool), timeout per file and per engine
- [ ] Verdict aggregation with a configurable policy (one positive engine is enough, etc.)
- [ ] Limits: maximum file size, number of files, directory depth
- [ ] JSON scan report (device, files, verdicts, engines, signature versions)
- [ ] Test set: EICAR, harmless samples, known false positives

## Phase 2 — Minimal hardened image

Goal: ship a ready-to-flash system image with the smallest possible attack surface.

### Build

- [ ] Image based on Debian 13 (trixie), built with `mkosi`
- [ ] Reproducible builds and an SBOM generated for every release
- [ ] Single target: x86_64 (see reference hardware); ARM64 is not targeted, as the Raspberry Pi proved too slow
- [ ] Signed image and published checksums

### Reference hardware

- **Computer**: refurbished Lenovo ThinkCentre (x86_64)
- **Display**: 7-inch touchscreen
- **Enclosure**: 3D-printed

Tasks:

- [ ] List of validated ThinkCentre models (CPU, RAM, USB ports, Secure Boot support)
- [ ] Touchscreen model selection, driver support and calibration
- [ ] Enclosure design published in the repository (source files + STL), under an open hardware license
- [ ] Assembly guide (bill of materials, printing settings, wiring, USB port layout for the user)
- [ ] Physical hardening: only the scanning USB ports reachable from the outside, other ports and BIOS access protected
- [ ] BIOS configuration guide (password, boot order locked, Secure Boot with project keys)

### System integrity

- [ ] Read-only root filesystem, variable data on a separate partition
- [ ] `dm-verity` on the system partition
- [ ] Unified Kernel Image (UKI) and Secure Boot
- [ ] Atomic A/B partition updates (`systemd-sysupdate`)

### Hardening

- [ ] No interactive account by default, no SSH (explicitly enabled in maintenance mode only)
- [ ] Hardened kernel settings (`sysctl`, `lockdown`, unused modules disabled)
- [ ] `nftables` firewall: deny all by default
- [ ] **USBGuard**: only mass-storage devices are allowed (BadUSB protection)
- [ ] Blacklist of USB HID and USB network kernel modules
- [ ] Devices mounted with `ro,noexec,nosuid,nodev`, no automount
- [ ] Limited set of supported filesystems (vfat, exfat, ntfs3, ext4)
- [ ] Hardened systemd services (`ProtectSystem`, `PrivateNetwork`, `NoNewPrivileges`, seccomp filters)
- [ ] Each analyzer runs in a `bubblewrap` sandbox, without network, under a dedicated user
- [ ] Audit log (`auditd`) for sensitive operations
- [ ] Assessment with `lynis` and the ANSSI configuration recommendations for GNU/Linux systems

### Signature updates

- [ ] Online updates through a dedicated channel (proxy, domain allowlist)
- [ ] Offline updates from a signed USB device, for air-gapped kiosks
- [ ] Signature verification before loading databases

## Phase 3 — Kiosk interface

- [ ] Local web interface (FastAPI + htmx) displayed in kiosk mode (`cage` + Chromium)
- [ ] User flow: insertion, progress, verdict, available actions
- [ ] Touch-first interface designed for the 7-inch screen (large buttons, no keyboard needed)
- [ ] Security awareness messages during the scan
- [ ] Internationalization: FR, EN, DE, NL
- [ ] Protected administrator mode (curses or web): scan reports, signature status
- [ ] Accessibility (contrast, font size)

## Phase 4 — Advanced analysis

- [ ] Office documents: `oletools` (olevba, mraptor)
- [ ] PDF: `pdfid` (JavaScript, automatic actions, embedded files)
- [ ] Archives: controlled extraction (libarchive / 7-Zip), protection against decompression bombs
- [ ] Encrypted archives flagged as unscannable
- [ ] Executables: `capa` (optional, can be disabled for performance)
- [ ] Detection of extension / real type mismatches
- [ ] **Content disarm and reconstruction (CDR)** to a trusted device using Dangerzone
- [ ] Selective copy of clean files only to a second device

## Phase 5 — Fleet management and traceability

- [ ] Log export as syslog / JSON to a SIEM (Wazuh, etc.)
- [ ] Printed or exported scan receipt for the user
- [ ] Optional central server: kiosk inventory, reports, signature status
- [ ] Centralized distribution of signed updates
- [ ] Statistics dashboard (devices scanned, detections)
- [ ] Integration with Mercator (kiosks inventoried in the IT map)

## Phase 6 — Assurance and compliance

- [ ] Documented threat model
- [ ] Fuzzing of entry points (mounting, metadata parsing)
- [ ] Detection regression test corpus
- [ ] External security audit of the image
- [ ] Deployment guide: kiosk placement, user procedure, associated USB policy
- [ ] Mapping to NIS2 and ISO 27001 requirements (control 7.10 "Storage media")

---

## Out of scope (for now)

- Workstation agent blocking devices that have not been scanned
- Dynamic analysis (execution sandbox)
- Encrypted devices (BitLocker, VeraCrypt)
- Smartphones and MTP devices
- `.deb` package installable on an existing system: USB-Pasteur is only distributed as a complete hardened image

## Open questions

- Default policy for a "suspicious" verdict: block or warn?

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

USB-Pasteur is free software, licensed under the [GNU General Public License v3.0](LICENSE).
