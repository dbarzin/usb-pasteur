"""Test corpus of the virtual machine tests.

The files of the emulated USB key, the verdicts expected for each of them, and
the test-only signatures that detect them (installed by the image test
profile). Also a command line tool:

    python3 corpus.py key FOLDER         write the key files into FOLDER
    python3 corpus.py signatures FOLDER  write the test signature set into FOLDER
    python3 corpus.py canary FILE        write the dm-verity canary file
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# EICAR is stored encoded in the repository (tests/samples.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from samples import eicar  # type: ignore[import-not-found]

YARA_MARKER = b"USB-PASTEUR-VM-YARA-MARKER"
YARA_RULE = f"""
rule UsbPasteur_VM_Marker {{
    meta: score = 90
    strings: $a = "{YARA_MARKER.decode()}"
    condition: $a
}}
"""
MALWAREBAZAAR_SAMPLE = b"pretend malware sample listed in MalwareBazaar (VM test)\n"
KNOWN_FILE = b"a well known file listed in hashlookup (VM test)\n"
# Detected by MalwareBazaar only in the signature set of the update test
NEW_SAMPLE = b"pretend malware sample listed by a signature update (VM test)\n"
# File of the root filesystem of the test image, modified on the disk by the
# dm-verity test. Its first line must be unique in the image; it fills whole
# filesystem blocks, so that the modified block holds nothing else.
VERITY_CANARY_PATH = "/usr/share/usb-pasteur/verity-canary"
VERITY_CANARY_MARKER = b"USB-PASTEUR-VERITY-CANARY-" + b"5d1c0a7e93f2b864" * 4 + b"\n"
VERITY_CANARY = (VERITY_CANARY_MARKER * (3 * 4096 // len(VERITY_CANARY_MARKER) + 1))[: 3 * 4096]

# Files of the USB key and the engine expected to detect each of them
# ("" when the file must be reported clean and stay on the key)
KEY: dict[str, tuple[bytes, str]] = {
    "readme.txt": (b"hello from the USB-Pasteur VM test\n", ""),
    "known.txt": (KNOWN_FILE, ""),
    "docs/eicar.com": (eicar(), "clamav"),
    "docs/marker.bin": (b"xx " + YARA_MARKER + b" xx\n", "yara"),
    "sample.bin": (MALWAREBAZAAR_SAMPLE, "malwarebazaar"),
}


def write_key(folder: Path) -> None:
    for path, (content, _) in KEY.items():
        target = folder / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


# Files of the test signature set (the default paths of the engines, but YARA)
MALWAREBAZAAR_DB = "malwarebazaar/malwarebazaar.sha256.bin"
HASHLOOKUP_BLOOM = "hashlookup/hashlookup-full.bloom"
YARA_RULES = "yara/vm-test/rules.yar"
CLAMAV_DB = "clamav/usb-pasteur-test.hdb"


def write_signatures(folder: Path, malwarebazaar: tuple[bytes, ...] = ()) -> None:
    """Write a signature set detecting the key files, and nothing else.

    malwarebazaar: more samples to detect (signature update test).
    """
    from usb_pasteur.bloom import write_filter
    from usb_pasteur.hashdb import write_database

    for name in (MALWAREBAZAAR_DB, HASHLOOKUP_BLOOM, YARA_RULES, CLAMAV_DB):
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
    samples = (MALWAREBAZAAR_SAMPLE, *malwarebazaar)
    write_database([hashlib.sha256(s).digest() for s in samples], folder / MALWAREBAZAAR_DB)
    write_filter(folder / HASHLOOKUP_BLOOM, [hashlib.sha1(KNOWN_FILE).hexdigest().upper().encode()])
    (folder / YARA_RULES).write_text(YARA_RULE)
    sample = eicar()
    (folder / CLAMAV_DB).write_text(
        f"{hashlib.md5(sample).hexdigest()}:{len(sample)}:UsbPasteur.Test.EICAR\n"
    )


def write_canary(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(VERITY_CANARY)


def main(argv: list[str]) -> int:
    commands = {"key": write_key, "signatures": write_signatures, "canary": write_canary}
    if len(argv) != 2 or argv[0] not in commands:
        print(__doc__, file=sys.stderr)
        return 2
    commands[argv[0]](Path(argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
