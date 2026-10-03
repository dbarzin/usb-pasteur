"""Test corpus of the virtual machine tests.

The files of the emulated USB key, the verdicts expected for each of them, and
the test-only signatures that detect them (installed by the image test
profile). Also a command line tool:

    python3 corpus.py key FOLDER         write the key files into FOLDER
    python3 corpus.py signatures FOLDER  write the test signatures into FOLDER
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


def write_signatures(folder: Path) -> None:
    """Write the signatures that detect the key files, and nothing else."""
    from usb_pasteur.bloom import write_filter
    from usb_pasteur.hashdb import write_database

    folder.mkdir(parents=True, exist_ok=True)
    write_database(
        [hashlib.sha256(MALWAREBAZAAR_SAMPLE).digest()], folder / "malwarebazaar.sha256.bin"
    )
    write_filter(
        folder / "hashlookup.bloom", [hashlib.sha1(KNOWN_FILE).hexdigest().upper().encode()]
    )
    (folder / "rules.yar").write_text(YARA_RULE)
    sample = eicar()
    (folder / "usb-pasteur-test.hdb").write_text(
        f"{hashlib.md5(sample).hexdigest()}:{len(sample)}:UsbPasteur.Test.EICAR\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("key", "signatures"):
        print(__doc__, file=sys.stderr)
        return 2
    (write_key if argv[0] == "key" else write_signatures)(Path(argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
