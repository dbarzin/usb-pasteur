#!/usr/bin/env python3
"""DEVELOPMENT HELPER ONLY - do not use it to update a kiosk.

Download the signature databases and rules used by the USB-Pasteur engines
into a local development folder, and print the matching configuration.
Nothing is verified beyond TLS: signed production updates come with phase 2.

    python scripts/fetch-dev-signatures.py [--dest dev-signatures] [--skip hashlookup]

Sources:
- YARA Forge "core" rule package (GitHub release)
- signature-base YARA rules (GitHub, master branch)
- MalwareBazaar full SHA-256 export (needs a free abuse.ch Auth-Key in the
  ABUSECH_AUTH_KEY environment variable), converted with usb_pasteur.hashdb
- CIRCL hashlookup Bloom filter (about 1 GB)

ClamAV signatures are managed by freshclam on the system: see docs/engines.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

YARA_FORGE = (
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
)
SIGNATURE_BASE = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz"
MALWAREBAZAAR = "https://bazaar.abuse.ch/export/txt/sha256/full/"
HASHLOOKUP = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
SOURCES = ("yara-forge", "signature-base", "malwarebazaar", "hashlookup")


def download(url: str, target: Path, headers: dict[str, str] | None = None) -> str:
    """Download url to target; return the SHA-256 of the content."""
    print(f"downloading {url}")
    if not url.startswith("https://"):
        raise ValueError(f"not an HTTPS URL: {url}")
    request = urllib.request.Request(  # noqa: S310  (HTTPS only, checked above)
        url, headers={"User-Agent": "usb-pasteur-dev", **(headers or {})}
    )
    digest = hashlib.sha256()
    tmp = target.with_name(f".{target.name}.part")
    with urllib.request.urlopen(request, timeout=120) as response, tmp.open("wb") as out:  # noqa: S310
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            out.write(chunk)
    tmp.replace(target)
    return digest.hexdigest()


def write_manifest(folder: Path, name: str, source: str, sha256: str, version: str = "") -> None:
    manifest_path = folder / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        manifest = {}
    manifest[name] = {
        "version": version or datetime.now(UTC).strftime("%Y-%m-%d"),
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "source": source,
        "sha256": sha256,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def fetch_yara_forge(dest: Path) -> Path:
    folder = dest / "yara" / "yara-forge"
    folder.mkdir(parents=True, exist_ok=True)
    archive = dest / "yara-forge-rules-core.zip"
    sha256 = download(YARA_FORGE, archive)
    with zipfile.ZipFile(archive) as z:
        member = next(n for n in z.namelist() if n.endswith("yara-rules-core.yar"))
        target = folder / "yara-rules-core.yar"
        target.write_bytes(z.read(member))
    archive.unlink()
    write_manifest(folder, target.name, YARA_FORGE, sha256)
    return target


def fetch_signature_base(dest: Path) -> Path:
    folder = dest / "yara" / "signature-base"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    archive = dest / "signature-base.tar.gz"
    sha256 = download(SIGNATURE_BASE, archive)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = PurePosixPath(member.name).parts
            # Only regular files of the yara/ folder, without any path trick
            if len(parts) < 3 or parts[1] != "yara" or not member.isfile():
                continue
            if any(p in ("", ".", "..") for p in parts) or member.name.startswith("/"):
                continue
            target = folder.joinpath(*parts[2:])
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is not None:
                target.write_bytes(source.read())
    archive.unlink()
    write_manifest(dest / "yara", "signature-base", SIGNATURE_BASE, sha256)
    return folder


def fetch_malwarebazaar(dest: Path) -> Path | None:
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        print("skipping MalwareBazaar: set ABUSECH_AUTH_KEY (free key: https://auth.abuse.ch/)")
        return None
    from usb_pasteur.hashdb import read_export, write_database

    folder = dest / "malwarebazaar"
    folder.mkdir(parents=True, exist_ok=True)
    export = folder / "full_sha256.zip"
    download(MALWAREBAZAAR, export, {"Auth-Key": key})
    digests, source_sha256 = read_export(export)
    database = folder / "malwarebazaar.sha256.bin"
    count = write_database(digests, database, source_sha256)
    export.unlink()
    write_manifest(folder, database.name, MALWAREBAZAAR, source_sha256, f"{count} hashes")
    print(f"MalwareBazaar: {count} hashes")
    return database


def fetch_hashlookup(dest: Path) -> Path:
    folder = dest / "hashlookup"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "hashlookup-full.bloom"
    sha256 = download(HASHLOOKUP, target)
    write_manifest(folder, target.name, HASHLOOKUP, sha256)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, default=Path("dev-signatures"))
    parser.add_argument("--skip", action="append", choices=SOURCES, default=[])
    args = parser.parse_args()
    dest: Path = args.dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path | None] = {}
    if "yara-forge" not in args.skip:
        paths["yara-forge"] = fetch_yara_forge(dest)
    if "signature-base" not in args.skip:
        paths["signature-base"] = fetch_signature_base(dest)
    if "malwarebazaar" not in args.skip:
        paths["malwarebazaar"] = fetch_malwarebazaar(dest)
    if "hashlookup" not in args.skip:
        paths["hashlookup"] = fetch_hashlookup(dest)

    print("\n# Development configuration (add to usb-pasteur.toml):\n")
    mb, hl = paths.get("malwarebazaar"), paths.get("hashlookup")
    print("[engines.malwarebazaar]")
    print(f'database = "{mb}"' if mb else "enabled = false")
    print("\n[engines.hashlookup]")
    print(f'bloom = "{hl}"' if hl else "enabled = false")
    rules = [(n, paths[n]) for n in ("yara-forge", "signature-base") if paths.get(n)]
    print("\n[engines.yara]")
    if rules:
        print("rules = [")
        for name, path in rules:
            print(f'    {{ name = "{name}", path = "{path}" }},')
        print("]")
        print(f'cache_dir = "{dest / "cache"}"')
    else:
        print("enabled = false")
    print("\n[signatures]")
    print("# Development signatures are not a signed set (docs/signatures.md)")
    print("verify = false")
    print("\n# ClamAV: install clamav-daemon and run freshclam, see docs/engines.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
