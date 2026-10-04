"""Online signature updates (usb-pasteur-update.service, image profile "online").

The update service runs in two steps:

1. as the usb-pasteur-update user, the only one the firewall lets out:

       usb-pasteur-signatures download --staging DIR

   downloads the manifest of the published set (updates.url) and its
   signature, verifies them with the trusted keys and, when the set is newer
   than the installed one, downloads the files that changed into DIR, each
   checked against its size and SHA-256;

2. as root, without network:

       usb-pasteur-signatures install DIR --staged

   installs the set: sigsets.install() verifies everything again and takes
   the unchanged files from the installed set.

The kiosk loads the new set the next time it is idle. The published set is
signed: HTTPS is recommended, HTTP is accepted (an internal mirror).
"""

from __future__ import annotations

import hashlib
import shutil
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import IO

from usb_pasteur import sigsets
from usb_pasteur.config import Config

_CHUNK = 1024 * 1024


class UpdateError(Exception):
    pass


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects to http(s) URLs only (urllib also follows ftp)."""

    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ) -> urllib.request.Request | None:
        if not newurl.startswith(("https://", "http://")):
            raise UpdateError(f"{req.full_url}: redirect to {newurl} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self, proxy: str = "", timeout: float = 300.0) -> None:
        # Only the configured proxy: never the proxy of the environment
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies), _SafeRedirect()
        )
        self.timeout = timeout

    def open(self, url: str) -> IO[bytes]:
        if not url.startswith(("https://", "http://")):
            raise UpdateError(f"not an http(s) URL: {url}")
        request = urllib.request.Request(  # noqa: S310  (http(s) only, checked above)
            url, headers={"User-Agent": "usb-pasteur-update"}
        )
        response: IO[bytes] = self.opener.open(request, timeout=self.timeout)
        return response

    def read(self, url: str, limit: int) -> bytes:
        with self._open(url) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise UpdateError(f"{url}: too big")
        return data

    def save(self, url: str, target: Path, entry: sigsets.FileEntry) -> None:
        """Download a file of the set, checked against its manifest entry."""
        digest = hashlib.sha256()
        size = 0
        with self._open(url) as response, target.open("wb") as out:
            while chunk := response.read(_CHUNK):
                size += len(chunk)
                if size > entry.size:
                    raise UpdateError(f"{entry.path}: bigger than in the manifest")
                digest.update(chunk)
                out.write(chunk)
        if size != entry.size or digest.hexdigest() != entry.sha256:
            raise UpdateError(f"{entry.path}: content does not match the manifest")

    def _open(self, url: str) -> IO[bytes]:
        try:
            return self.open(url)
        except urllib.error.HTTPError as ex:
            raise UpdateError(f"{url}: HTTP {ex.code} {ex.msg}") from ex
        except (urllib.error.URLError, OSError) as ex:
            raise UpdateError(f"{url}: {getattr(ex, 'reason', ex)}") from ex


def download(
    config: Config,
    staging: Path,
    fetcher: Fetcher | None = None,
    log: Callable[[str], None] = print,
) -> sigsets.Manifest | None:
    """Download the published set into staging when it is newer; return it."""
    updates = config.updates
    if not updates.enabled:
        log("online updates are disabled (updates.enabled)")
        return None
    staging.mkdir(parents=True, exist_ok=True)
    for path in staging.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    fetcher = fetcher or Fetcher(updates.proxy, updates.timeout)
    base = updates.url.rstrip("/") + "/"

    data = fetcher.read(base + sigsets.MANIFEST, sigsets.MAX_MANIFEST_SIZE)
    signature = fetcher.read(base + sigsets.SIGNATURE, sigsets.MAX_SIGNATURE_SIZE)
    try:
        sigsets.verify_signature(data, signature, sigsets.trusted_keys(config.signatures.keys))
        manifest = sigsets.parse_manifest(data)
    except sigsets.SignatureSetError as ex:
        raise UpdateError(f"published set refused: {ex}") from ex
    installed = sigsets.installed_manifest(config.signatures.folder)
    if installed is not None and manifest.serial <= installed.serial:
        log(f"up to date: published set {manifest.serial}, installed set {installed.serial}")
        return None

    changed = []
    for entry in manifest.files:
        old = None if installed is None else installed.entry(entry.path)
        if old is None or (old.sha256, old.size) != (entry.sha256, entry.size):
            changed.append(entry)
    log(f"set {manifest.serial}: downloading {len(changed)} of {len(manifest.files)} files")
    for entry in changed:
        target = staging / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        fetcher.save(base + urllib.parse.quote(entry.path), target, entry)
    # Written last: a staged set is complete
    (staging / sigsets.SIGNATURE).write_bytes(signature)
    (staging / sigsets.MANIFEST).write_bytes(data)
    return manifest
