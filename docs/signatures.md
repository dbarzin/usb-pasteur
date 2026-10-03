# Signature updates

The detection engines of a kiosk only use a **signed signature set**,
verified at each start. A set is installed from a **signature update
device**: a USB key holding a set, for kiosks without network. Online updates
come later (phase 2).

## Signature sets

A signature set is a folder holding the signature files of the engines and a
signed list of them (`src/usb_pasteur/sigsets.py`):

```
manifest.json          serial, creation date, and the SHA-256 and size of every file
manifest.json.sig      Ed25519 signature of manifest.json
clamav/main.cvd        ClamAV databases (clamd reads this folder)
clamav/daily.cvd
malwarebazaar/malwarebazaar.sha256.bin
hashlookup/hashlookup-full.bloom
yara/yara-forge/yara-rules-core.yar
```

The paths are those of the default configuration
(`/var/lib/usb-pasteur-signatures/current/...`). The `manifest.json` of a
subfolder (written by `scripts/fetch-dev-signatures.py`) gives the source,
version and date of its files; without it, the date of a file is the
creation date of the set, used for the signature freshness warnings.

## Trust

- The kiosk trusts the Ed25519 public keys (`*.pem`) of `signatures.keys`,
  `/usr/share/usb-pasteur/keys/` in the image: they are part of the root
  filesystem, protected by dm-verity and Secure Boot. The update key is
  separate from the image signing key: sets are signed far more often.
- The signature is verified with `openssl`, on the exact bytes of the
  manifest, before anything else of the set is read.
- A set is only installed when its serial is higher than the installed one:
  an older set, even validly signed, is refused (no rollback).
- Every file is copied with its size and SHA-256 checked against the
  manifest; files not listed are ignored; paths are plain names (no `..`,
  no hidden name) and links are never followed.
- The set is installed next to the current one, then a `current` link is
  switched atomically: an interrupted update changes nothing. The previous
  set is kept.
- At each start, the kiosk verifies the installed set again (signature, then
  every file) and refuses engine files that are not part of it
  (`signatures.verify`). Without a valid set, **it scans nothing**: it shows
  `NO VALID SIGNATURES` and only accepts a signature update device. A new
  kiosk therefore starts by asking for one.

ClamAV databases (`.cvd`) are also signed by Cisco Talos and verified by
clamd. clamd reads the `clamav` folder of the installed set
(`DatabaseDirectory`), and is restarted when it changes.

## Updating a kiosk

Copy a signed set into a `usb-pasteur-signatures` folder at the root of a
USB key (vfat, exFAT, NTFS or ext4) and insert it into the kiosk. The kiosk
verifies and installs the set, reloads its engines, then asks to remove the
key: a signature update device is never scanned, so do not use it to carry
other files.

The kiosk shows and logs the result (`signatures_installed`,
`signatures_refused` with the reason, or `signatures_not_newer`).

## Publishing a set

The `usb-pasteur-signatures` command builds, signs, verifies and installs
sets. Signing uses `openssl`, so that the private key can stay in a hardware
token (OpenSSL provider).

```sh
# Signature files in a folder, with the layout above
usb-pasteur-signatures build FOLDER --key update.key   # manifest.json + signature
usb-pasteur-signatures verify FOLDER --keys KEYS_FOLDER
cp -r FOLDER /media/KEY/usb-pasteur-signatures
```

`build` numbers the set with its creation date (`YYYYMMDDHHMMSS`) unless
`--serial` is given. `install` installs a set by hand
(`--target /var/lib/usb-pasteur-signatures`).

The service that will download the sources (ClamAV, YARA Forge,
MalwareBazaar, Hashlookup), build and sign sets with the release key of the
project is a task of phase 2. Until then, sets are built by hand, for
instance from `scripts/fetch-dev-signatures.py` and the ClamAV databases of
`freshclam`.

## Development keys

`image/build.sh` generates a development key pair, `image/update.key` and
`image/update.pem` (ignored by git), when they do not exist: the image trusts
`update.pem`, and the test image installs a set signed with `update.key`.
Never use them for a kiosk.

On a development computer, the signatures of
`scripts/fetch-dev-signatures.py` are not a signed set: set `verify = false`
in `[signatures]`.
