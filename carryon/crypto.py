"""Envelope encryption for the Archive, and passphrase encryption for files.

Shells out to openssl rather than taking a Python dependency: openssl ships on
macOS and every Linux distribution, and this tool's whole point is running on a
machine that has nothing installed yet.

The one non-obvious decision (ADR-0003): iteration count depends on what the
passphrase is. A recovery passphrase or pairing code is low-entropy, so wrapping
the master key costs the full 600,000 PBKDF2 iterations. A blob under the master
key uses -iter 1, because the key is 256 random bits and iterations only exist
to slow brute-force of secrets weak enough to brute-force - this is what makes
encrypting thousands of Sessions per push affordable. Key material goes in on
stdin, never argv - arguments are visible in `ps` and land in shell history.

An Archive object is sealed rather than merely encrypted: AES-CBC is malleable
and says nothing about where its ciphertext was meant to live, and a Destination
is untrusted storage that may edit a blob or serve one object's bytes under
another object's key. So every object carries an HMAC over its own label, and
unseal checks it before openssl ever sees the ciphertext. The plaintext Setup
cannot be sealed without giving up ADR-0004, so it gets the MAC without the
encryption - setup_tag, under a key of its own. The wrapped pairing blob is
the one object with neither: it is guarded by the pairing code, not the master
key, and the machine reading it has no master key yet.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as hmac_mod
import pathlib
import secrets
import shutil
import subprocess
import tempfile
from typing import Tuple

CIPHER = "aes-256-cbc"
ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256, low-entropy path
BLOB_ITERATIONS = 1   # master key is 256 random bits; iterations buy nothing

RECOVERY_BYTES = 20             # 160 bits: exactly 32 base32 chars, no padding
MASTER_BYTES = 32               # what _derive_master produces, and all it is
MASTER_SALT = b"carryon.master.v1"

MAC_INFO = b"carryon.mac.v1"    # domain separator for the derived MAC key
NAME_INFO = b"carryon.name.v1"  # and for the key object names are HMACed under
SETUP_INFO = b"carryon.setup.v1"  # and for the plaintext Setup's manifest MAC
MAC_BYTES = 32                  # HMAC-SHA256, stored as the blob's prefix


class CryptoError(RuntimeError):
    pass


def build_args(mode: str, src: pathlib.Path, dst: pathlib.Path,
               iterations: int = ITERATIONS) -> list:
    """The openssl command line. Kept separate so a test can inspect it."""
    args = [
        "openssl", "enc", f"-{CIPHER}", "-pbkdf2", "-iter", str(iterations),
        "-salt", "-in", str(src), "-out", str(dst), "-pass", "stdin",
    ]
    if mode == "decrypt":
        args.insert(2, "-d")
    return args


def _run(mode: str, src: pathlib.Path, dst: pathlib.Path, passphrase: str,
         iterations: int = ITERATIONS) -> None:
    if not shutil.which("openssl"):
        raise CryptoError("openssl not found on PATH")
    if not src.is_file():
        raise CryptoError(f"no such file: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        build_args(mode, src, dst, iterations),
        input=passphrase + "\n",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # openssl leaves a partial or empty file behind on failure. Remove it,
        # so a failed decrypt cannot be mistaken for a successful one.
        dst.unlink(missing_ok=True)
        # openssl's own message is a C source path and an error code, which
        # tells the user nothing. The only failure that matters in practice
        # has one cause.
        if mode == "decrypt":
            raise CryptoError("wrong key or passphrase, or this was not "
                              "encrypted by carryon")
        detail = (result.stderr or "").strip().splitlines()
        raise CryptoError(detail[-1] if detail else
                          f"openssl exited {result.returncode}")


def encrypt(src: pathlib.Path, dst: pathlib.Path, passphrase: str) -> None:
    _run("encrypt", src, dst, passphrase)


def decrypt(src: pathlib.Path, dst: pathlib.Path, passphrase: str) -> None:
    _run("decrypt", src, dst, passphrase)


# --- recovery key ---


def new_recovery_key() -> Tuple[str, bytes]:
    """Generate the trust root (ADR-0004): a display string for the user's
    password manager, and the 32-byte master key derived from it."""
    raw = secrets.token_bytes(RECOVERY_BYTES)
    b32 = base64.b32encode(raw).decode("ascii")
    display = "-".join(b32[i:i + 4] for i in range(0, len(b32), 4))
    return display, _derive_master(raw)


def parse_recovery_key(text: str) -> bytes:
    """The master key from a typed recovery key. Tolerant of case, spacing and
    hyphens, because this gets typed by hand from a password manager."""
    compact = "".join(text.split()).replace("-", "").upper()
    if len(compact) != 32:
        raise CryptoError(
            f"a recovery key has 32 characters (8 groups of 4); "
            f"got {len(compact)}")
    try:
        raw = base64.b32decode(compact)
    except binascii.Error:
        raise CryptoError(
            "not a valid recovery key: only letters A-Z and digits 2-7 appear "
            "in one (0, 1, 8 and 9 never do)")
    return _derive_master(raw)


def _derive_master(recovery_bytes: bytes) -> bytes:
    # One iteration: the recovery key is already high-entropy, so this is a
    # fixed derivation, not a stretch.
    return hashlib.pbkdf2_hmac("sha256", recovery_bytes, MASTER_SALT, 1, 32)


# --- blobs under the master key ---


def _run_bytes(mode: str, data: bytes, passphrase: str,
               iterations: int) -> bytes:
    """Round-trip bytes through the file pipeline via a private 0700 tmpdir.

    openssl only speaks files; the tmpdir keeps the plaintext's time on disk
    short and unreadable by other users, and is removed even on failure - which
    also disposes of any partial output.
    """
    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="carryon-"))  # mode 0700
    try:
        src = tmpdir / "in"
        dst = tmpdir / "out"
        src.write_bytes(data)
        _run(mode, src, dst, passphrase, iterations)
        return dst.read_bytes()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _master_pass(master_key: bytes) -> str:
    return base64.b64encode(master_key).decode("ascii")


def _mac_key(master_key: bytes) -> bytes:
    """A separate key for authentication.

    Derived rather than reused so the same 32 bytes never both encrypt and
    authenticate: one key, one job, and a flaw in either use cannot be
    levered against the other.
    """
    return hmac_mod.new(master_key, MAC_INFO, hashlib.sha256).digest()


def _tag(master_key: bytes, label: str, ciphertext: bytes) -> bytes:
    # The NUL separates label from ciphertext so no label can be extended
    # into the ciphertext and produce another object's tag.
    return hmac_mod.new(_mac_key(master_key),
                        label.encode("utf-8") + b"\0" + ciphertext,
                        hashlib.sha256).digest()


def seal(data: bytes, master_key: bytes, label: str) -> bytes:
    """One Archive object: encrypt-then-MAC, bound to what the object IS.

    `label` is the object's logical identity - a Session's uuid, a project's
    cwd, the Index - not its storage key, so a Destination that serves one
    object's ciphertext under another object's key fails the MAC rather than
    decrypting into the wrong place.
    """
    ciphertext = _run_bytes("encrypt", data, _master_pass(master_key),
                            BLOB_ITERATIONS)
    return _tag(master_key, label, ciphertext) + ciphertext


def unseal(blob: bytes, master_key: bytes, label: str) -> bytes:
    """The plaintext of a sealed object, or CryptoError.

    Authentication happens first and in constant time: AES-CBC is malleable,
    so a flipped byte in an untrusted blob otherwise decrypts to plaintext
    the attacker chose part of.
    """
    if len(blob) < MAC_BYTES:
        raise CryptoError(
            f"the stored object for {label!r} is too short to be a carryon "
            "object - it carries no authentication tag at all")
    tag, ciphertext = blob[:MAC_BYTES], blob[MAC_BYTES:]
    if not hmac_mod.compare_digest(tag, _tag(master_key, label, ciphertext)):
        raise CryptoError(
            f"the stored object for {label!r} does not authenticate: it was "
            "modified, or served in place of another object. A Destination "
            "is untrusted storage - this is the check that says so.")
    return _run_bytes("decrypt", ciphertext, _master_pass(master_key),
                      BLOB_ITERATIONS)


# --- authenticating the plaintext Setup ---


def _setup_key(master_key: bytes) -> bytes:
    """A third derived key, for the Setup's manifest MAC.

    The Setup is the Archive's one plaintext half (ADR-0004), so it cannot be
    sealed - but its content is executable (settings.json hooks, skills), so
    it cannot go unauthenticated either. Same derivation as _mac_key, own
    domain separator: the key that authenticates encrypted objects and the
    key that authenticates the plaintext Setup are never the same 32 bytes
    doing two jobs.
    """
    return hmac_mod.new(master_key, SETUP_INFO, hashlib.sha256).digest()


def setup_tag(master_key: bytes, label: str, payload: bytes) -> bytes:
    """The MAC over a Setup manifest, bound to which machine's Setup it is.

    The NUL separates label from payload for the reason _tag's does: no
    label may extend into the payload and produce another Setup's tag.
    """
    return hmac_mod.new(_setup_key(master_key),
                        label.encode("utf-8") + b"\0" + payload,
                        hashlib.sha256).digest()


def setup_tag_ok(master_key: bytes, label: str, payload: bytes,
                 tag: bytes) -> bool:
    """Constant-time, like unseal's check: the tag came off untrusted
    storage, and a comparison that leaks where it diverges helps forge one."""
    return hmac_mod.compare_digest(tag, setup_tag(master_key, label, payload))


def new_stamp() -> str:
    """A value one push writes into two places, so the two can be checked
    against each other later.

    The Setup's tag proves a key holder wrote a tree; it says nothing about
    WHICH tree they meant last, so every superseded tree a Destination kept
    still verifies. The push therefore stamps the tag and the encrypted Index
    entry with the same fresh value, and the pull requires them to agree.

    Random rather than a timestamp or a counter: a timestamp is only as fine
    as the clock it is read from - two pushes in one second stamp the same
    string, and the second-granularity one carryon records is exactly that
    case - and a counter has to be read from somewhere the attacker chooses
    what to serve. 128 bits from the OS collide with nothing, including with
    an Archive rolled back to a state some other machine wrote.
    """
    return secrets.token_hex(16)


# --- wrapping the master key under a low-entropy secret ---


def wrap_key(master_key: bytes, secret: str) -> bytes:
    """Encrypt the master key under a pairing code or recovery passphrase."""
    return _run_bytes("encrypt", master_key, secret, ITERATIONS)


def unwrap_key(blob: bytes, secret: str) -> bytes:
    return _run_bytes("decrypt", blob, secret, ITERATIONS)


# --- object naming ---


def _name_key(master_key: bytes) -> bytes:
    """A separate key again, for naming.

    Without this, hmac_name(master, MAC_INFO.decode()) was byte-for-byte the
    first 20 bytes of _mac_key's output - object names and the MAC key were
    the same function of the master key. No label reachable today is that
    string, but "one key, one job" has to hold at the derivation, not by
    happy accident about what the labels look like.
    """
    return hmac_mod.new(master_key, NAME_INFO, hashlib.sha256).digest()


def hmac_name(master_key: bytes, label: str) -> str:
    """An Archive object name: the Destination learns sizes and counts, never
    Session UUIDs."""
    return hmac_mod.new(_name_key(master_key), label.encode("utf-8"),
                        hashlib.sha256).hexdigest()[:40]
