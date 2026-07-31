"""Pairing - the one-time code, its two halves, and the payload it wraps.

Giving a new machine the master key by way of a short code that travels
through the Destination rather than between the machines directly. The one
non-obvious thing: the code's two halves never do each other's job. The
Locator is published as a filename on untrusted storage and guards nothing;
the Pairing secret is the only part any key derivation ever sees, and is
never written anywhere the Destination can read. They are kept apart by type
here so neither can be passed where the other belongs.

A leaf over crypto and the stdlib: it knows what a pairing code and a pairing
payload are, and nothing about Destinations, Archives or commands. `pair` and
`init --join` are commands and stay in sync.py, which sequences them.
"""

from __future__ import annotations

import json
import math
import secrets as stdlib_secrets  # carryon.secrets is the scanner, not this
from typing import NamedTuple

from . import crypto

PAIRING_TTL_SECONDS = 24 * 3600


# A pairing code has two halves that never mix. Six characters name the
# object in the Archive and are not a secret; ten characters wrap the master
# key and are never written down anywhere. 32 unambiguous characters, 5 bits
# each: 30 bits of public locator, 50 bits behind PBKDF2 at 600,000
# iterations - roughly 1.3e21 SHA-256 compressions to search, about 2000
# GPU-years. The whole code used to be 40 bits AND its sha256 was the object
# name, which put the guard at 55 GPU-seconds.
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"  # no I, L, O or U
LOCATOR_CHARS = 6
SECRET_CHARS = 10
CODE_CHARS = LOCATOR_CHARS + SECRET_CHARS
CODE_DISPLAY = "-".join(["XXXX"] * (CODE_CHARS // 4))

# What a hurried reader turns into what: the alphabet omits these, so a code
# containing one was mistyped in a direction we can undo.
_AMBIGUOUS = {"I": "1", "L": "1", "O": "0"}


class PairingCode(NamedTuple):
    """The two halves, kept apart by type so neither can be used as the other.

    locator names the object on the Destination and is published there;
    secret is the only thing ever handed to the key-wrapping KDF.
    """
    locator: str
    secret: str


def _canon_code(code: str) -> str:
    stripped = "".join(code.split()).replace("-", "").upper()
    return "".join(_AMBIGUOUS.get(c, c) for c in stripped)


def parse_pairing_code(code: str) -> PairingCode:
    """A typed pairing code split into its locator and secret halves.

    Tolerant of case, hyphens, spacing and the characters people substitute
    for the ones the alphabet leaves out; strict about everything else, so a
    mangled code fails here with an explanation instead of reaching the
    Destination and failing as 'no pairing blob'."""
    canon = _canon_code(code)
    if len(canon) != CODE_CHARS or not set(canon) <= set(PAIR_ALPHABET):
        raise SystemExit(
            f"{code!r} is not a pairing code: {CODE_CHARS} characters shown "
            f"as {CODE_DISPLAY}, letters and digits only (I, L, O and U never "
            "appear - a typed I or L reads as 1, a typed O as 0)")
    return PairingCode(canon[:LOCATOR_CHARS], canon[LOCATOR_CHARS:])


def new_pairing_code() -> str:
    """A fresh code for display, in groups of four.

    Every character is drawn on its own, so the locator half carries no
    information about the secret half: an attacker reading the object's name
    off the Destination learns the six characters that name it and nothing
    that shortens the search for the other ten."""
    raw = "".join(stdlib_secrets.choice(PAIR_ALPHABET)
                  for _ in range(CODE_CHARS))
    return "-".join(raw[i:i + 4] for i in range(0, CODE_CHARS, 4))


def _pairing_payload(raw: bytes) -> dict:
    """A pairing payload, having proved it is one. SystemExit if it is not.

    The pairing blob is the one Archive object with no MAC - the machine
    reading it holds no master key yet - and AES-CBC is malleable, so a byte
    flipped anywhere but the last block leaves the PKCS#7 padding intact and
    openssl exits 0 over garbage. An exit code is therefore not proof the
    code opened the blob; a payload that parses and carries a 32-byte key is
    the strongest proof available, and it has to be had BEFORE the one-time
    delete, or tampering burns the code that would have worked.

    The message names a wrong code first because that is what usually lands
    here. Padding validates by luck for about one wrong code in 256, so this
    is the ordinary mistyped-code path often enough to matter, and the two
    causes are genuinely indistinguishable from inside: nothing carryon can
    check tells a wrong key from an edited blob when neither is authenticated.
    Reporting only the rarer one sent a user hunting for tampering that had
    not happened.

    Everything the caller will act on is proved here, before the one-time
    delete, and the creation time is part of that. It used to be read one
    line AFTER the delete with a bare float(), so a payload carrying no
    created_at, or one that is not a number, burnt the object and then raised
    ValueError or TypeError out of `carryon init --join` - the precise
    outcome the read/delete split exists to prevent, arrived at by the field
    the split does not cover. NaN is asked about too, and is the reason the
    test is 'finite' rather than 'a number': json.loads parses NaN happily, it
    survives float(), and it loses every comparison it takes part in, so
    `now - created_at > TTL` is False forever and a pairing code's 24-hour
    life quietly becomes unlimited.

    RecursionError joins the parse guard for the reason it joins every other
    one in carryon: json.loads answers nesting past the interpreter's limit
    with a RuntimeError, which a guard naming ValueError and UnicodeDecodeError
    walks straight past. Reaching it needs the pairing secret, so this is the
    same corruption-or-skew class as a damaged Archive object rather than an
    attack - and it takes the same named refusal.
    """
    tampered = SystemExit(
        "that pairing blob did not open into a pairing payload. Most likely "
        "it is a wrong or expired code that openssl happened not to reject: "
        "a pairing blob carries no authentication tag (the joining machine "
        "has no key to check one with), so roughly one wrong code in 256 "
        "gets this far. Failing that, the blob was tampered with or written "
        "by something other than carryon. It was left in place either way; "
        "mint a fresh code with `carryon pair`, and delete the old object if "
        "it stays broken.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise tampered
    if not isinstance(payload, dict):
        raise tampered
    try:
        master = bytes.fromhex(payload["master"])
    except (KeyError, TypeError, ValueError):
        raise tampered
    if len(master) != crypto.MASTER_BYTES:
        raise tampered
    payload["master_key"] = master
    created = payload.get("created_at")
    if (isinstance(created, bool) or not isinstance(created, (int, float))
            or not math.isfinite(created)):
        raise tampered
    payload["created_at"] = float(created)
    # The revision the pairing machine read, if this payload carries one.
    # Absent or nonsensical reads as 'nothing known about this Archive'
    # rather than a refusal: a pairing's job is to hand over the key, and a
    # payload written by a carryon that predates the field is not a reason to
    # leave a machine unable to join. What it costs is the freshness the
    # joining machine would otherwise start with - see pair().
    revision = payload.get("index_revision", 0)
    if (isinstance(revision, bool) or not isinstance(revision, int)
            or revision < 0):
        revision = 0
    payload["index_revision"] = revision
    return payload
