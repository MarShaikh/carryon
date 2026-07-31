"""Pairing hardening (ADR-0004, ADR-0005), at the function level.

Pairing hands a new machine the master key through the Destination, guarded
only by a short one-time code - so the edges are where the security lives:
code format, expiry, a typo, a replay, a Destination that is not there. Each
edge gets one test through the public functions, against a directory
Destination and fake homes. The one behaviour worth calling out: a blob that
will not unwrap must be left in place, because deleting on a failed unwrap
would let a typo burn the one code that works - and with the code split into
a locator that names the object and a secret that wraps the key, a typo in
the secret half now lands on the real object every time.

Every home is a temp dir; the OS keychain is forced to the fallback file so
nothing here touches the real keyring, and nothing reads the real ~/.claude.
"""

import argparse
import json
import pathlib
import re
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, crypto, keyring, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

CODE_SHAPE = r"[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}"
PAIR_CODE = re.compile(r"--join (" + CODE_SHAPE + ")")
A_CODE = "ABCD-EFGH-JKMN-PQRS"  # a well-formed code, no Destination behind it


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def paired_machine(tmp_path):
    """A home that already opens an Archive at a directory Destination."""
    home = tmp_path / "home_a"
    home.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    return home, dest_spec


def mint(home, capsys) -> str:
    sync.pair(ns(), home)
    return PAIR_CODE.search(capsys.readouterr().out).group(1)


def fresh_home(tmp_path, name) -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    return home


# --- code shape --------------------------------------------------------------


def test_codes_are_sixteen_unambiguous_chars_shown_grouped():
    for _ in range(64):
        code = sync.new_pairing_code()
        assert re.fullmatch(CODE_SHAPE, code), \
            "16 characters as XXXX-XXXX-XXXX-XXXX, always"
        assert set(code.replace("-", "")) <= set(sync.PAIR_ALPHABET)
        assert not set("ILOU") & set(code), \
            "the alphabet leaves out the characters people misread"


def test_a_code_splits_into_a_public_locator_and_a_secret():
    """Six characters name the object, ten wrap the key, and the display
    form is just the two concatenated."""
    code = sync.new_pairing_code()
    locator, secret = sync.parse_pairing_code(code)
    assert locator + secret == code.replace("-", "")
    assert len(locator) == 6 and len(secret) == 10


def test_parsing_tolerates_case_hyphens_and_spacing():
    for typed in ("ABCD-EFGH-JKMN-PQRS", "abcd-efgh-jkmn-pqrs",
                  "ABCDEFGHJKMNPQRS", "abcd efgh jkmn pqrs",
                  " ab cd-EF gh-JKMN-pqrs "):
        assert sync.parse_pairing_code(typed) == ("ABCDEF", "GHJKMNPQRS")


def test_parsing_forgives_the_characters_the_alphabet_leaves_out():
    """I and L are read as 1 and O as 0, because that is the direction a
    hurried reader mistypes them - the alphabet emits none of the three."""
    assert sync.parse_pairing_code("A1CD-EFGH-JKMN-PQR0") == \
        sync.parse_pairing_code("AlCD-EFGH-JKMN-PQRO")
    assert sync.parse_pairing_code("AICD-EFGH-JKMN-PQRO") == \
        ("A1CDEF", "GHJKMNPQR0")


def test_a_malformed_code_fails_before_the_destination_is_touched(tmp_path):
    """Wrong length or a character the alphabet never emits is caught
    locally - the Destination pointed at here does not even exist."""
    home = fresh_home(tmp_path, "home_b")
    nowhere = str(tmp_path / "nowhere")
    for bad in ("ABCD-EFGH", "ABCD-EFGH-JKMN-PQR", "ABCD-EFGH-JKMN-PQRST",
                "ABCD-EFGH-JKMN-PQR!", "-- --"):
        with pytest.raises(SystemExit) as exc:
            sync.init(ns(join=bad, dest=nowhere), home)
        message = str(exc.value)
        assert "pairing code" in message
        assert "XXXX-XXXX-XXXX-XXXX" in message, \
            "the message teaches the shape"


def test_join_accepts_a_mangled_but_correct_code(tmp_path, capsys):
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)

    home_b = fresh_home(tmp_path, "home_b")
    mangled = code.replace("-", "").lower()
    assert sync.init(ns(dest=dest_spec, join=mangled, machine="machine-b"),
                     home_b) == 0
    assert keyring.fetch_master(home=home_b) == \
        keyring.fetch_master(home=home_a)


# --- expiry ------------------------------------------------------------------


def test_an_expired_code_is_rejected_and_still_deleted(tmp_path, capsys,
                                                       monkeypatch):
    """created_at lives inside the wrapped payload, so the take side can
    enforce the 24h - and an expired blob is burnt, not left to rot."""
    home_a, dest_spec = paired_machine(tmp_path)
    code = mint(home_a, capsys)

    real_now = time.time()
    monkeypatch.setattr(sync.time, "time",
                        lambda: real_now + sync.PAIRING_TTL_SECONDS + 60)
    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert "expired" in str(exc.value)
    assert "24" in str(exc.value), "the message states the lifetime"
    assert keyring.fetch_master(home=home_b) is None, \
        "an expired code hands over nothing"
    dest = DirectoryDestination(tmp_path / "archive")
    assert dest.list(archive.PAIR_PREFIX) == [], \
        "the expired blob is deleted even though the join failed"


# --- a wrong code ------------------------------------------------------------


def test_a_code_that_will_not_unwrap_does_not_burn_the_blob(tmp_path):
    """However a code comes to name a blob it cannot unwrap - a mistyped
    secret half, a damaged blob - the failure must leave the object in
    place: deleting here would let a typo cost the user the code that
    works."""
    code = sync.parse_pairing_code(sync.new_pairing_code())
    other = sync.parse_pairing_code(sync.new_pairing_code())

    dest_root = tmp_path / "archive"
    dest = DirectoryDestination(dest_root)
    payload = json.dumps({"master": "00" * 32,
                          "created_at": time.time()}).encode("utf-8")
    # wrapped under a *different* secret than the one that will be typed
    archive.put_pairing(dest, code.locator,
                        crypto.wrap_key(payload, other.secret))

    home_b = fresh_home(tmp_path, "home_b")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=str(dest_root), join=code.locator + code.secret,
                     machine="machine-b"), home_b)

    assert "wrong or expired code" in str(exc.value)
    assert dest.read(archive.pairing_key(code.locator)) is not None, \
        "a failed unwrap leaves the blob for the right code to claim"
    assert keyring.fetch_master(home=home_b) is None


# --- a used code -------------------------------------------------------------


def test_a_used_code_gets_a_clear_message_the_second_time(tmp_path, capsys):
    home_a, dest_spec = paired_machine(tmp_path)
    used = mint(home_a, capsys)
    mint(home_a, capsys)  # a second outstanding code keeps the Archive alive

    home_b = fresh_home(tmp_path, "home_b")
    assert sync.init(ns(dest=dest_spec, join=used, machine="machine-b"),
                     home_b) == 0

    home_c = fresh_home(tmp_path, "home_c")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=used, machine="machine-c"), home_c)

    assert "already used" in str(exc.value)
    assert "carryon pair" in str(exc.value), \
        "the message says how to get a fresh code"
    assert keyring.fetch_master(home=home_c) is None
    dest = DirectoryDestination(tmp_path / "archive")
    assert len(dest.list(archive.PAIR_PREFIX)) == 1, \
        "the unused code's blob is untouched by the failed replay"


# --- an unreachable Destination ----------------------------------------------


def test_join_against_nothing_names_the_spec_it_tried(tmp_path):
    home_b = fresh_home(tmp_path, "home_b")
    nowhere = str(tmp_path / "nowhere")
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=nowhere, join=A_CODE, machine="machine-b"),
                  home_b)
    message = str(exc.value)
    assert nowhere in message, "the message names the spec it tried"
    assert "no pairing blob" not in message, \
        "an absent Destination is not reported as a mistyped code"
    assert keyring.fetch_master(home=home_b) is None
