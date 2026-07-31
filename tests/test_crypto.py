"""Encryption, file-level and envelope.

The file-level API is what the CLI's encrypt/decrypt commands use and must not
change. The envelope API (ADR-0003) exists because per-file PBKDF2 at 600,000
iterations is unaffordable across thousands of Sessions: the recovery key
derives a master key once, and each blob is encrypted under it at -iter 1.
These tests inspect the constructed openssl commands directly, because the two
properties that matter most - no key material in argv, the right iteration
count on each path - are invisible in a round-trip.

An Archive object is sealed rather than encrypted: the ciphertext alone says
nothing about which object it is, and a Destination gets to choose what it
serves from any key. So seal/unseal are tested on the label as much as on the
bytes - a blob that will not open under another object's label is the property,
not an implementation detail.
"""

import base64
import hashlib
import hmac
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import crypto  # noqa: E402

PASSPHRASE = "correct horse battery staple"
LABEL = "session:6b3c1c2e-9a71-4f0e-8f2d-4a5b6c7d8e9f"
OTHER_LABEL = "session:0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


# --- existing file-level API: these must keep passing unchanged ---


def test_round_trip_returns_the_original_bytes(tmp_path):
    src = tmp_path / "bundle.tar.gz"
    original = bytes(range(256)) * 40          # binary, not text
    src.write_bytes(original)

    enc = tmp_path / "bundle.tar.gz.enc"
    crypto.encrypt(src, enc, PASSPHRASE)
    assert enc.exists()
    assert enc.read_bytes() != original

    back = tmp_path / "restored.tar.gz"
    crypto.decrypt(enc, back, PASSPHRASE)
    assert back.read_bytes() == original


def test_ciphertext_does_not_contain_the_plaintext(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sk-ant-api03-NOTAREALKEYNOTAREALKEY")
    enc = tmp_path / "secret.enc"
    crypto.encrypt(src, enc, PASSPHRASE)

    assert b"sk-ant" not in enc.read_bytes()


def test_wrong_passphrase_never_yields_the_plaintext(tmp_path):
    """The property is what comes out, not what openssl exits with.

    This file format carries no authentication tag, so a wrong passphrase
    leaves PKCS#7 padding that validates by luck about once in 256 - measured
    at 0.40% over 3000 trials - and openssl exits 0 over garbage. Demanding
    the exception made this test fail one run in 250 for no reason. Both
    outcomes are asserted on their own terms: a rejection must clean up after
    itself, and an accepted wrong passphrase must still not produce the
    plaintext.
    """
    src = tmp_path / "bundle.bin"
    src.write_bytes(b"payload" * 100)
    enc = tmp_path / "bundle.enc"
    crypto.encrypt(src, enc, PASSPHRASE)

    out = tmp_path / "wrong.bin"
    try:
        crypto.decrypt(enc, out, "not the passphrase")
    except crypto.CryptoError:
        assert not out.exists(), \
            "a failed decrypt must not leave a partial file"
    else:
        assert out.read_bytes() != src.read_bytes(), \
            "the wrong passphrase reproduced the plaintext"


def test_passphrase_never_appears_in_the_argument_list():
    """Arguments are visible in `ps` and land in shell history."""
    args = crypto.build_args("encrypt", pathlib.Path("in"), pathlib.Path("out"))
    joined = " ".join(args)
    assert "correct horse" not in joined
    assert "-k" not in args, "-k puts the passphrase in argv"
    assert "-pass" in args and "stdin" in args


def test_encrypting_an_empty_file_still_round_trips(tmp_path):
    src = tmp_path / "empty"
    src.write_bytes(b"")
    enc = tmp_path / "empty.enc"
    back = tmp_path / "empty.back"

    crypto.encrypt(src, enc, PASSPHRASE)
    crypto.decrypt(enc, back, PASSPHRASE)
    assert back.read_bytes() == b""


# --- recovery key: generation, format, tolerant parsing ---


def test_new_recovery_key_format():
    recovery, master = crypto.new_recovery_key()
    # 20 random bytes are exactly 32 base32 characters: 8 groups of 4.
    assert re.fullmatch(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}", recovery)
    assert isinstance(master, bytes) and len(master) == 32


def test_new_recovery_keys_are_unique():
    a = crypto.new_recovery_key()
    b = crypto.new_recovery_key()
    assert a[0] != b[0]
    assert a[1] != b[1]


def test_parse_recovery_key_round_trips():
    recovery, master = crypto.new_recovery_key()
    assert crypto.parse_recovery_key(recovery) == master


def test_parse_recovery_key_tolerates_case_spacing_and_hyphens():
    recovery, master = crypto.new_recovery_key()
    assert crypto.parse_recovery_key(recovery.lower()) == master
    assert crypto.parse_recovery_key(recovery.replace("-", "")) == master
    assert crypto.parse_recovery_key(recovery.replace("-", " ")) == master
    assert crypto.parse_recovery_key("  " + recovery.lower().replace("-", "  ") + " ") == master


def test_parse_recovery_key_rejects_wrong_length():
    with pytest.raises(crypto.CryptoError) as exc:
        crypto.parse_recovery_key("ABCD-EFGH")
    assert "32" in str(exc.value), "the message should say what length is expected"


def test_parse_recovery_key_rejects_non_base32_characters():
    # 0, 1, 8, 9 are not in the base32 alphabet; a mistyped key must not
    # silently derive some other master key.
    bad = "0123-" * 7 + "0123"
    with pytest.raises(crypto.CryptoError):
        crypto.parse_recovery_key(bad)


# --- sealed objects under the master key ---


def test_seal_round_trips():
    _, master = crypto.new_recovery_key()
    data = bytes(range(256)) * 40
    blob = crypto.seal(data, master, LABEL)
    assert blob != data
    assert data not in blob
    assert crypto.unseal(blob, master, LABEL) == data


def test_seal_empty_input_round_trips():
    _, master = crypto.new_recovery_key()
    blob = crypto.seal(b"", master, LABEL)
    assert crypto.unseal(blob, master, LABEL) == b""


def test_unseal_with_the_wrong_key_raises():
    _, master = crypto.new_recovery_key()
    _, other = crypto.new_recovery_key()
    blob = crypto.seal(b"payload" * 100, master, LABEL)
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(blob, other, LABEL)


def test_unseal_under_another_label_raises():
    """The binding that makes a swapped blob fail instead of decrypting."""
    _, master = crypto.new_recovery_key()
    blob = crypto.seal(b"payload" * 100, master, LABEL)
    with pytest.raises(crypto.CryptoError) as exc:
        crypto.unseal(blob, master, OTHER_LABEL)
    assert "authenticate" in str(exc.value)
    assert OTHER_LABEL in str(exc.value), \
        "the message names the object that was asked for"


def test_a_modified_ciphertext_is_named_as_tampering_not_a_wrong_key():
    """AES-CBC is malleable: without the MAC a flipped byte in an early
    block decrypts into plaintext the attacker chose part of."""
    _, master = crypto.new_recovery_key()
    blob = bytearray(crypto.seal(b"A" * 512, master, LABEL))
    blob[crypto.MAC_BYTES + 24] ^= 0x01
    with pytest.raises(crypto.CryptoError) as exc:
        crypto.unseal(bytes(blob), master, LABEL)
    assert "modified" in str(exc.value)
    assert "passphrase" not in str(exc.value)


def test_the_tag_is_a_32_byte_prefix_over_label_and_ciphertext():
    _, master = crypto.new_recovery_key()
    blob = crypto.seal(b"payload", master, LABEL)
    assert crypto.MAC_BYTES == 32
    tag, ciphertext = blob[:crypto.MAC_BYTES], blob[crypto.MAC_BYTES:]

    mac_key = hmac.new(master, crypto.MAC_INFO, hashlib.sha256).digest()
    assert tag == hmac.new(mac_key,
                           LABEL.encode("utf-8") + b"\0" + ciphertext,
                           hashlib.sha256).digest()
    assert mac_key != master, "the MAC key is derived, never the master key"


def test_a_blob_too_short_to_hold_a_tag_is_refused():
    _, master = crypto.new_recovery_key()
    for blob in (b"", b"\x00", b"\x00" * (crypto.MAC_BYTES - 1)):
        with pytest.raises(crypto.CryptoError):
            crypto.unseal(blob, master, LABEL)


def test_blob_commands_use_iter_1_and_keep_key_out_of_argv(monkeypatch):
    """ADR-0003: one iteration is sound for a 256-bit random key, and the whole
    point of feeding it on stdin is that argv is visible in `ps`."""
    recorded = []
    real_run = crypto.subprocess.run

    def spy(args, **kwargs):
        recorded.append(list(args))
        return real_run(args, **kwargs)

    monkeypatch.setattr(crypto.subprocess, "run", spy)

    _, master = crypto.new_recovery_key()
    blob = crypto.seal(b"session tree bytes", master, LABEL)
    crypto.unseal(blob, master, LABEL)

    assert len(recorded) == 2
    key_b64 = base64.b64encode(master).decode()
    for args in recorded:
        assert args[args.index("-iter") + 1] == "1"
        joined = " ".join(args)
        assert key_b64 not in joined
        assert master.hex() not in joined
        assert "-k" not in args
        assert "-pass" in args and "stdin" in args


def test_blob_temp_files_do_not_outlive_the_call(monkeypatch, tmp_path):
    """Plaintext touches disk only inside a private tmpdir that is removed."""
    seen_dirs = []
    real_run = crypto.subprocess.run

    def spy(args, **kwargs):
        src = pathlib.Path(args[args.index("-in") + 1])
        seen_dirs.append(src.parent)
        assert src.parent.stat().st_mode & 0o777 == 0o700
        return real_run(args, **kwargs)

    monkeypatch.setattr(crypto.subprocess, "run", spy)

    _, master = crypto.new_recovery_key()
    blob = crypto.seal(b"private", master, LABEL)
    crypto.unseal(blob, master, LABEL)

    assert seen_dirs
    for d in seen_dirs:
        assert not d.exists(), "the tmpdir must be removed after the call"


# --- key wrapping: for the recovery passphrase path and pairing codes ---


def test_wrap_key_round_trips():
    _, master = crypto.new_recovery_key()
    blob = crypto.wrap_key(master, "ABCD-EFGH")
    assert master not in blob
    assert crypto.unwrap_key(blob, "ABCD-EFGH") == master


def test_unwrap_key_with_the_wrong_secret_never_yields_the_master_key():
    """A wrong pairing secret must not produce the key, however openssl exits.

    The wrapped blob is unauthenticated on purpose (ADR-0005: the joining
    machine has nothing to check a tag with), so the padding of a wrong
    passphrase validates by luck about once in 256 and openssl returns
    garbage with status 0. That is precisely why sync._pairing_payload
    proves a code opened a blob by parsing what came out of it, and why this
    asserts the same thing rather than the exit code.
    """
    _, master = crypto.new_recovery_key()
    blob = crypto.wrap_key(master, "ABCD-EFGH")
    try:
        opened = crypto.unwrap_key(blob, "WXYZ-2345")
    except crypto.CryptoError:
        return  # the ordinary outcome: openssl rejects the padding
    # compared as a digest so a failure cannot print the key it found
    assert not hmac.compare_digest(opened, master), \
        "the wrong secret unwrapped the master key"


def test_wrap_commands_use_600000_iterations_and_keep_secret_out_of_argv(monkeypatch):
    """A pairing code is low-entropy, so this path keeps the full PBKDF2 cost."""
    recorded = []
    real_run = crypto.subprocess.run

    def spy(args, **kwargs):
        recorded.append(list(args))
        return real_run(args, **kwargs)

    monkeypatch.setattr(crypto.subprocess, "run", spy)

    _, master = crypto.new_recovery_key()
    blob = crypto.wrap_key(master, "ABCD-EFGH")
    crypto.unwrap_key(blob, "ABCD-EFGH")

    assert len(recorded) == 2
    for args in recorded:
        assert args[args.index("-iter") + 1] == "600000"
        joined = " ".join(args)
        assert "ABCD-EFGH" not in joined
        assert "-k" not in args
        assert "-pass" in args and "stdin" in args


# --- object naming ---


def test_hmac_name_is_40_hex_chars_and_deterministic():
    _, master = crypto.new_recovery_key()
    name = crypto.hmac_name(master, "session:0000-uuid")
    assert re.fullmatch(r"[0-9a-f]{40}", name)
    assert crypto.hmac_name(master, "session:0000-uuid") == name


def test_hmac_name_varies_with_label_and_key():
    _, master = crypto.new_recovery_key()
    _, other = crypto.new_recovery_key()
    assert crypto.hmac_name(master, "a") != crypto.hmac_name(master, "b")
    assert crypto.hmac_name(master, "a") != crypto.hmac_name(other, "a")
