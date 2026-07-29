"""Encryption, so a bundle can cross a network you do not control.

The carryon bundle does not need this - it holds no credentials. An entangle
chat bundle does: transcripts are unredacted and record everything printed to
a terminal. Encrypting one is what makes object storage an option at all,
rather than USB being the only safe route.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import crypto  # noqa: E402

PASSPHRASE = "correct horse battery staple"


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


def test_wrong_passphrase_fails_and_leaves_no_output(tmp_path):
    src = tmp_path / "bundle.bin"
    src.write_bytes(b"payload" * 100)
    enc = tmp_path / "bundle.enc"
    crypto.encrypt(src, enc, PASSPHRASE)

    out = tmp_path / "wrong.bin"
    try:
        crypto.decrypt(enc, out, "not the passphrase")
    except crypto.CryptoError:
        pass
    else:
        raise AssertionError("decrypt accepted the wrong passphrase")

    assert not out.exists(), "a failed decrypt must not leave a partial file"


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
