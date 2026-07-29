"""Passphrase encryption for a bundle that has to cross a network.

Shells out to openssl rather than taking a Python dependency: openssl ships on
macOS and every Linux distribution, and this tool's whole point is running on a
machine that has nothing installed yet.

AES-256-CBC with PBKDF2 and a random salt. The passphrase goes in on stdin,
never as an argument - arguments are visible in `ps` and land in shell history.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

CIPHER = "aes-256-cbc"
ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256


class CryptoError(RuntimeError):
    pass


def build_args(mode: str, src: pathlib.Path, dst: pathlib.Path) -> list:
    """The openssl command line. Kept separate so a test can inspect it."""
    args = [
        "openssl", "enc", f"-{CIPHER}", "-pbkdf2", "-iter", str(ITERATIONS),
        "-salt", "-in", str(src), "-out", str(dst), "-pass", "stdin",
    ]
    if mode == "decrypt":
        args.insert(2, "-d")
    return args


def _run(mode: str, src: pathlib.Path, dst: pathlib.Path, passphrase: str) -> None:
    if not shutil.which("openssl"):
        raise CryptoError("openssl not found on PATH")
    if not src.is_file():
        raise CryptoError(f"no such file: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        build_args(mode, src, dst),
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
            raise CryptoError("wrong passphrase, or the file is not a carryon "
                              "encrypted bundle")
        detail = (result.stderr or "").strip().splitlines()
        raise CryptoError(detail[-1] if detail else
                          f"openssl exited {result.returncode}")


def encrypt(src: pathlib.Path, dst: pathlib.Path, passphrase: str) -> None:
    _run("encrypt", src, dst, passphrase)


def decrypt(src: pathlib.Path, dst: pathlib.Path, passphrase: str) -> None:
    _run("decrypt", src, dst, passphrase)
