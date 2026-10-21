#!/usr/bin/env python3
"""Seal an Archive under one openssl and open it under another.

    interop.py seal <dir> <expect>   push and pair from a fresh home into <dir>
    interop.py open <dir> <expect>   join with <dir>'s code, pull, check it all

<expect> is "LibreSSL" or "OpenSSL 3": the openssl this machine must be
running, so a runner image that puts a different one first on PATH fails here
instead of quietly comparing a library with itself.

carryon seals through the `openssl` command line, and macOS ships LibreSSL as
`openssl` while Linux ships OpenSSL 3. Every test in the suite seals and opens
on the same machine, so nothing in it can show the two agree. This drives the
real journey across them: the pairing blob (wrapped under the code, 600,000
iterations), the sealed Setup and a sealed Session (each under the master key,
one iteration, behind its HMAC tag), and the Index that names them. A pull
that lands every file with the right bytes is the proof; anything less fails
naming both openssls in the order the bytes travelled.
"""

import argparse
import contextlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import keyring, rekey, sync  # noqa: E402

SESSION = "11111111-1111-4111-8111-111111111111"
PROJECT = "code/app"
SETTINGS = '{"model": "opus"}'
INSTRUCTIONS = "Answer briefly.\n"
PAIR_CODE = re.compile(r"--join (\S+)")

# The fallback key file in the throwaway home, never a runner's keychain.
keyring._backend = lambda platform=None: "file"


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def openssl_version(expect: str) -> str:
    version = subprocess.run(["openssl", "version"], capture_output=True,
                             text=True, check=True).stdout.strip()
    if not version.startswith(expect):
        sys.exit(f"interop: expected {expect} as openssl, found {version}")
    return f"{version} on {sys.platform}"


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def run(step, fn, args, home, want=0) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(args, home)
    if code != want:
        raise RuntimeError(f"{step} exited {code}:\n{out.getvalue()}")
    return out.getvalue()


def seal(where: pathlib.Path, version: str) -> None:
    home = pathlib.Path(tempfile.mkdtemp()) / "home_a"
    cwd = str(home / PROJECT)
    claude = home / ".claude"
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (claude / "settings.json").write_text(SETTINGS)
    (claude / "CLAUDE.md").write_text(INSTRUCTIONS)
    (project / (SESSION + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "text": f"edit {cwd}/main.py"}))

    archive = where / "archive"
    run("init", sync.init, ns(dest=str(archive), machine="sealer"), home)
    run("push", sync.push, ns(apply=True), home)
    code = PAIR_CODE.search(run("pair", sync.pair, ns(), home)).group(1)
    (where / "code").write_text(code)
    (where / "sealed-by").write_text(version)


def unseal(where: pathlib.Path, version: str) -> None:
    home = pathlib.Path(tempfile.mkdtemp()) / "home_b"
    home.mkdir()
    code = (where / "code").read_text()
    run("join (the pairing exchange)", sync.init,
        ns(dest=str(where / "archive"), join=code, machine="opener"), home)
    run("pull (the sealed Setup and History)", sync.pull, ns(apply=True), home)

    cwd = str(home / PROJECT)
    session = (home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
               / (SESSION + ".jsonl"))
    checks = {
        "Setup settings.json": lambda: (
            (home / ".claude" / "settings.json").read_text() == SETTINGS),
        "Setup CLAUDE.md": lambda: (
            (home / ".claude" / "CLAUDE.md").read_text() == INSTRUCTIONS),
        "History Session": lambda: (
            json.loads(session.read_text().splitlines()[1])["text"]
            == f"edit {cwd}/main.py"),
    }
    for name, check in checks.items():
        try:
            ok = check()
        except (OSError, ValueError, IndexError, KeyError):
            ok = False
        if not ok:
            raise RuntimeError(f"{name} did not land as sealed")


def main(argv) -> int:
    if len(argv) != 4 or argv[1] not in ("seal", "open"):
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    mode, where, version = argv[1], pathlib.Path(argv[2]).resolve(), \
        openssl_version(argv[3])
    if mode == "seal":
        where.mkdir(parents=True, exist_ok=True)
        seal(where, version)
        print(f"sealed with {version}")
        return 0

    direction = f"{(where / 'sealed-by').read_text()} -> {version}"
    try:
        unseal(where, version)
    except Exception as exc:  # any failure here is the finding
        print(f"interop FAILED, {direction}: {type(exc).__name__}: {exc}")
        return 1
    print(f"interop ok, {direction}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
