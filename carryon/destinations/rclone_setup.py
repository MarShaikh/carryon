"""Creating a Remote, and offering to create what it points at (ADR-0011).

carryon creates a **Remote** because that is a line in a config file
belonging to a tool the user already installed, and the credential passes
through without being kept - rclone stores it (obscuring the fields it
treats as passwords). It offers to create a **bucket**, and asks first,
because that is a billable resource in a region and under a name carryon
has no business choosing. It creates nothing else, and it never writes a
credential of its own.

Values reach `rclone config create` on argv, where `ps` can see them for
the life of the call. That is the constraint keyring.py already documents
for macOS's security(1): the exposure is same-uid, and anyone able to read
it can read rclone.conf itself, so it is recorded rather than worked
around.

The argv is fixed: verb, name, type, key=value pairs, one flag. Nothing
user-typed may become a flag, which is why a name or value with a leading
dash is refused here rather than escaped - rclone has no `--` convention
for `config create`'s positional arguments, so refusal is the only spelling
that cannot be misread.

What `rclone mkdir remote:bucket` does was verified against rclone's own
backends rather than guessed: on s3 it calls CreateBucket (with the
configured ACL and location constraint), on gcs it creates the bucket and
refuses without a project number, on b2 it posts b2_create_bucket. On sftp
it makes a directory. So `make_place` is exactly the "create the bucket"
step, and its caller asks the user before running it.
"""

from __future__ import annotations

import shutil
import subprocess

from .base import printable


def _rclone() -> str:
    rclone = shutil.which("rclone")
    if not rclone:
        raise SystemExit(
            "rclone not found on PATH - install it (https://rclone.org) "
            "or choose a directory or git Destination")
    return rclone


def _run(*args) -> subprocess.CompletedProcess:
    """rclone on a fixed argv, decoded the way the transport decodes it:
    what rclone prints is the remote's string, never the locale's."""
    return subprocess.run([_rclone()] + list(args), capture_output=True,
                          text=True, encoding="utf-8",
                          errors="surrogateescape")


def _tail(stderr: str, lines: int = 3) -> str:
    return "\n".join(printable(line)
                     for line in (stderr or "").strip().splitlines()[-lines:])


def existing_remotes() -> list:
    """The remotes rclone will answer for, without their trailing colons.

    From `rclone listremotes` rather than from parsing a config file:
    rclone resolves where its config lives (RCLONE_CONFIG, XDG, a legacy
    path), and asking it is the one spelling that cannot disagree with it.
    A listremotes that fails reads as no remotes - the create below then
    speaks to the same broken rclone and its refusal names the real reason.
    """
    result = _run("listremotes")
    if result.returncode != 0:
        return []
    return [line.strip().rstrip(":")
            for line in result.stdout.splitlines() if line.strip()]


def create_remote(name: str, rclone_type: str, pairs) -> None:
    """`rclone config create NAME TYPE key=value ...`, or SystemExit.

    Refuses a name rclone already has: `config create` over an existing
    name UPDATES it, and a Remote belongs to rclone and the user - carryon
    may create one and never rewrite one it did not just make.
    """
    if name.startswith("-") or rclone_type.startswith("-"):
        raise SystemExit(
            f"remote name {printable(name)!r}: a name starting with '-' "
            "would reach rclone as a flag, and the argv here is fixed on "
            "purpose. Pick another name.")
    if any("\x00" in part for pair in pairs for part in pair) \
            or "\x00" in name or "\x00" in rclone_type:
        # Named by position, never by value: one of these parts is a secret,
        # and a refusal that echoes it has published it. subprocess would
        # answer the NUL with a ValueError whose text differs between the
        # two interpreters carryon must pass (cli.py's door says the same).
        raise SystemExit(
            "one of the values for the remote holds a NUL, which no config "
            "and no argv will take - run init again and retype it")
    if name in existing_remotes():
        raise SystemExit(
            f"rclone already has a remote named {printable(name)!r} - "
            "carryon creates a Remote and never rewrites one. Pick another "
            "name, or point --dest at the existing one: "
            f"rclone:{printable(name)}:BUCKET")
    args = ["config", "create", name, rclone_type]
    args += [f"{key}={value}" for key, value in pairs]
    args += ["--non-interactive"]
    result = _run(*args)
    if result.returncode != 0:
        raise SystemExit(
            f"rclone would not create the remote {printable(name)!r}:\n"
            + (_tail(result.stderr) or f"exit {result.returncode}")
            + "\nNothing was set up on this machine.")


def make_place(target: str, flags=()):
    """None if `rclone mkdir target` succeeded, else the sentence why not.

    A sentence rather than a raise because the caller has already asked the
    user and owes them the outcome either way: a bucket that could not be
    made is a reason to stop and say so, and the saying is the caller's.

    `flags` come off the Provider table, not from any answer: the S3-family
    Remotes are created with `no_check_bucket=true` so no ordinary write can
    conjure a bucket (providers.py says why), and this one call - the
    offered creation the user just said yes to - is where the table switches
    the check back on.
    """
    if target.startswith("-"):
        return f"{printable(target)!r} would reach rclone as a flag"
    if "\x00" in target:
        return "the name holds a NUL, which no argv will take"
    result = _run("mkdir", target, *flags)
    if result.returncode != 0:
        return (_tail(result.stderr)
                or f"rclone mkdir exited {result.returncode}")
    return None
