"""Destination registry: one module per type, as adapters/ is one per agent.

from_spec turns the one string a user configures into a working Destination;
detect_candidates looks around a machine for places an Archive could live -
synced folders that already exist, git if it could already authenticate,
rclone remotes already configured. Detection borrows the user's existing
access and carryon stores no credentials of its own for any of them.

The non-obvious decision in parsing: git indicators win over the directory
rule, so '/backups/archive.git' is a local *bare repo to push to*, not a
directory to write files into - pointing the directory type at a bare repo
would fill it with loose files git does not track.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

from .base import Destination
from .directory import DirectoryDestination
from .git_repo import GitDestination, git_env
from .rclone_remote import RcloneDestination

SPEC_FORMS = ("a path ('/...', '~/...', 'dir:PATH'), a git remote "
              "('git:URL', 'git@...', 'ssh://...', '...*.git'), or "
              "'rclone:remote:path'")

# (path under $HOME, human label) - each is a folder some sync client owns
SYNCED_FOLDERS = (
    ("Library/Mobile Documents/com~apple~CloudDocs", "iCloud Drive"),
    ("Dropbox", "Dropbox"),
    ("Google Drive", "Google Drive"),
    ("OneDrive", "OneDrive"),
    ("Sync", "Sync (Syncthing)"),
)


def _expand(path: str, home: pathlib.Path):
    """'~' against the given home, never the real one - tests hand in fakes.

    lstrip on the remainder, because `Path('/home/me') / '/etc'` is '/etc': a
    spec of '~//etc' expanded to somewhere outside the home it names, and
    every later push targeted it. `cli._expanded` lstrips for that exact
    reason, two modules over and inside the same command - two doors in one
    package normalising '~' differently is the shape ADR-0010 is about, and a
    '~' is easier to spell twice than a check is.
    """
    if path == "~":
        return home
    if path.startswith("~/"):
        return home / path[2:].lstrip("/")
    return pathlib.Path(path)


def _directory_root(text: str, spec: str, home: pathlib.Path) -> pathlib.Path:
    """Where a directory Destination lives, or SystemExit.

    A Destination root has to be one place, and a RELATIVE path is not one:
    `Path('')` and `Path('.')` both mean the process working directory, so
    `--dest 'dir:'` stored a spec that expanded to wherever the command
    happened to run. `push --apply` then wrote carryon/index.enc and a
    plaintext carryon/setups/<machine>/ tree into that directory, at exit 0,
    and the Archive followed the user between projects - present in two of
    them and complete in neither.

    `--dest '.'` was already refused, by the bare spec falling through to the
    SPEC_FORMS sentence at the foot of `from_spec`. That is the same rule,
    spelled one level too high: three characters of prefix put the emptiness
    INSIDE the spec, where cli._spelling's empty-argument door cannot see it
    either. It is answered here because this is the function that owns what a
    spec means, and the CLI deliberately does not expand one - a spec is
    stored verbatim and expanded against each machine's own home, which is
    what keeps an Archive machine-neutral.
    """
    root = _expand(text, home)
    if not root.is_absolute():
        raise SystemExit(
            f"cannot understand Destination spec {spec!r}: a directory "
            "Destination names one place, and that is a relative path - it "
            "means whatever directory the command is run in, so the Archive "
            "would follow you between projects. Give an absolute path "
            "('/...'), or one under this machine's home ('~/...').")
    return root


def from_spec(spec: str, home=None) -> Destination:
    home = pathlib.Path(home) if home else pathlib.Path.home()
    spec = spec.strip()

    if spec.startswith("dir:"):
        return DirectoryDestination(_directory_root(spec[4:], spec, home))
    if spec.startswith("rclone:"):
        target = spec[len("rclone:"):]
        if ":" not in target:
            raise SystemExit(f"bad rclone spec {spec!r}: expected "
                             "'rclone:remote:path' (see `rclone listremotes`)")
        return RcloneDestination(target)
    if spec.startswith("git:"):
        return GitDestination(spec[4:], home=home)
    if spec.startswith(("git@", "ssh://")) or spec.endswith(".git"):
        return GitDestination(spec, home=home)
    if spec.startswith("/") or spec == "~" or spec.startswith("~/"):
        return DirectoryDestination(_directory_root(spec, spec, home))

    raise SystemExit(f"cannot understand Destination spec {spec!r}: "
                     f"expected {SPEC_FORMS}")


def detect_candidates(home=None) -> list:
    """(spec, label) pairs for places an Archive could live on this machine."""
    home = pathlib.Path(home) if home else pathlib.Path.home()
    found = []

    for rel, label in SYNCED_FOLDERS:
        if (home / rel).is_dir():
            found.append((f"~/{rel}", label))

    git = shutil.which("git")
    if git and (_has_ssh_key(home) or _has_credential_helper(git, home)):
        found.append(("git:<url>",
                      "a private git repository - replace <url> with yours"))

    rclone = shutil.which("rclone")
    conf = home / ".config" / "rclone" / "rclone.conf"
    if rclone and conf.is_file() and conf.stat().st_size > 0:
        for remote in _rclone_remotes(rclone, conf):
            found.append((f"rclone:{remote}", f"rclone remote {remote}"))

    return found


def _has_ssh_key(home: pathlib.Path) -> bool:
    ssh = home / ".ssh"
    return ssh.is_dir() and any(p.name.startswith("id_")
                                and not p.name.endswith(".pub")
                                for p in ssh.iterdir())


def _has_credential_helper(git: str, home: pathlib.Path) -> bool:
    env = git_env()
    env["HOME"] = str(home)  # read the given home's config, never the real one
    # macOS ships osxkeychain in the *system* gitconfig, which would make every
    # Mac claim git credentials. Only a helper the user configured counts.
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    result = subprocess.run([git, "config", "--get", "credential.helper"],
                            capture_output=True, text=True, env=env)
    return result.returncode == 0 and bool(result.stdout.strip())


def _rclone_remotes(rclone: str, conf: pathlib.Path) -> list:
    env = dict(os.environ)
    env["RCLONE_CONFIG"] = str(conf)
    result = subprocess.run([rclone, "listremotes"],
                            capture_output=True, text=True, env=env)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


__all__ = [
    "Destination", "DirectoryDestination", "GitDestination",
    "RcloneDestination", "from_spec", "detect_candidates",
]
