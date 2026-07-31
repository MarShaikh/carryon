"""The master key's resting place between runs.

ADR-0004 makes the recovery key the trust root; the OS keychain is only a
convenience cache of it, so that pushing twice does not mean typing the key
twice. Losing an entry here costs a re-pair or the recovery key, never the
Archive. Service 'carryon', account 'master', value hex-encoded.

One honest limitation: macOS's security(1) only takes the secret as an
argument to `add-generic-password`, so on store the key is briefly visible in
`ps`. Keeping it off argv would need security's brittle interactive shell, so
the exposure is documented rather than worked around; fetch and delete never
put it on argv. On Linux, secret-tool reads the secret on stdin, and the
fallback file involves no argv at all.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

from . import config, crypto

HOME = pathlib.Path.home()
SERVICE = "carryon"
ACCOUNT = "master"


def _backend(platform=None) -> str:
    platform = platform or sys.platform
    if platform == "darwin" and shutil.which("security"):
        return "security"
    if platform.startswith("linux") and shutil.which("secret-tool"):
        return "secret-tool"
    return "file"


def _fallback_path(home: pathlib.Path) -> pathlib.Path:
    # config.state_dir rather than a second spelling of '.carryon': the whole
    # of the capture leg's carve-out is written against that one function, and
    # a directory named twice is a directory that can come to mean two things.
    return config.state_dir(home) / "master.key"


def _corrupt(path=None) -> str:
    """What to say about a key that read cleanly and is not one.

    Deliberately not "re-run `carryon init`" for the file backend, which is
    what this used to advise: `init` mints a FRESH master key, and a key file
    that is corrupt on this machine is very often recoverable somewhere else -
    a synced folder's version history, a backup, another paired machine. The
    one irreversible action must not be the first suggestion, which is the
    same reasoning `fetch_master`'s docstring gives for never answering None
    about a key it merely could not read.
    """
    where = f" at {path}" if path is not None else ""
    return (f"the stored master key{where} is not the hex carryon wrote "
            "there - a truncated write or a synced folder's conflict copy is "
            "the usual cause. Put that file back, or pair this machine again "
            "from one that still holds the key.")


def _decode(text: str, path=None) -> bytes:
    # Length is part of being the hex carryon wrote, not a separate question.
    # Hex carries no length of its own, so a torn write - the cause _corrupt
    # names as usual - decodes as cleanly as a whole one and hands back a
    # short key. Nothing downstream would notice: openssl accepts any
    # passphrase, so the Archive simply does not open and nothing says why.
    try:
        key = bytes.fromhex(text.strip())
    except ValueError:
        raise SystemExit(_corrupt(path))
    if len(key) != crypto.MASTER_BYTES:
        raise SystemExit(_corrupt(path))
    return key


def _run(argv, secret_stdin=None):
    return subprocess.run(argv, input=secret_stdin, capture_output=True,
                          text=True)


def store_master(key: bytes, home: pathlib.Path = HOME,
                 platform=None) -> None:
    backend = _backend(platform)
    if backend == "security":
        # -U updates an existing entry instead of failing on it
        result = _run(["security", "add-generic-password", "-U",
                       "-s", SERVICE, "-a", ACCOUNT, "-w", key.hex()])
    elif backend == "secret-tool":
        result = _run(["secret-tool", "store", "--label=carryon-master",
                       "service", SERVICE, "account", ACCOUNT],
                      secret_stdin=key.hex())
    else:
        # Through config.write_state_file, which is where the O_NOFOLLOW and
        # the hard-link check live: this is the one write in carryon that
        # would publish the trust root if it followed a link (ADR-0007), and
        # the config beside it takes the identical route.
        path = _fallback_path(home)
        config.write_state_file(path, key.hex() + "\n")
        print(f"warning: no OS keychain available - master key stored at "
              f"{path} (chmod 0600); guard that file", file=sys.stderr)
        return
    if result.returncode != 0:
        detail = (result.stderr or "").strip() or f"exit {result.returncode}"
        raise SystemExit(f"could not store the master key via {backend}: "
                         f"{detail}")


def _fault(backend: str, result) -> str:
    detail = (result.stderr or "").strip() or f"exit {result.returncode}"
    return (f"could not read the master key via {backend}: {detail} - this "
            "machine may still hold the key; fix the keychain rather than "
            "pairing again")


def fetch_master(home: pathlib.Path = HOME, platform=None):
    """The master key, or None when this machine genuinely holds none yet.

    None is reserved for not-stored, because callers turn it into "pair this
    machine" - the wrong advice for a keychain that is merely locked.
    security(1) says not-found with exit 44; secret-tool exits 1 both for
    not-found and for faults, but only a fault says why on stderr.

    The file backend kept that promise for exactly one case, "no file", and
    answered None for every other way a path can fail to be read: a symlink
    loop, a directory, a mode this user cannot open, a ~/.carryon that is not
    searchable. That is verbatim the shape config.load was hardened out of for
    the file sitting beside this one - an is_file() ahead of the read answers
    about the path it saw rather than the one the read gets, re-raises EACCES
    from the check itself, and swallows ELOOP as 'missing'. What it costs
    here is worse than a wrong sentence: `carryon init` asks this same
    question, and a key it merely could not read reads as no key at all, so
    init mints a fresh recovery key and orphans the Archive the old one
    opened. `push --category config` needs no key by design (ADR-0004) and so
    carries on, writing a Setup with no tag over one the encrypted Index still
    records as authenticated - after which every pull from every machine
    refuses that Setup whole.

    So the read is the guard. ENOENT and ENOTDIR are the two errnos that mean
    'nothing is stored here', the same two config.load names; everything else
    is a fault, and a fault says so.
    """
    backend = _backend(platform)
    if backend == "security":
        result = _run(["security", "find-generic-password",
                       "-s", SERVICE, "-a", ACCOUNT, "-w"])
        if result.returncode == 0:
            return _decode(result.stdout)
        if result.returncode == 44:  # errSecItemNotFound
            return None
        raise SystemExit(_fault("security", result))
    if backend == "secret-tool":
        result = _run(["secret-tool", "lookup",
                       "service", SERVICE, "account", ACCOUNT])
        if result.returncode == 0:
            return _decode(result.stdout)
        if (result.stderr or "").strip():
            raise SystemExit(_fault("secret-tool", result))
        return None
    path = _fallback_path(home)
    state = config.read_state_bytes(path)
    if state.absent:
        return None
    if state.why is not None:
        raise SystemExit(
            f"could not read the master key at {path} - {state.why}. This "
            "machine may still hold the key, so fix that file rather than "
            "pairing again or re-running `carryon init`, which would mint a "
            "new key and leave the Archive's History unopenable.")
    try:
        text = state.value.decode("utf-8")
    except UnicodeDecodeError:
        # The gate hands back bytes, so a key file of binary rubbish answers
        # here rather than at _decode's hex parse. Same fact, same sentence -
        # and it names the file, because the cure is about that file.
        raise SystemExit(_corrupt(path))
    return _decode(text, path)


def forget_master(home: pathlib.Path = HOME, platform=None) -> None:
    """Remove the cached key. Nothing to remove is not an error - the point
    is the state afterwards, not what was there before."""
    backend = _backend(platform)
    if backend == "security":
        _run(["security", "delete-generic-password",
              "-s", SERVICE, "-a", ACCOUNT])
    elif backend == "secret-tool":
        _run(["secret-tool", "clear", "service", SERVICE, "account", ACCOUNT])
    else:
        _fallback_path(home).unlink(missing_ok=True)
