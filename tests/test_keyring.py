"""Keyring behaviour, exercised against fake OS tools on a prepended PATH.

Real `security` would write to this machine's login keychain - a destructive
experiment. The fakes record their argv and round-trip through a temp file, so
these tests pin the exact command lines as well as the behaviour.
"""

import os
import pathlib
import stat
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import argparse
import re

from carryon import crypto, keyring, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

KEY = bytes(range(32))

SECURITY_FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
case "$1" in
  add-generic-password) for a; do secret="$a"; done; printf '%s' "$secret" > "{store}" ;;
  find-generic-password) [ -f "{store}" ] || exit 44; cat "{store}" ;;
  delete-generic-password) [ -f "{store}" ] || exit 44; rm "{store}" ;;
  *) exit 2 ;;
esac
"""

SECRET_TOOL_FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
case "$1" in
  store) cat > "{store}" ;;
  lookup) [ -f "{store}" ] || exit 1; cat "{store}" ;;
  clear) rm -f "{store}" ;;
  *) exit 2 ;;
esac
"""


def install_fake(tmp_path, monkeypatch, name, template):
    """A fake `name` on a prepended PATH, backed by a temp store and argv log."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / f"{name}.log"
    store = tmp_path / f"{name}.store"
    tool = bin_dir / name
    tool.write_text(template.format(log=log, store=store))
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return log, store


def no_tools(tmp_path, monkeypatch):
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


# --- darwin: security(1) ----------------------------------------------------

def test_darwin_round_trip_via_security(tmp_path, monkeypatch):
    log, _ = install_fake(tmp_path, monkeypatch, "security", SECURITY_FAKE)

    keyring.store_master(KEY, home=tmp_path, platform="darwin")
    assert keyring.fetch_master(home=tmp_path, platform="darwin") == KEY

    keyring.forget_master(home=tmp_path, platform="darwin")
    assert keyring.fetch_master(home=tmp_path, platform="darwin") is None

    lines = log.read_text().splitlines()
    add = [l for l in lines if l.startswith("add-generic-password")][0]
    assert "-s carryon" in add and "-a master" in add
    assert "-U" in add, "store must update an existing entry, not fail on it"
    find = [l for l in lines if l.startswith("find-generic-password")][0]
    assert "-s carryon" in find and "-a master" in find and "-w" in find
    assert any(l.startswith("delete-generic-password") for l in lines)


def test_darwin_fetch_is_none_when_nothing_stored(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "security", SECURITY_FAKE)
    assert keyring.fetch_master(home=tmp_path, platform="darwin") is None


LOCKED_SECURITY_FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
echo 'security: SecKeychainItemCopyContent: User interaction is not allowed.' >&2
exit 51
"""


def test_darwin_fetch_surfaces_a_keychain_fault_not_none(tmp_path, monkeypatch):
    """security(1) says not-found with exit 44; anything else is a fault -
    a locked keychain, most likely. Returning None there would send the user
    off to re-pair a machine that already holds the key."""
    install_fake(tmp_path, monkeypatch, "security", LOCKED_SECURITY_FAKE)

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=tmp_path, platform="darwin")
    assert "User interaction is not allowed" in str(exc.value)


# --- linux: secret-tool -----------------------------------------------------

def test_linux_round_trip_via_secret_tool(tmp_path, monkeypatch):
    log, _ = install_fake(tmp_path, monkeypatch, "secret-tool", SECRET_TOOL_FAKE)

    keyring.store_master(KEY, home=tmp_path, platform="linux")
    assert keyring.fetch_master(home=tmp_path, platform="linux") == KEY

    keyring.forget_master(home=tmp_path, platform="linux")
    assert keyring.fetch_master(home=tmp_path, platform="linux") is None

    text = log.read_text()
    assert "store" in text and "lookup" in text and "clear" in text
    assert "service carryon account master" in text
    # secret-tool reads the secret on stdin; it must never appear in argv,
    # where `ps` would show it
    assert KEY.hex() not in text


def test_linux_fetch_is_none_when_nothing_stored(tmp_path, monkeypatch):
    """secret-tool's silent exit 1 is genuinely 'no key here'."""
    install_fake(tmp_path, monkeypatch, "secret-tool", SECRET_TOOL_FAKE)
    assert keyring.fetch_master(home=tmp_path, platform="linux") is None


NO_DBUS_SECRET_TOOL_FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
echo 'secret-tool: Cannot autolaunch D-Bus without X11' >&2
exit 1
"""


def test_linux_fetch_surfaces_a_secret_tool_fault_not_none(tmp_path,
                                                           monkeypatch):
    """secret-tool exits 1 both for not-found and for faults, but only a
    fault says why on stderr - and that must reach the user instead of
    reading as an unpaired machine."""
    install_fake(tmp_path, monkeypatch, "secret-tool", NO_DBUS_SECRET_TOOL_FAKE)

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=tmp_path, platform="linux")
    assert "D-Bus" in str(exc.value)
    assert "--key-file" in str(exc.value), \
        "a server with no keyring is the usual cause, and its cure is unnamed"


# --- fallback file ----------------------------------------------------------

def test_fallback_file_is_0600_and_warns_once(tmp_path, monkeypatch, capsys):
    no_tools(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir()

    keyring.store_master(KEY, home=home, platform="linux")

    path = home / ".carryon" / "master.key"
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text().strip() == KEY.hex()

    err = capsys.readouterr().err
    assert "master.key" in err
    assert len(err.strip().splitlines()) == 1, "one-line warning, not an essay"

    assert keyring.fetch_master(home=home, platform="linux") == KEY
    keyring.forget_master(home=home, platform="linux")
    assert not path.exists()
    assert keyring.fetch_master(home=home, platform="linux") is None


def test_fallback_fetch_is_none_when_no_file(tmp_path, monkeypatch):
    no_tools(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir()
    assert keyring.fetch_master(home=home, platform="darwin") is None


def test_corrupt_store_is_a_named_error_not_a_traceback(tmp_path, monkeypatch):
    no_tools(tmp_path, monkeypatch)
    home = tmp_path / "home"
    (home / ".carryon").mkdir(parents=True)
    (home / ".carryon" / "master.key").write_text("not hex at all")

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "master" in str(exc.value)


# A truncated write is the failure `_corrupt` names as usual, and hex has no
# length of its own: 62 digits decode as cleanly as 64 do. Without a length
# check the caller gets a 31-byte key and every derivation built on it is
# silently wrong - openssl takes any passphrase, so the Archive does not open
# and nothing says why. The refusal must fire on the length, not on the hex.
@pytest.mark.parametrize("digits, why", [
    (62, "one byte short of a master key"),
    (66, "one byte long"),
    (0, "an empty file, which a torn write leaves behind"),
])
def test_a_key_of_the_wrong_length_is_refused_not_returned(
        tmp_path, monkeypatch, digits, why):
    no_tools(tmp_path, monkeypatch)
    home = tmp_path / "home"
    (home / ".carryon").mkdir(parents=True)
    (home / ".carryon" / "master.key").write_text("ab" * (digits // 2))

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "master" in str(exc.value), why


def test_a_key_of_the_right_length_still_comes_back(tmp_path, monkeypatch):
    """The control: the length check must not refuse an honest key."""
    no_tools(tmp_path, monkeypatch)
    home = tmp_path / "home"
    (home / ".carryon").mkdir(parents=True)
    key = bytes(range(crypto.MASTER_BYTES))
    (home / ".carryon" / "master.key").write_text(key.hex())

    assert keyring.fetch_master(home=home, platform="linux") == key


# --- the fallback file, when it is there and will not read -------------------
#
# The two keychain backends each distinguish "nothing stored" from "the
# keychain would not answer", because fetch_master's own docstring reserves
# None for the first: callers turn it into "pair this machine", which is the
# wrong advice for a keychain that is merely locked - and, for the file
# backend, catastrophic advice. `carryon init` mints a FRESH master key over
# one it merely could not read, and orphans the whole Archive.
#
# The file backend asked `path.is_file()` and returned None for everything
# else: a symlink loop, a directory, a $HOME that came back from a backup with
# the wrong owner. That is verbatim the shape config.load was hardened against
# for the file sitting beside it in the same directory - an exists() ahead of
# the read answers about the path it saw, not the one the read gets, and it
# does not answer 'no' cleanly either.


def state_dir(tmp_path):
    home = tmp_path / "home"
    (home / ".carryon").mkdir(parents=True)
    return home


def test_fallback_fetch_says_fault_not_nothing_stored_on_a_symlink_loop(
        tmp_path, monkeypatch):
    """The key material is still on this machine; nothing about a loop at the
    path says otherwise. Answering None sends `carryon init` off to mint a new
    master key, which is the one action that cannot be undone."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    path = home / ".carryon" / "master.key"
    other = home / ".carryon" / "master-loop.key"
    path.symlink_to(other)
    other.symlink_to(path)

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "master.key" in str(exc.value), "the refusal does not name the file"


def test_fallback_fetch_says_fault_not_nothing_stored_on_a_directory(
        tmp_path, monkeypatch):
    """A directory standing where the key file goes - a synced folder's doing,
    or a restored backup. is_file() says False, which reads as 'this machine
    was never paired'."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    (home / ".carryon" / "master.key").mkdir()

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "master.key" in str(exc.value), "the refusal does not name the file"


def test_fallback_fetch_says_fault_when_the_state_dir_will_not_open(
        tmp_path, monkeypatch):
    """The other half of the same syscall: a ~/.carryon this user cannot
    search. is_file() re-raises EACCES there rather than answering, so this
    was a raw PermissionError traceback out of every subcommand - which
    ADR-0009's last section says is not a refusal."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    (home / ".carryon" / "master.key").write_text(KEY.hex() + "\n")
    (home / ".carryon").chmod(0o000)
    try:
        if os.access(home / ".carryon" / "master.key", os.R_OK):
            return  # running as root: the mode decides nothing
        with pytest.raises(SystemExit) as exc:
            keyring.fetch_master(home=home, platform="linux")
        assert "master.key" in str(exc.value), \
            "the refusal does not name the file"
    finally:
        (home / ".carryon").chmod(0o700)


def test_fallback_fetch_says_corrupt_when_the_file_is_not_text(
        tmp_path, monkeypatch):
    """read_text decodes, and a key file of binary rubbish answers with a
    UnicodeDecodeError before _decode's ValueError guard is ever reached."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    (home / ".carryon" / "master.key").write_bytes(b"\xff\xfe\x00\x01")

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "master" in str(exc.value)


# --- the fallback file, when something else owns the path --------------------
#
# ADR-0007: carryon never writes through a link it does not own. The capture
# leg already treats ~/.carryon as sacred - a captured path that so much as
# lands there is refused, because the master key is bare hex no credential
# pattern matches - and this is the master key itself, written through a link
# into whatever repo put it there, and chmod 0600 applied at the far end.


def test_the_master_key_is_never_written_through_a_link(tmp_path, monkeypatch,
                                                         capsys):
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    elsewhere = tmp_path / "dotfiles" / "master.key"
    elsewhere.parent.mkdir()
    elsewhere.write_text("someone else's file\n")
    (home / ".carryon" / "master.key").symlink_to(elsewhere)

    with pytest.raises(SystemExit) as exc:
        keyring.store_master(KEY, home=home, platform="linux")

    assert "master.key" in str(exc.value), "the refusal does not name the path"
    assert elsewhere.read_text() == "someone else's file\n", \
        "the master key was written through a link into another tree"


def test_the_master_key_is_never_written_to_a_second_name(tmp_path,
                                                           monkeypatch):
    """A hard link is the same publication one syscall over, and it is the
    case a symlink check cannot see: the path resolves to itself. The
    Destination layer already refuses a write to a key with st_nlink > 1 for
    exactly this reason."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    path = home / ".carryon" / "master.key"
    path.write_text("old key\n")
    second = tmp_path / "dotfiles-second-name"
    os.link(path, second)

    with pytest.raises(SystemExit) as exc:
        keyring.store_master(KEY, home=home, platform="linux")

    assert "master.key" in str(exc.value), "the refusal does not name the path"
    assert second.read_text() == "old key\n", \
        "the master key was written to a path another name shares"


def test_storing_over_carryons_own_key_file_still_works(tmp_path, monkeypatch,
                                                        capsys):
    """The ordinary case the two refusals above must not break: a key file
    carryon itself wrote, replaced by a re-pair, still ending 0600."""
    no_tools(tmp_path, monkeypatch)
    home = state_dir(tmp_path)
    path = home / ".carryon" / "master.key"
    path.write_text("00" * 32 + "\n")
    path.chmod(0o644)

    keyring.store_master(KEY, home=home, platform="linux")

    assert keyring.fetch_master(home=home, platform="linux") == KEY
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, \
        "a key file that was already there kept its old mode"


# --- a headless Linux machine: secret-tool installed, no keyring (#38) -------
#
# Both shapes reproduced in an Ubuntu 24.04 container answer every
# subcommand with exit 1 and a reason on stderr: no D-Bus at all ("Cannot
# autolaunch D-Bus without X11 $DISPLAY") and a bus with no Secret Service on
# it ("org.freedesktop.secrets was not provided by any .service files").
# The same answer comes from a desktop whose keyring is only unreachable over
# SSH, where the key may well be sitting - so carryon never moves to the file
# on its own guess. `init --key-file` moves it, and the file then decides.

NO_KEYRING_SECRET_TOOL_FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
echo 'secret-tool: The name org.freedesktop.secrets was not provided by any .service files' >&2
exit 1
"""


def test_key_file_stores_in_the_file_and_never_asks_the_keyring(
        tmp_path, monkeypatch, capsys):
    log, _ = install_fake(tmp_path, monkeypatch, "secret-tool",
                          NO_KEYRING_SECRET_TOOL_FAKE)
    home = state_dir(tmp_path)

    keyring.store_master(KEY, home=home, platform="linux", key_file=True)

    path = home / ".carryon" / "master.key"
    assert path.read_text().strip() == KEY.hex()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "master.key" in capsys.readouterr().err, "the warning was dropped"
    assert not log.exists(), "secret-tool was run for a key bound for the file"


def test_once_the_file_exists_every_command_reads_it_and_not_the_keyring(
        tmp_path, monkeypatch):
    log, _ = install_fake(tmp_path, monkeypatch, "secret-tool",
                          NO_KEYRING_SECRET_TOOL_FAKE)
    home = state_dir(tmp_path)
    keyring.store_master(KEY, home=home, platform="linux", key_file=True)

    assert keyring.fetch_master(home=home, platform="linux") == KEY
    keyring.store_master(bytes(32), home=home, platform="linux")
    assert keyring.fetch_master(home=home, platform="linux") == bytes(32), \
        "a re-store went somewhere other than the file the key lives in"
    keyring.forget_master(home=home, platform="linux")
    assert not (home / ".carryon" / "master.key").exists()
    assert not log.exists(), "secret-tool was asked about a key in the file"


def test_the_file_wins_over_a_working_keyring_too(tmp_path, monkeypatch):
    """Where the key lives is read off the disk, not off which tools happen
    to work today: a keyring that comes up later must not shadow the file."""
    _, store = install_fake(tmp_path, monkeypatch, "secret-tool",
                            SECRET_TOOL_FAKE)
    store.write_text(bytes(32).hex())
    home = state_dir(tmp_path)
    (home / ".carryon" / "master.key").write_text(KEY.hex() + "\n")

    assert keyring.fetch_master(home=home, platform="linux") == KEY


def test_without_key_file_a_dead_keyring_is_still_a_fault_not_no_key(
        tmp_path, monkeypatch):
    """The desktop-over-SSH case: answering None here is what lets init mint
    a second master key over one the keyring still holds."""
    install_fake(tmp_path, monkeypatch, "secret-tool",
                 NO_KEYRING_SECRET_TOOL_FAKE)
    home = state_dir(tmp_path)

    with pytest.raises(SystemExit) as exc:
        keyring.fetch_master(home=home, platform="linux")
    assert "org.freedesktop.secrets" in str(exc.value)
    assert not (home / ".carryon" / "master.key").exists()


def test_key_file_takes_a_dead_keyring_at_the_users_word(tmp_path,
                                                          monkeypatch):
    install_fake(tmp_path, monkeypatch, "secret-tool",
                 NO_KEYRING_SECRET_TOOL_FAKE)
    home = state_dir(tmp_path)
    assert keyring.fetch_master(home=home, platform="linux",
                                key_file=True) is None


def test_key_file_still_finds_a_key_a_working_keyring_holds(tmp_path,
                                                             monkeypatch):
    """So `init --key-file` on a machine already set up refuses, rather than
    writing a second key into a file that would then shadow the first."""
    install_fake(tmp_path, monkeypatch, "secret-tool", SECRET_TOOL_FAKE)
    home = state_dir(tmp_path)
    keyring.store_master(KEY, home=home, platform="linux")

    assert keyring.fetch_master(home=home, platform="linux",
                                key_file=True) == KEY
    assert not (home / ".carryon" / "master.key").exists()


def init_ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, recover=False, machine=None,
                key_file=False)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def headless(tmp_path, monkeypatch):
    """A Linux machine as #38 found it, whatever this test runs on."""
    install_fake(tmp_path, monkeypatch, "secret-tool",
                 NO_KEYRING_SECRET_TOOL_FAKE)
    monkeypatch.setattr(keyring, "_backend",
                        lambda platform=None: "secret-tool")


def test_init_on_a_headless_machine_refuses_and_names_key_file(
        tmp_path, headless):
    home = state_dir(tmp_path)
    spec = str(tmp_path / "archive")

    with pytest.raises(SystemExit) as exc:
        sync.init(init_ns(dest=spec, machine="vm"), home)

    assert "--key-file" in str(exc.value)
    assert sorted(p.name for p in (home / ".carryon").iterdir()) == [], \
        "a refused init left something behind"


def test_init_and_join_with_key_file_on_headless_machines(
        tmp_path, headless, capsys):
    home_a, home_b = tmp_path / "a", tmp_path / "b"
    home_a.mkdir()
    home_b.mkdir()
    spec = str(tmp_path / "archive")

    assert sync.init(init_ns(dest=spec, machine="vm-a", key_file=True),
                     home_a) == 0
    key_a = keyring.fetch_master(home=home_a)
    assert len(key_a) == crypto.MASTER_BYTES

    assert sync.pair(argparse.Namespace(), home_a) == 0
    code = re.search(r"--join (\S+)", capsys.readouterr().out).group(1)
    assert sync.init(init_ns(dest=spec, join=code, machine="vm-b",
                             key_file=True), home_b) == 0
    assert keyring.fetch_master(home=home_b) == key_a
    assert (home_b / ".carryon" / "master.key").is_file()

    with pytest.raises(SystemExit) as exc:
        sync.init(init_ns(dest=spec, machine="vm-b", key_file=True), home_b)
    assert "already holds a master key" in str(exc.value)
    assert DirectoryDestination(tmp_path / "archive").list("carryon/pair/") \
        == []
