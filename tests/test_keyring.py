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

from carryon import keyring  # noqa: E402

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

    keyring.store_master(KEY, platform="darwin")
    assert keyring.fetch_master(platform="darwin") == KEY

    keyring.forget_master(platform="darwin")
    assert keyring.fetch_master(platform="darwin") is None

    lines = log.read_text().splitlines()
    add = [l for l in lines if l.startswith("add-generic-password")][0]
    assert "-s carryon" in add and "-a master" in add
    assert "-U" in add, "store must update an existing entry, not fail on it"
    find = [l for l in lines if l.startswith("find-generic-password")][0]
    assert "-s carryon" in find and "-a master" in find and "-w" in find
    assert any(l.startswith("delete-generic-password") for l in lines)


def test_darwin_fetch_is_none_when_nothing_stored(tmp_path, monkeypatch):
    install_fake(tmp_path, monkeypatch, "security", SECURITY_FAKE)
    assert keyring.fetch_master(platform="darwin") is None


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
        keyring.fetch_master(platform="darwin")
    assert "User interaction is not allowed" in str(exc.value)


# --- linux: secret-tool -----------------------------------------------------

def test_linux_round_trip_via_secret_tool(tmp_path, monkeypatch):
    log, _ = install_fake(tmp_path, monkeypatch, "secret-tool", SECRET_TOOL_FAKE)

    keyring.store_master(KEY, platform="linux")
    assert keyring.fetch_master(platform="linux") == KEY

    keyring.forget_master(platform="linux")
    assert keyring.fetch_master(platform="linux") is None

    text = log.read_text()
    assert "store" in text and "lookup" in text and "clear" in text
    assert "service carryon account master" in text
    # secret-tool reads the secret on stdin; it must never appear in argv,
    # where `ps` would show it
    assert KEY.hex() not in text


def test_linux_fetch_is_none_when_nothing_stored(tmp_path, monkeypatch):
    """secret-tool's silent exit 1 is genuinely 'no key here'."""
    install_fake(tmp_path, monkeypatch, "secret-tool", SECRET_TOOL_FAKE)
    assert keyring.fetch_master(platform="linux") is None


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
        keyring.fetch_master(platform="linux")
    assert "D-Bus" in str(exc.value)


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
