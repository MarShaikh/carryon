"""The Setup is authenticated: a hostile Destination cannot swap its content.

The Setup travels plaintext - that is what makes a git Destination worth
having (ADR-0004) - and settings.json's hooks are shell commands the agent
executes, so anyone with write access to the Destination used to hold code
execution on every pulling machine, with no key. Round one's path allowlist
stops an attacker naming NEW paths; it says nothing about the CONTENT of a
declared one.

The fix under test: push MACs a manifest of the Setup tree (relative path plus
sha256 per file) under a key derived from the master key with its own domain
separator, and the encrypted Index - the one thing here the attacker cannot
write (ADR-0009) - records whether a machine's Setup is authenticated. Pull
verifies BEFORE anything is written and refuses a failing Setup WHOLE: a
partial Setup is worse than none. The keyless posture survives: a push with no
master key still works, warns that it cannot be verified, and is restored with
a warning - unless the Index has recorded that machine as authenticated, in
which case a stripped or keyless overwrite is refused rather than silently
accepted as a downgrade.

The attacker modelled here holds no master key and only writes files under the
Destination root. Fixtures come from hostile_archive so this suite cannot
drift from the other two Setup-half suites.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, crypto, keyring, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_CLAUDE_MD, GOOD_SETTINGS, SETUP_CATEGORIES,
    build_home_a, build_home_b, file_keyring, link_home, ns, paired,
    stored_setup)


def pull_report(home, capsys, code: int = 0) -> str:
    """A real applied pull, with the report it printed.

    `code` is the exit status the pull is expected to end on, and it is a
    parameter rather than a constant zero because a refused Setup now says so
    in the status: a forged tag, a stripped one and a planted file each print
    their refusal AND report failure, so a script can tell this run from one
    that restored. 2 is an applied run that refused, which is the number
    `push` already uses for a Setup it would not publish.
    """
    assert sync.pull(ns(apply=True), home) == code
    return capsys.readouterr().out


# --- the core attack: tampered content in a declared path --------------------


def test_a_tampered_settings_json_is_refused_whole_on_pull(paired, capsys):
    """settings.json is a path the allowlist accepts and its hooks are shell
    commands, so editing the stored copy used to be code execution on every
    pulling machine. Refused WHOLE, and named: the honest files beside it do
    not land either, because a partial Setup is worse than none."""
    (stored_setup(paired.dest_root, "machine-a")
     / "claude" / "settings.json").write_text(EVIL_SETTINGS)

    out = pull_report(paired.home_b, capsys, code=2)

    claude = paired.home_b / ".claude"
    assert not (claude / "settings.json").exists(), \
        "a tampered settings.json was restored - code execution on pull"
    assert not (claude / "CLAUDE.md").exists(), \
        "the Setup was partially restored; the refusal must be whole"
    assert "refuse" in out, "the refused Setup is not named in the report"
    assert "machine-a" in out
    assert "settings.json" in out, "the mismatching file is not named"


def test_a_forged_mac_does_not_authenticate_a_tampered_setup(paired, capsys):
    """The attacker can recompute the manifest - it is just paths and hashes -
    but not the tag: the MAC key is derived from the master key they do not
    hold. A forged SETUP.mac beside tampered content must fail exactly like a
    missing one."""
    base = stored_setup(paired.dest_root, "machine-a")
    (base / "claude" / "settings.json").write_text(EVIL_SETTINGS)
    forged_files = archive.setup_tree_manifest(base) \
        if hasattr(archive, "setup_tree_manifest") else {}
    payload = json.dumps({"version": 1, "files": forged_files},
                         sort_keys=True, separators=(",", ":")).encode()
    (base / "SETUP.mac").write_bytes(b"00" * 32 + b"\n" + payload)

    out = pull_report(paired.home_b, capsys, code=2)

    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "an attacker-authored SETUP.mac authenticated a tampered Setup"
    assert "refuse" in out


def test_an_extra_file_planted_in_an_authenticated_setup_is_refused(
        paired, capsys):
    """A planted file under a declared tree (a new 'skill' or command) is
    executable content too. The manifest is exact: extras fail verification
    the same as edits."""
    (stored_setup(paired.dest_root, "machine-a")
     / "claude" / "commands" / "evil.md").write_text("planted\n")

    out = pull_report(paired.home_b, capsys, code=2)

    assert not (paired.home_b / ".claude" / "commands" / "evil.md").exists(), \
        "a file planted in an authenticated Setup was restored"
    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "the refusal must be whole, not per file"
    assert "refuse" in out


# --- the downgrade: stripping the MAC must not buy the keyless path ----------


def test_a_stripped_mac_on_an_index_authenticated_machine_is_refused(
        paired, capsys):
    """The MAC lives in the plaintext half, so the attacker can delete it.
    What they cannot delete is the encrypted Index's record that this
    machine's Setup is authenticated - so a missing tag is a refusal, not a
    quiet downgrade to the keyless path."""
    mac = stored_setup(paired.dest_root, "machine-a") / "SETUP.mac"
    assert mac.is_file(), \
        "a keyed push did not authenticate the Setup - nothing to strip"
    mac.unlink()

    out = pull_report(paired.home_b, capsys, code=2)

    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "stripping the MAC downgraded the pull to the unauthenticated path"
    assert "refuse" in out
    assert "machine-a" in out


def test_a_keyless_push_is_not_silently_accepted_once_authenticated(
        paired, capsys):
    """The other spelling of the downgrade, produced by carryon itself: once
    the Index records machine-a as authenticated, a later keyless push (which
    cannot MAC and cannot touch the Index) must not be restored as if nothing
    happened - an attacker who can strip a MAC can also author exactly this
    tree."""
    # the fallback file keyring makes 'lose the key' a one-file operation
    (paired.home_a / ".carryon" / "master.key").unlink()
    assert keyring.fetch_master(home=paired.home_a) is None
    (paired.home_a / ".claude" / "settings.json").write_text(
        '{"model": "haiku"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES),
                     paired.home_a) == 0
    capsys.readouterr()

    out = pull_report(paired.home_b, capsys, code=2)

    assert not (paired.home_b / ".claude" / "settings.json").exists(), \
        "a keyless push was silently accepted for an authenticated machine"
    assert "refuse" in out


# --- ADR-0004's keyless posture survives -------------------------------------


def test_a_genuinely_keyless_push_still_round_trips_with_a_warning(
        tmp_path, capsys):
    """A machine that never authenticated its Setup keeps working: the push
    warns, in one plain line, that what it wrote cannot be verified by the
    machines that pull it; the pull restores it and flags it rather than
    implying safety."""
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    master = keyring.fetch_master(home=home)
    (home / ".carryon" / "master.key").unlink()
    capsys.readouterr()

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    push_out = capsys.readouterr().out
    assert "cannot be verified" in push_out, \
        "a keyless push does not warn that its Setup is unverifiable"

    home_b = build_home_b(tmp_path)
    link_home_with_master(home_b, dest_spec, master)
    out = pull_report(home_b, capsys)

    assert (home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "the keyless round trip broke (ADR-0004)"
    assert "vouches" in out, \
        "the unverified Setup restored without its warning"


def link_home_with_master(home, dest_spec, master) -> None:
    keyring.store_master(master, home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = "machine-b"
    config.save(cfg, home)


def test_an_index_entry_from_before_setup_auth_warns_and_restores(
        paired, capsys):
    """Index says unauthenticated (here: an entry written before Setups were
    authenticated at all): restore with the warning, matching the keyless
    case - old Archives must not become unreadable.

    The stored tag goes with the flag, because a carryon old enough to write
    an entry with no 'authenticated' in it wrote no SETUP.mac either - the two
    arrived in the same change. Deleting only the flag described an Archive
    that no version of carryon can produce, and it is the shape a DELETED
    Index produces instead: a tag a key holder wrote, with nothing in the
    catalogue accounting for it. That is refused by name now
    (sync._detached_tag_refusal), so an old Archive has to be modelled as an
    old Archive.
    """
    dest = sync.destinations.from_spec(paired.dest_spec, paired.home_a)
    master = keyring.fetch_master(home=paired.home_a)
    index = archive.load_index(dest, master)
    del index["setups"]["machine-a"]["authenticated"]
    archive.save_index(dest, master, index)
    (stored_setup(paired.dest_root, "machine-a")
     / archive.SETUP_MAC_NAME).unlink()

    out = pull_report(paired.home_b, capsys)

    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "a pre-authentication Archive stopped restoring"
    assert "cannot be verified" in out, \
        "an unverifiable Setup restored without saying so"


# --- the write side cannot launder unvouched content -------------------------


def test_a_keyed_partial_push_onto_an_unauthenticated_setup_refuses(
        tmp_path, capsys):
    """A partial push overlays onto the stored tree, and the stored tree is
    the Destination's to author when no MAC vouches for it (ADR-0009).
    Carrying its hashes into a fresh MAC would sign attacker content with the
    user's own key, so the push stops with a sentence naming the fix: one
    full push, which replaces the tree with content read from this machine."""
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    master = keyring.fetch_master(home=home)
    (home / ".carryon" / "master.key").unlink()
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    keyring.store_master(master, home=home)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), home)
    assert "whole Setup" in str(exc.value), \
        "the refusal does not name the full push as the fix"


# --- the derivation: one key, one job ----------------------------------------


def test_the_setup_mac_key_is_not_the_object_mac_key():
    """The Setup MAC reuses the derivation object MACs use, under its own
    domain separator - so the same 32 bytes never authenticate both an
    encrypted object and the plaintext Setup, and a flaw in either use cannot
    be levered against the other."""
    master = b"\x01" * crypto.MASTER_BYTES
    assert crypto.SETUP_INFO not in (crypto.MAC_INFO, crypto.NAME_INFO)
    assert crypto.setup_tag(master, "setup:m", b"payload") != \
        crypto._tag(master, "setup:m", b"payload")


# --- the feature still works -------------------------------------------------


def test_an_untampered_setup_verifies_and_restores_as_before(paired, capsys):
    """Regression guard, green by construction: authentication must cost an
    honest pull nothing, and the MAC file itself is bookkeeping - it never
    lands in $HOME."""
    out = pull_report(paired.home_b, capsys)

    claude = paired.home_b / ".claude"
    assert (claude / "settings.json").read_text() == GOOD_SETTINGS
    assert (claude / "CLAUDE.md").read_text() == GOOD_CLAUDE_MD
    assert "Setup: 3 file(s) written" in out
    assert not (paired.home_b / "SETUP.mac").exists()
    assert not list(claude.rglob("SETUP.mac")), \
        "the MAC file was restored as if it were part of the Setup"
