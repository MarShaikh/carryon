"""The Setup is sealed: a hostile Destination cannot author or swap it.

This suite used to be about a MAC. The Setup travelled plaintext, because a
keyless push had to be able to write one (ADR-0004), and settings.json's hooks
are shell commands the agent executes - so anyone with write access to the
Destination held code execution on every pulling machine unless a tag caught
them. ADR-0014 removed the reason for the plaintext and the tag with it: a
Setup is one sealed object now, and "a master key holder wrote these bytes,
and they are this machine's Setup" is answered by it opening at all.

So the attacks worth writing down changed shape. An attacker with write access
to the Destination can no longer edit one file inside a Setup, plant an extra
one, or strip a tag - none of those are things you can do to a sealed object
without the key. What they CAN still do is write whatever bytes they like at
the key, and - the one that sealing does not answer - serve back an earlier
sealed Setup that this Archive really did hold once. Every object a key holder
ever pushed goes on opening for ever.

That last one is why `authentication.py` still exists, and it is the test in
here that matters most.

The attacker modelled holds no master key and only writes under the
Destination root. Fixtures come from hostile_archive so this suite cannot
drift from the other two Setup-half suites.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, crypto, keyring, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_CLAUDE_MD, GOOD_SETTINGS, SETUP_CATEGORIES,
    build_home_a, build_home_b, file_keyring, link_home, ns, paired)


def pull_report(home, capsys, code: int = 0) -> str:
    """A real applied pull, with the report it printed.

    `code` is the exit status the pull is expected to end on: a refused Setup
    says so in the status as well as in the report, so a script can tell this
    run from one that restored. 2 is an applied run that refused, the number
    `push` already uses for a Setup it would not publish.
    """
    assert sync.pull(ns(apply=True), home) == code
    return capsys.readouterr().out


def stored_object(dest_root, machine="machine-a") -> pathlib.Path:
    """The one object a machine's Setup is, as a path the attacker can write.

    Not `hostile_archive.stored_setup`, which unseals into a scratch directory
    for a test to read: this is the bytes at the Destination, which is all an
    attacker has.
    """
    return (pathlib.Path(dest_root) / "carryon" / "setups"
            / f"{machine}.tar.enc")


def restored_nothing(home) -> bool:
    claude = home / ".claude"
    return not (claude / "settings.json").exists() \
        and not (claude / "CLAUDE.md").exists()


# --- what an attacker can still do to a sealed object ------------------------


def test_tampered_ciphertext_is_refused_whole_on_pull(paired, capsys):
    """The core attack, in the only form left. An attacker cannot find
    settings.json inside the object to edit it, so the most they can do is
    change bytes and hope. The seal catches it, and the refusal is WHOLE -
    the honest files do not land either, because a partial Setup is worse
    than none."""
    blob = bytearray(stored_object(paired.dest_root).read_bytes())
    blob[-1] ^= 0xFF
    stored_object(paired.dest_root).write_bytes(bytes(blob))

    out = pull_report(paired.home_b, capsys, code=2)

    assert restored_nothing(paired.home_b), \
        "a tampered Setup was restored - code execution on pull"
    assert "refuse" in out
    assert "machine-a" in out


def test_an_attacker_authored_setup_does_not_open(paired, capsys):
    """What replacing the Setup looks like now. The attacker can build a
    perfectly well-formed tar holding a malicious settings.json - it is just
    a tar - and they cannot seal it, so it never becomes a Setup."""
    evil = archive.pack([("MANIFEST.json", b"{}"),
                         ("claude/settings.json", EVIL_SETTINGS.encode())])
    stored_object(paired.dest_root).write_bytes(evil)

    out = pull_report(paired.home_b, capsys, code=2)

    assert restored_nothing(paired.home_b), \
        "an unsealed tar was restored as a Setup"
    assert "refuse" in out


def test_a_setup_sealed_under_the_attackers_own_key_does_not_open(
        paired, capsys):
    """The same attack by someone who knows how carryon seals things. Sealing
    is not the question - sealing UNDER THIS ARCHIVE'S KEY is, and that is the
    one thing they do not have."""
    evil = archive.pack([("claude/settings.json", EVIL_SETTINGS.encode())])
    stored_object(paired.dest_root).write_bytes(
        crypto.seal(evil, b"\x99" * 32, archive.setup_label("machine-a")))

    out = pull_report(paired.home_b, capsys, code=2)

    assert restored_nothing(paired.home_b)
    assert "refuse" in out


def test_a_setup_sealed_for_another_machine_is_refused_at_this_key(
        paired, capsys):
    """The seal's label binds the bytes to the machine as the Index spells it.
    Without it, an Archive holding several machines lets the Destination
    choose which one you get - so the substitution has to be refused at the
    key the pull actually reads, not merely left unchosen.

    Sealed here under a different machine's label and served at machine-a's
    key, which is the shape that reaches a reader: planting a whole extra
    machine does not, because the pull ranks a name the encrypted Index
    vouches for above one it has never heard of.
    """
    master = keyring.fetch_master(home=paired.home_a)
    honest = crypto.unseal(stored_object(paired.dest_root).read_bytes(),
                           master, archive.setup_label("machine-a"))
    stored_object(paired.dest_root).write_bytes(
        crypto.seal(honest, master, archive.setup_label("machine-b")))

    out = pull_report(paired.home_b, capsys, code=2)

    assert restored_nothing(paired.home_b)
    assert "refuse" in out


# --- the one sealing does NOT answer ------------------------------------------


def test_a_replayed_sealed_setup_is_refused_on_pull(paired, capsys):
    """The reason authentication.py survived ADR-0014.

    Every sealed Setup a Destination has ever held goes on opening for ever,
    so a versioned bucket, a git history or a synced folder's trash is an
    unlimited supply of objects that pass. Serving an old one back silently
    undoes whatever the last push tightened - and it opens, so nothing about
    the seal can tell. Only the stamp inside it, against the sealed Index's
    copy, says which one is current.
    """
    old = stored_object(paired.dest_root).read_bytes()
    # machine-a tightens something and pushes again.
    (paired.home_a / ".claude" / "settings.json").write_text(
        '{"model": "opus", "permissions": "strict"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES),
                     paired.home_a) == 0
    # The Destination serves the superseded object back in its place.
    stored_object(paired.dest_root).write_bytes(old)

    out = pull_report(paired.home_b, capsys, code=2)

    assert restored_nothing(paired.home_b), \
        "a superseded Setup was restored over a tightened one"
    assert "refuse" in out
    assert "earlier" in out, "the report does not say it is a replay"


def test_a_partial_push_refuses_to_launder_a_replayed_setup(paired, capsys):
    """The same rule at the other door, which is the one that was missing.

    A partial push merges the stored tree into the object it seals. Carrying a
    superseded tree forward under a NEW stamp makes it the current Setup,
    signed by the user's own key, at exit 0 - so the push leg has to ask the
    same question the pull leg asks.
    """
    old = stored_object(paired.dest_root).read_bytes()
    (paired.home_a / ".claude" / "settings.json").write_text(
        '{"model": "opus", "permissions": "strict"}')
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES),
                     paired.home_a) == 0
    stored_object(paired.dest_root).write_bytes(old)

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), paired.home_a)

    assert "current" in str(exc.value) or "earlier" in str(exc.value)
    assert stored_object(paired.dest_root).read_bytes() == old, \
        "the refused push wrote to the Archive anyway"


# --- the honest path still works ---------------------------------------------


def test_an_honest_sealed_setup_round_trips(paired, capsys):
    """The positive control. Everything above is a refusal, and a suite of
    refusals passes just as well when nothing restores at all."""
    out = pull_report(paired.home_b, capsys)

    claude = paired.home_b / ".claude"
    assert (claude / "settings.json").read_text() == GOOD_SETTINGS
    assert (claude / "CLAUDE.md").read_text() == GOOD_CLAUDE_MD
    assert "refuse" not in out
