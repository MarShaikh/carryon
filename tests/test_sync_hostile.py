"""A pull never crashes and never goes quiet, on the syscall as well as the
string.

pull's own comment states the rule: never crash, an abort partway through
leaves a $HOME with someone else's History in it and no report saying what
landed; never go quiet, an item dropped without a word reads as a restore that
succeeded and is mysteriously short a file. The Setup leg enforced it at the
boundaries it was written against, and every check there is a check on the
STRING while every remaining crash is in the SYSCALL that follows it. A guard
that answers "is this a well-formed relative path" does not answer "will the
kernel accept this path", and a guard that answers "can this go back into a
key" does not answer "will lstat accept it".

So these tests hand a pull input that is lexically perfect and physically
impossible - a dst past PATH_MAX, a machine name with a NUL in it, a src whose
parent exists locally as a file - and assert the pull finishes and names what
it declined. They also cover the two places the same posture was missing
entirely: the stored MANIFEST a PARTIAL push reads back before it overlays,
and the vouched lookup, which decides whose Setup a pull trusts by comparing
machine names exactly while the rule beside it case-folds.

The attacker holds no master key and only writes files under the Destination
root (ADR-0009). Fixtures come from hostile_archive so the two Setup-half
suites cannot drift apart.
"""

import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import config, destinations, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_CLAUDE_MD, GOOD_COMMAND, GOOD_SETTINGS, SECRET,
    SETUP_CATEGORIES, ListsOneExtraKey, author_setup, build_home_a,
    file_keyring, files_containing, item, manifest, ns, paired, remac_setup,
    stored_setup)

# Since the Setup gained its authentication tag (test_setup_auth.py), a tree
# edited without the master key is refused whole before any item is read.
# The string-vs-syscall guards here still have to hold for a tree a key
# holder DID stamp - a compromised source machine is exactly that - so each
# tamper of the vouched tree below is re-stamped with remac_setup, keeping
# those guards the thing under test.

# A forged report line, spelled the way pull spells the real one.
FORGERY = "  Setup: 6 file(s) written, 0 refused"


def pull_report(home, capsys, code: int = 0) -> str:
    """A real applied pull, with the report it printed. Never a traceback.

    `code` is what the pull is expected to end on: 0 where the stored Setup
    was used and 2 where carryon refused it, because a refused Setup now says
    so in the status as well as in the report. Never a traceback either way -
    that is what these tests are about, and a status is not a raise.
    """
    assert sync.pull(ns(apply=True), home) == code
    return capsys.readouterr().out


# --- a path the kernel will not take is not a well-formed path ---------------


@pytest.mark.parametrize("dst", [
    "claude/" + "a" * 5000,               # one component past NAME_MAX
    "claude/" + "/".join(["ab"] * 600),    # many components past PATH_MAX
])
def test_a_dst_the_kernel_will_not_take_does_not_abort_the_pull(
        paired, capsys, dst):
    """dst is bounded in shape - relative, no '..', no backslash, no NUL -
    and not in length, and `staging / dst` then goes straight to a syscall
    whose OSError filter ignores ENOENT and re-raises ENAMETOOLONG.

    src is a declared path, or the item would be refused on the write leg
    before dst is ever looked at and the test would pass for the wrong
    reason."""
    author_setup(paired.dest_root, "machine-a", [
        item(".claude/settings.json", dst),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
    ], files={"claude/CLAUDE.md": GOOD_CLAUDE_MD})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert "refuse" in out, "the impossible dst is not named in the report"
    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD, "the honest item was lost with the refused one"


def test_a_src_the_kernel_will_not_take_does_not_abort_the_pull(paired,
                                                                capsys):
    """The write leg has the same shape: a declared tree's name plus 5000
    characters is still 'under a path an adapter declares'."""
    author_setup(paired.dest_root, "machine-a", [
        item(".claude/commands/" + "a" * 5000, "claude/settings.json"),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
    ], files={"claude/settings.json": GOOD_SETTINGS,
              "claude/CLAUDE.md": GOOD_CLAUDE_MD})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert "refuse" in out
    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD


def test_a_src_that_is_only_too_long_once_joined_to_home_is_refused(
        paired, capsys):
    """Bounding the relative half is not the same question as bounding what
    a syscall sees. A `src` comfortably inside PATH_MAX on its own is past it
    with $HOME in front, and external.plan walks that path with is_symlink()
    - so the crash moved one function further out rather than closing."""
    home_len = len(str(paired.home_b)) + 1
    # long enough that $HOME plus it clears PATH_MAX, short enough that the
    # relative half on its own does not - which is the whole gap.
    want = min(1020, 1024 - home_len + 120)
    src = ".claude/commands"
    while len(src) < want:
        src += "/ab"
    assert len(src) <= 1024, "the relative half must still look acceptable"
    assert home_len + len(src) > 1024, "and the joined path must not"
    author_setup(paired.dest_root, "machine-a", [
        item(src, "claude/settings.json"),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
    ], files={"claude/settings.json": GOOD_SETTINGS,
              "claude/CLAUDE.md": GOOD_CLAUDE_MD})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert "refuse" in out
    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD


def test_a_src_below_a_local_file_does_not_abort_the_pull(paired, capsys):
    """_is_declared accepts everything BELOW a declared tree, and
    '.claude/commands/ship.md' is an ordinary file on the pulling machine, so
    mkdir(parents=True, exist_ok=True) raises FileExistsError - exist_ok
    forgives an existing DIRECTORY only. The crash lands mid-loop, after
    earlier items were written and their backups taken."""
    commands = paired.home_b / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "ship.md").write_text("mine\n")
    author_setup(paired.dest_root, "machine-a", [
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
        item(".claude/commands/ship.md/evil.md", "claude/settings.json"),
    ], files={"claude/CLAUDE.md": GOOD_CLAUDE_MD,
              "claude/settings.json": EVIL_SETTINGS})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert (commands / "ship.md").read_text() == "mine\n"
    assert "refuse" in out
    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD


def test_a_file_item_naming_a_local_directory_does_not_abort_the_pull(
        paired, capsys):
    """src='.claude/commands' with kind='file' passes the allowlist by the
    `posix == t` branch, and .claude/commands is a directory here. is_file()
    is False for a directory so no backup is attempted; the write is the
    first thing that touches it, and it raises IsADirectoryError."""
    commands = paired.home_b / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "ship.md").write_text("mine\n")
    author_setup(paired.dest_root, "machine-a", [
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
        item(".claude/commands", "claude/settings.json"),
    ], files={"claude/CLAUDE.md": GOOD_CLAUDE_MD,
              "claude/settings.json": EVIL_SETTINGS})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert (commands / "ship.md").read_text() == "mine\n"
    assert "refuse" in out
    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD


# --- a stored MANIFEST is parsed, and json.loads has more than two failures --


NESTED = "[" * 200000 + "]" * 200000


def test_a_deeply_nested_stored_manifest_does_not_abort_the_pull(paired,
                                                                 capsys):
    """The guard is `except (ValueError, UnicodeDecodeError, AttributeError)`
    around json.loads. A nested JSON array raises RecursionError, which is
    none of the three."""
    (stored_setup(paired.dest_root, "machine-a")
     / "MANIFEST.json").write_text(NESTED)
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    # code=2: no abort, and no false success either - the Setup carryon chose
    # could not be used, and the status says so while the report survives.
    out = pull_report(paired.home_b, capsys, code=2)

    assert "MANIFEST" in out, "the unusable stored MANIFEST is not named"


def test_a_planted_directory_alone_can_kill_no_pull(tmp_path, paired, capsys):
    """Worse than replacing the honest MANIFEST, because it needs the honest
    machine's directory not at all: one new directory under setups/ and every
    pull from every machine dies while machine-a's Setup sits there intact."""
    planted = paired.dest_root / "carryon" / "setups" / "planted"
    planted.mkdir(parents=True)
    (planted / "MANIFEST.json").write_text(NESTED)

    out = pull_report(paired.home_b, capsys)

    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "an invented directory took the honest Setup down"
    assert "planted" in out


def test_a_machine_name_with_a_nul_is_skipped_not_fatal(paired, capsys,
                                                        monkeypatch):
    """require_key is asked whether a name can go back into a key, and it is
    not the rule the very next line enforces: it accepts a NUL, and the NUL
    reaches os.lstat as ValueError."""
    real = destinations.from_spec(paired.dest_spec, paired.home_b)
    evil = "carryon/setups/nul\x00name/MANIFEST.json"
    monkeypatch.setattr(destinations, "from_spec",
                        lambda spec, home: ListsOneExtraKey(real, evil))

    out = pull_report(paired.home_b, capsys)

    assert "machine-a" in out, "the honest Setup was lost with the bad name"
    assert (paired.home_b / ".claude" / "settings.json").is_file()


def test_a_machine_name_too_long_to_be_a_directory_is_skipped_not_fatal(
        paired, capsys, monkeypatch):
    """The same shape one errno over: require_key accepts any length, and the
    next line's read reaches a syscall that will not."""
    real = destinations.from_spec(paired.dest_spec, paired.home_b)
    evil = "carryon/setups/" + "z" * 400 + "/MANIFEST.json"
    monkeypatch.setattr(destinations, "from_spec",
                        lambda spec, home: ListsOneExtraKey(real, evil))

    out = pull_report(paired.home_b, capsys)

    assert "machine-a" in out
    assert (paired.home_b / ".claude" / "settings.json").is_file()


# --- the sibling read path: a partial push reads the Archive too -------------


def partial_push_home(tmp_path) -> tuple:
    home = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    return home, dest_root


@pytest.mark.parametrize("stored", [
    "{not json at all",
    NESTED,
    '{"agents": "not-an-object", "categories": 7}',
])
def test_a_hostile_stored_manifest_does_not_traceback_out_of_a_push(
        tmp_path, capsys, stored):
    """A partial push must first read the Archive's stored MANIFEST to overlay
    onto it, and handed it straight to json.loads and then to a set union over
    stored['categories']. Three tracebacks out of one user command, from a
    file ADR-0009 names as input."""
    home, dest_root = partial_push_home(tmp_path)
    (stored_setup(dest_root, "machine-a")
     / "MANIFEST.json").write_text(stored)
    capsys.readouterr()

    try:
        code = sync.push(ns(apply=True, category="config"), home)
    except SystemExit as exc:
        # a sentence naming the file is a fine outcome; a traceback is not
        assert "MANIFEST" in str(exc), \
            f"a push died without naming what it choked on: {exc}"
        return
    assert code == 0
    out = capsys.readouterr().out
    assert "Setup" in out


def test_a_partial_push_really_withholds_what_it_says_it_withheld(tmp_path,
                                                                  capsys):
    """Withholding is done by deleting the file from staging, and only a FULL
    push's stale-key sweep turns that into a deletion in the Archive. On a
    partial push the overlay never deletes, so a copy an earlier version
    published stays in the plaintext half with the source machine's home in
    it - while the report says "They stayed here and a pull elsewhere will be
    without them"."""
    home = (tmp_path / "home_w").resolve()
    skill = home / ".claude" / "skills" / "shipping"
    skill.mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(GOOD_SETTINGS)
    (skill / "SKILL.md").write_text("Ship it.\n")
    (skill / "notes.bin").write_bytes(
        b"\xff\xfe" + f"cache lives at {home}/.cache\n".encode())
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-w"), home)
    assert sync.push(ns(apply=True, category="capability"), home) == 0

    # what an earlier version of carryon left in the Archive
    published = (stored_setup(dest_root, "machine-w")
                 / "claude" / "skills" / "shipping" / "notes.bin")
    published.parent.mkdir(parents=True, exist_ok=True)
    published.write_bytes(b"\xff\xfe" + f"cache lives at {home}/.cache\n"
                          .encode())
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="capability"), home) == 0
    out = capsys.readouterr().out

    assert "notes.bin" in out, "the withheld file is not named"
    assert files_containing(dest_root, str(home)) == [], \
        "a partial push left a file naming this machine's home in the Archive"
    assert not published.exists(), \
        "the report says the file stayed here; the Archive still holds it"


# --- the one field an attacker cannot forge, compared the wrong way ----------


def test_a_case_variant_setup_directory_is_still_vouched_for(paired, capsys):
    """The '.carryon' carve-out beside this one case-folds and calls that the
    spelling of the rule to copy; the vouched lookup then compares machine
    names exactly. On a case-insensitive Destination, renaming
    setups/machine-a to setups/MACHINE-A is the SAME directory on disk with
    the same honest content, and index['setups'] is keyed exactly - so the one
    field ADR-0009 says an attacker cannot forge reads false, for a rename."""
    setups = paired.dest_root / "carryon" / "setups"
    os.rename(setups / "machine-a", setups / "MACHINE-A")
    author_setup(paired.dest_root, "evil",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})

    out = pull_report(paired.home_b, capsys)

    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "a rename denied the Setup restore at exit 0"
    assert "evil" in out


def test_the_catalogue_vouches_for_a_case_variant_of_a_known_machine(paired):
    """Stated directly, because the pull above could pass for other reasons."""
    setups = paired.dest_root / "carryon" / "setups"
    os.rename(setups / "machine-a", setups / "MACHINE-A")
    dest = destinations.from_spec(paired.dest_spec, paired.home_b)
    index = {"setups": {"machine-a": {"pushed_at": "2026-01-01T00:00:00Z"}}}

    catalogue, _refused = sync._setup_catalogue(dest, index)

    assert catalogue["MACHINE-A"]["vouched"] is True


VOUCHING_INDEX = {"setups": {"machine-a": {"pushed_at": "2026-01-01T00:00:00Z"}}}


def test_an_exactly_named_setup_still_beats_a_case_variant_of_it():
    """The tightening that keeps the fold from being a gift: where the two
    spellings really are two directories - a case-SENSITIVE Destination - the
    one the Index names exactly is the one a key holder wrote, and the variant
    beside it gets nothing.

    Stated against the rule rather than through a Destination, because
    whether a filesystem can hold both spellings at once is the filesystem's
    decision, and this machine's answer is not the interesting one."""
    assert sync._vouched_machines(VOUCHING_INDEX, {"machine-a", "MACHINE-A"}) \
        == {"machine-a": "machine-a"}


def test_two_case_variants_and_no_exact_name_vouch_for_neither():
    """Ambiguity is not vouching. Two directories folding to one Index entry
    with nothing named exactly means carryon cannot say which one the key
    holder wrote, and guessing is what the vouched flag exists to avoid."""
    assert sync._vouched_machines(VOUCHING_INDEX,
                                  {"MACHINE-A", "Machine-A"}) == {}


# --- a member of a stored tree that produces neither a write nor a refusal ---


def test_a_symlinked_directory_member_of_a_stored_tree_is_named(tmp_path,
                                                                paired):
    """_tree_members filters with `not p.is_dir()`, which follows a symlink,
    so a linked DIRECTORY member is dropped before the is_symlink() refusal
    beside it can see it: no write, no refusal, no report line. That is the
    silent drop _setup_writes' docstring rules out."""
    staging = tmp_path / "staging"
    (staging / "claude" / "commands").mkdir(parents=True)
    (staging / "claude" / "commands" / "ship.md").write_text(GOOD_COMMAND)
    (staging / "claude" / "commands" / "pwn").symlink_to(
        paired.home_b / ".ssh")
    doc = manifest([item(".claude/commands", "claude/commands", kind="tree")])

    cfg = config.load(paired.home_b)
    declared = sync._declared_paths(
        sync._effective_adapters(cfg, paired.home_b))
    writes, refused = sync._setup_writes(doc, staging, paired.home_b, declared)

    sources = [str(src) for _, src in writes]
    assert not any("id_ed25519" in s for s in sources), \
        "a linked directory member was read through"
    assert any("pwn" in label for label, _ in refused), \
        "a linked directory member was dropped with no line to show for it"
    assert any("ship.md" in s for s in sources), "the honest member still moves"


# --- the report line is the control, end to end ------------------------------


def test_a_planted_object_name_cannot_forge_a_line_of_the_pull_report(
        paired, capsys):
    """The destinations layer escapes what it prints; this is the same claim
    made where the user actually reads it - inside a real applied pull, whose
    Setup section this line is trying to overwrite."""
    os.symlink(paired.home_b / ".ssh" / "id_ed25519",
               stored_setup(paired.dest_root, "machine-a")
               / f"q\n{FORGERY}\nr")

    out = pull_report(paired.home_b, capsys)

    assert FORGERY not in out.splitlines(), \
        "a planted object name authored a line of the pull report"
    assert files_containing(paired.home_b, SECRET) == [".ssh/id_ed25519"]


def test_a_planted_machine_name_cannot_forge_a_line_of_the_pull_report(
        paired, capsys):
    """The destinations layer is not the only place a report line is built
    from a name the Destination chose. A directory under setups/ is a machine
    name as far as the catalogue is concerned, and it reaches four lines of
    the Setup section - the source, the refusals, the ignored list, and the
    prefix every write line names its source file under."""
    author_setup(paired.dest_root, f"evil\n{FORGERY}\nx",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})

    out = pull_report(paired.home_b, capsys)

    assert FORGERY not in out.splitlines(), \
        "a planted machine name authored a line of the pull report"
    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS


def test_a_manifest_agent_key_cannot_forge_a_line_of_the_pull_report(
        paired, capsys):
    """Every refusal in _setup_writes is labelled with the agent key out of
    the stored MANIFEST, and a JSON object key is as much the attacker's
    string as a filename is."""
    doc = manifest([item("/etc/passwd", "claude/settings.json")])
    doc["agents"] = {f"claude-code\n{FORGERY}\nz": doc["agents"]["claude-code"]}
    (stored_setup(paired.dest_root, "machine-a")
     / "MANIFEST.json").write_text(json.dumps(doc, indent=2))
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert FORGERY not in out.splitlines(), \
        "a MANIFEST agent key authored a line of the pull report"
    assert "refuse" in out, "the planted item is still refused by name"


def test_a_stored_tree_member_cannot_forge_a_line_of_the_pull_report(
        paired, capsys):
    """A tree item's write lines name the member, which comes from the stored
    tree rather than from the MANIFEST - so validating the MANIFEST's two
    fields does not reach it."""
    stored = stored_setup(paired.dest_root, "machine-a")
    (stored / "claude" / "commands" / f"a\n{FORGERY}\nb.md").write_text("hi\n")
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    out = pull_report(paired.home_b, capsys)

    assert FORGERY not in out.splitlines(), \
        "a stored tree member's name authored a line of the pull report"


# --- the feature still works -------------------------------------------------


def test_an_honest_pull_is_unchanged_by_all_of_the_above(paired, capsys):
    """The regression guard: none of these refusals may be bought by making
    an ordinary restore refuse, go quiet, or stop naming both sides."""
    out = pull_report(paired.home_b, capsys)

    claude = paired.home_b / ".claude"
    assert (claude / "settings.json").read_text() == GOOD_SETTINGS
    assert (claude / "CLAUDE.md").read_text() == GOOD_CLAUDE_MD
    assert (claude / "commands" / "ship.md").read_text() == GOOD_COMMAND
    assert "Setup: 3 file(s) written" in out
    assert "setups/machine-a/claude/settings.json" in out
