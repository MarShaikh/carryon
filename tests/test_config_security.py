"""carryon must never carry its own key material.

ADR-0008 lets a user handpick extra paths into their Setup and says the
fail-closed credential scanner protects them for free. It does not protect them
from carryon's OWN state: the fallback master.key under ~/.carryon is bare hex
that matches no pattern in secrets.py, so a handpicked path that lands there
would push, in the plaintext half of the Archive, the key that decrypts the
same Archive's History. The config that names the Destination and the
high-water mark that detects a rollback live there too.

Two ways a string comparison against '.carryon' misses the directory, and both
must be closed on BOTH legs - capture (config.py) and restore (sync.py):

  case    APFS and NTFS fold case, so '~/.Carryon/master.key' IS
          '~/.carryon/master.key' - one file under two names.
  symlink the guard is lexical on the unresolved path, so a link that resolves
          into ~/.carryon is lexically nowhere near '.carryon'.

And one way that misses it however carefully the rule is written, if the rule
is only ever asked about the path someone NAMED: both legs act on path trees
that are expanded after the answer. '~/.mytool' and '~/.claude/commands' are
innocent directories; a link one component inside either is read through on
the way out and written through on the way in. So the rule is asked again for
every path an expansion produces - and for every member of a restored
History, which is the third leg.

The rule is the same on all of them by construction (config.lands_in_state),
so they cannot drift into disagreeing again - the drift is exactly what left
the weaker spelling reachable on the capture leg while the restore leg already
folded. Every home here is synthetic; the "master.key" is invented bytes.
"""

import io
import json
import pathlib
import sys
import tarfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, config, history, rekey, sync  # noqa: E402
from carryon.adapters import CONFIG  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    GOOD_COMMAND, GOOD_SETTINGS, SETUP_CATEGORIES, author_setup, build_home_a,
    build_home_b, file_keyring, files_containing, item, manifest, ns, paired,
    remac_setup, stored_setup)

# The end-to-end restore-leg tests below re-stamp the tampered tree with
# remac_setup: since the Setup gained its authentication tag
# (test_setup_auth.py), an unstamped tamper is refused whole before the
# state carve-out under test here is ever consulted, and the carve-out must
# hold even for a Setup a hostile key holder authenticated.

FAKE_KEY = "00112233445566778899aabbccddeeff" * 2 + "\n"


def build_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def plant_state(home) -> pathlib.Path:
    """A ~/.carryon with a master.key in it, as a real machine has."""
    key = home / ".carryon" / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(FAKE_KEY)
    return key


# --- the capture leg: config.user_adapter must refuse its own state ----------


def test_capture_refuses_a_case_variant_of_carryon_state(tmp_path):
    """'~/.Carryon/master.key': on a case-folding filesystem this IS the master
    key, and the exact '.carryon' compare read only one of its names. Refused
    on a case-sensitive filesystem too, where the variant is harmless - that
    costs nothing, and assuming the filesystem does not fold costs the key."""
    home = build_home(tmp_path)
    plant_state(home)
    cfg = config.default_config()
    cfg["carry"] = ["~/.Carryon/master.key"]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    msg = str(exc.value)
    assert ".carryon" in msg.lower()
    assert "master key" in msg


def test_capture_refuses_a_symlink_that_resolves_into_carryon_state(tmp_path):
    """A handpicked path whose parts spell nothing like '.carryon' but which
    resolves there through a link the user has - or one an attacker with $HOME
    write access planted. capture reads through links (ADR-0007), so this would
    copy the master key into the plaintext Setup."""
    home = build_home(tmp_path)
    plant_state(home)
    (home / "vault").symlink_to(home / ".carryon")
    cfg = config.default_config()
    cfg["carry"] = ["~/vault/master.key"]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert ".carryon" in str(exc.value).lower()


def test_capture_refuses_a_symlinked_directory_into_carryon_state(tmp_path):
    """The whole directory, not just a leaf: '~/vault' with vault -> ~/.carryon
    would carry every file under it, key included."""
    home = build_home(tmp_path)
    plant_state(home)
    (home / "vault").symlink_to(home / ".carryon")
    cfg = config.default_config()
    cfg["carry"] = ["~/vault"]

    with pytest.raises(SystemExit):
        config.user_adapter(cfg, home=home)


ATTACKER_BYTES = "deadbeef" * 8 + "\n"


def push_setup(home, tmp_path, capsys=None):
    """An applied Setup-only push, with its report."""
    code = sync.push(ns(apply=True, category=SETUP_CATEGORIES), home)
    return code, (capsys.readouterr().out if capsys else "")


def test_capture_refuses_a_link_one_component_inside_a_handpicked_tree(
        tmp_path, capsys):
    """The whole point, end to end. '~/.mytool' is refused by nothing - and
    should not be - so guarding the handpicked ROOT guards nothing: the engine
    walks the tree, follows '.mytool/notes.md -> ~/.carryon/master.key' and
    copies the key's bytes into the plaintext Setup, under a report that says
    'SECRET SCAN: clean' because bare hex matches no pattern."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    key_file = home / ".carryon" / "master.key"
    assert key_file.is_file(), "this test needs the fallback file key"
    key_hex = key_file.read_text().strip()
    (home / ".mytool").mkdir()
    (home / ".mytool" / "conf.json").write_text("{}")
    (home / ".mytool" / "notes.md").symlink_to(key_file)
    cfg = config.load(home)
    cfg["carry"] = ["~/.mytool"]
    config.save(cfg, home)
    capsys.readouterr()

    code, out = push_setup(home, tmp_path, capsys)

    assert not files_containing(tmp_path / "archive", key_hex), \
        "the master key was published in the Archive's plaintext half"
    assert code != 0, "the push reported success over a refused Setup"
    assert ".mytool/notes.md" in out, "the offending path is not named"
    assert "carryon's own state" in out


def test_capture_refuses_a_link_inside_an_adapter_declared_tree(tmp_path,
                                                                capsys):
    """No handpicking involved: the same link inside ~/.claude/commands, which
    an adapter declares, never reaches config.py's guard at all."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    key_file = home / ".carryon" / "master.key"
    key_hex = key_file.read_text().strip()
    (home / ".claude" / "commands" / "notes.md").symlink_to(key_file)
    capsys.readouterr()

    code, out = push_setup(home, tmp_path, capsys)

    assert not files_containing(tmp_path / "archive", key_hex), \
        "the master key was published in the Archive's plaintext half"
    assert code != 0
    assert ".claude/commands" in out


def test_capture_still_reads_through_a_link_that_stays_out_of_state(tmp_path,
                                                                    capsys):
    """The fix is not 'refuse every symlink'. ADR-0007 says carryon reads
    through an externally owned path happily; only the ones landing in
    ~/.carryon are refused, and a Setup with an ordinary link in it still
    goes."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    (home / "notes").mkdir()
    (home / "notes" / "real.md").write_text("carried through the link\n")
    (home / ".claude" / "commands" / "linked.md").symlink_to(
        home / "notes" / "real.md")
    capsys.readouterr()

    code, out = push_setup(home, tmp_path, capsys)

    assert code == 0, out
    stored = (tmp_path / "archive" / "carryon" / "setups" / "machine-a"
              / "claude" / "commands" / "linked.md")
    assert stored.read_text() == "carried through the link\n"


def test_carry_cannot_leave_home_through_a_doubled_slash(tmp_path):
    """'~/' is stripped by string surgery, so '~//abs/path' arrived at the
    $HOME boundary check as an absolute path with its branch already spent -
    and published a file from outside $HOME in the plaintext Setup."""
    home = build_home(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("not under $HOME\n")
    cfg = config.default_config()
    cfg["carry"] = ["~/" + str(outside / "loot.txt")]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "outside $HOME" in str(exc.value)


@pytest.mark.parametrize("spelling", ["~/foo\x00bar", "~/\ud800"])
def test_carry_a_path_no_filesystem_can_spell_is_a_refusal(tmp_path,
                                                           spelling):
    """A NUL comes back from resolve() as a ValueError and a lone surrogate as
    a UnicodeEncodeError, neither of which the state guard's except clause
    named - so one bad line in config.json was a traceback out of every
    command rather than a sentence."""
    home = build_home(tmp_path)
    plant_state(home)
    cfg = config.default_config()
    cfg["carry"] = [spelling]

    with pytest.raises(SystemExit):
        config.user_adapter(cfg, home=home)


def test_capture_positive_control_an_ordinary_path_still_carries(tmp_path):
    """The fix is not 'refuse everything': a path that does not land in
    ~/.carryon still becomes a handpicked Item the engine will capture."""
    home = build_home(tmp_path)
    plant_state(home)
    (home / ".mytool").mkdir()
    (home / ".mytool" / "conf.json").write_text("{}")
    cfg = config.default_config()
    cfg["carry"] = ["~/.mytool"]

    adapter = config.user_adapter(cfg, home=home)
    assert [i.src for i in adapter.items] == [".mytool"]
    assert adapter.items[0].category == CONFIG


# --- the restore leg: sync._setup_target must refuse the same -----------------
#
# The restore leg already folded case on parts[0], so the case-variant test
# below was green before the fix - it is a regression guard, not the red one.
# The symlink and --force tests are the ones that were red: the restore guard
# was lexical too, so a path resolving into ~/.carryon walked straight past it.


def test_restore_refuses_a_case_variant_of_carryon_state(paired, capsys):
    """Regression guard on the restore leg (was already green): a stored
    MANIFEST naming '.Carryon/master.key' is refused, the file untouched."""
    author_setup(paired.dest_root, "machine-a",
                 [item(".Carryon/master.key", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert ".Carryon/master.key" in out
    assert "refuse" in out


def test_restore_refuses_a_declared_src_that_resolves_into_carryon_state(
        paired):
    """The restore leg's real gap: a src whose first component is not
    '.carryon' but which resolves there through a link - and which an adapter
    declares, so declared-ness alone lets it through. The state check has to
    sit BEFORE the declared check and win regardless."""
    (paired.home_b / "vault").symlink_to(paired.home_b / ".carryon")
    # 'somehow declared' - the state refusal must not depend on this being
    # false; it precedes the declared check by design.
    declared = ({"vault/master.key"}, set())

    target, why = sync._setup_target("vault/master.key", paired.home_b,
                                     declared)
    assert target is None, "a declared src resolving into ~/.carryon was allowed"
    assert why is not None


def test_restore_symlink_into_carryon_state_leaves_the_key_untouched(
        paired, capsys):
    """The same shape end to end: a stored MANIFEST names a src that resolves
    into ~/.carryon through a link in the pulling home. The master key must be
    exactly as it was, and the item named in the report."""
    (paired.home_b / "vault").symlink_to(paired.home_b / ".carryon")
    author_setup(paired.dest_root, "machine-a",
                 [item("vault/master.key", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert "vault/master.key" in out


def test_pull_force_never_writes_into_carryon_state(paired, capsys):
    """--force means 'write through a dotfiles link I own' (ADR-0007), never
    'write into carryon's own state'. With ~/.claude/commands linked into
    ~/.carryon, the declared tree item '.claude/commands' resolves there; under
    --force the write used to go through the link into ~/.carryon."""
    claude = paired.home_b / ".claude"
    (claude / "commands").symlink_to(paired.home_b / ".carryon")
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()
    author_setup(paired.dest_root, "machine-a",
                 [item(".claude/commands", "claude/commands", kind="tree")],
                 files={"claude/commands/ship.md": GOOD_COMMAND})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / ".carryon" / "ship.md").exists(), \
        "--force wrote a Setup file into ~/.carryon through a link"
    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert "commands" in out and "refuse" in out


# --- the restore leg, one component below the item root ----------------------
#
# The item root is what _setup_target checks. A stored tree expands into
# members whose names come from the tree rather than from the MANIFEST, and
# under --force nothing after that check stands between a member and the
# write: --force discards ADR-0007's deference, which is what was quietly
# catching these.


@pytest.mark.parametrize("member", ["master.key", "config.json"])
def test_force_never_writes_through_a_link_below_the_item_root(paired, capsys,
                                                               member):
    """'.claude/commands' resolves to itself, so the item passes. The stored
    member 'sub/master.key' lands through '.claude/commands/sub -> ~/.carryon'
    and replaced the key that opens this very Archive; the config.json
    spelling rewrites the file that names the Destination."""
    claude = paired.home_b / ".claude"
    (claude / "commands").mkdir(parents=True, exist_ok=True)
    (claude / "commands" / "sub").symlink_to(paired.home_b / ".carryon")
    before = (paired.home_b / ".carryon" / member).read_bytes()
    author_setup(paired.dest_root, "machine-a",
                 [item(".claude/commands", "claude/commands", kind="tree")],
                 files={"claude/commands/sub/" + member: ATTACKER_BYTES})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / member).read_bytes() == before, \
        "--force wrote a stored member into ~/.carryon through a link"
    assert "refuse" in out and member in out


def test_force_never_writes_through_a_leaf_link(paired, capsys):
    """The link is the member itself rather than a directory above it."""
    claude = paired.home_b / ".claude"
    (claude / "commands").mkdir(parents=True, exist_ok=True)
    (claude / "commands" / "notes.md").symlink_to(
        paired.home_b / ".carryon" / "master.key")
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()
    author_setup(paired.dest_root, "machine-a",
                 [item(".claude/commands", "claude/commands", kind="tree")],
                 files={"claude/commands/notes.md": ATTACKER_BYTES})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert "refuse" in out and "notes.md" in out


def test_force_still_writes_an_ordinary_member_through_a_dotfiles_link(
        paired, capsys):
    """The control for the two above: --force exists to write through a link
    the user owns (ADR-0007), and it still does - only ~/.carryon is out of
    bounds."""
    claude = paired.home_b / ".claude"
    owned = paired.home_b / "dotfiles" / "commands"
    owned.mkdir(parents=True)
    (claude / "commands").symlink_to(owned)
    author_setup(paired.dest_root, "machine-a",
                 [item(".claude/commands", "claude/commands", kind="tree")],
                 files={"claude/commands/ship.md": GOOD_COMMAND})
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    capsys.readouterr()

    assert (owned / "ship.md").read_text() == GOOD_COMMAND


# --- the third leg: a restored History ---------------------------------------


def one_member_tar(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_a_restored_session_never_writes_into_state(tmp_path):
    """unpack_session derives its root from a cwd the Archive recorded and
    writes tar members under it. Link that project dir into ~/.carryon and a
    member named 'master.key' lands on the key - the same shape as both Setup
    legs, on the leg neither of them covers.

    The key surviving is the property; a SystemExit is not. The refusal used
    to resolve, which made one planted link a permanent abort of every pull
    from every machine (ADR-0009 rules that shape out in as many words), so a
    path that only RESOLVES into the state directory is deference like any
    other link and a path that SPELLS it still refuses - see the test below.
    """
    home = build_home(tmp_path)
    key = plant_state(home)
    root = (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / "p")))
    root.parent.mkdir(parents=True)
    root.symlink_to(home / ".carryon")

    _, report = history.unpack_session(
        one_member_tar("master.key", b"deadbeef\n"),
        {"agent": "claude-code", "cwd": str(home / "p")}, home)

    assert key.read_text() == FAKE_KEY, "a Session member overwrote the key"
    assert report.members == 0 and len(report.deferred) == 1


def test_a_restored_session_refuses_a_member_that_spells_state(tmp_path):
    """And the half that is a key holder's doing: no link anywhere, the
    derived root itself under ~/.carryon."""
    home = build_home(tmp_path)
    key = plant_state(home)

    with pytest.raises(SystemExit) as exc:
        sync._extract_tree(one_member_tar("master.key", b"deadbeef\n"),
                           home / ".carryon", home, [])

    assert key.read_text() == FAKE_KEY
    assert "carryon" in str(exc.value)


def test_restored_project_residue_never_writes_into_state(tmp_path):
    """The residue half of the same leg: _extract_tree writes under a root
    derived the same way."""
    home = build_home(tmp_path)
    key = plant_state(home)
    root = home / "project"
    root.symlink_to(home / ".carryon")
    deferred = []

    written, _, _, _, _ = sync._extract_tree(
        one_member_tar("master.key", b"deadbeef\n"), root, home, [],
        deferred=deferred)

    assert key.read_text() == FAKE_KEY
    assert (written, len(deferred)) == (0, 1)


def test_a_divergent_session_still_lands_in_the_conflicts_directory(tmp_path):
    """The one caller whose root IS carryon's own state, on purpose: a
    divergent incoming copy is kept under ~/.carryon/conflicts rather than in
    the agent's tree, where it would be discovered as a phantom Session
    (ADR-0002). The state rule must not swallow that."""
    home = build_home(tmp_path)
    plant_state(home)
    conflicts = home / ".carryon" / "conflicts" / "uuid"

    written, _, _, _, _ = sync._extract_tree(
        one_member_tar("main.jsonl", b"{}\n"), conflicts, home, [],
        into_state=True)

    assert written == 1
    assert (conflicts / "main.jsonl").read_bytes() == b"{}\n"


# --- one rule, every leg -----------------------------------------------------


def test_both_legs_consult_the_one_shared_rule(tmp_path, paired):
    """The drift that made the weaker spelling reachable was two spellings of
    one rule. Pin it: the capture leg and the restore leg refuse the SAME
    symlink-resolving path, and do so through config.lands_in_state."""
    assert sync.config.lands_in_state is config.lands_in_state

    home = build_home(tmp_path)
    plant_state(home)
    (home / "vault").symlink_to(home / ".carryon")

    # capture leg
    cfg = config.default_config()
    cfg["carry"] = ["~/vault/master.key"]
    with pytest.raises(SystemExit):
        config.user_adapter(cfg, home=home)

    # restore leg, same shape, same home
    target, why = sync._setup_target("vault/master.key", home,
                                     ({"vault/master.key"}, set()))
    assert target is None and why is not None


def test_lands_in_state_folds_case_and_follows_links(tmp_path):
    """The rule itself, in isolation. A sibling like '.carryon-backup' must not
    trip it (the comparison is per path component, not a string prefix)."""
    home = build_home(tmp_path)
    (home / ".carryon").mkdir()
    (home / "vault").symlink_to(home / ".carryon")

    assert config.lands_in_state(home / ".carryon" / "master.key", home)
    assert config.lands_in_state(home / ".Carryon" / "master.key", home)
    assert config.lands_in_state(home / "vault" / "master.key", home)
    assert config.lands_in_state(home / ".carryon", home)
    assert not config.lands_in_state(home / ".carryon-backup" / "x", home)
    assert not config.lands_in_state(home / ".mytool" / "conf.json", home)


def test_a_linked_directory_into_state_inside_a_captured_tree_is_refused(
        tmp_path, capsys):
    """rglob does not descend into a linked directory, so this one leaks no
    content today - and is refused anyway. What the walk happens to do with a
    link is not something the state rule should depend on."""
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    (home / ".claude" / "commands" / "sub").symlink_to(home / ".carryon")
    capsys.readouterr()

    code, out = push_setup(home, tmp_path, capsys)

    assert code != 0
    assert "carryon's own state" in out


# --- the same rule about carryon's own writes --------------------------------
#
# Everything above is about what carryon must not READ out of its state
# directory, or write INTO it. This is the other direction and the same ADR:
# the two files carryon keeps there are written with plain opens, and a link
# standing at either name sends the write through it - into the dotfiles repo
# that put the link there. The config names the Destination; the file beside it
# is the master key. carryon defers to whatever owns a path (ADR-0007) and
# these are the two writes in the package that did not.


def test_the_config_is_never_written_through_a_link(tmp_path):
    home = build_home(tmp_path)
    (home / ".carryon").mkdir()
    elsewhere = tmp_path / "dotfiles" / "carryon.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text('{"someone": "else"}\n')
    (home / ".carryon" / "config.json").symlink_to(elsewhere)
    cfg = config.default_config()
    cfg["destination"] = str(tmp_path / "archive")

    with pytest.raises(SystemExit) as exc:
        config.save(cfg, home)

    assert "config.json" in str(exc.value), "the refusal does not name the file"
    assert elsewhere.read_text() == '{"someone": "else"}\n', \
        "carryon wrote its config through a link into another tree"


def test_carryons_own_config_is_still_rewritten_in_place(tmp_path):
    """The ordinary case the refusal must not break: `carryon init` run twice,
    over a config carryon itself wrote."""
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["destination"] = str(tmp_path / "archive")
    config.save(cfg, home)
    cfg["machine"] = "renamed"

    config.save(cfg, home)

    assert config.load(home)["machine"] == "renamed"


def test_a_state_directory_that_is_a_file_is_a_sentence_not_a_traceback(
        tmp_path):
    """The mkdir above the write, guarded for the same reason config.load's
    read is: ~/.carryon standing there as an ordinary file - a restored
    backup, a stray redirect - is a FileExistsError that exist_ok forgives
    only for a directory, straight out of `carryon init`."""
    home = build_home(tmp_path)
    (home / ".carryon").write_text("not a directory\n")
    cfg = config.default_config()
    cfg["destination"] = str(tmp_path / "archive")

    with pytest.raises(SystemExit) as exc:
        config.save(cfg, home)

    assert ".carryon" in str(exc.value), "the refusal does not name the path"
