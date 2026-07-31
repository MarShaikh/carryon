"""Attack tests for the Setup half of a Snapshot: both directions distrust.

setups/ is plaintext and unauthenticated by design - ADR-0004 has pushing a
Setup need no master key at all - so anyone who can write to the Destination
can author a MANIFEST.json: a git collaborator, the storage provider, a
compromised synced-folder account. The attacker modelled here holds no master
key and only writes files under the Destination root.

On the way in, two legs driven by the same MANIFEST: `src` says where a
restored file lands on this machine, `dst` says which packed file it is read
from. These tests assert a pull neither writes where the attacker points nor
reads what the attacker names, and that the Setup a pull trusts is not chosen
by a timestamp - or a directory name - out of that same plaintext tree.

$HOME is not the boundary those tests once assumed. It holds ~/.zshrc and
~/.ssh/authorized_keys, so `src` is held to the paths the LOCAL adapters
declare: the set this machine already agreed to carry. That is also the only
rule that survives --force, which discards the ADR-0007 deference the lexical
containment check leans on.

On the way out, the Destination is honest-but-curious and the question is what
a push tells it. ADR-0006 leaves the Archive machine-neutral, and CONTEXT.md
puts it plainly: what sits in the Archive does not mention your laptop's home
at all. The last tests here hold the plaintext half to that, whole-tree.

Every home here is synthetic, the OS keychain is forced to the fallback file,
and the "secret" planted in the victim's home is invented text.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import config, destinations, rekey, sync  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    EVIL_SETTINGS, GOOD_CLAUDE_MD, GOOD_COMMAND, GOOD_SETTINGS, SECRET,
    SETUP_CATEGORIES, ListsOneExtraKey, author_setup, build_home_a,
    build_home_b, file_keyring, files_containing, item, link_home, manifest,
    ns, paired, remac_setup, stored_setup)

# Since the Setup gained its authentication tag (test_setup_auth.py), a tree
# edited by a KEYLESS attacker is refused whole before any item is read. The
# item-level guards these tests assert still have to hold - a hostile or
# compromised key holder produces exactly an authenticated tree full of
# malicious items - so each tamper below is re-stamped with remac_setup to
# model that source, and the guards stay the thing under test.


# --- the write leg: src decides where a restored file lands ------------------


def test_absolute_src_is_not_written(tmp_path, paired, capsys):
    """`pathlib.Path(home) / "/etc/cron.d/x"` collapses to the absolute path -
    pathlib drops the left operand - so an absolute src writes wherever the
    attacker likes with the user's own permissions."""
    landing = tmp_path / "pwned" / "cron.d" / "x"
    author_setup(paired.dest_root, "machine-a",
                 [item(str(landing), "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not landing.exists(), "an absolute src wrote outside $HOME"
    assert not landing.parent.exists(), "an absolute src created directories"
    assert str(landing) in out, "the refused item is named, not dropped"


def test_src_climbing_out_of_home_is_not_written(tmp_path, paired, capsys):
    landing = tmp_path / "outside" / "evil.txt"
    author_setup(paired.dest_root, "machine-a",
                 [item("../outside/evil.txt", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not landing.exists(), "'..' in src escaped $HOME"
    assert "../outside/evil.txt" in out


def test_src_pointing_into_carryons_own_state_is_not_written(paired, capsys):
    """~/.carryon holds the fallback master.key and the config naming the
    Destination - the carve-out config._relative_to_home already makes."""
    author_setup(paired.dest_root, "machine-a",
                 [item(".carryon/master.key", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert ".carryon/master.key" in out


# --- the read leg: dst decides which local file is copied --------------------


def test_dst_climbing_out_of_the_staging_dir_reads_nothing(paired, capsys):
    """Enough '..' segments reach the filesystem root from any staging depth,
    so the packed source becomes an arbitrary local file - and its bytes land
    at whatever src names, which may be a synced folder or the git clone."""
    secret = paired.home_b / ".ssh" / "id_ed25519"
    author_setup(paired.dest_root, "machine-a",
                 [item("leak.txt", "../" * 40 + str(secret).lstrip("/"))])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / "leak.txt").exists()
    assert files_containing(paired.home_b, SECRET) == [".ssh/id_ed25519"], \
        "the secret was copied somewhere the attacker chose"
    assert SECRET not in out
    assert "leak.txt" in out, "the refused item is named, not dropped"


def test_absolute_dst_reads_nothing(paired, capsys):
    secret = paired.home_b / ".ssh" / "id_ed25519"
    author_setup(paired.dest_root, "machine-a",
                 [item("leak.txt", str(secret))])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / "leak.txt").exists()
    assert files_containing(paired.home_b, SECRET) == [".ssh/id_ed25519"]
    assert SECRET not in out


def test_a_refused_item_does_not_stop_the_rest_of_the_setup(
        tmp_path, paired, capsys):
    """Fail closed per item, not per pull: the honest items still land, so a
    refusal cannot be turned into a denial of service on the whole Setup."""
    author_setup(paired.dest_root, "machine-a", [
        item(str(tmp_path / "pwned" / "x"), "claude/settings.json"),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
    ])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    capsys.readouterr()

    assert (paired.home_b / ".claude" / "CLAUDE.md").read_text() == \
        GOOD_CLAUDE_MD


# --- choosing whose Setup to restore -----------------------------------------


def test_a_planted_machine_cannot_win_on_a_forged_timestamp(paired, capsys):
    """captured_at lives in the same plaintext tree the attacker authored, so
    a value of 9999 beats every honest ISO timestamp. Only the encrypted
    Index says which machines a key holder ever pushed a Setup for."""
    author_setup(paired.dest_root, "evil",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "the planted Setup won on its forged captured_at"
    assert "evil" in out, "the ignored machine is named, not dropped"
    assert "machine-a" in out


def test_a_planted_machine_alone_is_not_restored(tmp_path, capsys):
    """Nothing vouched for and more than one candidate: carryon restores none
    rather than let the attacker's timestamp decide."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    # a keyless Setup push records nothing in the Index (ADR-0004); simulate
    # that Archive by removing the Index the keyed push wrote
    (tmp_path / "archive" / "carryon" / "index.enc").unlink()
    author_setup(tmp_path / "archive", "evil",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)

    # 2: the Archive holds a Setup and carryon would use none of it.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert not (home_b / ".claude" / "settings.json").exists(), \
        "an unvouched Setup was restored while another candidate existed"
    assert "evil" in out and "machine-a" in out


# --- the feature still works -------------------------------------------------


def test_an_honest_setup_restores_and_the_report_names_both_sides(
        paired, capsys):
    """The regression guard: none of the above may be bought by breaking the
    restore. The report shows source and target, so an exfiltration attempt
    is visible in the dry run instead of reading as a normal write."""
    assert sync.pull(ns(apply=False), paired.home_b) == 0
    dry = capsys.readouterr().out
    assert not (paired.home_b / ".claude" / "settings.json").exists()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    claude = paired.home_b / ".claude"
    assert (claude / "settings.json").read_text() == GOOD_SETTINGS
    assert (claude / "CLAUDE.md").read_text() == GOOD_CLAUDE_MD
    assert (claude / "commands" / "ship.md").read_text() == GOOD_COMMAND

    for text in (dry, out):
        assert "~/.claude/settings.json" in text
        assert "setups/machine-a/claude/settings.json" in text, \
            "the report never names the file a write is read from"
        assert "setups/machine-a/claude/commands/ship.md" in text


# --- what a push tells the Destination ---------------------------------------


def build_home_c(tmp_path) -> pathlib.Path:
    """A machine whose skills directory holds a dotfiles symlink.

    The "typically a dotfiles repo" case capture.do_skills names, which is the
    default shape here: one skill in ~/.claude/skills points outside
    ~/.agents/skills, so capture resolves it and records an absolute local
    path. Nothing written into this home contains the home path itself, so an
    occurrence found in the Archive can only have come from carryon.

    Resolved on purpose: capture resolves symlink targets, and on macOS a tmp
    path ('/var/...') and its real form ('/private/var/...') are different
    strings - an unresolved home would make these tests pass or fail for a
    reason that has nothing to do with the Archive.
    """
    home = (tmp_path / "home_c").resolve()
    dotfiles = home / "dotfiles" / "skills" / "shipping"
    dotfiles.mkdir(parents=True)
    (dotfiles / "SKILL.md").write_text("Ship it.\n")

    claude = home / ".claude"
    skills = claude / "skills"
    skills.mkdir(parents=True)
    (skills / "shipping").symlink_to(dotfiles)
    (skills / "reviewing").mkdir()
    (skills / "reviewing" / "SKILL.md").write_text("Review it.\n")
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    (claude / "CLAUDE.md").write_text(GOOD_CLAUDE_MD)
    return home


def test_a_full_push_leaves_no_home_path_anywhere_in_the_archive(
        tmp_path, capsys):
    """The plaintext Setup names this machine's home nowhere - not in the
    MANIFEST, not in the RESTORE.md rendered from it.

    A resolved symlink target is an absolute path under $HOME, and it reaches
    the Destination in two files at once. Naming the leak per field is how it
    got there, so this walks the whole Archive instead."""
    home = build_home_c(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-c"), home)

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    capsys.readouterr()

    assert files_containing(dest_root, str(home)) == [], \
        "the Archive names this machine's home (ADR-0006)"

    # and the report is still usable on the machine that reads it
    stored = stored_setup(dest_root, "machine-c")
    doc = json.loads((stored / "MANIFEST.json").read_text())
    assert doc["source_home"] == "~"
    skills = [i for agent in doc["agents"].values()
              for i in agent["items"] if i["kind"] == "skills"]
    assert skills[0]["external"] == {"shipping": "~/dotfiles/skills/shipping"}
    notes = (stored / "RESTORE.md").read_text()
    assert "shipping  <- ~/dotfiles/skills/shipping" in notes, \
        "RESTORE.md no longer says where an external skill came from"


def test_a_partial_push_leaves_no_home_path_anywhere_in_the_archive(
        tmp_path, capsys):
    """The same promise on the overlay path, which writes its own MANIFEST and
    RESTORE.md: once with nothing stored yet, once merging onto what the first
    push left - two different pieces of code putting those files up."""
    home = build_home_c(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-c"), home)

    assert sync.push(ns(apply=True, category="capability"), home) == 0
    assert files_containing(dest_root, str(home)) == [], \
        "the first partial push named this machine's home"

    assert sync.push(ns(apply=True, category="capability"), home) == 0
    capsys.readouterr()

    assert files_containing(dest_root, str(home)) == [], \
        "the merged MANIFEST or RESTORE.md named this machine's home"
    notes = (stored_setup(dest_root, "machine-c") / "RESTORE.md").read_text()
    assert "~/dotfiles/skills/shipping" in notes


# --- the source a pull trusts: a directory name vouches for nothing ----------


def test_a_setup_named_after_this_machine_cannot_win_on_a_forged_timestamp(
        paired, capsys):
    """A machine name is a guessable string (socket.gethostname()), not a
    secret and not vouched by anything. Filing a planted Setup under the
    PULLING machine's own name must not buy it the timestamp contest."""
    author_setup(paired.dest_root, "machine-b",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".claude" / "settings.json").read_text() == \
        GOOD_SETTINGS, "a Setup named after this machine won on its own claim"
    assert "machine-b" in out, "the ignored machine is named, not dropped"


def test_an_unvouched_setup_named_after_this_machine_does_not_break_the_tie(
        tmp_path, capsys):
    """The deliberate fail-closed case: nothing vouched for, more than one
    candidate, restore none. Naming one of them after the pulling machine
    must not smuggle it past that."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    (tmp_path / "archive" / "carryon" / "index.enc").unlink()
    author_setup(tmp_path / "archive", "machine-b",
                 [item(".claude/settings.json", "claude/settings.json")],
                 captured_at="9999-12-31T23:59:59Z",
                 files={"claude/settings.json": EVIL_SETTINGS})
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)

    assert sync.pull(ns(apply=True), home_b) == 2
    capsys.readouterr()

    assert not (home_b / ".claude" / "settings.json").exists(), \
        "an unvouched Setup was restored because it carried this machine's name"


def test_the_unvouched_flag_describes_the_chosen_source(paired):
    """The one warning a user can act on must be about the Setup actually
    restored, not about whether any candidate existed at all."""
    setups = {"machine-a": {"pushed_at": "2026-01-01T00:00:00Z",
                            "vouched": True},
              "machine-b": {"pushed_at": "9999-12-31T23:59:59Z",
                            "vouched": False}}
    source, unvouched, ignored = sync._choose_setup_source(setups,
                                                           ["machine-a"],
                                                           False)
    assert source == "machine-a"
    assert unvouched is False
    assert ignored == ["machine-b"]


# --- src: what a stored MANIFEST is allowed to name --------------------------


def test_a_case_variant_of_carryons_own_state_is_not_written(paired, capsys):
    """macOS APFS and Windows fold case, so a byte comparison against
    '.carryon' is not the carve-out it reads as: '.Carryon/master.key'
    resolves to the same file."""
    author_setup(paired.dest_root, "machine-a",
                 [item(".Carryon/master.key", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    before = (paired.home_b / ".carryon" / "master.key").read_bytes()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert (paired.home_b / ".carryon" / "master.key").read_bytes() == before
    assert ".Carryon/master.key" in out, "the refused item is named"
    assert "refuse" in out


def test_a_case_variant_of_carryons_config_is_not_written(paired, capsys):
    """The config names the Destination and lists `carry` (ADR-0008); a
    planted one turns the next push into arbitrary $HOME file publication."""
    author_setup(paired.dest_root, "machine-a",
                 [item(".CARRYON/config.json", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)
    before = (paired.home_b / ".carryon" / "config.json").read_bytes()

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    capsys.readouterr()

    assert (paired.home_b / ".carryon" / "config.json").read_bytes() == before
    assert config.load(paired.home_b)["carry"] == []


def test_a_src_no_adapter_declares_is_not_written(paired, capsys):
    """$HOME is not a boundary against code execution: ~/.zshrc and
    ~/.ssh/authorized_keys are both under it and both run on next login.
    A restore fills in the paths this machine already carries."""
    author_setup(paired.dest_root, "machine-a", [
        item(".zshrc", "claude/settings.json"),
        item(".ssh/authorized_keys", "claude/settings.json"),
    ])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert not (paired.home_b / ".zshrc").exists()
    assert not (paired.home_b / ".ssh" / "authorized_keys").exists()
    assert ".zshrc" in out and ".ssh/authorized_keys" in out


def test_force_does_not_turn_an_undeclared_src_into_a_write_anywhere(
        tmp_path, paired, capsys):
    """--force means 'write through the dotfiles link I own', not 'write
    anywhere': the src is still the attacker's, and ~/mnt -> /outside makes
    a lexically contained path land outside $HOME."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (paired.home_b / "mnt").symlink_to(outside)
    author_setup(paired.dest_root, "machine-a",
                 [item("mnt/evil.sh", "claude/settings.json")])
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    capsys.readouterr()

    assert not (outside / "evil.sh").exists(), "--force wrote outside $HOME"


def test_force_still_writes_through_a_dotfiles_link_for_a_declared_path(
        paired, capsys):
    """The regression guard on the rule above: --force keeps meaning what
    ADR-0007 says it means for a path an adapter declares."""
    dotfiles = paired.home_b / "dotfiles"
    dotfiles.mkdir()
    (dotfiles / "CLAUDE.md").write_text("B's own.\n")
    (paired.home_b / ".claude" / "CLAUDE.md").symlink_to(
        dotfiles / "CLAUDE.md")

    assert sync.pull(ns(apply=True, force=True), paired.home_b) == 0
    capsys.readouterr()

    assert (dotfiles / "CLAUDE.md").read_text() == GOOD_CLAUDE_MD


def test_a_symlink_inside_a_stored_tree_item_is_not_read_through(
        tmp_path, paired):
    """A tree item is expanded with rglob into per-file writes, and the
    containment check ran on the item's root only. A link among the members
    is read through even though the root validated."""
    staging = tmp_path / "staging"
    (staging / "claude" / "commands").mkdir(parents=True)
    (staging / "claude" / "commands" / "ship.md").write_text(GOOD_COMMAND)
    (staging / "claude" / "commands" / "pwn.md").symlink_to(
        paired.home_b / ".ssh" / "id_ed25519")
    doc = manifest([item(".claude/commands", "claude/commands", kind="tree")])

    cfg = config.load(paired.home_b)
    declared = sync._declared_paths(
        sync._effective_adapters(cfg, paired.home_b))
    writes, refused = sync._setup_writes(doc, staging, paired.home_b, declared)

    sources = [str(src) for _, src in writes]
    assert not any("pwn.md" in s for s in sources), \
        "a symlinked member of a tree item was read through"
    assert any("ship.md" in s for s in sources), "the honest member still moves"


def test_a_missing_packed_file_is_named_rather_than_silently_dropped(
        paired, capsys):
    """A Destination with write access can delete individual stored files.
    Dropping them silently reads as a clean restore that is quietly short."""
    author_setup(paired.dest_root, "machine-a", [
        item(".claude/settings.json", "claude/settings.json"),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),
    ], files={"claude/settings.json": GOOD_SETTINGS})
    (stored_setup(paired.dest_root, "machine-a")
     / "claude" / "CLAUDE.md").unlink()
    # re-stamped AFTER the deletion: the missing-file naming under test is
    # the MANIFEST item's, not the authentication tag's
    remac_setup(paired.dest_root, "machine-a", paired.home_a)

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out

    assert "claude/CLAUDE.md" in out
    assert "refuse" in out, \
        "a stored file the Destination removed is not reported at all"


def test_a_bare_file_where_a_setup_tree_belongs_does_not_abort_the_pull(
        paired, capsys):
    """An attacker-triggered abort after the History has been laid down is
    still an abort. A key that names no directory of its own is not a Setup."""
    tree = paired.dest_root / "carryon" / "setups" / "machine-a"
    for path in sorted(tree.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    tree.rmdir()
    tree.write_text("not a Setup")

    assert sync.pull(ns(apply=True), paired.home_b) == 0
    out = capsys.readouterr().out
    assert "Setup:" in out


def test_a_machine_name_no_destination_key_can_hold_is_skipped_not_fatal(
        tmp_path, paired, capsys, monkeypatch):
    """The catalogue filtered '.' and '..' and admitted everything else.

    A backslash is legal in a directory name on every filesystem carryon runs
    on, and not in a key. So the name went into the catalogue and came back
    out of the very next read as a ValueError - a traceback out of a pull
    whose History was already on disk, which an attacker with write access to
    the Destination could trigger at will."""
    evil = "carryon/setups/back\\slash/MANIFEST.json"
    real = destinations.from_spec(paired.dest_spec, paired.home_b)
    monkeypatch.setattr(sync.destinations, "from_spec",
                        lambda spec, home: ListsOneExtraKey(real, evil))

    assert sync.pull(ns(apply=True), paired.home_b) == 0, \
        "a machine name carryon cannot even ask for aborted the pull"
    out = capsys.readouterr().out

    assert "back" in out, "the skipped machine is not named in the report"
    assert "machine-a" in out, "the honest Setup was lost with the bad name"
    assert (paired.home_b / ".claude" / "settings.json").is_file()


def test_a_setup_named_dot_does_not_enter_the_catalogue(paired):
    """'.' passes require_key, so leaving the name check to it would admit a
    machine whose stored Setup is the setups/ directory itself - a competitor
    in the tie-break that no push ever wrote."""
    assert sync._machine_name_refusal(".", has_tree=True) is not None
    assert sync._machine_name_refusal("..", has_tree=True) is not None
    assert sync._machine_name_refusal("machine-a", has_tree=True) is None


def test_every_manifest_item_is_either_written_or_refused(tmp_path, paired):
    """The function's own docstring: a refused item comes back named rather
    than dropped, because a silent skip reads as a restore that is quietly
    missing a file. Three items, three fates - a file the Destination
    deleted, a tree it emptied, and an honest file - and the two lists must
    account for all three."""
    staging = tmp_path / "staging-accounting"
    (staging / "claude" / "commands").mkdir(parents=True)
    (staging / "claude" / "settings.json").write_text(GOOD_SETTINGS)
    doc = manifest([
        item(".claude/settings.json", "claude/settings.json"),
        item(".claude/CLAUDE.md", "claude/CLAUDE.md"),       # never stored
        item(".claude/commands", "claude/commands", kind="tree"),  # emptied
    ])

    cfg = config.load(paired.home_b)
    declared = sync._declared_paths(
        sync._effective_adapters(cfg, paired.home_b))
    writes, refused = sync._setup_writes(doc, staging, paired.home_b, declared)

    assert len(writes) == 1
    assert len(refused) == 2, (
        "an item that yields neither a write nor a refusal is the silent "
        f"drop the docstring rules out; got {refused}")
    assert any("commands" in label for label, _ in refused)


# --- what a push tells the Destination, in every spelling of the home --------


def build_home_d(tmp_path, name="home_d") -> pathlib.Path:
    """Like build_home_c but the home is NOT pre-resolved: `home` is a
    symlink to `real`, which is what $HOME looks like on plenty of machines
    (/home/x -> /export/home/x, an external volume, an automounted home)."""
    real = tmp_path / (name + "_real")
    real.mkdir()
    home = tmp_path / name
    home.symlink_to(real)

    dotfiles = home / "dotfiles" / "skills" / "shipping"
    dotfiles.mkdir(parents=True)
    (dotfiles / "SKILL.md").write_text("Ship it.\n")
    claude = home / ".claude"
    skills = claude / "skills"
    skills.mkdir(parents=True)
    (skills / "shipping").symlink_to(dotfiles)
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    (claude / "CLAUDE.md").write_text(GOOD_CLAUDE_MD)
    return home, real


def test_a_symlinked_home_is_still_neutralised(tmp_path, capsys):
    """capture records `path.resolve()`; the CLI hands push an unresolved
    $HOME. A byte-exact prefix compare between the two misses, and the real
    home travels into MANIFEST.json and RESTORE.md."""
    home, real = build_home_d(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-d"), home)

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    capsys.readouterr()

    assert files_containing(dest_root, str(real)) == [], \
        "the Archive names the machine's real home"
    assert files_containing(dest_root, str(home)) == []


def test_a_path_outside_home_is_withheld_from_the_archive(tmp_path, capsys):
    """A skill symlinked to a team share names a directory on this machine.
    An Archive names no machine (ADR-0006), and 'outside $HOME' does not
    make an absolute path less identifying."""
    home = (tmp_path / "home_e").resolve()
    shared = (tmp_path / "opt" / "team" / "skills" / "ops")
    shared.mkdir(parents=True)
    (shared / "SKILL.md").write_text("Ops.\n")
    claude = home / ".claude"
    (claude / "skills").mkdir(parents=True)
    (claude / "skills" / "ops").symlink_to(shared)
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-e"), home)

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    capsys.readouterr()

    assert files_containing(dest_root, str(shared)) == [], \
        "an external path outside $HOME reached the Archive verbatim"


def test_a_case_variant_home_is_not_published(tmp_path):
    """macOS is case-insensitive, so a symlink target can be stored as
    /users/alice while $HOME is /Users/alice, and resolve() does not
    case-normalise. ADR-0006 forbids folding case when rewriting - so the
    value is withheld rather than shipped."""
    home = tmp_path / "Home_f"
    home.mkdir()
    variant = str(home).replace("Home_f", "home_f")
    doc = {"agents": {"claude-code": {"items": [
        {"src": ".claude/skills", "dst": "claude/skills", "kind": "skills",
         "external": {"shipping": variant + "/dotfiles/skills/shipping"}}]}}}

    neutral, withheld = sync._neutralise_manifest(doc, home)
    published = json.dumps(neutral)
    assert variant not in published, "a case-variant home was published"
    assert withheld >= 1


def test_a_unicode_variant_home_is_not_published(tmp_path):
    """NFC vs NFD for an accented username: capture's resolve() preserves
    whichever form the link holds, and the two are different strings."""
    import unicodedata
    home = tmp_path / unicodedata.normalize("NFC", "José")
    home.mkdir()
    decomposed = unicodedata.normalize("NFD", str(home))
    doc = {"agents": {"claude-code": {"items": [
        {"src": ".claude/skills", "dst": "claude/skills", "kind": "skills",
         "external": {"shipping": decomposed + "/dotfiles/skills/x"}}]}}}

    neutral, _ = sync._neutralise_manifest(doc, home)
    published = json.dumps(neutral, ensure_ascii=False)
    assert decomposed not in published
    assert "~/dotfiles/skills/x" in published, \
        "a decomposed home should canonicalise, not merely vanish"


def test_a_home_in_the_middle_of_a_value_is_neutralised(tmp_path):
    """_canon_home strips a prefix; rekey rewrites every occurrence. The
    docstring promises the stronger guarantee, so the next adapter that
    records descriptive text with a path in it must inherit it."""
    home = tmp_path / "home_g"
    home.mkdir()
    value = f"shipping -> {home}/dotfiles/skills/shipping (dotfiles)"
    assert str(home) not in sync._canon_home(value, home)


def test_a_captured_files_content_names_no_home(tmp_path, capsys):
    """The Setup carries the CONTENT of settings.json and CLAUDE.md, and a
    hook command or an instruction line routinely spells the home out. The
    Archive is machine-neutral whole-tree, not just in the two files carryon
    generates itself."""
    home = (tmp_path / "home_h").resolve()
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text(
        json.dumps({"hooks": {"Stop": f"{home}/bin/notify"}}))
    (claude / "CLAUDE.md").write_text(f"Notes live in {home}/notes.\n")
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-h"), home)

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    capsys.readouterr()

    assert files_containing(dest_root, str(home)) == [], \
        "the captured files name this machine's home"


def test_a_file_that_is_not_utf8_does_not_carry_the_home_into_the_archive(
        tmp_path, capsys):
    """Neutralisation skipped anything that failed to decode, which is a
    decision by accident rather than by intent: the docstring justified it
    with images in a skill, and it covered every latin-1 note, every
    truncated log and every file with one stray byte in it - each of which
    carries the home verbatim into the plaintext half of the Archive."""
    home = (tmp_path / "home_n").resolve()
    skill = home / ".claude" / "skills" / "shipping"
    skill.mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(GOOD_SETTINGS)
    (skill / "SKILL.md").write_text("Ship it.\n")
    (skill / "notes.bin").write_bytes(
        b"\xff\xfe" + f"cache lives at {home}/.cache\n".encode())
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-n"), home)

    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home) == 0
    out = capsys.readouterr().out

    assert files_containing(dest_root, str(home)) == [], \
        "a file that is not UTF-8 carried this machine's home to the Archive"
    assert "notes.bin" in out, \
        "a file the push declined to neutralise must be named in the report"
    assert files_containing(dest_root, "Ship it.") != [], \
        "the rest of the skill still travels"


def test_a_restored_setup_expands_the_home_against_this_machine(
        tmp_path, capsys):
    """The other half of the promise: a machine-neutral Setup is only useful
    if the pulling machine expands it against its own home."""
    home_a = (tmp_path / "home_i").resolve()
    claude = home_a / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    (claude / "CLAUDE.md").write_text(f"Notes live in {home_a}/notes.\n")
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-i"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    home_b = (tmp_path / "home_j").resolve()
    (home_b / ".claude").mkdir(parents=True)
    link_home(home_b, dest_spec, "machine-j", master_from=home_a)

    assert sync.pull(ns(apply=True), home_b) == 0
    capsys.readouterr()

    assert (home_b / ".claude" / "CLAUDE.md").read_text() == \
        f"Notes live in {home_b}/notes.\n"


# --- push against an Index that has gone backwards ---------------------------


def test_push_refuses_against_a_rolled_back_index(tmp_path, capsys):
    """pull warns; push is the path that makes a rollback permanent. Re-
    sealing a stale catalogue unlinks every Session another machine pushed
    since, and strips its vouched Setup entry - the one field an attacker
    cannot forge."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0

    index_path = tmp_path / "archive" / "carryon" / "index.enc"
    stale = index_path.read_bytes()
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    index_path.write_bytes(stale)  # the rollback
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a)
    assert "rolled back" in str(exc.value) or "rollback" in str(exc.value)
    assert index_path.read_bytes() == stale, "push wrote over the stale Index"


def test_the_high_water_mark_is_per_destination(tmp_path):
    """One global number warns 'rolled back' about a brand-new Archive the
    moment a home is pointed at a second Destination."""
    home = tmp_path / "home_k"
    home.mkdir()
    sync._record_revision(home, "dir:/a", 12)
    assert sync._seen_revision(home, "dir:/a") == 12
    assert sync._seen_revision(home, "dir:/b") == 0


# --- a label binds which object, not which version ---------------------------


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


UUID_S = "11111111-1111-4111-8111-111111111111"


def build_home_with_a_session(tmp_path, name) -> pathlib.Path:
    home = tmp_path / name
    cwd = str(home / "code" / "app")
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (project / (UUID_S + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "user", "text": "first"}))
    return home


def test_an_older_authentic_session_object_is_refused(tmp_path, capsys):
    """A label says WHICH object a blob is, never which VERSION of it. An
    earlier tar for the same Session was sealed by a key holder under the
    same label, so it unseals cleanly - a Destination that keeps old copies
    can roll one transcript back and nothing downstream notices. The Index
    already carries the hash that settles it."""
    home_a = build_home_with_a_session(tmp_path, "home_s")
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0

    dest_root = tmp_path / "archive"
    objects = sorted((dest_root / "carryon" / "sessions").iterdir())
    assert len(objects) == 1
    stale = objects[0].read_bytes()

    main = (home_a / ".claude" / "projects"
            / rekey.encode_project_dir(str(home_a / "code" / "app"))
            / (UUID_S + ".jsonl"))
    main.write_text(main.read_text()
                    + jline({"cwd": str(home_a / "code" / "app"),
                             "type": "user", "text": "second"}))
    assert sync.push(ns(apply=True), home_a) == 0
    objects[0].write_bytes(stale)          # the rollback, still authentic

    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    landed = (home_b / ".claude" / "projects"
              / rekey.encode_project_dir(str(home_b / "code" / "app"))
              / (UUID_S + ".jsonl"))
    assert not landed.exists(), "a rolled-back Session tree was laid down"
    assert UUID_S in out and "Index" in out
