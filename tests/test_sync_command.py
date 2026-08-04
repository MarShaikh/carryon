"""`carryon sync` is two one-way moves in a fixed order, and reconciles
nothing (ADR-0012).

The order is the feature: pull first, then push. Push first and a Session the
Archive is ahead on is skipped as BEHIND; the pull that follows unions it, and
the merged copy does not reach the Archive until the NEXT push - so
push-then-pull leaves the Archive a round stale at exit 0. Every test here
drives sync.sync(args, home) or the argparse table, over synthetic homes, and
asserts on what LANDED - on this machine's tree and on the Destination's -
rather than on what was printed, except where ADR-0012 makes the words
themselves the contract (the dry-run caveat, the help text's refusal to
promise a merge).

Also here: pull's own `--category` (the gap the sync design found - pull had
none), and `all` in the shared subset parsers, because sync passes
`--category` through verbatim and grows no vocabulary of its own.

Every home is synthetic (the house pattern from test_sync.build_home_a);
nothing reads the real ~/.claude, and the OS keychain is forced to the
fallback file. All transcript content is invented.
"""

import argparse
import io
import json
import os
import pathlib
import sys
import tarfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, cli, config, keyring, rekey, sync  # noqa: E402
from carryon.adapters import CATEGORIES  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"   # shared between machines
UUID_D = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"   # local to machine-b only
UUID_F = "ffffffff-ffff-4fff-8fff-ffffffffffff"   # Archive only: new to b

PROJ_REL = "code/app"
# The member the union and divergence cases are played out on, and the member
# only machine-b ever holds - the same shapes tests/test_pull_member_union.py
# builds, because R10 is that file's neither-extends case met by sync.
SHARED = "subagents/journal.jsonl"
LOCAL_ONLY = "local-only.jsonl"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def main_lines(cwd, n) -> str:
    """A main Transcript of n lines. Re-keying rewrites the cwd both ways, so
    the prefix relation between two machines' copies survives the round trip.
    """
    text = jline({"cwd": cwd, "type": "meta"})
    for i in range(1, n):
        text += jline({"type": "user", "text": "edit {}/main.py".format(cwd),
                       "n": i})
    return text


def journal(machine, count, start=1) -> str:
    """Lines with no path in them, so canonical bytes are the bytes on disk
    and a byte-prefix on one machine is a byte-prefix on the other."""
    return "".join(jline({"from": machine, "step": i})
                   for i in range(start, start + count))


def project_root(home, rel=PROJ_REL) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / rel)))


def write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def build_home_a(tmp_path) -> pathlib.Path:
    """The founding machine: a two-item Setup (one config, one knowledge)
    plus one Session with a journal beneath it and one bare Session."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Global instructions.\n")
    project = project_root(home)
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 3))
    write(project / UUID_A / SHARED, journal("machine-a", 2))
    write(project / (UUID_F + ".jsonl"),
          jline({"cwd": cwd, "type": "meta", "tag": "f"}))
    return home


def build_home_b(tmp_path) -> pathlib.Path:
    """The partner machine: a Setup of its own and one Session of its own -
    the two things a sync must respectively leave alone and publish."""
    home = tmp_path / "home_b"
    cwd = str(home / PROJ_REL)
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text('{"model": "local"}')
    write(project_root(home) / (UUID_D + ".jsonl"),
          jline({"cwd": cwd, "type": "meta", "tag": "d"}))
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    """Give a second fake home the same master key and Destination, without
    the pairing theatre (that flow has its own test)."""
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


def tree_state(root) -> dict:
    root = pathlib.Path(root)
    if not root.exists():
        return {}
    state = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            state[rel] = ("link", os.readlink(str(path)))
        elif path.is_file():
            state[rel] = ("file", path.read_bytes())
    return state


def stored_session_members(dest, master, uuid) -> dict:
    """{member name: bytes} of the Archive's copy of one Session tree."""
    index = archive.load_index(dest, master)
    tar_bytes = archive.get_session(dest, master, uuid,
                                    index["sessions"][uuid]["object"])
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        return {m.name: tar.extractfile(m).read()
                for m in tar.getmembers() if m.isfile()}


def flat(text: str) -> str:
    """Lowercased with runs of whitespace collapsed, so an assertion about a
    sentence survives the line wrapping of whoever prints it."""
    return " ".join(text.lower().split())


def sync_subparser():
    """The `sync` subcommand's own parser, or a failing assertion: half the
    contract here is that the command EXISTS beside the others (R1)."""
    parser = cli.build_parser()
    subs = [action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
    assert len(subs) == 1
    assert "sync" in subs[0].choices, "there is no `carryon sync` subcommand"
    return parser, subs[0].choices["sync"]


@pytest.fixture
def pushed(tmp_path):
    """home_a initialised and fully pushed to a directory Destination."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    return home_a, dest_spec


@pytest.fixture
def partner(tmp_path, pushed):
    """machine-b on the same Archive: its own Setup, its own Session, and
    none of machine-a's History yet."""
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_b


# --- R1: the command, and pull-before-push observable in one pass -------------


def test_sync_pulls_first_then_pushes_in_one_pass(partner, tmp_path, capsys):
    """One `sync --apply` converges a Session the Archive is ahead on AND
    publishes what only this machine holds - which is only possible in the
    pull-then-push order ADR-0012 fixes.

    machine-b is level with the Archive on UUID_A's main and missing the
    journal beneath it, so push ALONE skips the Session as BEHIND ('pull
    first') - the control asserts exactly that. The pull half of the sync
    unions the journal in, at which point this machine is AHEAD (it holds a
    member the Archive does not), and the push half in the SAME run carries
    the merged tree up. Push-then-pull would have left the Archive without
    local-only.jsonl until the next day's run - the round-stale state the
    command exists to make impossible.
    """
    project = project_root(partner)
    cwd = str(partner / PROJ_REL)
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 3))
    write(project / UUID_A / LOCAL_ONLY, journal("machine-b", 1))
    capsys.readouterr()

    # The control: push on its own cannot move this Session yet. A dry run,
    # so the Archive is untouched and UUID_D is not published early.
    assert sync.push(ns(apply=False, category="history"), partner) == 0
    control = capsys.readouterr().out
    assert "pull first" in control, \
        "machine-b was not behind, so this test would prove nothing"

    code = sync.sync(ns(apply=True), partner)
    capsys.readouterr()
    assert code == 0

    # The pull half ran: the Session only the Archive held is here now.
    assert (project / (UUID_F + ".jsonl")).is_file(), \
        "a Session only the Archive held never landed"
    assert (project / UUID_A / SHARED).read_text() == \
        journal("machine-a", 2), \
        "the member this machine was behind on was never caught up"

    # And the push half ran AFTER it, in the same pass: the Archive holds
    # this machine's Session and the merged copy of the shared one.
    master = keyring.fetch_master(home=partner)
    dest = DirectoryDestination(tmp_path / "archive")
    index = archive.load_index(dest, master)
    assert UUID_D in index["sessions"], \
        "the local-only Session never reached the Archive"
    stored = stored_session_members(dest, master, UUID_A)
    assert "{}/{}".format(UUID_A, LOCAL_ONLY) in stored, \
        "the Archive is a round stale: the member only this machine held " \
        "did not go up in the same sync, so the push half ran before the " \
        "pull half (ADR-0012)"
    assert "{}/{}".format(UUID_A, SHARED) in stored


# --- R2: dry-run by default, and the caveat ------------------------------------


def test_sync_without_apply_writes_nothing_and_names_the_caveat(
        partner, tmp_path, capsys):
    """Both halves plan; nothing lands under $HOME and nothing at the
    Destination. And the plan says its own limit out loud: the push half was
    planned against this machine as it stands, and a real pull can only make
    it push MORE, never less (ADR-0012 / rubric R2).
    """
    dest_root = tmp_path / "archive"
    home_before = tree_state(partner)
    dest_before = tree_state(dest_root)
    capsys.readouterr()

    assert sync.sync(ns(apply=False), partner) == 0
    out = capsys.readouterr().out

    assert tree_state(partner) == home_before, \
        "a dry-run sync wrote under $HOME"
    assert tree_state(dest_root) == dest_before, \
        "a dry-run sync wrote at the Destination"
    lowered = flat(out)
    assert "real pull" in lowered, \
        "the dry run never says the push plan is provisional on the pull: " \
        + out
    assert "push more" in lowered or "grow" in lowered, \
        "the caveat does not say the push half can only grow: " + out


# --- R4: a History by default, on both halves ----------------------------------


def test_a_default_sync_moves_the_history_only(partner, tmp_path, capsys):
    """No --category means `history`, for BOTH halves. The local Setup
    survives even though the Archive holds a DIFFERENT one for it (recency
    is beside the point - a Setup restore never consults it, so what this
    pins is that the leg did not run at all), and the Archive gains no
    setups/ tree from this machine.
    """
    capsys.readouterr()
    assert sync.sync(ns(apply=True), partner) == 0
    capsys.readouterr()

    # The pull half left the Setup alone - no replacement, no backup, and
    # the knowledge file the Archive carries was not laid down either.
    assert (partner / ".claude" / "settings.json").read_text() == \
        '{"model": "local"}', \
        "a default sync replaced the local Setup (ADR-0012 defaults to " \
        "history)"
    assert not (partner / ".claude" / "CLAUDE.md").exists(), \
        "a default sync laid down a Setup item"
    assert not (partner / ".carryon" / "backups").exists(), \
        "a backup was taken, so a Setup write was attempted"

    # ... while the History moved both ways.
    assert (project_root(partner) / (UUID_F + ".jsonl")).is_file(), \
        "the History half never landed, so this proves nothing"
    dest = DirectoryDestination(tmp_path / "archive")
    setups = dest.list("carryon/setups/")
    assert setups, "machine-a's Setup should still be in the Archive"
    assert all("machine-b" not in key for key in setups), \
        "a default sync published this machine's Setup"


# --- R5 + R7: --category passes through, and `all` is shared vocabulary --------


def test_sync_category_all_carries_the_setup_half_too(
        partner, tmp_path, capsys):
    """`--category all` widens both halves: the pull half replaces the Setup
    (after a backup, ADR-0002) and the push half publishes this machine's.
    sync adds no per-file exceptions inside a chosen category (R5).
    """
    capsys.readouterr()
    assert sync.sync(ns(apply=True, category="all"), partner) == 0
    capsys.readouterr()

    assert (partner / ".claude" / "settings.json").read_text() == \
        '{"model": "opus"}', "the pull half did not carry the Setup"
    assert (partner / ".claude" / "CLAUDE.md").read_text() == \
        "Global instructions.\n"
    dest = DirectoryDestination(tmp_path / "archive")
    assert "carryon/setups/machine-b/MANIFEST.json" in \
        dest.list("carryon/setups/"), \
        "the push half did not publish this machine's Setup under " \
        "--category all"


def test_push_understands_category_all_as_push_with_no_flag(
        tmp_path, capsys):
    """R7 on the push leg: `push --category all` is a full push - both
    halves land, exactly as if no flag had been given."""
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    capsys.readouterr()

    assert sync.push(ns(apply=True, category="all"), home) == 0
    capsys.readouterr()

    dest = DirectoryDestination(tmp_path / "archive")
    assert "carryon/setups/machine-a/MANIFEST.json" in \
        dest.list("carryon/setups/"), \
        "--category all left the Setup half behind"
    assert len(dest.list("carryon/sessions/")) == 2, \
        "--category all left the History half behind"


def test_the_shared_subset_parsers_understand_all(capsys):
    """`all` is taught to the shared parsers rather than to sync, so it means
    the full set to push, pull, capture and sync alike and sync grows no
    vocabulary of its own (ADR-0012).
    """
    full = set(CATEGORIES)
    assert cli._parse_subset("all", CATEGORIES, "category") == full
    got = sync._subset("all", CATEGORIES, "category")
    # None is _subset's existing spelling of 'everything'; the full set is
    # the other honest answer. Either way every caller behaves as if no
    # subset had been asked for.
    assert got is None or got == full


# --- R10: a landed divergence does not stop the push half ----------------------


def test_sync_runs_the_push_half_past_a_landed_divergence_and_exits_non_zero(
        pushed, tmp_path, capsys):
    """The neither-extends case (built the way tests/test_pull_member_union.py
    builds it): the pull half files the Archive's copy under
    ~/.carryon/conflicts/ and returns non-zero. sync carries on past that
    RETURN - one divergent Session must not block the publication of
    everything else - and its own exit code is the max of the halves
    (ADR-0012: a raise propagates, a return does not stop the run).
    """
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    project = project_root(home_b)
    cwd = str(home_b / PROJ_REL)
    # Behind on the main (a strict byte-prefix authorises the replacement),
    # divergent on the journal beneath it: neither copy extends the other.
    write(project / (UUID_A + ".jsonl"), main_lines(cwd, 1))
    write(project / UUID_A / SHARED, journal("machine-b", 40))
    capsys.readouterr()

    code = sync.sync(ns(apply=True), home_b)
    capsys.readouterr()

    aside = (home_b / ".carryon" / "conflicts" / UUID_A / UUID_A / SHARED)
    assert aside.is_file(), \
        "the divergence never landed, so this test proves nothing"
    assert (project / UUID_A / SHARED).read_text() == \
        journal("machine-b", 40), "the local copy did not survive"

    # The push half still ran: the Session only this machine holds is in
    # the Archive's catalogue.
    master = keyring.fetch_master(home=home_b)
    index = archive.load_index(DirectoryDestination(tmp_path / "archive"),
                               master)
    assert UUID_D in index["sessions"], \
        "a divergence in the pull half blocked the push half (ADR-0012 " \
        "says sync continues past a non-zero return)"

    # And the divergence is an exit code: max of the halves, and the pull
    # half landed one under --apply, so 2 (ADR-0012's `2 if apply else 1`).
    assert code == 2


# --- R11: the flags -------------------------------------------------------------


def test_sync_takes_exactly_apply_and_category(capsys):
    """--map and --force stay pull-only, --agent stays push/capture-only.
    Anyone needing those uses the halves directly (ADR-0012)."""
    parser, _sub = sync_subparser()

    ok = parser.parse_args(["sync", "--apply", "--category", "history"])
    assert ok.apply is True
    assert ok.category == "history"

    for argv in (["sync", "--map", "/a=/b"],
                 ["sync", "--force"],
                 ["sync", "--agent", "claude-code"]):
        with pytest.raises(SystemExit):
            parser.parse_args(argv)
        capsys.readouterr()  # argparse prints its usage line; swallow it


# --- R12: the words -------------------------------------------------------------


def test_sync_help_says_a_session_extended_on_two_machines_is_not_merged(
        capsys):
    """ADR-0012 requires the help text to say what sync does NOT do: resume
    one Session on two machines at once and neither transcript is a prefix of
    the other - that divergence is filed, reported, and stays. A command
    called sync that quietly fails to converge is worse than no command.
    """
    parser, sub = sync_subparser()
    text = flat(sub.format_help() + " " + parser.format_help())
    assert "merge" in text, \
        "sync's help never mentions merging at all: " + text
    assert ("not merge" in text or "never merge" in text
            or "not merged" in text or "never merged" in text), \
        "sync's help does not say a divergent Session is NOT merged: " + text
    assert "session" in text


# --- R6: pull gains --category --------------------------------------------------


def test_pull_category_history_restores_sessions_and_skips_the_setup_leg(
        partner, capsys):
    """`pull --category history --apply` lays the Sessions down and leaves
    the local Setup untouched - and the report SAYS the Setup leg was
    skipped because no setup category was chosen, rather than leaving the
    user to infer it from a missing line.
    """
    capsys.readouterr()
    assert sync.pull(ns(apply=True, category="history"), partner) == 0
    out = capsys.readouterr().out

    assert (project_root(partner) / (UUID_F + ".jsonl")).is_file(), \
        "the History was not restored"
    assert (partner / ".claude" / "settings.json").read_text() == \
        '{"model": "local"}', \
        "pull --category history replaced the local Setup"
    assert not (partner / ".claude" / "CLAUDE.md").exists()
    assert not (partner / ".carryon" / "backups").exists(), \
        "a backup was taken, so a Setup write was attempted"
    setup_lines = [line for line in out.splitlines()
                   if "setup" in line.lower()]
    assert setup_lines, "the report says nothing about the Setup leg at all"
    assert any("categor" in line.lower() for line in setup_lines), \
        "the report does not tie the skipped Setup leg to the chosen " \
        "categories: " + out


def test_pull_category_knowledge_restores_only_knowledge_items(
        partner, capsys):
    """The Setup leg restores only the stored MANIFEST items whose `category`
    is in the chosen set (items carry one - capture.py:453): the knowledge
    file lands, the config file does not, and `history` was not chosen so
    the Session legs do not run.
    """
    capsys.readouterr()
    assert sync.pull(ns(apply=True, category="knowledge"), partner) == 0
    capsys.readouterr()

    assert (partner / ".claude" / "CLAUDE.md").read_text() == \
        "Global instructions.\n", "the knowledge item never landed"
    assert (partner / ".claude" / "settings.json").read_text() == \
        '{"model": "local"}', \
        "a config item was restored under --category knowledge"
    assert not (project_root(partner) / (UUID_F + ".jsonl")).exists(), \
        "the Session legs ran although history was not chosen"
