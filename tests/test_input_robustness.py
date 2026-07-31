"""The inputs that still escaped as a traceback rather than a report line.

Every other suite here asks what carryon *decides* about hostile or malformed
input. This one asks a smaller question the final gate found still open in
five places: does it decide anything at all, or does the interpreter answer
first? A traceback is not a refusal. It names a Python type instead of a file,
it carries no cure, and on the pull leg it lands after the History has already
begun writing into $HOME - so the user is left with a half-restored home and a
stack trace about `str.replace`.

The five are not one bug. Two are the Index's own fields, reached through a
guard that stops one level above where the code indexes; one is the stored
MANIFEST a keyless partial push merges and re-renders; one is carryon's own
config file, which every subcommand reads before it does anything; and one is
a walk that follows a symlink in the module whose whole rule is that nothing
found on a Destination is followed.

Only the first of them needs an attacker, and it needs no master key: the
plant is pure-ASCII valid JSON in the plaintext half of the Archive
(ADR-0004), and it aborts `carryon push --category config` on a machine that
holds no key at all. The rest are reachable by an honest Archive written by a
carryon whose shape this one does not know, or by a $HOME that came back
wrong from a backup.
"""

import argparse
import json
import os
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (archive, config, destinations, keyring, rekey,  # noqa: E402
                     restore, sync)

# A lone high surrogate. Legal in JSON, legal in a Python str, and impossible
# to encode as UTF-8 - which is what every writer in carryon does. It is
# spelled as a \u escape so the planted file is pure ASCII on disk: nothing
# about the bytes an attacker writes is unusual, and nothing between here and
# the crash is looking at bytes.
LONE_SURROGATE = "\ud800"

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
PROJ_ONE = "code/one"
PROJ_TWO = "code/two"

SETUP_CATEGORIES = "config,capability,knowledge"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def unprivileged() -> bool:
    """False when root, which reads a mode-000 file regardless.

    A guard rather than a skip marker, matching test_destinations_hostile:
    run_tests.py stands in for pytest on a machine that has none, and its
    stub covers the three APIs the suites actually need. Growing that stub
    for one platform caveat costs more than a sentence here.
    """
    return not (hasattr(os, "geteuid") and os.geteuid() == 0)


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def build_home_a(tmp_path) -> pathlib.Path:
    """A Setup and two Sessions in two projects.

    Two, not one, because the harm these tests describe is a traceback that
    lands *after* work has begun: with a single Session there is nothing yet
    on disk when the crash happens and the test would pass for the wrong
    reason. U1 sorts first, so tampering with U2's Index entry leaves U1 as
    the Session a pull has already written by the time it reaches the bad
    field.
    """
    home = tmp_path / "home_a"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Answer briefly.\n")

    for uuid, proj in ((U1, PROJ_ONE), (U2, PROJ_TWO)):
        cwd = str(home / proj)
        project = claude / "projects" / rekey.encode_project_dir(cwd)
        project.mkdir(parents=True)
        (project / (uuid + ".jsonl")).write_text(
            jline({"cwd": cwd, "type": "meta"})
            + jline({"type": "user", "text": f"work in {cwd}"}))
    return home


def build_home_b(tmp_path) -> pathlib.Path:
    home = tmp_path / "other" / "home_b"
    (home / ".claude").mkdir(parents=True)
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


@pytest.fixture
def archived(tmp_path, capsys):
    """machine-a has pushed a whole Snapshot; machine-b is paired to pull."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()
    return types.SimpleNamespace(home_a=home_a, home_b=home_b,
                                 dest_spec=dest_spec,
                                 dest_root=tmp_path / "archive")


def tamper_index(archived, edit) -> None:
    """Re-seal the Archive's Index with `edit` applied.

    The Index is sealed, so only a master key holder can write one - which is
    exactly the case these two fields describe. This is not an attacker: it
    is a carryon that recorded a shape this one does not know, or an Index
    restored from somewhere it should not have been.
    """
    master = keyring.fetch_master(home=archived.home_a)
    dest = destinations.from_spec(archived.dest_spec, archived.home_a)
    index = archive.load_index(dest, master)
    edit(index)
    archive.save_index(dest, master, index)


def restored_sessions(home) -> set:
    root = pathlib.Path(home) / ".claude" / "projects"
    return {p.stem for p in root.rglob("*.jsonl")} if root.exists() else set()


def fresh_manifest(target: str) -> dict:
    """A manifest as `carryon capture` produces one, holding an externally
    owned skill link. `external` is where a resolved symlink target reaches a
    document - the one field whose value comes from readlink rather than from
    an adapter declaration or a path this machine composed."""
    return {"tool": "carryon", "version": "0.1.0",
            "captured_at": "2026-07-30T00:00:00Z", "source_home": "~",
            "categories": ["capability"], "scope": "all",
            "agents": {"claude-code": {
                "name": "Claude Code",
                "layout_drift": [],
                "items": [{"src": ".claude/skills", "dst": "claude/skills",
                           "kind": "skills", "category": "capability",
                           "carried": [], "re_resolvable": [],
                           "external": {"deploy": target}}],
                "excluded": []}}}


# --- 1. a stored MANIFEST string carryon cannot write back out ---------------


def plant_stored_manifest(dest_root, machine, agents) -> str:
    """Author the plaintext MANIFEST a partial push reads back and merges.

    No key involved: ADR-0004 makes the Setup half plaintext so that
    `push --category config` works on a machine that never paired, which is
    the same property that lets anyone with write access to the Destination
    author this file. Returned as text so the test can assert the bytes are
    ordinary ASCII - json.dumps escapes the surrogate on the way out, so
    nothing about the file on disk looks unusual.
    """
    doc = {"tool": "carryon", "version": "0.1.0",
           "captured_at": "2026-07-29T12:00:00Z", "source_home": "~",
           "categories": ["config"], "agents": agents}
    raw = json.dumps(doc, indent=2)
    base = pathlib.Path(dest_root) / "carryon" / "setups" / machine
    base.mkdir(parents=True, exist_ok=True)
    (base / "MANIFEST.json").write_text(raw)
    return raw


@pytest.fixture
def keyless(tmp_path):
    """A machine with a Destination and no master key at all (ADR-0004)."""
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    (home / ".carryon" / "master.key").unlink()
    assert keyring.fetch_master(home=home) is None
    return types.SimpleNamespace(home=home, dest_spec=dest_spec,
                                 dest_root=tmp_path / "archive")


@pytest.mark.parametrize("agents,what", [
    ({"codex": {"name": "Codex " + LONE_SURROGATE, "items": [],
                "excluded": []}}, "an agent's name"),
    ({"codex": {"name": "Codex",
                "items": [{"src": ".codex/config.toml",
                           "dst": "codex/" + LONE_SURROGATE,
                           "kind": "file", "category": "config"}],
                "excluded": []}}, "an item's dst"),
    ({"codex": {"name": "Codex", "items": [],
                "excluded": [{"path": "~/.codex/auth.json", "what": "creds",
                              "why": LONE_SURROGATE}]}}, "an exclusion note"),
])
def test_a_stored_manifest_string_that_will_not_render_is_dropped_and_named(
        keyless, capsys, agents, what):
    """A partial push regenerates RESTORE.md from the MERGED manifest, and the
    merge takes agents the capture did not produce straight out of the stored
    document. `_carryable_agent` was written for exactly that rendering - one
    key left out of a planted entry used to be a KeyError out of
    `push --category` - and it asks `isinstance(x, str)`, which a lone
    surrogate answers yes to. write_text then encodes it, strictly, and
    UnicodeEncodeError comes out of a push on a machine holding no key.

    The plant is pure ASCII valid JSON in the Archive's plaintext half, so
    the whole of it is available to anyone with write access to the
    Destination and no key at all - the only item in this suite an attacker
    can drive.
    """
    raw = plant_stored_manifest(keyless.dest_root, "machine-a", agents)
    assert all(ord(c) < 128 for c in raw), \
        "the plant is meant to be ordinary ASCII on disk"

    assert sync.push(ns(apply=True, category="config"), keyless.home) == 0, \
        f"{what} that will not encode ended the push"
    out = capsys.readouterr().out

    assert "codex" in out, \
        f"{what} was dropped from the Archive's MANIFEST without a word"
    stored = keyless.dest_root / "carryon" / "setups" / "machine-a"
    assert (stored / "RESTORE.md").is_file(), "the push wrote no RESTORE.md"
    # The whole entry goes when the unrenderable string is the agent's own,
    # the one item goes when it is an item's - what matters either way is
    # that the string this machine could not write is not what it published.
    assert "\\ud800" not in (stored / "MANIFEST.json").read_text(), \
        "the string carryon cannot render was carried into the Archive anyway"


def test_a_stored_manifest_the_push_can_render_still_carries_its_agents(
        keyless, capsys):
    """The other half of the same rule: an agent the capture did not produce
    still survives a partial push, which is the whole reason the merge reads
    the stored document. A guard that dropped every uncaptured agent would
    pass the test above and silently empty the Archive's MANIFEST."""
    plant_stored_manifest(keyless.dest_root, "machine-a", {
        "codex": {"name": "Codex", "items": [], "excluded": []}})

    assert sync.push(ns(apply=True, category="config"), keyless.home) == 0
    capsys.readouterr()

    stored = keyless.dest_root / "carryon" / "setups" / "machine-a"
    merged = json.loads((stored / "MANIFEST.json").read_text())
    assert "codex" in merged["agents"], \
        "a renderable stored agent was dropped from the merge"
    assert "Codex" in (stored / "RESTORE.md").read_text()


# --- 2. the Index's cwd, which pull expands against the local home -----------


def test_an_index_cwd_that_is_not_a_string_is_refused_before_the_pull_writes(
        archived, capsys):
    """history._expand_path calls value.replace() on the cwd the Index
    records, and the only guard above it is `if not cwd` - which a truthy
    non-string passes. AttributeError then comes out of unpack_session, mid
    pull, after earlier Sessions have already landed in $HOME.

    archive._validated proves the entry is an object one level above this and
    stops there, so the refusal belongs there too: the Index is read before a
    pull writes anything, which is the difference between a sentence and a
    half-restored home.

    Before anything is written is where the DECISION belongs; it is not an
    argument for the pull writing nothing. One entry carrying a cwd no reader
    can expand says nothing about the Session beside it, so U1 lands and U2 is
    named - the remedy the size of the damage.
    """
    tamper_index(archived, lambda index: index["sessions"][U2].update(
        {"cwd": ["not", "a", "string"]}))

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), archived.home_b)
    out = capsys.readouterr().out

    assert "cwd" in str(exc.value), "the refusal does not name the field"
    assert U2 in str(exc.value), "the refusal does not name the entry"
    assert "-" * 74 in out, "the pull stopped before it printed its summary"
    assert restored_sessions(archived.home_b) == {U1}, \
        "one entry with an unreadable field took the whole Archive with it"


# --- 3. the Index's main_path, which both legs hand to tarfile ---------------


def test_an_index_main_path_that_is_not_a_string_is_refused_on_the_pull_leg(
        archived, capsys):
    """_main_member passes it straight to tarfile.getmember, which rstrips
    it. Its neighbours main_size, main_sha256 and object are all
    isinstance-checked at the point of use, so this is an omission rather
    than a decision - and the same field is read again on the push leg.

    The two runners disagree about the symptom and agree about the defect,
    which is why the assertion is on the refusal rather than on the crash.
    3.10 onwards spells getmember as `self._getmember(name.rstrip('/'))`, so
    the field reaches str.rstrip and AttributeError comes out of the pull;
    3.9 compares the name unrstripped, so the lookup merely misses and the
    pull reports that the stored tree holds no member named 17 - a sentence
    about a Session the Archive is serving perfectly well. Neither is a
    decision this code made.
    """
    tamper_index(archived, lambda index: index["sessions"][U2].update(
        {"main_path": 17}))

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), archived.home_b)

    assert "main_path" in str(exc.value), "the refusal does not name the field"
    assert U2 in str(exc.value), "the refusal does not name the entry"
    assert restored_sessions(archived.home_b) == {U1}, \
        "one entry with an unreadable field took the whole Archive with it"


def test_an_index_main_path_that_is_not_a_string_is_refused_on_the_push_leg(
        archived, capsys):
    """The second leg into the same field: a Session the Archive already
    holds a different version of goes through _push_skip_reason, which asks
    _main_mismatch the same question the pull does.

    Setting the entry aside is what makes this leg's answer load-bearing. The
    union rule is asked only where an entry exists, so an entry dropped from
    the catalogue would send this Session down the branch that writes without
    comparing - and this machine's copy is one turn AHEAD, which is the case
    that looks like a successful push right up until the machine that was
    ahead is the one that pushed second. So the Session is skipped by name and
    the Archive's stored copy is left exactly as it was.
    """
    project = (archived.home_a / ".claude" / "projects"
               / rekey.encode_project_dir(str(archived.home_a / PROJ_TWO)))
    with (project / (U2 + ".jsonl")).open("a") as fh:
        fh.write(jline({"type": "user", "text": "one more turn"}))
    tamper_index(archived, lambda index: index["sessions"][U2].update(
        {"main_path": 17}))
    master = keyring.fetch_master(home=archived.home_a)
    dest = destinations.from_spec(archived.dest_spec, archived.home_a)
    stored_before = dest.read(archive.session_key(master, U2))

    assert sync.push(ns(apply=True), archived.home_a) == 0
    out = capsys.readouterr().out

    assert f"skip     {U2}" in out, "the Session was not named as skipped"
    assert "main_path" in out, "the report does not name the field"
    assert dest.read(archive.session_key(master, U2)) == stored_before, \
        "a record this machine could not read was taken for no record, and " \
        "the Archive's copy was overwritten without the union rule"


def test_an_index_agent_that_is_not_a_string_is_refused_rather_than_raised(
        archived, capsys):
    """The third field of the same shape, found by asking what else both legs
    index out of a catalogue entry: `agent not in effective` is a dict lookup
    and an unhashable value raises TypeError there, before any adapter is
    consulted. Guarded in the same place as its two neighbours rather than at
    each of its four uses, which is the omission that left the other two."""
    tamper_index(archived, lambda index: index["sessions"][U2].update(
        {"agent": ["claude-code"]}))

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True), archived.home_b)

    assert "agent" in str(exc.value), "the refusal does not name the field"
    assert U2 in str(exc.value), "the refusal does not name the entry"
    assert restored_sessions(archived.home_b) == {U1}, \
        "one entry with an unreadable field took the whole Archive with it"


def test_a_session_pushed_without_a_cwd_still_pulls(tmp_path, capsys):
    """The field check has to let null through, because carryon writes one.

    A Transcript that records no cwd is reported and carried anyway rather
    than guessed at (history.discover), and the Index entry it produces holds
    `"cwd": null` - so a check reading 'present and not a string is refused'
    would refuse an honest Archive whole, on the pull leg, for a Session the
    pull leg already has a report line about. Absent and null are the same
    fact to every reader of these fields, which is what makes them the shape
    to allow rather than the shape to guard.
    """
    home_a = build_home_a(tmp_path)
    project = (home_a / ".claude" / "projects"
               / rekey.encode_project_dir(str(home_a / PROJ_ONE)))
    (project / (U1 + ".jsonl")).write_text(
        jline({"type": "user", "text": "no cwd was ever recorded here"}))
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0, \
        "a Session carryon itself pushed without a cwd stopped the pull"
    out = capsys.readouterr().out
    assert U1 in out and "cwd" in out, \
        "the cwd-less Session was neither restored nor named"
    assert restored_sessions(home_b) == {U2}, \
        "the Sessions that do have a cwd stopped landing"


def test_an_index_entry_this_carryon_never_wrote_still_pulls(archived, capsys):
    """A field check is not licence to refuse an Index that is merely newer.
    An entry carrying a key this carryon does not know, and leaving out one
    it does, restores exactly as before - the guard is about the fields both
    legs then index out of, not about the shape as a whole."""
    tamper_index(archived, lambda index: index["sessions"][U2].update(
        {"pushed_by": {"future": True}, "main_size": None}))

    assert sync.pull(ns(apply=True), archived.home_b) == 0
    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "an Index from a newer carryon stopped restoring"


# --- 4. carryon's own config and state, read by every subcommand -------------


def deep_json(depth=200000) -> str:
    """JSON nested past any recursion limit. Parses to nothing; raises
    RecursionError on the way, which is a RuntimeError and so misses a guard
    naming ValueError and UnicodeDecodeError."""
    return "[" * depth


@pytest.fixture
def configured(tmp_path):
    home = build_home_a(tmp_path)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    return home


def test_a_config_that_is_a_directory_is_refused_by_name(configured):
    """~/.carryon/config.json existing as a directory is not exotic - a
    synced folder or a restored backup makes one. read_text() sits outside
    config.load's guard, so IsADirectoryError came out of init, push, pull
    and capture alike."""
    path = config.config_path(configured)
    path.unlink()
    path.mkdir()

    with pytest.raises(SystemExit) as exc:
        config.load(configured)

    assert str(path) in str(exc.value), "the refusal does not name the file"


def test_a_config_that_will_not_read_is_refused_by_name(configured):
    """The same guard, one errno over: a config.json this user cannot read is
    a PermissionError rather than a parse failure, and the guard named only
    parse failures."""
    if not unprivileged():
        return
    path = config.config_path(configured)
    path.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as exc:
            config.load(configured)
    finally:
        path.chmod(0o600)

    assert str(path) in str(exc.value), "the refusal does not name the file"


def test_a_config_that_is_a_symlink_loop_is_refused_by_name(configured):
    """The errno the exists() ahead of the read used to swallow. A loop is
    'missing' to Path.exists() and ELOOP to open(), so carryon silently ran
    on the defaults - reporting no Destination on a machine that has one -
    for a config.json that is plainly there and plainly broken.

    Tested on both runners deliberately: this is the shape where 3.9 and 3.13
    have disagreed before (resolve() raises on a loop under one and returns
    the unresolved path under the other), and the answer here must not depend
    on which of them is running.
    """
    path = config.config_path(configured)
    path.unlink()
    other = path.parent / "config-loop.json"
    path.symlink_to(other)
    other.symlink_to(path)

    with pytest.raises(SystemExit) as exc:
        config.load(configured)

    assert str(path) in str(exc.value), "the refusal does not name the file"


def test_a_home_with_no_carryon_directory_still_loads_the_defaults(tmp_path):
    """The other side of dropping exists(): a missing file, and a missing
    ~/.carryon around it, are still the effortless default rather than a
    refusal. `carryon init` runs on a machine that has neither."""
    assert config.load(tmp_path / "never-set-up")["destination"] == ""


def test_a_config_nested_past_the_recursion_limit_is_refused_by_name(
        configured):
    """json.loads answers deep nesting with RecursionError, which is not a
    ValueError - the one exception a two-name guard misses, and the cheapest
    to produce."""
    path = config.config_path(configured)
    path.write_text(deep_json())

    with pytest.raises(SystemExit) as exc:
        config.load(configured)

    assert str(path) in str(exc.value), "the refusal does not name the file"


def test_a_config_that_will_not_read_stops_a_subcommand_with_a_sentence(
        configured, capsys):
    """Driven through a subcommand rather than through config.load, because
    'a traceback out of EVERY subcommand' is the claim: load runs before push
    has decided anything at all."""
    path = config.config_path(configured)
    path.unlink()
    path.mkdir()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), configured)

    assert str(path) in str(exc.value)


def test_state_nested_past_the_recursion_limit_is_nothing_seen_yet(
        configured, capsys):
    """The high-water mark is deliberately never a gate: unreadable or
    malformed state means 'nothing seen yet', not a refused pull, because
    the mark exists to make carryon notice MORE and a mark that cannot be
    read must not become a way to stop a machine working. RecursionError was
    missing from the guard that already says so, so a nested state.json was
    a traceback rather than the zero the docstring promises - and it says so
    now instead of going quiet.
    """
    path = sync._state_path(configured)
    path.write_text(deep_json())

    assert sync._seen_revision(configured, "dir:whatever") == 0
    assert "state.json" in capsys.readouterr().out, \
        "an unreadable high-water mark weakened a check without a word"
    assert sync.push(ns(apply=True), configured) == 0, \
        "a malformed high-water mark stopped a push"


# --- 5. the walk in archive that followed a link -----------------------------


def test_tree_hash_does_not_follow_a_symlink(tmp_path):
    """put_setup and setup_tree_manifest both walk a tree with `p.is_file()
    and not p.is_symlink()`; tree_hash walks the same shape of tree with
    is_file() alone, and is_file() follows.

    It has no caller in carryon today, which is the reason to fix it rather
    than leave it: a link-following walk sitting in the module whose whole
    rule is that nothing found on a Destination is followed (ADR-0009) gets
    adopted eventually, and the sibling three functions up is the rule.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("PRIVATE-KEY-BODY-INVENTED-FOR-THIS-TEST\n")

    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "main.jsonl").write_text("line\n")

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "main.jsonl").write_text("line\n")
    (linked / "stolen.txt").symlink_to(secret)

    assert archive.tree_hash(linked) == archive.tree_hash(plain), \
        "tree_hash read through a symlink the sibling walks exclude"
    assert list(archive.setup_tree_manifest(linked)) == ["main.jsonl"], \
        "the sibling walk this one is measured against has drifted"


def test_tree_hash_does_not_read_through_a_link_to_an_unreadable_file(
        tmp_path):
    """The same rule with the traceback it also removes: following a link
    means read_bytes() on whatever it points at, and a link is the one thing
    in a tree whose target the walker did not choose. is_file() says yes to a
    link pointing at a file this process may stat and may not read, and
    PermissionError comes out of a hash."""
    if not unprivileged():
        return
    secret = tmp_path / "secret.txt"
    secret.write_text("PRIVATE-KEY-BODY-INVENTED-FOR-THIS-TEST\n")
    secret.chmod(0o000)

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "main.jsonl").write_text("line\n")
    (linked / "stolen.txt").symlink_to(secret)

    try:
        digest = archive.tree_hash(linked)
    finally:
        secret.chmod(0o600)

    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "main.jsonl").write_text("line\n")
    assert digest == archive.tree_hash(plain)


# --- 6. the re-keying itself, on an ordinary Transcript ----------------------
#
# The five above were reached through the Destination or through carryon's own
# state. These are reached through a Transcript a local agent wrote, on the
# push leg, and one of them leaves the Archive unusable for every machine
# rather than merely ending one command.


def test_a_transcript_line_with_a_surrogate_escape_does_not_brick_the_archive(
        tmp_path, capsys):
    """A '\\ud83d' ESCAPE is six ASCII characters in a JSONL file and exactly
    what a tool emits when an emoji is truncated mid-pair by an output limit.
    json.loads makes it a lone surrogate; rekey re-dumps every CHANGED line
    with ensure_ascii=False, so a line that also mentions the home comes back
    as text that will not encode - and apply_to_bytes guards the decode only.

    The crash lands between the Session objects being written and the Index
    being sealed, which is the state _canonical_members' own docstring exists
    to prevent: on a first push it leaves an Archive that refuses every later
    push AND pull, from every machine, with 'delete the Archive's carryon/
    objects as well and push afresh' as the only cure. No attacker, no
    Destination access, no key.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    cwd = str(home / PROJ_TWO)
    main = (home / ".claude" / "projects"
            / rekey.encode_project_dir(cwd) / (U2 + ".jsonl"))
    planted = jline({"cwd": cwd, "text": "emoji cut in half " + LONE_SURROGATE})
    assert all(ord(c) < 128 for c in planted), \
        "the plant is meant to be ordinary ASCII on disk"
    main.write_text(main.read_text() + planted)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home) == 0, \
        "a surrogate escape in one Transcript line ended the push"

    # The Index is what a half-finished push leaves missing, so the proof is
    # another machine reading the Archive rather than the exit status alone.
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert restored_sessions(home_b) == {U1, U2}, \
        "the Archive was sealed without the Session that held the surrogate"
    landed = [p for p in (home_b / ".claude" / "projects").rglob("*.jsonl")
              if p.stem == U2][0].read_text().splitlines()[-1]
    assert json.loads(landed)["text"].endswith(LONE_SURROGATE), \
        "the surrogate did not survive the round trip"


def test_a_transcript_line_nested_past_the_recursion_limit_still_pushes(
        tmp_path, capsys):
    """The same guard as the config and state files, on the files those two
    tests were written from: a Transcript line is read by rekey.read_cwd and
    rewritten by canonicalise_jsonl, and both answer deep nesting with
    RecursionError where they guard ValueError. A line that will not parse
    passes through unchanged everywhere else in rekey; this one took the push
    down with it, after the Setup had been captured and reported.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    cwd = str(home / PROJ_TWO)
    main = (home / ".claude" / "projects"
            / rekey.encode_project_dir(cwd) / (U2 + ".jsonl"))
    main.write_text(deep_json(20000) + "\n" + main.read_text())
    capsys.readouterr()

    assert sync.push(ns(apply=True), home) == 0, \
        "one unparsable Transcript line ended the push"

    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert U2 in restored_sessions(home_b), \
        "the Session was carried without the cwd its second line records"
    landed = [p for p in (home_b / ".claude" / "projects").rglob("*.jsonl")
              if p.stem == U2][0]
    assert landed.read_text().splitlines()[0] == deep_json(20000), \
        "the line that would not parse was not passed through unchanged"


def test_an_external_link_target_this_machine_cannot_render_still_pushes(
        tmp_path):
    """The stored MANIFEST is guarded and the FRESH one is not, and both are
    fed to the same renderer. APFS refuses an invalid-UTF-8 filename and
    accepts an invalid-UTF-8 symlink TARGET, so an externally owned skill link
    into a dotfiles repo - which CONTEXT.md calls the ordinary case - puts a
    surrogateescape string into the manifest that write_text will not encode.

    Asserted of build_restore rather than of one of its callers: the guard
    that only covered the stored document is why this survived, and there are
    three call sites (a full push, a partial push, `carryon capture`) rendering
    the same document with the same writer.
    """
    manifest = fresh_manifest("~/dotfiles/caf\udce9")

    text = restore.build_restore(manifest)

    text.encode("utf-8")  # the write every caller does; must not raise
    assert "caf" in text, "the external link was dropped rather than escaped"


def test_a_full_push_renders_a_manifest_it_cannot_encode(tmp_path):
    """The owned call site, driven directly: the full push re-renders
    RESTORE.md from the neutralised manifest, and neutralising rewrites the
    home without asking whether what is left can be written."""
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "MANIFEST.json").write_text("{}")
    (staging / "RESTORE.md").write_text("")
    manifest = fresh_manifest(str(tmp_path / "dotfiles" / "caf\udce9"))

    sync._neutralise_staged_setup(staging, manifest, tmp_path)

    assert (staging / "RESTORE.md").read_text(), \
        "the push wrote no RESTORE.md"


# --- 7. the high-water mark's own read ---------------------------------------


def test_state_that_is_a_symlink_loop_says_so_rather_than_going_quiet(
        configured, capsys):
    """config.load dropped its pre-read exists() this round because it
    'swallows ELOOP as missing'; the mark's own reader kept the same two
    syscalls. A loop at state.json is False to is_file(), so the mark reads as
    'nothing seen yet' with no line printed at all - and _load_state's
    docstring says in as many words that it is never a gate AND never silent,
    because a mark that cannot be read is a check that has just got weaker.
    """
    path = sync._state_path(configured)
    other = path.parent / "state-loop.json"
    path.symlink_to(other)
    other.symlink_to(path)

    assert sync._seen_revision(configured, "dir:whatever") == 0
    assert "state.json" in capsys.readouterr().out, \
        "an unreadable high-water mark weakened a check without a word"


def test_state_this_machine_cannot_reach_is_a_sentence_not_a_traceback(
        configured, capsys):
    """The same pre-read stat, one errno over: a state.json whose directory
    this user cannot search raises PermissionError from is_file(), which sits
    OUTSIDE the try that guards the read - so it came out of `carryon push`
    and `carryon pull` as a traceback, where config.json's identical shape is
    a named refusal."""
    if not unprivileged():
        return
    blocked = configured / ".carryon" / "blocked"
    blocked.mkdir(parents=True)
    (blocked / "state.json").write_text("{}")
    path = sync._state_path(configured)
    path.symlink_to(blocked / "state.json")
    blocked.chmod(0o000)

    try:
        assert sync._seen_revision(configured, "dir:whatever") == 0
    finally:
        blocked.chmod(0o700)

    assert "state.json" in capsys.readouterr().out, \
        "the mark could not be read and the pull said nothing"


def test_the_state_warning_is_said_once_per_command_not_once_per_process(
        configured, capsys):
    """Said once per file, by a module-level set that was never cleared - so
    the second command in one interpreter dropped the line entirely. That is
    the test suite, and any future in-process loop, and the set grows without
    bound besides."""
    sync._state_path(configured).write_text(deep_json())

    assert sync.push(ns(apply=True), configured) == 0
    assert "state.json" in capsys.readouterr().out
    # Written again because the first push repaired it: what is under test is
    # the set that remembers having said it, not the file.
    sync._state_path(configured).write_text(deep_json())
    assert sync.push(ns(apply=True), configured) == 0
    assert "state.json" in capsys.readouterr().out, \
        "the second command in the same process said nothing about the mark"


# --- 8. an Index key in a report line ----------------------------------------


def test_a_session_uuid_a_filename_can_hold_is_escaped_in_the_report(
        tmp_path, capsys):
    """A Session's UUID is the stem of a file the agent named, and a filename
    may hold an ESC - the character that starts a CSI sequence - as readily as
    a hex digit. It travels into the Index as a catalogue key, and every
    machine that pulls prints it: `new <uuid> (<agent>)`, `keep`, `conflict`,
    `?? <uuid>: <why>`. archive._validated proves an Index entry's fields are
    strings and asks nothing about whether this machine can say them, which is
    what `printable` exists for and what ADR-0009's report lines depend on -
    an unescaped name writes its own lines into the report meant to name it,
    and can blank the ones above.

    Honest path throughout: no attacker, no key, one oddly named file.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    cwd = str(home / PROJ_ONE)
    project = home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
    weird = "33333333-3333-4333-8333-3333333\x1b[2J3"
    (project / (weird + ".jsonl")).write_text(jline({"cwd": cwd,
                                                     "type": "meta"}))
    assert sync.push(ns(apply=True), home) == 0
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert "\\x1b" in out, "the Index key went into the report unescaped"
    assert "\x1b" not in out, \
        "an escape sequence out of an Index key reached the report"


def test_a_transcript_cwd_this_machine_cannot_spell_does_not_brick_the_archive(
        tmp_path, capsys):
    """A cwd is read out of a Transcript and becomes an Archive LABEL - the
    name a project's object is keyed and authenticated by. A JSONL line may
    spell it with a '\\udce9' escape and stay pure ASCII on disk (a directory
    whose name is not valid UTF-8 is ordinary on Linux, and os.fsdecode hands
    it back exactly like that), and hmac_name then encodes it strictly: a
    UnicodeEncodeError with Session objects already written and the Index
    never sealed, which is the state that makes every later push and pull
    from every machine refuse.

    A cwd this machine cannot spell is not a cwd it can key an object by, so
    it is treated as one that was never recorded - the case discovery already
    reports and carries the Session without.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    cwd = str(home / PROJ_TWO)
    main = (home / ".claude" / "projects"
            / rekey.encode_project_dir(cwd) / (U2 + ".jsonl"))
    planted = jline({"cwd": cwd + "/caf\udce9", "type": "meta"})
    assert all(ord(c) < 128 for c in planted), \
        "the plant is meant to be ordinary ASCII on disk"
    main.write_text(planted + main.read_text())
    # A memory file beside it, because a project's RESIDUE is the half keyed
    # by the cwd: a Session object is named after its UUID, and the label a
    # cwd becomes belongs to the projects catalogue.
    memory = main.parent / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text("notes\n")
    capsys.readouterr()

    assert sync.push(ns(apply=True), home) == 0, \
        "a cwd this machine cannot encode ended the push"

    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert U1 in restored_sessions(home_b), \
        "the Archive was sealed without the Session pushed before the bad one"


# --- the local tree, which is an input too ------------------------------------
#
# Everything above is something the Destination or a stored document said.
# These are the other direction: the machine's own $HOME, which discovery
# walks on every push and every pull. It is not attacker-authored and it does
# not have to be - a Transcript root-owned by an agent that ran under sudo, a
# project directory left mode 000 by a backup restore, a memory file whose
# permissions came back wrong - and every one of them reached the syscall with
# no guard on it. The capture engine closed exactly these shapes on the Setup
# leg and says so in its own docstrings; the History leg never got them.


def unreadable(path) -> bool:
    """Make `path` unreadable and say whether it took. Root reads anything,
    and so does a filesystem mounted without permission bits."""
    path.chmod(0o000)
    if not unprivileged():
        return False
    try:
        if path.is_dir():
            list(path.iterdir())
        else:
            path.read_bytes()
    except OSError:
        return True
    return False


def test_a_transcript_this_machine_cannot_read_is_reported_not_raised(
        archived, capsys):
    """A main Transcript the walk finds and the read cannot have.

    discovery opens every main Transcript to recover its cwd, and that open
    had no guard: one mode-000 file - an agent that ran under sudo, a $HOME
    restored with the wrong owner - ended `carryon push` with a
    PermissionError, before the report and after the Setup had been captured.
    capture.do_file names this exact errno in its own docstring for the Setup
    leg; this is the same syscall on the other one.
    """
    home = archived.home_a
    main = next((home / ".claude" / "projects").rglob(U2 + ".jsonl"))
    if not unreadable(main):
        return
    capsys.readouterr()
    try:
        assert sync.push(ns(apply=True), home) == 0
        out = capsys.readouterr().out
    finally:
        main.chmod(0o644)

    assert "Sessions:" in out, "the push ended before its report"
    assert U2 in out, "the Transcript it could not read went unnamed"
    assert U1 in restored_sessions(home), "the readable Session was lost"


def test_a_project_directory_this_machine_cannot_list_is_reported(
        archived, capsys):
    """One directory below the same walk. `iterdir` on a mode-000 project dir
    raises where `is_dir` did not, so the guard has to sit on the listing
    rather than on the question above it - and the other projects still have
    to be walked, since a push that stops at the first unreadable directory
    carries nothing at all."""
    home = archived.home_a
    project = next(p for p in (home / ".claude" / "projects").iterdir()
                   if p.is_dir())
    if not unreadable(project):
        return
    capsys.readouterr()
    try:
        assert sync.push(ns(apply=True), home) == 0
        out = capsys.readouterr().out
    finally:
        project.chmod(0o755)

    assert "Sessions:" in out, "the push ended before its report"
    assert project.name in out, "the directory it could not list went unnamed"


def test_a_projects_root_this_machine_cannot_list_is_reported(
        archived, capsys):
    """The same listing one level up, where the answer is 'this agent's whole
    History' rather than one project - which is all the more reason to say it
    rather than raise it."""
    home = archived.home_a
    root = home / ".claude" / "projects"
    if not unreadable(root):
        return
    capsys.readouterr()
    try:
        assert sync.push(ns(apply=True), home) == 0
        out = capsys.readouterr().out
    finally:
        root.chmod(0o755)

    assert "Sessions: 0 pushed" in out, "the push ended before its report"
    assert ".claude/projects" in out, "the root it could not list went unnamed"


def test_a_memory_file_this_machine_cannot_read_does_not_end_a_pull(
        archived, capsys):
    """The pull leg's copy of the same syscall, and the one place it was still
    a raise after the push leg had been fixed.

    push answers an unreadable residue member with a skip line
    (`_canonical_members` returns None). pull hashed the same tree through
    `_canonical_tree_hash`, which turns that None into a MemberUnreadable -
    an exception nothing on the pull leg catches, thrown after the Session
    half has already written into $HOME.
    """
    home_a, home_b = archived.home_a, archived.home_b
    project_a = next(p for p in (home_a / ".claude" / "projects").iterdir()
                     if p.is_dir())
    (project_a / "memory").mkdir()
    (project_a / "memory" / "MEMORY.md").write_text("machine-a's notes\n")
    assert sync.push(ns(apply=True), home_a) == 0
    assert sync.pull(ns(apply=True), home_b) == 0
    capsys.readouterr()

    memory = next((home_b / ".claude" / "projects").rglob("MEMORY.md"))
    # Edited first, so the stored tree_hash no longer matches and the pull has
    # to compare rather than take the fast path past it.
    memory.write_text("notes this machine cannot re-read\n")
    if not unreadable(memory):
        return
    try:
        assert sync.pull(ns(apply=True), home_b) == 0
        out = capsys.readouterr().out
    finally:
        memory.chmod(0o644)

    assert "Project residue:" in out, "the pull ended before its report"
    assert "could not be read" in out, \
        "the residue it could not compare against went unnamed"


# --- the key file beside the config ------------------------------------------
#
# Section 4 hardened ~/.carryon/config.json because every subcommand reads it
# before it has decided anything. The file next to it in the same directory is
# the master key, and its reader kept the exact shape config.load was hardened
# out of - an is_file() ahead of the read - so everything that is not a plain
# readable file there answered "this machine holds no key".
#
# What a wrong answer costs is not the same, which is why it is tested through
# the subcommands rather than at the reader. A config that reads as absent is a
# push saying "no Destination configured". A master key that reads as absent is
# `carryon init` minting a fresh one over a key that was merely unreadable, and
# `push --category config` silently taking ADR-0004's keyless path over a Setup
# the Index still records as authenticated - after which every pull from every
# machine refuses that Setup whole, naming files as if the Destination had been
# tampered with.


def break_master_key(home) -> pathlib.Path:
    """Leave a master.key at the usual path that no read can answer about.

    A symlink loop: the key material is untouched somewhere else, or was never
    there, and nothing about the path says the machine is unpaired.
    """
    path = home / ".carryon" / "master.key"
    path.unlink()
    other = path.parent / "master-loop.key"
    path.symlink_to(other)
    other.symlink_to(path)
    return path


def test_a_master_key_that_will_not_read_never_becomes_a_keyless_push(
        tmp_path, capsys):
    """`push --category config` needs no master key by design (ADR-0004), so
    it is the one leg that carries on when fetch_master answers None - and the
    Setup it then writes carries no SETUP.mac while the encrypted Index still
    records `authenticated: True`. That is the state ADR-0009 refuses on every
    pull, so one unreadable file here is every machine's Setup, gone.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    assert sync.push(ns(apply=True), home) == 0
    break_master_key(home)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), home)

    assert "master.key" in str(exc.value), "the refusal does not name the file"


def test_init_does_not_mint_a_fresh_master_key_over_one_it_cannot_read(
        tmp_path, capsys):
    """The same question asked by the one subcommand whose answer cannot be
    taken back. init refuses outright when this machine already holds a key;
    a key it cannot read reads as no key, so it went on to mint a new recovery
    key, a new master key, and an Archive whose History nothing now opens.

    A dangling link rather than a loop, because that is the shape where every
    later syscall SUCCEEDS: the read says ENOENT, and the write that follows
    creates the target and puts this machine's trust root in whatever tree the
    link points into (ADR-0007).
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    real = keyring.fetch_master(home=home)
    path = home / ".carryon" / "master.key"
    path.unlink()
    elsewhere = tmp_path / "dotfiles" / "master.key"
    elsewhere.parent.mkdir()
    path.symlink_to(elsewhere)
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, machine="machine-a"), home)

    assert "master.key" in str(exc.value), "the refusal does not name the file"
    assert not elsewhere.exists(), \
        "a fresh master key was written through a link into another tree"
    assert real is not None


def test_the_high_water_mark_is_never_written_through_a_link(configured,
                                                             capsys):
    """The third file in carryon's own state directory, and the third plain
    write. A link at state.json sends the Archive's revision into whatever
    tree the link points into - the same ADR-0007 breach as the config and the
    master key beside it, on the file that exists to notice a rolled-back
    Index.

    Still a warning rather than a refusal, which is the other half: the mark
    is never a gate. A mark that cannot be written costs one check, and a push
    that stopped over it would cost the whole Snapshot.
    """
    path = sync._state_path(configured)
    if path.exists() or path.is_symlink():
        path.unlink()
    elsewhere = tmp_dotfiles = configured.parent / "dotfiles" / "state.json"
    tmp_dotfiles.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(elsewhere)
    capsys.readouterr()

    assert sync.push(ns(apply=True), configured) == 0, \
        "an unwritable high-water mark stopped a push"
    out = capsys.readouterr().out

    assert not elsewhere.exists(), \
        "the high-water mark was written through a link into another tree"
    assert "state.json" in out, "the mark went unwritten without a word"
