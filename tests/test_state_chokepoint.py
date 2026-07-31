"""One question about carryon's own state, asked wherever content is read.

Seven rounds have each found the same defect in a new place: a rule closed
where it was reviewed and open where it was not. The last three arrivals - a
hard link to the master key in a Session tree, a Setup backup written through
a link, and `capture --archive` handing a whole directory to `tar.add` - were
each an already-closed question asked somewhere nobody had looked. So this
suite is not about any of the instances. It is about the question having ONE
answer and every leg reaching it:

  the read side   `config.carry_refusal` asks the path question and the
                  identity question together, and `config.read_carryable` is
                  the only way in this package to turn a user path into bytes
                  that leave it. The legs are parametrised below, so a future
                  leg that grows its own read fails a test rather than a
                  review - and `test_no_content_read_bypasses_the_gate` walks
                  the package's own syntax tree to say so about a leg nobody
                  has written yet.
  the answer      the identity half rests on a walk of ~/.carryon, and that
                  walk used to answer "nothing" for a directory it could not
                  list, which every reader took for "no". `blind-state` is
                  the leg for it: mode 0300 on the state directory, which
                  carryon goes on using by name without noticing, and the one
                  rule a hard link cannot defeat switched off in silence.
  the write side  the same enumeration in the other direction. The eighth
                  round collapsed it: `external.write_owned` is the one
                  function that puts content at a path carryon does not own,
                  and it asks and writes in one call, so the entries that
                  used to read "external.owner_of, asked immediately above
                  the call" are gone rather than re-approved. What is left
                  writes into an Archive or into a directory this process
                  just made.
  the removals    a third enumeration, because two of the three properties
                  here are promises that something SURVIVES and both
                  scanners above watch bytes arriving. The sweep that
                  unlinked a machine's own workflow journals made no write
                  at all.
  the granularity an allowlist entry pins the CALLS a function may make, not
                  the function. Keyed on the function alone it excused
                  everything inside `sync.pull` - seven hundred lines, and
                  where the defect it was written for actually lived.
  the name        a backup directory stamped to the second is one a second
                  pull in the same second overwrites, which loses the copy
                  ADR-0002 promises is recoverable.

Every home here is synthetic and the "master key" is invented hex - except in
the one test that hard-links the genuine article a fresh `init` wrote, where
being sure nothing about the plant is special is the whole point. What is
asserted is that those bytes are nowhere in what left the machine, so they
must be recognisable and must not be anybody's real key.
"""

import ast
import gzip
import json
import os
import pathlib
import stat
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, config, history, keyring, rekey, sync  # noqa: E402
from tests.hostile_archive import (build_home_a, files_containing,  # noqa: E402
                                   link_home, ns)
from tests.timeouts import time_limit  # noqa: E402

# 32 hex characters with nothing in front of them - the shape ADR-0001 names
# as the reason this carve-out cannot be a question put to the scanner.
FAKE_KEY = "00112233445566778899aabbccddeeff" * 2 + "\n"
NEEDLE = FAKE_KEY.strip()

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJ_REL = "code/snake_case_proj"
# A directory you may enter and may not list. carryon opens its own config and
# its own master.key by name and neither notices; the walk that collects the
# state's inodes comes back empty.
SEARCH_ONLY = 0o300
MANAGED = "# managed by my dotfiles repo\n"
LOCAL_SETTINGS = '{"model": "local-tweak"}'


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def plant_state(home) -> pathlib.Path:
    key = home / ".carryon" / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text(FAKE_KEY)
    return key


def write_config(home, **kw) -> None:
    cfg = config.default_config()
    cfg.update(kw)
    config.save(cfg, home)


def project_root(home, rel=PROJ_REL) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(str(home / rel)))


def build_history_home(tmp_path) -> pathlib.Path:
    """A home with one Session tree and one project residue beside it."""
    home = tmp_path / "home_h"
    project = project_root(home)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(
        jline({"cwd": str(home / PROJ_REL), "type": "meta"}))
    (project / UUID_A).mkdir()
    (project / UUID_A / "notes.jsonl").write_text(jline({"step": 1}))
    (project / "memory").mkdir()
    (project / "memory" / "MEMORY.md").write_text("ordinary memory\n")
    plant_state(home)
    return home


def build_codex_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home_c"
    day = home / ".codex" / "sessions" / "2026" / "07" / "31"
    day.mkdir(parents=True)
    (day / f"rollout-2026-07-31T09-00-00-{UUID_A}.jsonl").write_text(
        jline({"payload": {"cwd": str(home / PROJ_REL)}, "type": "meta"}))
    plant_state(home)
    return home


# --- the legs ----------------------------------------------------------------
#
# Each leg plants ONE hard link to ~/.carryon/master.key somewhere the leg
# reads, runs the leg the way a user reaches it, and hands back what left the
# machine plus the report that was printed. A hard link is the shape no path
# rule can see: not a symlink, resolve() answers with its own path, it sits
# under $HOME and nowhere near '.carryon', and it is a second name for the
# key's bytes.


class Outcome(types.SimpleNamespace):
    """carried: byte blobs this leg would hand on. named: the path that has to
    appear in what the leg printed, which the test reads off capsys."""


def _capture_outcome(home, out, named, effective=None):
    """`capture.run` over the raw registry, or over the effective one a
    handpicked path needs (ADR-0008), and everything it wrote."""
    if effective is None:
        code, _ = capture.run(out=out, dry=False, home=home)
    else:
        with sync._swapped_registry(effective):
            code, _ = capture.run(out=out, dry=False, home=home)
    carried = [p.read_bytes() for p in sorted(out.rglob("*"))
               if p.is_file() and not p.is_symlink()]
    return Outcome(carried=carried, named=named, code=code)


def leg_setup_tree(tmp_path):
    """An adapter-declared tree: '.claude/commands' holds whatever the
    filesystem holds, and no handpicking is involved at all."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    os.link(key, home / ".claude" / "commands" / "notes.md")
    return _capture_outcome(home, tmp_path / "setup",
                            ".claude/commands/notes.md")


def leg_handpicked_tree(tmp_path):
    """`carry: ['~/.mytool']` (ADR-0008): an ordinary directory no rule
    refuses, expanded into a tree after the judgment."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    tool = home / ".mytool"
    tool.mkdir()
    os.link(key, tool / "notes.md")
    write_config(home, carry=["~/.mytool"])
    cfg = config.load(home)
    return _capture_outcome(home, tmp_path / "setup", ".mytool/notes.md",
                            effective=sync._effective_adapters(cfg, home))


def leg_handpicked_file(tmp_path):
    """The same identity handpicked by name - a `file` Item, which do_file
    reads in one call with no walk in front of it to filter anything."""
    home = build_home_a(tmp_path)
    key = plant_state(home)
    os.link(key, home / "decoy")
    write_config(home, carry=["~/decoy"])
    cfg = config.load(home)
    return _capture_outcome(home, tmp_path / "setup", "decoy",
                            effective=sync._effective_adapters(cfg, home))


def _history_outcome(home, named):
    """Discovery, then every tar the push would build from it. The tar is what
    leaves the machine; the Archive it lands in is sealed under the very key
    at issue, so the bytes are checked before they are encrypted."""
    from carryon.adapters import ADAPTERS
    found = history.discover(home, list(ADAPTERS.values()))
    carried = []
    for record in list(found.sessions) + list(found.residues):
        try:
            tar_bytes, _ = history.pack_session(record, home)
        except history.MemberUnreadable:
            continue
        carried.append(tar_bytes)
    for rel in found.withheld:
        print(f"  -- ~/{rel}")
    return Outcome(carried=carried, named=named, code=0)


def leg_history_session(tmp_path):
    """A member of a Session's subtree. The Setup leg asks both questions
    here; this leg asked only the path one."""
    home = build_history_home(tmp_path)
    key = home / ".carryon" / "master.key"
    os.link(key, project_root(home) / UUID_A / "notes.md")
    rel = (project_root(home) / UUID_A / "notes.md").relative_to(home)
    return _history_outcome(home, rel.as_posix())


def leg_history_main(tmp_path):
    """The main Transcript itself, which discovery names a Session by. It is
    read twice - once for its cwd, once to pack it."""
    home = build_history_home(tmp_path)
    key = home / ".carryon" / "master.key"
    other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    os.link(key, project_root(home) / (other + ".jsonl"))
    rel = (project_root(home) / (other + ".jsonl")).relative_to(home)
    return _history_outcome(home, rel.as_posix())


def leg_history_residue(tmp_path):
    """The per-project memory that accretes beside a Session. Part of a
    History (CONTEXT.md) and packed by the same function."""
    home = build_history_home(tmp_path)
    key = home / ".carryon" / "master.key"
    os.link(key, project_root(home) / "memory" / "keys.md")
    rel = (project_root(home) / "memory" / "keys.md").relative_to(home)
    return _history_outcome(home, rel.as_posix())


def leg_codex_rollout(tmp_path):
    """The other layout. A rollout file IS the whole Session, so the link is
    the Session - and a layout is exactly the kind of thing a later round
    adds, which is why the leg is in the table rather than in one test."""
    home = build_codex_home(tmp_path)
    key = home / ".carryon" / "master.key"
    day = home / ".codex" / "sessions" / "2026" / "07" / "31"
    other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    os.link(key, day / f"rollout-2026-07-31T10-00-00-{other}.jsonl")
    rel = (day / f"rollout-2026-07-31T10-00-00-{other}.jsonl").relative_to(home)
    return _history_outcome(home, rel.as_posix())


def leg_blind_state(tmp_path):
    """The same hard link, met by a gate that cannot walk its own state.

    Mode 0300 on ~/.carryon: carryon opens its config and its master key by
    name and neither notices, and the walk that collects the state's inodes
    comes back empty. An empty set read as "no" is the identity half of the
    gate switched off in silence - so this leg is the path rules alone, which
    is exactly what a hard link defeats.
    """
    home = build_history_home(tmp_path)
    key = home / ".carryon" / "master.key"
    plant = project_root(home) / UUID_A / "notes.md"
    os.link(key, plant)
    rel = plant.relative_to(home).as_posix()
    os.chmod(str(home / ".carryon"), SEARCH_ONLY)
    try:
        return _history_outcome(home, rel)
    finally:
        os.chmod(str(home / ".carryon"), 0o700)


def leg_capture_archive(tmp_path):
    """`capture --out DIR --archive FILE.tar.gz`, the eighth leg.

    The tar was built with `tar.add(out, arcname=out.name)`, which turns a
    whole TREE into content in one call that meets no gate: `--out` is a path
    the user names and carryon never clears, so a second name for
    ~/.carryon/master.key sitting in it went into setup.tar.gz verbatim - at
    exit 0, under 'SECRET SCAN: clean', and under a closing line saying
    private storage of any kind will do. tarfile stores the first occurrence
    of an inode as an ordinary file, so a hard link is packed with its
    contents.
    """
    home = build_home_a(tmp_path)
    key = plant_state(home)
    out = tmp_path / "setup"
    out.mkdir()
    os.link(key, out / "notes.md")
    archive_path = tmp_path / "setup.tar.gz"

    code, _ = capture.run(out=out, dry=False, home=home,
                          archive=archive_path)
    # The archive alone: the plant is IN the output directory, so reading that
    # directory back would find the key under the name the test put it there
    # under. What leaves the machine is the tar.
    carried = []
    if archive_path.is_file():
        carried.append(archive_path.read_bytes())
        with gzip.open(str(archive_path), "rb") as handle:
            carried.append(handle.read())
    return Outcome(carried=carried, named="notes.md", code=code)


LEGS = {
    "setup-tree": leg_setup_tree,
    "handpicked-tree": leg_handpicked_tree,
    "handpicked-file": leg_handpicked_file,
    "history-session": leg_history_session,
    "history-main": leg_history_main,
    "history-residue": leg_history_residue,
    "codex-rollout": leg_codex_rollout,
    "capture-archive": leg_capture_archive,
    "blind-state": leg_blind_state,
}


@pytest.mark.parametrize("leg", sorted(LEGS))
def test_a_hard_link_to_the_master_key_never_leaves_by_any_leg(leg, tmp_path,
                                                               capsys):
    """The one property, asked of every content-reading leg there is.

    A leg added later that grows its own read is a new entry in LEGS and a new
    failure here; a leg added later that does not appear here at all is what
    `test_no_content_read_bypasses_the_gate` is for.
    """
    outcome = LEGS[leg](tmp_path)
    report = capsys.readouterr().out

    assert not any(NEEDLE.encode() in blob for blob in outcome.carried), \
        f"the {leg} leg carried the master key's bytes off this machine"
    assert outcome.named in report, \
        f"the {leg} leg withheld the key without naming the path"


def test_push_names_the_withheld_hard_link_and_still_pushes(tmp_path, capsys):
    """The leg table above stops at the tar; this is the command a user runs.

    ADR-0001's posture on this half is REPORT, not refuse: a History cannot be
    fixed retroactively and a project tree is a place users make links, so the
    push carries on and says what it left behind. A withheld member with no
    line is the failure mode the whole report exists to prevent - a Session
    quietly short a file reads as one that was carried.
    """
    home = build_history_home(tmp_path)
    # init refuses over a machine that already holds a key, and this home was
    # built with the stand-in planted; let init mint the real one.
    (home / ".carryon" / "master.key").unlink()
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    # The real fallback key this init just wrote, not the stand-in above:
    # linking the genuine article is the only way to be sure nothing about
    # the plant is special. It is hard-linked AFTER init, because writing
    # ~/.carryon/master.key through a second name is the mirror-image refusal
    # config.write_state_bytes exists for.
    key = home / ".carryon" / "master.key"
    secret = key.read_text().strip()
    os.link(key, project_root(home) / UUID_A / "notes.md")

    code = sync.push(ns(apply=True, category="history"), home)
    report = capsys.readouterr().out

    assert code == 0, "one link in one project refused a whole History"
    assert "WITHHELD" in report
    assert f"{UUID_A}/notes.md" in report
    assert not files_containing(tmp_path / "archive", secret), \
        "the master key reached the Archive"


def test_an_ordinary_hard_link_inside_a_session_is_carried(tmp_path):
    """The rule is identity with carryon's OWN state, not 'this file has more
    than one name'. Hard links turn up in backup schemes and in build trees,
    and a History that refused every one of them would leave a user with
    Transcripts that never travel and nothing they can do about it."""
    home = build_history_home(tmp_path)
    twin = home / PROJ_REL
    twin.mkdir(parents=True)
    (twin / "twin.jsonl").write_text(jline({"twin": "ordinary"}))
    member = project_root(home) / UUID_A / "twin.jsonl"
    os.link(twin / "twin.jsonl", member)

    from carryon.adapters import ADAPTERS
    found = history.discover(home, list(ADAPTERS.values()))
    session = next(s for s in found.sessions if s.uuid == UUID_A)

    assert f"{UUID_A}/twin.jsonl" in session.files, \
        "an ordinary hard link between two of the user's own files was withheld"
    assert not found.withheld
    tar_bytes, report = history.pack_session(session, home)
    assert b"ordinary" in tar_bytes


def test_an_ordinary_setup_capture_is_unaffected(tmp_path, capsys):
    """The other direction of the same worry: the gate must not turn an
    everyday capture into a refusal."""
    home = build_home_a(tmp_path)
    plant_state(home)
    out = tmp_path / "setup"

    code, _ = capture.run(out=out, dry=False, home=home)
    report = capsys.readouterr().out

    assert code == 0, report
    assert (out / "claude" / "commands" / "ship.md").read_text() == "ship it\n"


# --- one question, one implementation ----------------------------------------


def test_the_gate_answers_both_questions_about_one_path(tmp_path):
    """The chokepoint itself, away from any leg. Identity and path are one
    call, so a caller cannot ask half of it."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    key = plant_state(home)
    hard = home / ".claude" / "hard.md"
    os.link(key, hard)
    soft = home / ".claude" / "soft.md"
    soft.symlink_to(key)
    plain = home / ".claude" / "plain.md"
    plain.write_text("ordinary\n")

    assert config.carry_refusal(hard, home) == config.WHY_STATE
    assert config.carry_refusal(soft, home) == config.WHY_STATE
    assert config.carry_refusal(plain, home) is None


def test_the_gate_reads_and_refuses_in_one_call(tmp_path):
    """read_carryable is the read, not a check beside one: a refusal comes
    back instead of the bytes, so there is no arrangement of the two calls
    that reads first and asks afterwards."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    key = plant_state(home)
    hard = home / ".claude" / "hard.md"
    os.link(key, hard)

    data, why = config.read_carryable(hard, home)
    assert data is None
    assert why == config.WHY_STATE

    plain = home / ".claude" / "plain.md"
    plain.write_text("ordinary\n")
    data, why = config.read_carryable(plain, home)
    assert why is None
    assert data == b"ordinary\n"


def test_the_gate_treats_an_unresolvable_path_as_state(tmp_path):
    """Fail closed on the carve-out: carryon cannot prove a path it will not
    resolve is not its own state."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    plant_state(home)
    loop = home / ".claude" / "loop.md"
    loop.symlink_to(home / ".claude" / "loop2.md")
    (home / ".claude" / "loop2.md").symlink_to(loop)

    data, why = config.read_carryable(loop, home)
    assert data is None
    assert why is not None


def test_the_gate_re_asks_identity_on_the_descriptor_it_reads(tmp_path,
                                                              monkeypatch):
    """The one thing a check beside a read can never do, and the whole
    argument for the gate reading rather than answering: 'the walk->read
    TOCTOU no check-beside-a-read can close'.

    Deleting the fstat re-check left the suite green, so the property was
    load-bearing in a docstring and dead weight in the tests. The race is
    modelled by making the PATH answer come back clean - which is what a
    project directory anybody can write to hands you between the walk and the
    read - and asking whether the bytes still come back.
    """
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    key = plant_state(home)
    swapped = home / ".claude" / "swapped.md"
    os.link(key, swapped)
    monkeypatch.setattr(config, "carry_refusal",
                        lambda *a, **kw: None)

    data, why = config.read_carryable(swapped, home)

    assert data is None, ("the path answer went stale and the read handed "
                          "over the master key's bytes")
    assert why == config.WHY_STATE


def test_the_gate_reads_only_an_ordinary_file(tmp_path):
    """A named pipe answers read() by waiting for a writer that may never
    come - a `carryon push` that never returns and prints nothing. The
    Destination layer refuses one for exactly this reason, and the refusal
    here was untested: deleting it left the suite green.
    """
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    plant_state(home)
    fifo = home / ".claude" / "pipe"
    os.mkfifo(str(fifo))
    assert stat.S_ISFIFO(fifo.stat().st_mode)

    # Under the shared limit, because the regression this test is for is not a
    # wrong verdict: dropping O_NONBLOCK from the open below wedged this very
    # test for ever, with no output from either runner.
    with time_limit(what="the gate never came back from the pipe"):
        data, why = config.read_carryable(fifo, home)

    assert data is None
    assert "ordinary file" in why


# --- a walk that could not look is not a walk that found nothing -------------
#
# The identity half of the gate is the only one that can see a hard link, and
# it is answered from a set of (st_dev, st_ino) collected by walking
# ~/.carryon. That walk swallowed every error and answered with an empty set,
# and `_is_state_content` read an empty set as "no", so the identity rule
# turned itself OFF for the whole run, in silence.
#
# Mode 0300 is the reachable spelling and the reason this is not a curiosity: a
# directory you may enter and may not list. carryon opens its own config and
# its own master.key by name and neither notices, the push runs normally, the
# report says nothing - and a hard link to that key in a Session tree is packed
# and laid down on every machine that pulls. A backup restored with the wrong
# modes and a botched chmod both produce one, which are the two causes
# layout.py already calls ordinary and needing no attacker.
#
# It is the shape ADR-0009's last section names one document over: an answer
# inherited from a level that could not answer. Every other walk in this
# package reports a directory it could not list - capture.tree_files,
# history._listing, layout._entries, destinations/base._local_keys, each in as
# many words. This was the last one that did not, and it is the one whose
# silence costs the trust root.

def unreadable_state(home) -> pathlib.Path:
    """A ~/.carryon holding the key, which carryon can use and cannot list."""
    key = plant_state(home)
    os.chmod(str(home / ".carryon"), SEARCH_ONLY)
    return key


def test_a_state_walk_that_could_not_look_says_so(tmp_path):
    """The answer carries whether it is complete, because 'nothing' and 'I
    could not tell' are different answers and only one of them means no."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    plant_state(home)

    assert config.state_identities(home).complete
    assert config.state_identities(tmp_path / "never-initialised").complete, \
        "a machine with no ~/.carryon at all has an answerable 'none'"

    unreadable_state(home)
    try:
        assert not config.state_identities(home).complete
    finally:
        os.chmod(str(home / ".carryon"), 0o700)


def test_the_gate_refuses_while_it_cannot_answer_about_the_state(tmp_path):
    """Fail closed, like every other rule about ~/.carryon: an unanswerable
    carve-out is a refusal, not a pass. The sentence is its own, because
    'it reads carryon's own state' would be a claim about this file that
    carryon has not made."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    key = unreadable_state(home)
    hard = home / ".claude" / "agents.md"
    os.link(key, hard)
    plain = home / ".claude" / "plain.md"
    plain.write_text("ordinary\n")

    try:
        data, why = config.read_carryable(hard, home)
        assert data is None, ("the master key's bytes came back through a "
                              "second name while the state walk was blind")
        assert config.WHY_STATE_UNANSWERED in why

        # and not only the planted name: while the question cannot be
        # answered it cannot be answered about anything.
        assert config.carry_refusal(plain, home) is not None
    finally:
        os.chmod(str(home / ".carryon"), 0o700)


def test_a_push_that_cannot_answer_about_its_own_state_carries_nothing(
        tmp_path, capsys):
    """The whole leg, because a rule that refuses in a unit test and lets a
    push through is no rule.

    Nothing here is degraded except the one directory's mode: carryon reads
    its config and its master key by name throughout, so the push runs, and
    what it must not do is publish a second name for that key. The Session is
    left behind and named, which is what every other withheld member already
    is (history._packable).
    """
    home = build_history_home(tmp_path)
    key = home / ".carryon" / "master.key"
    hard = project_root(home) / UUID_A / "notes.jsonl"
    hard.unlink()
    os.link(key, hard)
    dest_root = tmp_path / "archive"
    write_config(home, destination=str(dest_root), machine="a")
    os.chmod(str(home / ".carryon"), SEARCH_ONLY)

    try:
        code = sync.push(ns(apply=True), home)
        report = capsys.readouterr().out
    finally:
        os.chmod(str(home / ".carryon"), 0o700)

    assert NEEDLE not in report
    assert config.WHY_STATE_UNANSWERED in report, \
        "nothing in the report says the state walk could not answer"
    assert code != 0, report
    # Nothing at all went up: a Session object is sealed under the very key at
    # issue, so what has to be true is that none was written, not that a grep
    # of the ciphertext comes back empty.
    sessions = dest_root / "carryon" / "sessions"
    assert not sessions.is_dir() or not list(sessions.iterdir()), \
        "a Session was packed while nobody could answer for its members"


# --- the enforcement: what stops the seventh caller --------------------------
#
# Two scanners over the package's own syntax tree, one per direction, and both
# of them had the same two holes - each demonstrated against the shipped code
# rather than argued about:
#
#   the verbs  `shutil.copy` is one character from the `copy2` they scanned
#              for, and `shutil.move`, `copyfileobj`, `writelines`,
#              `json.dump`, `os.replace` and a tarfile opened on a PATH were
#              in neither set. A function doing all of those passed both
#              scanners green. `capture.write_archive` was the live instance:
#              `tar.add(out, arcname=...)` turned a whole tree into content in
#              one call neither scanner could see.
#   the unit   an entry was a (module, function) pair, which is coarser than
#              the defect. The Setup backup that prompted this suite lived
#              INSIDE `sync.pull`, and `sync.pull` has to be allowlisted - so
#              a read of ~/.carryon/master.key planted at the top of pull left
#              every enforcement test green. A tripwire whose granularity is
#              larger than the unit the defects arrive in says nothing.
#
# So an entry pins the CALLS rather than the function: the verbs that function
# may make, with multiplicity. A call added inside an allowlisted function is
# a failure naming the function, and the edit that silences it is the review
# this suite exists to force.
#
# What no scanner can see is a write made through a descriptor some other
# object holds - a tarfile opened on an fd, a subprocess handed a path. Those
# are why `capture` has exactly one writer and `crypto` shells out from a
# TemporaryDirectory: the shape is chosen so the scanner CAN see it.

# Verbs whose bare name is nobody else's: a call to one of these is a path
# becoming content (or content becoming a file) whatever it is called on.
READ_ATTRS = {"read_bytes", "read_text", "open"}
WRITE_ATTRS = {"write_bytes", "write_text", "writelines", "write", "copymode",
               "extract", "extractall"}

# Verbs whose bare name belongs to somebody else - `str.replace` is not
# `os.replace` and `dict.copy` is not `shutil.copy` - so the receiver is part
# of the name. A from-import (`from shutil import copy2`) is caught too: the
# bare call carries the same name.
READ_CALLS = {("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
              ("shutil", "copytree"), ("shutil", "copyfileobj"),
              ("shutil", "move"), ("os", "readlink")}
WRITE_CALLS = {("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
               ("shutil", "copytree"), ("shutil", "copyfileobj"),
               ("shutil", "move"), ("os", "rename"), ("os", "replace"),
               ("os", "link"), ("json", "dump")}

# The third direction, and the one no scanner watched at all. Two of the three
# properties these suites are about are promises that something SURVIVES -
# ADR-0002 opens its Consequences with "Pull never deletes" - and both scanners
# above watch bytes arriving. A branch that unlinks a Transcript, or truncates
# one it then declines to write, passes each of them green; the branch that
# swept a Session tree, which is the defect tests/test_pull_never_deletes.py
# exists for, made no write at all.
REMOVE_ATTRS = {"unlink", "rmdir", "truncate"}
REMOVE_CALLS = {("shutil", "rmtree"), ("os", "remove"), ("os", "unlink"),
                ("os", "rmdir"), ("os", "removedirs"), ("os", "truncate"),
                ("os", "ftruncate")}

# `X.open(...)` where X is one of these is ordinarily bytes carryon already
# holds - `tarfile.open(fileobj=buf)` - and is a path turning into content
# exactly when it is handed a path. Which is what `tar.add` used to hide
# behind: the open was excused wholesale, so everything done through it was.
MODULE_OPENS = {"tarfile", "gzip", "zipfile", "io"}


def _enclosing(tree):
    """{node: function name} for every node under a function definition."""
    owner = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                owner.setdefault(child, node.name)
    return owner


def _opens_a_path(node) -> bool:
    return bool(node.args) or any(kw.arg in ("name", "filename")
                                  for kw in node.keywords)


def _verb_of(node, attrs, calls):
    """What this call does to a path, or None."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name):
        if func.id in attrs:
            return func.id
        for _module, attr in calls:
            if func.id == attr:
                return attr
        return None
    if not isinstance(func, ast.Attribute):
        return None
    receiver = func.value.id if isinstance(func.value, ast.Name) else None
    if func.attr == "open" and receiver in MODULE_OPENS:
        return "open" if _opens_a_path(node) else None
    if receiver is not None and (receiver, func.attr) in calls:
        return f"{receiver}.{func.attr}"
    if func.attr in attrs:
        return func.attr
    return None


def _calls_in(rel: str, source: str, attrs, calls) -> list:
    """(module, function, line, verb) for every such call in one module."""
    tree = ast.parse(source)
    owner = _enclosing(tree)
    found = []
    for node in ast.walk(tree):
        verb = _verb_of(node, attrs, calls)
        if verb is not None:
            found.append((rel, owner.get(node, "<module>"), node.lineno, verb))
    return found


def _package_calls(attrs, calls) -> list:
    root = pathlib.Path(__file__).resolve().parents[1] / "carryon"
    found = []
    for path in sorted(root.rglob("*.py")):
        found += _calls_in(path.relative_to(root).as_posix(),
                           path.read_text(), attrs, calls)
    return found


def _package_reads() -> list:
    return _package_calls(READ_ATTRS, READ_CALLS)


def _package_writes() -> list:
    return _package_calls(WRITE_ATTRS, WRITE_CALLS)


def _package_removals() -> list:
    return _package_calls(REMOVE_ATTRS, REMOVE_CALLS)


def _bypasses(found, allowed) -> list:
    """Every call the allowlist does not account for, as report lines.

    Two ways to fail, and the second one is the point: a function nobody
    argued for, and a function that grew a call since somebody did.
    """
    made = {}
    for rel, where, line, verb in found:
        made.setdefault((rel, where), []).append((verb, line))
    stray = []
    for key, entries in sorted(made.items()):
        rel, where = key
        verbs = sorted(verb for verb, _line in entries)
        lines = ", ".join(str(line) for _verb, line in sorted(entries,
                                                              key=lambda e: e[1]))
        if key not in allowed:
            stray.append(f"{rel}:{lines} in {where}() - {', '.join(verbs)}")
            continue
        _why, pinned = allowed[key]
        if verbs != sorted(pinned):
            stray.append(
                f"{rel}:{lines} in {where}() makes {verbs}, and the allowlist "
                f"argues for {sorted(pinned)}")
    return stray


def _stale(found, allowed) -> list:
    live = {(rel, where) for rel, where, _line, _verb in found}
    return sorted(set(allowed) - live)


# Every place in the package that turns a path into bytes, with the reason it
# is not a carry and the calls it is allowed to make. A new one is a failure
# here, which is the whole point: a walk that can read a file's bytes without
# asking is a walk somebody will eventually write, and review has now missed
# the same question seven times.
ALLOWED_READS = {
    ("config.py", "read_carryable"): (
        "the gate itself - it asks, then reads", ("open",)),
    ("external.py", "write_owned"): (
        "the write chokepoint's O_NOFOLLOW open, which reads nothing",
        ("open",)),
    ("config.py", "read_state_bytes"): (
        "the state gate - it settles the type, then reads. The entries this "
        "replaced were ('config.py', 'load'), ('sync.py', '_load_state') and "
        "('keyring.py', 'fetch_master'), each excused as 'carryon's own "
        "config.json' / 'own state.json' / 'own master.key' - which is true "
        "and is not a reason. carryon writes those files and does not control "
        "what is at the name when it next reads one, so the excuse bought a "
        "traceback out of push and pull, a hang in every subcommand and a "
        "dangling link read as a machine that was never set up. The third one "
        "survived a round longer than the other two on a narrower excuse - it "
        "holds bare hex rather than a JSON document, so the gate's shape did "
        "not fit - and that is why the gate is now split: read_state_bytes IS "
        "the gate, and read_state_json is one caller of it. They are gone "
        "rather than re-approved, so the scanner enforces this the way it "
        "enforces read_carryable", ("open",)),
    ("crypto.py", "_run_bytes"): (
        "a temp file this process just wrote", ("read_bytes",)),
    ("history.py", "member_verdict"): (
        "the LOCAL file a write is compared against; nothing leaves - and it "
        "opens O_NOFOLLOW|O_NONBLOCK and requires S_ISREG, because a fifo "
        "there was a pull that hung for ever", ("open",)),
    ("history.py", "read_recorded_cwd"): (
        "a Transcript already past the gate, read for its cwd", ("open",)),
    ("rekey.py", "read_cwd"): (
        "the same read one module down, standalone", ("open",)),
    ("sync.py", "_neutralise_staged_setup"): (
        "carryon's own staging tree, already captured through the gate",
        ("read_bytes",)),
    ("sync.py", "_stored_manifest"): (
        "the stored Setup in carryon's staging", ("read_text",)),
    ("sync.py", "_stored_setup_tag"): (
        "the stored Setup in carryon's staging", ("read_bytes",)),
    ("sync.py", "_restore_setup_item"): (
        "the staged Setup being written out, an Archive's bytes on their way "
        "IN", ("read_bytes",)),
    ("archive.py", "setup_tree_manifest"): (
        "a Setup tree carryon staged", ("read_bytes",)),
    ("archive.py", "tree_hash"): ("a Setup tree carryon staged",
                                  ("read_bytes",)),
    ("destinations/base.py", "write_tree"): (
        "a tree carryon staged, on its way to a Destination", ("read_bytes",)),
    ("destinations/base.py", "_at_open"): (
        "the openat walk over a Destination's own tree (ADR-0009)",
        ("open", "open")),
    ("destinations/base.py", "_at_child"): (
        "the same walk, one component down", ("open",)),
    ("destinations/base.py", "_descend"): ("the same walk, at its root",
                                           ("open",)),
}


def test_no_content_read_bypasses_the_gate():
    """The structural half, and the honest answer to "what stops the seventh
    caller".

    Nothing in Python can take `read_bytes` away from a walk, so the package's
    own syntax tree is what enforces the chokepoint: every call that turns a
    path into content is either inside `config.read_carryable` or listed above
    with the reason it carries nothing. A new leg that reads for itself fails
    here with the file and the function named, which is a test failing rather
    than a reviewer noticing - and the reviewer has now missed this same
    question seven times running.
    """
    stray = _bypasses(_package_reads(), ALLOWED_READS)
    assert not stray, (
        "content is read outside carryon's one gate (config.read_carryable). "
        "Route it through the gate, or add it to ALLOWED_READS with the "
        "reason it carries nothing:\n  " + "\n  ".join(stray))


# The same enumeration for the other direction, and the eighth round's whole
# claim in one table: there is now exactly ONE function in this package that
# puts content at a path carryon does not own, and it both asks and writes.
#
# The seventh round left four chokepoints that ANSWERED - external.owner_of,
# config.state_write_path, config.write_state_bytes, the Destination base -
# and five call sites that then wrote with Path.write_bytes a syscall later.
# Every entry that used to sit here saying "external.owner_of, asked
# immediately above the call" was that gap written down and approved:
# `history.write_member`, `capture._write_owned`, `sync._restore_setup_item`.
# They are gone rather than re-argued, and `config.write_state_bytes` is the
# state leg's framing of the same call rather than a second implementation of
# it. What is left writes into an Archive, into a directory this process just
# minted, or is the chokepoint itself.
ALLOWED_WRITES = {
    ("external.py", "write_owned"): (
        "the write chokepoint itself - it asks owner_of about the ancestors, "
        "opens the leaf O_NOFOLLOW, and answers for the descriptor before it "
        "truncates anything", ("write",)),
    ("destinations/base.py", "read_tree"): (
        "the Destination base class's own openat walk (ADR-0009)",
        ("write_bytes",)),
    ("destinations/base.py", "write_tree"): (
        "Destination.write, the Archive chokepoint", ("write",)),
    ("destinations/base.py", "_local_write"): (
        "inside that walk, on a descriptor it opened", ("write",)),
    ("destinations/rclone_remote.py", "_write_blob"): (
        "a temp file this call made, handed to rclone", ("write",)),
    ("archive.py", "save_index"): ("Destination.write, the Archive chokepoint",
                                   ("write",)),
    ("archive.py", "_put_object"): (
        "Destination.write, the Archive chokepoint", ("write",)),
    ("archive.py", "put_pairing"): (
        "Destination.write, the Archive chokepoint", ("write",)),
    ("sync.py", "_neutralise_staged_setup"): (
        "carryon's own staging tree, under a staging root config."
        "state_write_path answered for", ("write_bytes", "write_text",
                                          "write_text")),
    ("destinations/base.py", "_at_replace"): (
        "the atomic rename of an in-flight blob into place, inside the "
        "descriptor the openat walk ended on (ADR-0009)",
        ("os.rename", "os.replace")),
    ("sync.py", "_push_partial_setup"): (
        "carryon's own staging tree", ("write_bytes", "write_text",
                                       "write_text")),
    ("sync.py", "push"): ("carryon's own staging tree", ("write_bytes",)),
    ("crypto.py", "_run_bytes"): ("a TemporaryDirectory this call made",
                                  ("write_bytes",)),
}


def test_no_content_write_bypasses_an_ownership_question():
    """The Setup backup was the last write of user content that asked nothing,
    and this is what says so - and keeps saying it.

    "Is that the LAST one" is a question a reviewer answers by reading, which
    is how the backup copy survived six rounds of readers: it sits inside a
    `try` in the middle of the longest function in the package, three lines
    from two writes that both ask. Enumerated here, a write that asks nothing
    is a failure naming the file and the function.
    """
    stray = _bypasses(_package_writes(), ALLOWED_WRITES)
    assert not stray, (
        "content is written without an ownership question. Route it through "
        "external.owner_of, config.state_write_path, config.write_state_bytes "
        "or the Destination base class, or add it to ALLOWED_WRITES with the "
        "reason it needs none:\n  " + "\n  ".join(stray))


# Every place the package removes something or makes it shorter, with what it
# is entitled to remove. Nothing in $HOME appears here and nothing may: ADR-0002
# says a pull never deletes, and a stale member that genuinely ought to go is
# `--mirror`, which the ADR defers on purpose. So this list is short by
# construction, and a leg that lengthens it has either built `--mirror` or
# reintroduced the sweep that took a machine's own workflow journals with it.
ALLOWED_REMOVALS = {
    ("external.py", "_leaf_refusal"): (
        "the write chokepoint's own truncate, which happens AFTER both "
        "answers - what it refuses it has not shortened", ("os.ftruncate",)),
    ("crypto.py", "_run"): (
        "openssl's own partial output on a failed run, so a failed decrypt "
        "cannot be mistaken for a successful one", ("unlink",)),
    ("crypto.py", "_run_bytes"): ("a TemporaryDirectory this call made",
                                  ("shutil.rmtree",)),
    ("destinations/base.py", "_at_unlink"): (
        "an Archive object, inside the openat walk (ADR-0009) - the push "
        "side of a mirror, never a local file", ("os.unlink", "os.unlink")),
    ("destinations/git_repo.py", "_sync"): (
        "carryon's own clone under ~/.carryon/git, which "
        "config.state_write_path answered for. Twice, because the clone is "
        "now made with --no-checkout and the checkout happens at the reset - "
        "so a name the checkout refuses fails one call later than it used to, "
        "and the sweep that stops a half-clone being taken for a stale one "
        "has to cover both",
        ("shutil.rmtree", "shutil.rmtree")),
    ("destinations/rclone_remote.py", "_write_blob"): (
        "the temp file this call handed to rclone", ("unlink",)),
    ("keyring.py", "forget_master"): (
        "the fallback master key, which is the whole of what that command "
        "was asked to do", ("unlink",)),
    ("sync.py", "_neutralise_staged_setup"): (
        "a file withheld from the staging tree so a full push clears one an "
        "earlier version published - carryon's own tree, on the push leg",
        ("unlink",)),
    ("sync.py", "push"): ("carryon's own staging tree, swept after a clean "
                          "push", ("shutil.rmtree",)),
}


def test_nothing_removes_or_shortens_what_a_pull_landed():
    """The third direction, and the one that had no scanner.

    Both enumerations above watch bytes arriving, and two of the three
    properties this suite is about are promises that something SURVIVES. The
    sweep that unlinked every local member the incoming tar did not name made
    no write at all, so neither scanner could have seen it; nor could either
    see a truncate that happens before the writer has decided anything.

    Nothing under $HOME may appear in the list this checks against, which is
    the claim rather than the mechanism: a pull never deletes (ADR-0002), and
    `--mirror` is deferred on purpose.
    """
    stray = _bypasses(_package_removals(), ALLOWED_REMOVALS)
    assert not stray, (
        "something is removed or truncated without an argued reason. A pull "
        "never deletes (ADR-0002) - if this is `--mirror`, it needs the ADR "
        "first:\n  " + "\n  ".join(stray))

    stale = _stale(_package_removals(), ALLOWED_REMOVALS)
    assert not stale, (
        "ALLOWED_REMOVALS excuses removals that are no longer made: "
        + ", ".join(map(str, stale)))


def test_the_removal_scanner_sees_the_verbs_a_sweep_would_use():
    """A verb set is a list of the ways somebody happened to write a deletion,
    and the sweep this property exists to prevent was `Path.unlink`. Each line
    is one that a branch reintroducing it would plausibly use."""
    sweep = ('''
import os, shutil

def _mirror(root, stale, handle):
    for path in stale:
        path.unlink()
        os.remove(path)
        os.unlink(path)
    shutil.rmtree(root)
    os.truncate(root, 0)
    handle.truncate(0)
''')
    verbs = {verb for _rel, _where, _line, verb
             in _calls_in("x.py", sweep, REMOVE_ATTRS, REMOVE_CALLS)}

    assert {"unlink", "os.remove", "os.unlink", "shutil.rmtree",
            "os.truncate", "truncate"} <= verbs, verbs


def test_the_allowlist_names_nothing_that_is_no_longer_there():
    """An allowlist that keeps entries for reads nobody makes any more is one
    that grows a hole nobody notices - the same silent drift run_tests.py's
    module list is guarded against, one directory over."""
    stale = _stale(_package_reads(), ALLOWED_READS)
    assert not stale, (
        "ALLOWED_READS excuses reads that are no longer made; drop them so "
        "the next one has to be argued for: " + ", ".join(map(str, stale)))

    stale = _stale(_package_writes(), ALLOWED_WRITES)
    assert not stale, (
        "ALLOWED_WRITES excuses writes that are no longer made: "
        + ", ".join(map(str, stale)))


# A function using every verb a reviewer would call a neighbour of the ones
# the scanners name. All of it passed both scanners green, and the tarfile
# line is not hypothetical - it is what `capture.write_archive` did.
NEIGHBOURS = '''
import json, os, shutil, tarfile

def _seventh_caller(src, dst, tar, handle, obj):
    shutil.copy(src, dst)
    shutil.move(src, dst)
    shutil.copyfileobj(src, dst)
    os.replace(src, dst)
    os.rename(src, dst)
    handle.writelines(["a"])
    json.dump(obj, handle)
    with tarfile.open(tar, "w:gz") as t:
        t.add(src)
'''


def test_the_scanners_see_the_neighbours_of_the_verbs_they_name():
    """A verb set is a list of the ways somebody happened to have written a
    read, and the next one is written by somebody else. Each line below is one
    character, one module or one import away from a verb that WAS scanned for,
    and a function containing all of them passed both scanners."""
    reads = {verb for _rel, _where, _line, verb
             in _calls_in("x.py", NEIGHBOURS, READ_ATTRS, READ_CALLS)}
    writes = {verb for _rel, _where, _line, verb
              in _calls_in("x.py", NEIGHBOURS, WRITE_ATTRS, WRITE_CALLS)}

    assert {"shutil.copy", "shutil.move", "shutil.copyfileobj",
            "open"} <= reads, reads
    assert {"shutil.copy", "shutil.move", "shutil.copyfileobj", "os.replace",
            "os.rename", "writelines", "json.dump", "open"} <= writes, writes


def test_a_tarfile_over_bytes_carryon_holds_is_not_a_path_read():
    """The other direction of the same rule, because a scanner that cries wolf
    is a scanner people route around: tarring an object carryon already has in
    memory is not a path turning into content, and both legs do it on every
    push and every pull."""
    memory = ("import io, tarfile\n"
              "def pack(buf):\n"
              "    return tarfile.open(fileobj=buf, mode='w')\n")

    assert not _calls_in("x.py", memory, READ_ATTRS, READ_CALLS)
    assert not _calls_in("x.py", memory, WRITE_ATTRS, WRITE_CALLS)


def test_a_second_read_inside_an_allowlisted_function_is_not_excused():
    """The granularity that made the tripwire vacuous where it mattered most.

    `(sync.py, pull)` was in both allowlists and had to be, so every read and
    every write anywhere in its seven hundred lines was pre-excused - and the
    defect this suite was written for was a copy2 inside pull. Applied
    retroactively, a membership test would not have caught it. An entry pins
    the calls, so one more of them is a failure.
    """
    live = _package_reads()
    victim = next((rel, where) for rel, where, _line, _verb in live
                  if (rel, where) in ALLOWED_READS)
    planted = live + [(victim[0], victim[1], 9999, "read_bytes")]

    stray = _bypasses(planted, ALLOWED_READS)

    assert stray, (f"a read planted inside {victim[1]}() - an allowlisted "
                   "function - was excused by the allowlist")
    assert victim[1] in " ".join(stray)


# --- the write side: a Setup backup is a write into carryon's own state ------


def setup_archive(tmp_path):
    """machine-a pushes a Setup; machine-b is paired and about to pull."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category="config,capability,knowledge"),
                     home_a) == 0
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    (home_b / ".claude" / "settings.json").write_text(LOCAL_SETTINGS)
    (home_b / "dotfiles").mkdir()
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return home_a, home_b


def backups_of(home) -> list:
    root = home / ".carryon" / "backups"
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file())


def test_an_ordinary_setup_backup_still_works(tmp_path, capsys):
    """The positive control for everything below: the local file is replaced
    and the copy ADR-0002 promises is recoverable is on disk and named."""
    _, home_b = setup_archive(tmp_path)

    assert sync.pull(ns(apply=True), home_b) == 0
    report = capsys.readouterr().out

    assert (home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "opus"}', report
    saved = [p for p in backups_of(home_b) if p.name == "settings.json"]
    assert saved, "the Setup was replaced with no backup taken"
    assert saved[0].read_text() == LOCAL_SETTINGS
    assert "backed up to" in report


def test_a_link_above_the_backup_directory_is_not_written_through(tmp_path,
                                                                  capsys):
    """`~/.carryon/backups -> ~/dotfiles`: the backup copy consulted neither
    external.classify nor config.write_state_file, so user Setup content was
    written into a tree carryon does not own. ~/.carryon itself may be a link
    into a synced folder (config.write_state_file says so) - the walk starts
    at the state directory, so it is the components carryon makes that are
    answered for."""
    _, home_b = setup_archive(tmp_path)
    victim = home_b / "dotfiles"
    (home_b / ".carryon").mkdir(exist_ok=True)
    (home_b / ".carryon" / "backups").symlink_to(victim)

    sync.pull(ns(apply=True), home_b)
    report = capsys.readouterr().out

    assert not [p for p in victim.rglob("*") if p.is_file()], \
        "a Setup backup was written into a tree carryon does not own"
    assert (home_b / ".claude" / "settings.json").read_text() == \
        LOCAL_SETTINGS, \
        "the local file was replaced with no backup to recover it from"
    assert "settings.json" in report


def test_a_link_at_the_backup_destination_is_not_written_through(
        tmp_path, monkeypatch, capsys):
    """The leaf, rather than the directory above it. A random suffix (below)
    makes the name unguessable, which is a reason not to leave the write
    unguarded rather than a substitute for guarding it - so the backup root is
    pinned here and a link planted where the copy lands."""
    _, home_b = setup_archive(tmp_path)
    managed = home_b / "dotfiles" / "settings.json"
    managed.write_text(MANAGED)
    pinned = home_b / ".carryon" / "backups" / "pinned"
    (pinned / ".claude").mkdir(parents=True)
    (pinned / ".claude" / "settings.json").symlink_to(managed)
    monkeypatch.setattr(sync, "_backup_root", lambda home: pinned)

    sync.pull(ns(apply=True), home_b)
    report = capsys.readouterr().out

    assert managed.read_text() == MANAGED, \
        "the backup copy was written through a link into a dotfiles repo"
    assert "settings.json" in report


def test_two_pulls_in_the_same_second_keep_both_backups(tmp_path,
                                                        monkeypatch):
    """ADR-0002's "recoverably from the backup" is a promise about the copy,
    and a directory stamped to the second is one the next pull inside that
    second overwrites. crypto.new_stamp already argues the case one object
    over: a timestamp is only as fine as the clock it is read from."""
    _, home_b = setup_archive(tmp_path)
    monkeypatch.setattr(sync, "_utc_now", lambda: "2026-07-31T00:00:00Z")

    assert sync.pull(ns(apply=True), home_b) == 0
    (home_b / ".claude" / "settings.json").write_text('{"model": "second"}')
    assert sync.pull(ns(apply=True), home_b) == 0

    saved = {p.read_text() for p in backups_of(home_b)
             if p.name == "settings.json"}
    assert LOCAL_SETTINGS in saved, \
        "the second pull in the same second overwrote the first pull's backup"
    assert '{"model": "second"}' in saved
