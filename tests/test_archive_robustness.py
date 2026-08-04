"""An Archive a master key holder wrote, and this machine still cannot use.

Every other suite here models a Destination that lies. This one models one
that is merely damaged: the Index opened, the seal verified, and what came out
from behind it is not the shape carryon writes. That needs no attacker at all
- ADR-0009's attacker cannot author either of these inputs, since the Index
and every Archive object are authenticated - and it needs no bug on the far
side either. A key holder's Archive on a disk that lost a block, a synced
folder's conflict copy, a carryon whose shape this one does not know: all
three arrive here, and all three used to take a leg down mid-run rather than
be refused by name.

The two shapes are one shape. A previous round moved the Index's validation
from the container down to the fields it indexes out of an entry, and never
brought the catalogue KEY into scope - so a Session UUID, which is used to
build a path and to seal an object, is the one string in the Index nothing has
ever asked about. A previous round turned every Destination-sourced failure
into ObjectRefused, and left four bare `tarfile.open` calls across two modules
and both legs - so a plaintext that is not a tar is a traceback from whichever
of the four the run happens to reach first. Both are the shape the round-five
gate named: a rule closed where it was reviewed and open where it was not.

And so was the first fix for them. Sections 4 and 5 below are the same
sentence applied one step further out, because each rule was spelled at the
leg that was being reviewed and at no other:

  - The catalogue-key check was put at the READER. Nothing asked the question
    where a key is MINTED, and carryon does not mint those names - the
    claude-projects layout takes the stem of a file the agent wrote. So one
    ordinary local filename went up at exit 0 and sealed an Index that no
    machine, including the one that wrote it, could open again. The reader's
    refusal names a cure ("push from a machine whose Index is intact") that
    does not exist once the poisoned Index IS the current one.

  - The not-a-tar refusal was put where the tar is OPENED, which is right, and
    stopped at the bytes. A tar that opens perfectly and holds a member named
    '../../../escape.txt' still takes the pull down from inside the loop that
    writes, with the Session's earlier members already in $HOME - the harm
    shape the ReadError fix was written to end, in the same loop.

Section 6 is the same sentence about the ANSWER rather than about the check.
Each check above descended a level and kept the refusal written for the level
above it, so one damaged record refused the whole Index: every Session, every
residue and every Setup, on both legs, on every machine, permanently. An
object's damage has always cost one object (ObjectRefused); an entry's damage
cost the Archive. The unit refused is now the unit the damage is in, which
raises the question that section asks - what a push then does with a record it
has just declined to read, and which it is about to seal again.
"""

import argparse
import io
import json
import pathlib
import sys
import tarfile
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (archive, config, crypto, destinations,  # noqa: E402
                     history, keyring, rekey, sync)

# A lone surrogate: legal JSON, legal in a Python str, six ASCII characters on
# the Destination, and impossible to encode as UTF-8 - which is what crypto
# does to every label it seals or names an object by.
LONE_SURROGATE = "\udcff"

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
PROJ_ONE = "code/one"
PROJ_TWO = "code/two"

NOT_A_TAR = b"this is not a tar"
# A gzip magic number and a deflate stream that is not one. tarfile's
# transparent-mode detection wraps this in a ReadError on 3.13 and lets
# zlib.error straight out of its own loop on 3.9 - the two interpreters
# carryon must pass disagreeing about the type of a failure they agree exists.
BAD_GZIP = b"\x1f\x8b\x08\x00" + b"\x00" * 200


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def build_home_a(tmp_path) -> pathlib.Path:
    """A Setup, two Sessions in two projects, and one project's residue.

    Two Sessions because the harm is a crash that lands after work has begun:
    with one there is nothing on disk yet when it happens and the test would
    pass for the wrong reason. U1 sorts first, so damaging U2 leaves U1 as the
    Session a pull has already written by the time it reaches the damage. The
    residue is under PROJ_TWO because the projects catalogue is the other half
    of every rule here and has its own object, its own key and its own reader.
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
    memory = (claude / "projects"
              / rekey.encode_project_dir(str(home / PROJ_TWO)) / "memory")
    memory.mkdir()
    (memory / "MEMORY.md").write_text("what machine-a learnt\n")
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


def open_archive(archived):
    """(dest, master, index) as a key holder sees them."""
    master = keyring.fetch_master(home=archived.home_a)
    dest = destinations.from_spec(archived.dest_spec, archived.home_a)
    return dest, master, archive.load_index(dest, master)


def seal_index(dest, master, index) -> None:
    """Write the Index the way a carryon without this round's guard would.

    archive.save_index now asks the reader's own question of every catalogue
    key before it seals one, so this carryon can no longer WRITE the Indexes
    section 1 is about - which is the fix, and would leave the reader's half
    of it untestable through the writer. What section 1 describes was never
    this carryon writing them anyway: it is an Index written by another
    version, or one that came back damaged. So the bytes are sealed here the
    way that Archive's bytes arrive, revision and all.
    """
    index["revision"] = archive.index_revision(index) + 1
    raw = json.dumps(index, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    dest.write(archive.INDEX_KEY,
               crypto.seal(raw, master, archive.INDEX_LABEL))


def tamper_index(archived, edit) -> None:
    """Re-seal the Archive's Index with `edit` applied.

    Only a master key holder can write an Index, which is exactly the case
    these tests describe: not an attacker, but a carryon that recorded a shape
    this one does not know, or an Index that came back damaged.
    """
    dest, master, index = open_archive(archived)
    edit(index)
    seal_index(dest, master, index)


def project_key(archived) -> str:
    """The projects catalogue's one key: the residue's cwd, machine-neutral."""
    _dest, _master, index = open_archive(archived)
    keys = sorted(index["projects"])
    assert len(keys) == 1, "the fixture pushed no project residue"
    return keys[0]


def damage_object(archived, catalogue, key, plaintext=NOT_A_TAR,
                  keep_main=False) -> str:
    """Replace one Archive object's plaintext, sealed and named correctly.

    A key holder's doing by construction - the seal covers the object's label,
    so nobody without the master key can put these bytes there. What is being
    modelled is an Archive that HAS been damaged, not one that is being
    attacked: this is the byte-level equivalent of a truncated write.

    main_sha256 is dropped unless the caller wants it, because the version
    check reads the tar to answer and would otherwise intercept every one of
    these before the reader under test is reached. Returns the object's key.
    """
    dest, master, index = open_archive(archived)
    entry = index[catalogue][key]
    label = (archive.session_label(key) if catalogue == "sessions"
             else archive.project_label(key))
    dest.write(entry["object"], crypto.seal(plaintext, master, label))
    if not keep_main:
        entry.pop("main_sha256", None)
    archive.save_index(dest, master, index)
    return entry["object"]


def clone_session(archived, new_uuid, source=U1) -> None:
    """Add a second, wholly valid Session to the Archive under `new_uuid`.

    Sealed and named under its own label, so it authenticates like any other
    object - the point of the tests that use this is that carryon RESTORES a
    key whose shape it would not have minted, and an object that failed its
    integrity check would prove nothing about that.
    """
    dest, master, index = open_archive(archived)
    meta = dict(index["sessions"][source])
    tar = archive.get_session(dest, master, source, meta["object"])
    archive.put_session(dest, master, new_uuid, tar, meta)
    index["sessions"][new_uuid] = meta
    archive.save_index(dest, master, index)


def restored_sessions(home) -> set:
    root = pathlib.Path(home) / ".claude" / "projects"
    return {p.stem for p in root.rglob("*.jsonl")} if root.exists() else set()


def extend_session(home, uuid, proj) -> None:
    """Append a turn to a main Transcript, so the next push has to compare
    against the Archive's copy rather than skip it as unchanged."""
    project = (pathlib.Path(home) / ".claude" / "projects"
               / rekey.encode_project_dir(str(pathlib.Path(home) / proj)))
    with (project / (uuid + ".jsonl")).open("a") as handle:
        handle.write(jline({"type": "user", "text": "one more turn"}))


# --- 1. the catalogue key, which nothing has ever asked about ----------------
#
# archive._validated descends from the catalogue to the entry to the fields a
# leg indexes out of an entry. The key those entries hang from was never in
# scope, and it is not a lesser string than the fields beside it: it seals the
# object (session_label, project_label), it names it (hmac_name), and a
# Session's is a directory ~/.carryon/conflicts/<uuid>.
#
# Each of these asks two things of one damaged key, because either alone reads
# as a pass while the other fails. That the entry is named - the check
# descended to the key - and that the entries beside it still landed, which is
# the remedy descending with it. The first version of this section asserted
# `restored_sessions == set()`, and it was asserting the defect: one record
# out of five taking the whole Archive down on every machine for ever.


def test_a_session_key_this_machine_cannot_spell_is_refused_by_name(
        archived, capsys):
    """A lone surrogate in a catalogue key is a UnicodeEncodeError out of
    crypto's strict label encode, raised from inside the pull's Session loop -
    after the Sessions that sort before it have already been written into
    $HOME. Every guard between the Index and that encode asks isinstance(x,
    str), which a surrogate answers yes to, and the entry beneath the key was
    checked field by field one round ago.

    The Index is sealed, so this is a key holder's Archive with something
    wrong in it rather than an attack - which is the whole reason it must be a
    sentence: the cure is to push a fresh Index, and a traceback names none.
    """
    bad = LONE_SURROGATE + "-x"
    tamper_index(archived, lambda index: index["sessions"].update(
        {bad: dict(index["sessions"][U1])}))

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert "sessions" in out, \
        "the refusal does not name the catalogue"
    assert LONE_SURROGATE not in out and r"\udcff" in out, \
        "the key this machine cannot encode was printed rather than escaped"
    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "one unusable key took every Session in the Archive down with it"


def test_a_project_key_this_machine_cannot_spell_is_refused_by_name(
        archived, capsys):
    """The projects catalogue's key is a cwd, and it is a label too -
    project_label seals the residue object under it. Same encode, same leg,
    and it lands even later in the pull: the residue loop runs after every
    Session has been restored."""
    bad = "~/" + LONE_SURROGATE
    tamper_index(archived, lambda index: index["projects"].update(
        {bad: dict(index["projects"][sorted(index["projects"])[0]])}))

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert "projects" in out, \
        "the refusal does not name the catalogue"
    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "an unusable residue key took the Session half of the pull with it"


@pytest.mark.parametrize("bad", ["../../../escape", "a/b", "..", "",
                                 "with\x00null", "."])
def test_a_session_key_that_is_not_a_path_component_is_refused(archived, bad):
    """A Session UUID is a path component and always has been.

    ~/.carryon/conflicts/<uuid>/ is where a divergent incoming Transcript is
    set aside (ADR-0002), and the uuid goes into it verbatim. A '..' walks out
    of carryon's own state, a '/' spreads one Session over a tree, and an
    embedded NUL is a ValueError out of the syscall rather than the OSError
    every write on that leg is written to answer. Nothing has ever checked it,
    because the shape was assumed by the code that uses it rather than stated
    where the Index is read.
    """
    dest, master, index = open_archive(archived)
    if bad.startswith("../"):
        conflicts = archived.home_b / ".carryon" / "conflicts"
        assert str(conflicts) not in str((conflicts / bad).resolve()), \
            "this key is meant to escape carryon's own state"
    index["sessions"][bad] = dict(index["sessions"][U1])
    seal_index(dest, master, index)

    opened = archive.load_index(dest, master)

    assert bad not in opened["sessions"], \
        "a key no path can be built from reached the catalogue the legs read"
    assert [r.key for r in opened.refused] == [bad], \
        "the key was dropped without being named, which is a Session quietly "\
        "missing from every later pull"
    assert opened.refused[0].catalogue == "sessions"
    assert sorted(opened["sessions"]) == [U1, U2], \
        "the entries beside it went with it"


def test_a_session_key_this_carryon_never_wrote_still_pulls(archived, capsys):
    """The other half of the rule, and the reason it is a component check
    rather than a UUID check. carryon does not mint these names: the
    claude-projects layout takes the stem of a file the agent wrote, and the
    codex-rollouts layout falls back to a whole rollout filename when its
    regex does not match. Refusing a key for not looking like a UUID would
    refuse an honest Archive, which is the same fault as letting a bad one
    through, pointing the other way."""
    clone_session(archived, "rollout-2026-07-30T10-00-00")

    assert sync.pull(ns(apply=True), archived.home_b) == 0
    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "a Session key this carryon would not have minted stopped the pull"


def test_a_setups_key_this_machine_cannot_spell_is_refused(archived):
    """The third catalogue, checked at the same door and for the same reason.

    A machine name out of the Index becomes a label too: the pull leg checks a
    stored Setup's tag under the INDEX's spelling of the machine rather than
    the stored directory's, so that a case-folding rename at the Destination
    does not break an honest tree - and crypto.setup_tag_ok encodes that label
    strictly.

    Not reachable end to end today, and that is the point rather than an
    excuse: what stops it is require_key refusing an un-encodable name in the
    Destination's listing, one module over, so the Index key only ever gets
    that far by matching one. A rule that holds because a different module
    happens to enforce it is the shape this whole round is about.
    """
    dest, master, index = open_archive(archived)
    index["setups"][LONE_SURROGATE] = dict(index["setups"]["machine-a"])
    seal_index(dest, master, index)

    opened = archive.load_index(dest, master)

    assert [r.key for r in opened.refused] == [LONE_SURROGATE]
    assert opened.refused[0].catalogue == "setups"
    assert "machine-a" in opened["setups"], \
        "the machine that really did push a Setup lost its vouching too"


def test_an_index_carryon_itself_wrote_still_opens(archived):
    """The check runs on every load, including the ones on the push leg, so
    an ordinary Archive has to pass it unchanged."""
    dest, master, index = open_archive(archived)

    assert sorted(index["sessions"]) == [U1, U2]
    assert sync.push(ns(apply=True), archived.home_a) == 0


# --- 2. a sealed object whose plaintext is not a tar -------------------------
#
# Four bare tarfile.open calls: _stored_members and _main_member on the push
# leg, _extract_tree and history.unpack_session on the pull leg. Each is
# reached by a different branch, which is why guarding them one at a time is
# how this survived - the branch that was reviewed got a guard and the three
# beside it did not.


def test_a_stored_session_that_is_not_a_tar_is_refused_on_the_pull_leg(
        archived, capsys):
    """The `new` branch: machine-b has never seen either Session, so the tar
    goes straight to history.unpack_session, which opens it with no guard at
    all. tarfile.ReadError comes out of the pull with U1 already restored, no
    report, no summary, and the Setup half never reached."""
    key = damage_object(archived, "sessions", U2)

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert key in out, "the refusal does not name the object"
    assert restored_sessions(archived.home_b) == {U1}, \
        "the rest of the pull did not carry on past the damaged object"
    assert "Setup:" in out, "the pull ended before the Setup half"


def test_a_stored_session_that_is_not_a_tar_is_refused_where_the_main_is_read(
        archived, capsys):
    """The version check reads the tar too, and reaches it first whenever the
    Index records a main_sha256 - so the same damage arrives at a second
    unguarded open, in a different function, on the same leg. _main_member is
    also the one the push leg shares, which is what makes it worth its own
    line here."""
    key = damage_object(archived, "sessions", U2, keep_main=True)

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert key in out, "the refusal does not name the object"
    assert restored_sessions(archived.home_b) == {U1}, \
        "the rest of the pull did not carry on past the damaged object"


def test_a_stored_session_that_is_not_a_tar_is_refused_on_the_push_leg(
        archived, capsys):
    """The push leg fetches the Archive's copy before it overwrites one
    (ADR-0002's union rule, mirrored) and hands it to _stored_members, which
    opens it with no guard. A push is the leg with a local copy in hand, so a
    refusal here has to leave the Archive alone and carry on with the rest -
    not abort with the Setup already captured and reported."""
    extend_session(archived.home_a, U2, PROJ_TWO)
    damage_object(archived, "sessions", U2)
    capsys.readouterr()

    assert sync.push(ns(apply=True), archived.home_a) == 0, \
        "a damaged stored object ended the push"
    out = capsys.readouterr().out

    assert U2 in out and "skip" in out, \
        "the Session it could not compare against went unnamed"
    dest, master, index = open_archive(archived)
    assert archive.get_session(dest, master, U2,
                               index["sessions"][U2]["object"]) == NOT_A_TAR, \
        "the push overwrote an object it could not compare against"


def test_a_stored_residue_that_is_not_a_tar_is_refused_on_the_pull_leg(
        archived, capsys):
    """The fourth call site: a project's residue goes through _extract_tree,
    which has its own tarfile.open and its own loop. The residue leg runs
    after every Session has landed, so the traceback here is the latest of the
    four and destroys the most report."""
    cwd = project_key(archived)
    key = damage_object(archived, "projects", cwd)

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert key in out, "the refusal does not name the object"
    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "the Sessions did not land before the residue was refused"
    assert "Setup:" in out, "the pull ended before the Setup half"


def test_a_stored_residue_that_is_not_a_tar_is_refused_on_the_push_leg(
        archived, capsys):
    """The residue's own push-leg reader. It has no main Transcript, so the
    version check that intercepts a damaged Session never runs here and
    _stored_members is reached directly."""
    memory = next((archived.home_a / ".claude" / "projects")
                  .rglob("MEMORY.md"))
    memory.write_text(memory.read_text() + "and one more thing\n")
    damage_object(archived, "projects", project_key(archived))
    capsys.readouterr()

    assert sync.push(ns(apply=True), archived.home_a) == 0, \
        "a damaged stored residue ended the push"
    assert "skip" in capsys.readouterr().out, \
        "the residue it could not compare against went unnamed"


@pytest.mark.parametrize("plaintext,what", [
    (NOT_A_TAR, "bytes that are no archive at all"),
    (b"", "an object truncated to nothing"),
    (BAD_GZIP, "a gzip header over a broken deflate stream"),
])
def test_every_way_a_plaintext_fails_to_be_a_tar_takes_the_same_refusal(
        archived, capsys, plaintext, what):
    """One refusal for the whole class, on both interpreters.

    tarfile does not answer these uniformly and the two runners do not agree
    about which it answers how: 3.9 lets zlib.error out of its own
    transparent-mode detection loop where 3.13 wraps the same failure in a
    ReadError. A guard naming tarfile's own exception is therefore green on
    one runner and a traceback on the other, which is the shape this project
    has been caught by before.
    """
    key = damage_object(archived, "sessions", U2, plaintext=plaintext)

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert key in out, f"{what} was not refused by name"
    assert restored_sessions(archived.home_b) == {U1}, \
        f"{what} stopped the rest of the pull"


def test_a_tar_that_stops_mid_walk_lays_down_none_of_its_members(
        archived, capsys):
    """The half-written case, which is what a damaged Archive most often
    holds: valid tar headers followed by fewer bytes than they promise.

    Two things at once, and they are the same thing. tarfile answers this
    while the members are being walked rather than at the open, so a guard
    wrapped around `tarfile.open` alone lets it straight through - and the
    walk is the loop that writes, so a refusal arriving partway is half a
    restore. A Session lands whole or is named and skipped; a project
    directory holding two of a Session's five Transcripts is neither.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel, size in ((U2 + ".jsonl", 64), (U2 + "/sub.jsonl", 4096)):
            info = tarfile.TarInfo(rel)
            info.size = size
            tar.addfile(info, io.BytesIO(b"x" * size))
    key = damage_object(archived, "sessions", U2,
                        plaintext=buf.getvalue()[:3000])

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert key in out, "the truncated tar was not refused by name"
    assert restored_sessions(archived.home_b) == {U1}, \
        "a member of a tar that will not finish the walk was written anyway"


# --- 3. the honest local Transcript ------------------------------------------
#
# Nothing below needs a Destination, a key or an Archive. A Transcript on this
# machine with an awkward byte sequence in it is the user's own file, and a
# push that dies on one is a push nobody can complete.


def test_a_transcript_holding_a_lone_surrogate_escape_pushes_and_pulls(
        tmp_path, capsys):
    """A '\\ud83d' escape is what a tool writes when an emoji is cut in half
    by an output limit: six ASCII characters on disk, valid UTF-8, and a lone
    surrogate once json.loads has read it. Re-keying re-dumps every CHANGED
    line with ensure_ascii=False, so encoding that line back raised
    UnicodeEncodeError out of a push - with Session objects already on the
    Destination and the Index never sealed, which is the state that makes
    every later push and pull from every machine refuse.

    Confirming rather than fixing: history.rekeyed already answers this, and
    every re-keying call in carryon - both directions, all three trees a
    Snapshot moves - goes through it. It was green the moment it was written,
    which is evidence about the finding and none at all about this round's
    fixes. rekey.apply_to_bytes below it still raises, deliberately: rekey is
    standalone, and the guard sits at the nearest boundary that catches every
    caller rather than at one call site.

    The line has to carry the home as well as the surrogate: an unchanged line
    passes through byte-identical and never reaches the encoder.
    """
    home = build_home_a(tmp_path)
    cwd = str(home / PROJ_ONE)
    main = (home / ".claude" / "projects"
            / rekey.encode_project_dir(cwd) / (U1 + ".jsonl"))
    planted = jline({"cwd": cwd, "text": "half an emoji: \ud83d"})
    assert all(ord(c) < 128 for c in planted), \
        "the plant is meant to be ordinary ASCII on disk"
    main.write_text(planted + main.read_text())
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)

    assert sync.push(ns(apply=True), home) == 0, \
        "a lone surrogate in a Transcript ended the push"

    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0, \
        "a lone surrogate in a Transcript ended the pull"
    restored = next((home_b / ".claude" / "projects").rglob(U1 + ".jsonl"))
    assert "half an emoji" in restored.read_text(), \
        "the line carrying the surrogate did not survive the round trip"


def test_a_transcript_line_nested_past_the_limit_is_carried_not_raised():
    """rekey's own line loop catches ValueError, which is every way a line
    fails to parse except the cheapest one to write: json.loads answers
    nesting past the interpreter's limit with RecursionError, which is a
    RuntimeError. The four json.loads guards in carryon all name it; the two
    readers in rekey - the one every re-keying pass runs through, and the cwd
    reader beside it - kept the bare ValueError they started with.

    A line that will not parse passes through unchanged and is counted
    malformed, which is what this loop already does for every other line that
    will not parse.
    """
    text = "[" * 200000 + "\n" + jline({"cwd": "/Users/x/proj"}).strip()

    out, stats = rekey.canonicalise_jsonl(text, "/Users/x")

    assert stats.malformed == 1, "the unparseable line was not counted"
    assert out.startswith("[" * 200000), \
        "the line that would not parse was not passed through unchanged"
    assert "~/proj" in out, "the line after it was not re-keyed"


def test_a_cwd_read_past_a_line_nested_past_the_limit(tmp_path):
    """The same guard in the reader beside it. rekey.read_cwd skips a line
    that will not parse and takes the cwd from the next one that has it - for
    every failure except the one that costs 200 KB of '[' to write."""
    path = tmp_path / "rollout.jsonl"
    path.write_text("[" * 200000 + "\n" + jline({"cwd": "/Users/x/proj"}))

    assert rekey.read_cwd(path) == "/Users/x/proj", \
        "a line nested past the limit ended the read rather than being skipped"


def test_the_high_water_marks_own_read_never_stats_first(tmp_path, capsys):
    """Confirming rather than fixing. _load_state reads and guards the read;
    it does not ask is_file() first, which is what swallowed ELOOP as
    'nothing seen yet' and re-raised EACCES outside the guard.

    Kept here because the two runners disagree about the neighbouring
    question - Path.resolve() answers a symlink loop with RuntimeError on
    3.9.6 and with the unresolved path on 3.13 - so a resolve-adjacent read
    that passes on one of them is no evidence about the other.
    """
    (tmp_path / ".carryon").mkdir()
    path = sync._state_path(tmp_path)
    other = path.parent / "state-loop.json"
    path.symlink_to(other)
    other.symlink_to(path)

    assert sync._seen_revision(tmp_path, "dir:whatever") == 0
    assert "state.json" in capsys.readouterr().out, \
        "an unreadable high-water mark weakened a check without a word"


# --- 4. the same rule where the key is minted --------------------------------
#
# Section 1 put the catalogue-key check at the reader, where a damaged Index is
# met. Nothing asked the same question at the writer, and the writer is not
# carryon: the claude-projects layout takes a Session's UUID from the STEM of a
# file the agent wrote, so any name that directory can hold is a name that
# reaches the Index. One of them - '...jsonl', whose stem is '..' - went up at
# exit 0 and sealed a catalogue no machine could open again, including the one
# that sealed it. A poisoned Index is worse than a refused push by every
# measure: it is permanent, it is Archive-wide, the reader's cure ("push from a
# machine whose Index is intact") names a machine that no longer exists, and
# every Session already in the Archive is still there and unreachable.


def plant_main(home, proj, name) -> pathlib.Path:
    """A second main Transcript in an existing project dir, named by us.

    Ordinary in every way except the filename: a cwd on the first line, a turn
    on the second, discovered exactly as U1 and U2 are. The claude-projects
    layout calls every top-level *.jsonl a main Transcript and its stem the
    Session's UUID, so this is the whole of what it takes to choose a
    catalogue key on a machine that holds no key at all.
    """
    cwd = str(pathlib.Path(home) / proj)
    project = (pathlib.Path(home) / ".claude" / "projects"
               / rekey.encode_project_dir(cwd))
    path = project / name
    path.write_text(jline({"cwd": cwd, "type": "meta"})
                    + jline({"type": "user", "text": "an ordinary turn"}))
    return path


def pushed_from(tmp_path, capsys, plant=None):
    """A fresh machine-a that has pushed once, with `plant(home)` run first.

    Returns (home_a, dest_spec, report). Not the `archived` fixture, because
    what is being tested is the FIRST push: the Index this push seals is the
    one every later run has to be able to open.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    if plant is not None:
        plant(home)
    capsys.readouterr()
    code = sync.push(ns(apply=True), home)
    assert code == 0, "the push itself refused"
    return home, dest_spec, capsys.readouterr().out


def index_of(home, dest_spec) -> dict:
    dest = destinations.from_spec(dest_spec, home)
    return archive.load_index(dest, keyring.fetch_master(home=home))


@pytest.mark.parametrize("name", ["...jsonl", "..jsonl"])
def test_a_local_filename_cannot_seal_an_index_nobody_can_open(
        tmp_path, capsys, name):
    """'...jsonl' has the stem '..'; '..jsonl' has the stem '.'. Both are
    legal POSIX filenames, neither needs an attacker or a key beyond the
    user's own, and both used to become a Session UUID, an object name and a
    catalogue key with nothing between them and the seal.

    The push reported '3 pushed' and exited 0. From that moment every later
    push and every pull, on this machine and on every other, died at
    load_index - a directory Destination keeps no history to restore from, and
    any machine still holding the file re-poisons the Index on its next push.

    So the Session is the unit that is refused, which is what it is on every
    other push-leg skip: named in the report, left on this machine, and the
    Archive still opens.
    """
    home, dest_spec, out = pushed_from(
        tmp_path, capsys, lambda h: plant_main(h, PROJ_ONE, name))

    index = index_of(home, dest_spec)

    assert sorted(index["sessions"]) == [U1, U2], \
        "a name carryon cannot use became a catalogue key"
    assert name in out, "the Session that was not carried went unnamed"
    assert sync.push(ns(apply=True), home) == 0, \
        "the Archive this push sealed cannot be pushed to again"
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0, \
        "the Archive this push sealed cannot be pulled from another machine"
    assert restored_sessions(home_b) == {U1, U2}


def test_a_local_filename_holding_a_backslash_is_carried_like_any_other(
        tmp_path, capsys):
    """The other half of the same fix, and the reason it is not just a matter
    of moving the check.

    The key check refused '\\\\' as well, borrowed from require_key one module
    over - where it is right, because a Destination key must not hold one.
    Applied to a LOCAL path component it is simply wrong: 'a\\\\b' is a name a
    directory can be called on macOS and on Linux, so a user with such a file
    got the same bricked Archive from a Session carryon should have carried
    without comment.
    """
    home, dest_spec, out = pushed_from(
        tmp_path, capsys, lambda h: plant_main(h, PROJ_ONE, "a\\b.jsonl"))

    assert sorted(index_of(home, dest_spec)["sessions"]) == \
        sorted([U1, U2, "a\\b"]), "an ordinary local filename was not carried"

    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home)
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    assert "a\\b" in restored_sessions(home_b), \
        "the Session did not survive the round trip"


def test_carryon_will_not_seal_an_index_it_could_not_open_again(archived):
    """The invariant behind the two tests above, asked at the one place an
    Index becomes bytes.

    The discovery-side refusal is what makes the outcome an actionable skip;
    this is what makes the outcome impossible to reach by any other route. A
    key that gets past every check upstream is a bug in carryon, and the
    difference between answering it here and answering it at the next load is
    the difference between one failed push and an Archive nobody can open.
    """
    dest, master, index = open_archive(archived)
    index["sessions"][".."] = dict(index["sessions"][U1])

    with pytest.raises(SystemExit) as exc:
        archive.save_index(dest, master, index)

    assert "sessions" in str(exc.value), "the refusal does not name the key"
    assert sorted(archive.load_index(dest, master)["sessions"]) == [U1, U2], \
        "the Index that was already there did not survive the refused write"


def test_a_machine_name_this_machine_cannot_spell_is_refused_at_the_config():
    """The third catalogue key, refused at the door it comes in by.

    A machine name keys the setups catalogue, seals the Setup's tag
    (setup_label) and names a directory on the Destination, and it comes from
    `--machine` or from socket.gethostname(). On Linux either can carry a lone
    surrogate - argv and the hostname are decoded with surrogateescape - and
    nothing between there and crypto's strict label encode asks. config.load
    runs before every subcommand, so this is where the answer belongs.
    """
    cfg = config.default_config()
    cfg["machine"] = "mac-" + LONE_SURROGATE

    with pytest.raises(SystemExit) as exc:
        config.validate(cfg)

    assert "machine" in str(exc.value), "the refusal does not name the setting"


# --- 5. a stored tar that opens, and holds a member that escapes -------------
#
# Section 2 refused a plaintext that is not a tar, at the open, before a member
# is yielded. A tar whose HEADERS are fine and whose member NAMES are not was
# still answered from inside the loop that writes: unpack_session and
# _extract_tree each check the name next to their own write, and raise there.
# The first members of the Session are on disk by then, the Setup half is never
# reached, and no summary prints - which is the shape ADR-0009 rules out and
# the one the ReadError fix was written to end.


def tar_of(*members) -> bytes:
    """A valid, uncompressed tar holding exactly these (name, bytes)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize("escaping", [
    "../../../../../../tmp/carryon-escape.txt",
    "sub/../../carryon-escape.txt",
    "/tmp/carryon-escape.txt",
])
def test_a_stored_member_that_escapes_its_root_is_refused_before_it_writes(
        archived, capsys, escaping):
    """Composing this needs the master key, like every other input in this
    file - which is the argument for refusing the OBJECT and against taking
    the whole run down. A key holder's Archive holding one member carryon
    will not lay down is one skipped Session; the rest of the Archive is
    still theirs to restore.

    The valid member is first in the tar so that the old behaviour writes it
    before it reaches the bad one: the assertion that nothing landed is the
    whole point, and a tar with the escape first would pass for the wrong
    reason.
    """
    good = U2 + ".jsonl"
    damage_object(archived, "sessions", U2,
                  plaintext=tar_of((good, b'{"type":"user"}\n'),
                                   (escaping, b"planted\n")))

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert restored_sessions(archived.home_b) == {U1}, \
        "a member of a tar carryon refuses was written anyway"
    assert "Setup:" in out, "the pull ended before the Setup half"
    assert U2 in out or U2 in out, \
        "the Session that was skipped went unnamed"
    assert not (archived.home_b / "tmp" / "carryon-escape.txt").exists()


def test_a_stored_residue_member_that_escapes_its_root_is_refused(
        archived, capsys):
    """The residue leg reaches its own loop, in another module, by another
    branch - which is exactly how the four bare tarfile.opens survived a round
    of fixes. It runs last, so the report it destroys is the whole report."""
    cwd = project_key(archived)
    damage_object(archived, "projects", cwd,
                  plaintext=tar_of(("memory/MEMORY.md", b"ordinary\n"),
                                   ("../../escape.md", b"planted\n")))

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert restored_sessions(archived.home_b) == {U1, U2}, \
        "the Sessions did not land before the residue was refused"
    assert "Setup:" in out, "the pull ended before the Setup half"
    assert "escape" in out or "escape" in out, \
        "the refusal does not say which member it was"
    assert not (archived.home_b / "escape.md").exists()


def test_a_stored_member_that_escapes_is_refused_on_the_push_leg_too(
        archived, capsys):
    """The push leg opens the Archive's copy to compare against before it
    overwrites one, through the same reader - so the refusal has to arrive
    there too, and has to leave the Archive alone.

    It already skipped this Session, and by an accident worth naming: the
    escaping member is a file the Archive holds and this machine does not, so
    the union rule read the local tree as BEHIND and told the user to pull
    first. The cure was wrong (pull will not lay that member down either) and
    the reason was wrong, and both came from comparing against a member
    carryon had already decided it would never write. The refusal now happens
    where the object is read, so what the user is told is what is true.
    """
    extend_session(archived.home_a, U2, PROJ_TWO)
    bad = tar_of((U2 + ".jsonl", b"{}\n"), ("../../escape.md", b"planted\n"))
    damage_object(archived, "sessions", U2, plaintext=bad)
    capsys.readouterr()

    assert sync.push(ns(apply=True), archived.home_a) == 0, \
        "a stored object carryon will not read ended the push"
    out = capsys.readouterr().out

    assert U2 in out and "skip" in out, "the skipped Session went unnamed"
    assert "could not fetch the Archive's copy" in out, \
        "the skip was decided by comparing against a member carryon refuses"
    dest, master, index = open_archive(archived)
    assert archive.get_session(dest, master, U2,
                               index["sessions"][U2]["object"]) == bad, \
        "the push overwrote an object it could not compare against"


def test_a_project_whose_cwd_cannot_key_the_archive_is_named_not_carried():
    """The sibling catalogue, asked at the same door.

    A project's residue is keyed by its cwd, which is a label too - the name
    the object is sealed and HMACed under - and today nothing can reach this:
    history.read_recorded_cwd already drops a cwd this machine cannot spell,
    treating it as one that was never recorded. That is exactly why the guard
    is asked of both catalogues here rather than of the one that had the bug.
    A rule that holds because a different function happens to enforce it is
    the shape this whole round is about, and the sibling leg is where it has
    twice been found open.

    A unit test rather than a push, because the reachable route is closed:
    what is being pinned is that discovery asks the question of a residue at
    all.
    """
    residue = history.ProjectResidue(
        "claude-code", "/home/u/caf" + LONE_SURROGATE,
        ".claude/projects/-home-u-caf", ("memory/MEMORY.md",))

    sessions, residues, unnamable = history._named_for_the_archive([],
                                                                   [residue])

    assert sessions == [] and residues == [], \
        "a cwd carryon cannot key an object by was carried anyway"
    assert len(unnamable) == 1 and ".claude/projects" in unnamable[0][0], \
        "the project that was not carried went unnamed"


def tar_with_a_nul_in_a_member_name(uuid) -> bytes:
    """A valid tar whose second member's name holds a NUL.

    tarfile will not write one - a NUL truncates the name in the header field
    - so it is patched into the PAX extended header's `path` record after the
    fact. The record's length prefix is unchanged and the extended header's
    own checksum covers the header block rather than its payload, so what
    comes back is a tar every reader accepts and one member nothing can spell.
    A key holder's Archive is where this arrives from: a tar written by
    something other than carryon, or bytes that came back damaged.
    """
    marker = "éaXb.jsonl"   # non-ASCII, so the name needs a PAX record
    raw = bytearray(tar_of((uuid + ".jsonl", b'{"type":"user"}\n'),
                           (marker, b"planted\n")))
    at = raw.find(b"aXb.jsonl")
    assert at != -1, "the PAX path record is not where this patch expects it"
    raw[at + 1] = 0
    return bytes(raw)


def test_a_stored_member_whose_name_holds_a_nul_is_refused(archived, capsys):
    """The third way a member name is not one, and the one that answers
    differently: '..' and '/abs' are refused by a check, while a NUL reaches
    the syscall and comes back as ValueError - which the writer, written to
    turn a bad write into a report line, caught nothing of. So it was a
    traceback out of the pull with the Session's first member already written,
    where the two beside it were at least a sentence. (The writer is
    external.write_owned now and takes ValueError with the rest; what refuses
    a NUL is still archive.member_refusal, before a member is handed out.)"""
    damage_object(archived, "sessions", U2,
                  plaintext=tar_with_a_nul_in_a_member_name(U2))

        # Flagged, not raised: a finished pull reports its shortfall
    # in the exit code (ADR-0012) so sync's push half still runs.
    assert sync.pull(ns(apply=True), archived.home_b) == 2
    out = capsys.readouterr().out

    assert restored_sessions(archived.home_b) == {U1}, \
        "a member of a tar carryon refuses was written anyway"
    assert "Setup:" in out, "the pull ended before the Setup half"
    assert "NUL" in out or "NUL" in out, \
        "the refusal does not say what was wrong with the name"


# --- 6. the remedy, which stayed one level above the check --------------------
#
# Sections 1 to 5 each moved a CHECK to where the code actually indexes. What
# none of them moved is the answer: an unusable catalogue key, an entry that is
# not an object, a field that is not a string - each was refused by taking the
# whole Index down, which is every Session, every residue and every Setup, on
# both legs, on every machine, until somebody restores an older Archive. That
# is the same permanent Archive-wide abort ADR-0009 already ruled out one layer
# over ("one planted object that raises is a permanent abort on every pull from
# every machine"), reached through the Index rather than through an object.
#
# So the unit refused is the unit the damage is in. What that leaves is a
# record carryon has decided it cannot read, sitting in a catalogue a push is
# about to seal again - which is the question these three ask.


def stored_index(dest, master) -> dict:
    """The Index as it sits on the Destination: what a leg was handed is not
    the same document, since load_index sets the unusable records aside."""
    raw = crypto.unseal(dest.read(archive.INDEX_KEY), master,
                        archive.INDEX_LABEL)
    return json.loads(raw.decode("utf-8"))


def test_a_push_carries_forward_the_record_it_could_not_read(archived):
    """Dropping it would be a repair carryon is not entitled to make.

    The entry is the only record of which object holds that Session, and its
    key is the only name that object was sealed under; this machine could read
    neither. Sealing the catalogue without it deletes a key holder's record of
    a Session whose object is still sitting in the Archive, at exit 0, with
    the report saying the push succeeded - and the next pull has nothing left
    to name.
    """
    bad = LONE_SURROGATE + "-x"
    dest, master, index = open_archive(archived)
    index["sessions"][bad] = dict(index["sessions"][U1])
    seal_index(dest, master, index)

    opened = archive.load_index(dest, master)
    assert bad not in opened["sessions"], "the record was not set aside"
    archive.save_index(dest, master, opened)

    written = stored_index(dest, master)
    assert written["sessions"][bad] == index["sessions"][bad], \
        "a push deleted the record it had just declined to read"
    assert sorted(written["sessions"]) == sorted([U1, U2, bad])
    reopened = archive.load_index(dest, master)
    assert [r.key for r in reopened.refused] == [bad], \
        "the damage stopped being reported after one push carried it forward"


def test_a_fresh_entry_wins_over_the_record_it_replaces(archived):
    """The carry-forward must not undo the repair it exists to make possible.

    An entry refused for its KEY can never collide with a live one - a key
    that fails key_refusal is exactly the one no live entry can carry - but an
    entry refused for its SHAPE hangs from a perfectly good name, and the cure
    the report names is a push from a machine that still holds that Session.
    That push writes a correct entry under the same key, and putting the old
    one back on top would make the cure a no-op for ever.
    """
    dest, master, index = open_archive(archived)
    index["sessions"][U2] = ["not an object"]
    seal_index(dest, master, index)

    opened = archive.load_index(dest, master)
    assert list(opened["sessions"]) == [U1], \
        "the damaged entry was not set aside"
    opened["sessions"][U2] = {"agent": "claude-code", "cwd": "~/code/two",
                              "tree_hash": "fresh", "object": "x"}
    archive.save_index(dest, master, opened)

    written = stored_index(dest, master)
    assert written["sessions"][U2]["tree_hash"] == "fresh", \
        "the record a push had just replaced came back over the top of it"
    assert archive.load_index(dest, master).refused == (), \
        "the Archive still reports damage a push repaired"


def test_a_residue_record_this_machine_cannot_read_is_never_overwritten(
        archived, capsys):
    """The push leg's half of the same rule, on the catalogue where losing it
    costs most.

    ADR-0002's union is asked only where an entry EXISTS, so a record set
    aside would send this project down the branch that replaces the stored tar
    without comparing anything - and a residue is memory, which accumulates:
    the copy in the Archive holds what every other machine wrote into it. A
    record this machine could not read is not a record it may act as though it
    never saw.
    """
    cwd = project_key(archived)
    tamper_index(archived, lambda index: index["projects"].update(
        {cwd: ["not an object"]}))
    memory = (archived.home_a / ".claude" / "projects"
              / rekey.encode_project_dir(str(archived.home_a / PROJ_TWO))
              / "memory" / "MEMORY.md")
    memory.write_text("a line only this machine has\n")
    dest, master, _ = open_archive(archived)
    stored_before = dest.read(archive.project_key(master, cwd))

    assert sync.push(ns(apply=True), archived.home_a) == 0
    out = capsys.readouterr().out

    assert "skip" in out and "could not read" in out, \
        "the project was replaced, or dropped without a word"
    assert dest.read(archive.project_key(master, cwd)) == stored_before, \
        "a record this machine could not read was taken for no record, and " \
        "the Archive's copy of the memory was overwritten"
