"""Four surfaces six rounds never looked at.

Each round's subject came from the previous round's findings, so anything
never implicated was never examined. These four were named as such:

  1. The rclone Destination end to end. Every other type has been driven
     through push, pull and pair against a real backing store; this one had
     only ever been unit-tested one verb at a time against a fake binary.
  2. The codex and cursor adapters, which have essentially only been
     declared - the claude-code one is what every round exercised.
  3. layout.py and `doctor`, the command a user runs when something is
     already wrong, walking real agent directories with no guard at all.
  4. pull's `--map`: user-supplied, rewrites paths inside restored
     Transcripts, never treated as input.

No network anywhere. rclone is a fake binary on a prepended PATH that backs a
whole Archive on a local directory, complete enough to be driven through the
full journey rather than one verb at a time - which is the whole point: the
defects below are all in what happens when a verb answers something other
than the one answer the unit tests gave it.

The round after that one found the same shape inside these four, which is why
several tests here are about a SECOND state rather than a second surface: a
write confirmed against a listing over an Archive that is EMPTY (the only
state in which that check is not vacuous), a `--map` rule that refuses every
non-path except the one that is also a path, and `list`/`doctor` given half of
what `capture` was given. A surface driven once is a surface driven in one
state.
"""

import argparse
import base64
import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (archive, cli, config, history, keyring,  # noqa: E402
                     layout, rekey, sync)
from carryon.adapters import ADAPTERS  # noqa: E402
from carryon.destinations.rclone_remote import RcloneDestination  # noqa: E402


# --- a fake rclone complete enough to back an Archive ------------------------
#
# The existing fakes answer one verb per test. This one is a store: lsf -R,
# copyto in both directions, cat, deletefile and listremotes over a local
# root, plus a control file that makes any of them misbehave the way a real
# remote can - a listing of the remote's own choosing, a copyto that reports
# success and writes nothing, a verb that starts failing partway through a
# run, a listing that is not the same on two calls.

FAKE_RCLONE = r'''#!__PY__
import base64, json, os, pathlib, shutil, sys

ROOT = pathlib.Path("__ROOT__")
CONTROL = pathlib.Path("__CONTROL__")
LOG = pathlib.Path("__LOG__")

argv = sys.argv[1:]
with LOG.open("a") as fh:
    fh.write(" ".join(argv) + "\n")

ctl = {}
if CONTROL.is_file():
    ctl = json.loads(CONTROL.read_text() or "{}")


def resolve(spec):
    if spec.startswith("fakeremote:"):
        return ROOT / spec[len("fakeremote:"):]
    return pathlib.Path(spec)


def calls(shape):
    """How many invocations so far match this argv prefix, this one included.

    'lsf' counts every listing; 'lsf -R' counts only the recursive ones,
    which is what a caller asking for a canned Archive enumeration means.
    """
    want = shape.split(" ")
    n = 0
    for line in LOG.read_text().splitlines():
        parts = line.split(" ")
        if all(w in parts for w in want) and parts[:1] == want[:1]:
            n += 1
    return n


def fail_now(verb):
    """The exit code this verb should fail with now, or None."""
    plan = ctl.get("fail", {}).get(verb)
    if plan is None:
        return None
    if isinstance(plan, int):
        return plan
    after = plan.get("after", 0)
    return plan["code"] if calls(verb) > after else None


verb = argv[0] if argv else ""
rest = [a for a in argv[1:] if not a.startswith("-")]

code = fail_now(verb)
if code is not None:
    sys.stderr.write("fake rclone: %s refused\n" % verb)
    raise SystemExit(code)

if verb == "lsf":
    deep = "-R" in argv
    canned = ctl.get("listing")
    if canned is not None and deep:
        # The canned answer is the ARCHIVE enumeration only. rclone's lsf
        # without -R lists one directory, and carryon asks that separately.
        if isinstance(canned, list):   # one per call, then the last repeats
            i = min(calls("lsf -R") - 1, len(canned) - 1)
            canned = canned[i]
        sys.stdout.buffer.write(base64.b64decode(canned))
        raise SystemExit(0)
    target = resolve(rest[0]) if rest else ROOT
    if not target.is_dir():
        sys.stderr.write("directory not found\n")
        raise SystemExit(3)
    found = target.rglob("*") if deep else target.iterdir()
    if "--dirs-only" in argv:
        # rclone spells a prefix with a trailing '/'. This store is a local
        # directory, so a name is never both an object and a prefix - the
        # store in test_destinations_hostile.py has the knob for that.
        names = sorted(str(p.relative_to(target).as_posix()) + "/"
                       for p in found if p.is_dir())
    else:
        names = sorted(str(p.relative_to(target).as_posix())
                       for p in found if p.is_file())
    sys.stdout.buffer.write(("\n".join(names) + "\n").encode()
                            if names else b"")
elif verb == "copyto":
    src, dst = resolve(rest[0]), resolve(rest[1])
    noop = ctl.get("copyto_noop")
    if noop:
        after = noop.get("after", 0) if isinstance(noop, dict) else 0
        only = noop.get("suffix") if isinstance(noop, dict) else None
        if calls("copyto") > after and (only is None or rest[1].endswith(only)):
            # "uploaded", and either nothing is there or the version that
            # was there before is still there - which is what dry_run and a
            # filter rule each look like from the outside.
            raise SystemExit(0)
    if not src.is_file():
        sys.stderr.write("source not found\n")
        raise SystemExit(1)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(src), str(dst))
elif verb == "cat":
    target = resolve(rest[0])
    if not target.is_file():
        sys.stderr.write("object not found\n")
        raise SystemExit(1)
    sys.stdout.buffer.write(target.read_bytes())
elif verb == "deletefile":
    target = resolve(rest[0])
    if not target.is_file():
        sys.stderr.write("object not found\n")
        raise SystemExit(1)
    target.unlink()
elif verb == "listremotes":
    sys.stdout.write("fakeremote:\n")
else:
    sys.stderr.write("unknown verb %s\n" % verb)
    raise SystemExit(2)
'''


class FakeRclone:
    """The store behind 'fakeremote:', and the knobs that make it misbehave."""

    def __init__(self, root, control, log):
        self.root = root
        self.control = control
        self.log = log

    def _set(self, **kw):
        current = json.loads(self.control.read_text() or "{}")
        current.update(kw)
        self.control.write_text(json.dumps(current))

    def listing(self, *raws):
        """Answer lsf with these exact bytes - one per call, last repeating."""
        self._set(listing=[base64.b64encode(raw).decode() for raw in raws])

    def honest_listing(self):
        self._set(listing=None)

    def fail(self, verb, code=1, after=0):
        self._set(fail=dict(json.loads(self.control.read_text()
                                       or "{}").get("fail", {}),
                            **{verb: {"code": code, "after": after}}))

    def copyto_writes_nothing(self, on=True, after=0, suffix=None):
        """copyto exits 0 and moves nothing - dry_run, or a filter rule.

        `after` leaves the first N transfers honest, which is the state every
        push but the first one runs in: an Archive that already holds a key
        of every name the push is about to write. `suffix` declines one kind
        of object, the way a --max-size or an --exclude does.
        """
        self._set(copyto_noop=({"after": after, "suffix": suffix} if on
                               else False))

    def argv_log(self):
        return [line.split(" ")
                for line in self.log.read_text().splitlines()] \
            if self.log.is_file() else []

    def objects(self):
        return sorted(p.relative_to(self.root).as_posix()
                      for p in self.root.rglob("*") if p.is_file())


def install_fake_rclone(tmp_path, monkeypatch, container="archive"
                        ) -> FakeRclone:
    """The store, with `container` already present - see the note on
    test_destinations_hostile.install_rclone_store. On an object store the
    first component of a path is a bucket, and ADR-0011's probe will not
    write into one that is not there."""
    root = tmp_path / "rclone-store"
    root.mkdir(exist_ok=True)
    if container:
        (root / container).mkdir(exist_ok=True)
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    control = tmp_path / "rclone-control.json"
    control.write_text("{}")
    log = tmp_path / "rclone-argv.log"
    log.write_text("")
    script = bin_dir / "rclone"
    script.write_text(FAKE_RCLONE
                      .replace("__PY__", sys.executable)
                      .replace("__ROOT__", str(root))
                      .replace("__CONTROL__", str(control))
                      .replace("__LOG__", str(log)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return FakeRclone(root, control, log)


# --- shared scaffolding -------------------------------------------------------

U1 = "11111111-1111-4111-8111-111111111111"
UB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SPEC = "rclone:fakeremote:archive"
RECOVERY_KEY = r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}"
_PAIR_CHAR = "[A-HJKMNP-TV-Z0-9]"
PAIR_CODE = r"--join ({c}{{4}}(?:-{c}{{4}}){{3}})(?!\S)".format(c=_PAIR_CHAR)


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


def build_claude_home(tmp_path, name="home_a") -> pathlib.Path:
    """A minimal Claude Code machine: a Setup and one Session."""
    home = tmp_path / name
    cwd = str(home / "code" / "app")
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Answer briefly.\n")
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (project / (U1 + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "text": f"see {cwd}/main.py"}))
    (project / "memory.md").write_text(f"notes about {cwd}\n")
    return home


# =============================================================================
# 1. THE RCLONE DESTINATION, END TO END
# =============================================================================
#
# rclone is the one Destination type nobody has driven. The unit suites ask it
# one verb at a time against a canned answer; the property ADR-0009 states is
# about a whole run - what landed, what did not, and what the report said -
# and a type that has never been asked to back an Archive has never been asked
# that at all.


@pytest.fixture
def rclone_journey(tmp_path, monkeypatch, capsys):
    """Machine A initialised and pushed to an rclone remote."""
    import re
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home_a = build_claude_home(tmp_path, "home_a")
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home_a) == 0
    recovery = re.search(RECOVERY_KEY, capsys.readouterr().out).group(0)
    assert sync.push(ns(apply=True), home_a) == 0
    push_out = capsys.readouterr().out
    return argparse.Namespace(fake=fake, home_a=home_a, recovery=recovery,
                              push_out=push_out, tmp_path=tmp_path)


def test_a_whole_journey_runs_against_an_rclone_remote(rclone_journey, capsys):
    """init, push, pair, join, pull - the full trip, over rclone only."""
    import re
    fake, home_a = rclone_journey.fake, rclone_journey.home_a

    objects = fake.objects()
    assert any(o.endswith("carryon/index.enc") for o in objects), objects
    assert any("carryon/sessions/" in o for o in objects), objects
    assert any("carryon/setups/mac-a/" in o for o in objects), objects

    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    home_b = build_claude_home(rclone_journey.tmp_path, "home_b")
    # B's own Session, so the pull has a local tree to union against
    own_cwd = str(home_b / "work" / "notes")
    own = home_b / ".claude" / "projects" / rekey.encode_project_dir(own_cwd)
    own.mkdir(parents=True)
    (own / (UB + ".jsonl")).write_text(jline({"cwd": own_cwd, "type": "meta"}))

    assert sync.init(ns(dest=SPEC, join=code, machine="box-b"), home_b) == 0
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    landed = home_b / ".claude" / "projects" / \
        rekey.encode_project_dir(str(home_b / "code" / "app")) / (U1 + ".jsonl")
    assert landed.is_file(), out
    text = landed.read_text()
    assert str(home_b) in text, "the incoming Transcript was re-keyed to B"
    assert str(home_a) not in text, "A's home reached B's disk"
    assert (own / (UB + ".jsonl")).is_file(), "a pull never deletes"
    assert (home_b / ".claude" / "CLAUDE.md").read_text() == \
        "Answer briefly.\n"


# --- what a verb answers is the remote's word, not carryon's ------------------
#
# Every other Destination type answers "there is nothing here" with a syscall
# that also says why not: LocalTreeDestination separates ENOENT/ENOTDIR from
# every other errno and reports the rest, and GitDestination answers a dead
# remote with SystemExit, which sync catches by name. rclone answered every
# non-zero exit of every verb the same way - absent, empty, nothing to say -
# so "the remote refused" and "the Archive is fresh" were one answer.


def test_a_copyto_that_writes_nothing_is_not_a_push(tmp_path, monkeypatch,
                                                    capsys):
    """rclone reads the user's own rclone.conf and environment. `dry_run` set
    there, or a filter matching the temp file carryon uploads from, makes
    every copyto exit 0 and transfer nothing - and carryon believed the exit
    code, printed 'Sessions: 1 pushed ... Setup: pushed (clean)' and returned
    0 over an Archive that holds not one object."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home) == 0
    capsys.readouterr()

    fake.copyto_writes_nothing()
    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home)

    assert fake.objects() == [], "the fake did write something after all"
    assert "rclone" in str(exc.value)
    out = capsys.readouterr().out
    assert "Setup: pushed" not in out, \
        "a push that stored nothing reported a stored Setup"


def stored_text(fake, rel: str) -> str:
    return (fake.root / "archive" / "carryon" / rel).read_text()


def test_a_second_push_confirms_the_bytes_it_uploaded(tmp_path, monkeypatch,
                                                      capsys):
    """The confirmation asked the store's LISTING whether a key of that name
    exists, which is evidence for a create and none at all for an update: on
    every push after the first, every key already exists - index.enc, every
    setups/<machine>/ file, and a Session tar whose key is its identity hash
    rather than a hash of its bytes.

    So the same `dry_run = true` the module docstring names was caught on the
    first push and invisible on the second: exit 0, 'Sessions: 1 pushed',
    'Setup: pushed to setups/mac-a/ (clean)', and an Archive still holding
    last week's CLAUDE.md. A stale object's seal verifies perfectly - a label
    binds identity, not revision - so nothing downstream notices either.
    """
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home) == 0
    assert sync.push(ns(apply=True), home) == 0
    capsys.readouterr()
    assert stored_text(fake, "setups/mac-a/claude/CLAUDE.md") == \
        "Answer briefly.\n"

    (home / ".claude" / "CLAUDE.md").write_text("Answer at length.\n")
    fake.copyto_writes_nothing()      # dry_run appears in rclone.conf

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home)
    out = capsys.readouterr().out

    assert "rclone" in str(exc.value)
    assert "Setup: pushed" not in out, \
        "a push that transferred nothing reported a stored Setup"
    assert stored_text(fake, "setups/mac-a/claude/CLAUDE.md") == \
        "Answer briefly.\n"

    # And the wedge that followed it: the vacuous push advanced this
    # machine's high-water mark past the Index the Archive actually holds, so
    # every later push - against a perfectly healthy remote - refused for
    # ever, naming a hand-edit of ~/.carryon/state.json as the only cure.
    # carryon manufactured the rollback and then wedged itself on it.
    fake.copyto_writes_nothing(False)
    assert sync.push(ns(apply=True), home) == 0, capsys.readouterr().out
    assert stored_text(fake, "setups/mac-a/claude/CLAUDE.md") == \
        "Answer at length.\n"


def test_a_push_that_stored_some_objects_does_not_claim_it_stored_none(
        tmp_path, monkeypatch, capsys):
    """'Nothing was stored; the Archive is as it was.' is the sentence the
    user acts on, and it is false whenever the write that failed is not the
    first. A filter declining one kind of object leaves the plaintext Setup
    half in the Archive with no Index beside it - which is the shape ADR-0009
    says a pull must refuse."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home) == 0
    capsys.readouterr()

    fake.copyto_writes_nothing(suffix=".tar.enc")   # a --max-size rule
    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home)
    capsys.readouterr()

    stored = fake.objects()
    assert stored, "the filter declined more than it was asked to"
    assert "the Archive is as it was" not in str(exc.value), (
        "the Archive holds " + ", ".join(stored) + " and the refusal says "
        "nothing was stored")


def test_a_listing_the_remote_refuses_is_not_an_empty_archive(tmp_path,
                                                              monkeypatch,
                                                              capsys):
    """`lsf` failing meant []. An empty listing plus an unreadable Index is
    exactly what load_index reads as a fresh Archive, and the guard that
    exists for this - Session objects with no Index - is asked OF that same
    listing, so a listing that lies about being empty walks straight past it.

    The machine holds no high-water mark, which ADR-0009 names as ordinary: a
    $HOME restored from a backup. What used to happen next was a brand new
    Index at revision 1, sealed over a populated Archive, at exit 0."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home) == 0
    assert sync.push(ns(apply=True), home) == 0
    capsys.readouterr()
    stored = fake.objects()
    assert stored, "the first push stored nothing"
    (home / ".carryon" / "state.json").unlink()   # a $HOME from a backup

    fake.fail("lsf", code=1)     # not 3: the target is there, rclone is not
    fake.fail("cat", code=5)     # 5 is rclone's own "temporary error"
    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home)

    assert "rclone" in str(exc.value)
    assert fake.objects() == stored, \
        "a remote that would not answer was read as a fresh Archive, and the " \
        "push wrote a new catalogue over the stored one"


def test_an_object_the_remote_will_not_serve_is_named_not_absent(tmp_path,
                                                                 monkeypatch,
                                                                 capsys):
    """A cat that fails on an object the listing still holds is the object
    being refused, not absent. Answering None there is the silence ADR-0009
    rules out: a Setup that arrives short reads as a successful pull."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    assert sync.init(ns(dest=SPEC, machine="mac-a"), home) == 0
    assert sync.push(ns(apply=True), home) == 0
    capsys.readouterr()

    dest = RcloneDestination("fakeremote:archive")
    key = "carryon/setups/mac-a/MANIFEST.json"
    assert key in dest.list(), dest.list()
    fake.fail("cat", code=6)     # rclone's "less serious errors"

    assert dest.read(key) is None
    out = capsys.readouterr().out
    assert "MANIFEST.json" in out and "skipping" in out, \
        "an object the remote holds and would not serve went unreported"


def test_a_hostile_listing_cannot_stop_a_pull(rclone_journey, capsys):
    """Everything lsf prints is input (ADR-0009). The five shapes a remote
    can answer with that no local filesystem would - '..', an absolute key,
    a lone surrogate, bytes that are not UTF-8, and an empty component - all
    at once, in the middle of a real pull."""
    fake, home_a = rclone_journey.fake, rclone_journey.home_a
    honest = "\n".join(fake.objects()).replace("archive/", "")
    fake.listing((honest + "\n"
                  "carryon/../../../../etc/passwd\n"
                  "/etc/passwd\n"
                  "carryon//empty.enc\n"
                  "carryon/lone\udcffsurrogate.enc\n").encode("utf-8",
                                                              "surrogateescape")
                 + b"carryon/raw\xff\xfe.enc\n")

    code = sync.pull(ns(apply=True), home_a)
    out = capsys.readouterr().out

    assert code in (0, 1), out
    assert "Traceback" not in out
    assert out.count("skipping") >= 5, out
    assert not pathlib.Path("/etc/passwd.carryon-test").exists()


# =============================================================================
# 2. THE CODEX AND CURSOR ADAPTERS
# =============================================================================
#
# Every round exercised claude-code. These two were declared and left. The
# declarations are checked here against a directory shaped like the real one,
# and the codex-rollouts layout - the one thing an adapter cannot supply, and
# the only layout in the engine that no round has driven - is taken through
# discover, pack, push, pull and re-key.

CODEX_UUID = "019df332-7547-7711-8cf0-fd9a2e5e04ff"
CODEX_REL = ("2026/05/04/rollout-2026-05-04T14-34-23-"
             + CODEX_UUID + ".jsonl")
# A second rollout on another day, so the date directories are exercised as
# part of the member path rather than assumed away.
CODEX_UUID2 = "019e01e1-c9f5-7d32-ae89-0f4fe14b2388"
CODEX_REL2 = ("2026/05/07/rollout-2026-05-07T11-00-35-"
              + CODEX_UUID2 + ".jsonl")


def build_codex_home(tmp_path, name="codex_a") -> pathlib.Path:
    """A ~/.codex shaped like the real one on this machine.

    Verified read-only against a live ~/.codex on 2026-07-31 (names and
    structure only): every top-level entry, the sessions/YYYY/MM/DD/
    rollout-<timestamp>-<uuid>.jsonl layout, and skills/ holding nothing but
    .system. The sqlite trio (state_N.sqlite, -shm, -wal) is here because it
    is what a running Codex actually leaves behind and it is what the
    adapter's `state_*.sqlite*` pattern has to cover.
    """
    home = tmp_path / name
    codex = home / ".codex"
    (codex / "memories").mkdir(parents=True)
    (codex / "skills" / ".system" / "review").mkdir(parents=True)
    (codex / "cache").mkdir()
    (codex / "log").mkdir()
    (codex / "tmp").mkdir()
    (codex / "shell_snapshots").mkdir()
    (codex / ".tmp" / "plugins").mkdir(parents=True)
    (codex / "config.toml").write_text('model = "gpt-5"\n')
    (codex / "AGENTS.md").write_text("Answer briefly.\n")
    (codex / "memories" / "notes.md").write_text("a memory\n")
    (codex / "auth.json").write_text('{"token": "INVENTED-NOT-A-REAL-TOKEN"}')
    (codex / "installation_id").write_text("0000-1111")
    (codex / "version.json").write_text('{"version": "1.0"}')
    (codex / "history.jsonl").write_text(jline({"prompt": "hi"}))
    (codex / "models_cache.json").write_text("{}")
    (codex / "state_5.sqlite").write_bytes(b"SQLite format 3\x00")
    (codex / "state_5.sqlite-shm").write_bytes(b"")
    (codex / "state_5.sqlite-wal").write_bytes(b"")
    (codex / "logs_2.sqlite").write_bytes(b"SQLite format 3\x00")
    (codex / ".personality_migration").write_text("1")

    cwd = str(home / "code" / "app")
    for rel, text in (
        (CODEX_REL,
         jline({"type": "session_meta",
                "payload": {"id": CODEX_UUID, "cwd": cwd}})
         + jline({"type": "message",
                  "payload": {"text": f"open {cwd}/main.py"}})),
        (CODEX_REL2,
         jline({"type": "session_meta",
                "payload": {"id": CODEX_UUID2, "cwd": cwd}})),
    ):
        path = codex / "sessions" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return home


def build_cursor_home(tmp_path, name="cursor_a") -> pathlib.Path:
    """A ~/.cursor shaped like the real one on this machine.

    Verified read-only against a live ~/.cursor on 2026-07-31 (names and
    structure only): every top-level entry below, skills-cursor holding
    .sync-manifest.json beside one directory per vendor-synced skill, and
    plugins/local. `rules` and `commands` are declared by the adapter and
    absent on that machine, which is what `required=False` is for.
    """
    home = tmp_path / name
    cursor = home / ".cursor"
    (cursor / "rules").mkdir(parents=True)
    (cursor / "commands").mkdir()
    (cursor / "agents").mkdir()
    (cursor / "extensions" / "some.ext-1.0.0").mkdir(parents=True)
    (cursor / "projects" / "abc").mkdir(parents=True)
    (cursor / "plugins" / "local").mkdir(parents=True)
    (cursor / "ai-tracking").mkdir()
    (cursor / "skills-cursor" / "review").mkdir(parents=True)
    (cursor / "cli-config.json").write_text(json.dumps({
        "version": 1,
        "authInfo": {"email": "someone@example.invalid", "teamId": 7},
    }))
    (cursor / "rules" / "style.md").write_text("prefer prose\n")
    (cursor / "commands" / "ship.md").write_text("ship it\n")
    (cursor / "agents" / "reviewer.md").write_text("review\n")
    (cursor / "skills-cursor" / ".sync-manifest.json").write_text('{"v": 1}')
    (cursor / "skills-cursor" / "review" / "SKILL.md").write_text("vendor\n")
    (cursor / "ai-tracking" / "ai-code-tracking.db").write_bytes(b"\x00")
    (cursor / "argv.json").write_text("{}")
    (cursor / "blocklist").write_text("")
    (cursor / "ide_state.json").write_text("{}")
    (cursor / "unified_repo_list.json").write_text("[]")
    (cursor / ".gitignore").write_text("*\n")
    return home


@pytest.mark.parametrize("build,agent", [
    (build_codex_home, "codex"),
    (build_cursor_home, "cursor"),
])
def test_the_adapter_accounts_for_every_entry_a_real_directory_holds(
        build, agent, tmp_path):
    """`doctor` reports what no adapter recognises, and that report is the
    early warning for a vendor reorganising. An adapter whose known_entries
    have gone stale answers it with noise, which is how a real drift gets
    read as more of the same."""
    home = build(tmp_path)
    report = layout.inspect(home, platform="darwin")

    assert agent in report, report
    assert report[agent]["unknown"] == [], \
        f"{agent}'s adapter does not account for what it found"
    assert report[agent]["platform_verified"]


def test_a_codex_rollout_makes_the_whole_round_trip(tmp_path, capsys):
    """codex-rollouts is the one layout in the engine no round has driven.

    A rollout Session is flat - one file, no subtree - and its project_dir is
    the sessions root itself, so the date directories above it are part of
    the member path rather than of the root. That makes the restore land it
    back at the same relative path, which is the whole of what the layout
    promises, and it is re-keyed like any other Transcript on the way.
    """
    import re
    home_a = build_codex_home(tmp_path, "codex_a")
    home_b = build_codex_home(tmp_path, "codex_b")
    # B has never seen these Sessions
    for rel in (CODEX_REL, CODEX_REL2):
        (home_b / ".codex" / "sessions" / rel).unlink()
    dest_spec = str(tmp_path / "archive")

    assert sync.init(ns(dest=dest_spec, machine="mac-a"), home_a) == 0
    capsys.readouterr()
    assert sync.push(ns(apply=True), home_a) == 0
    push_out = capsys.readouterr().out
    assert "Sessions: 2 pushed" in push_out, push_out

    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)
    assert sync.init(ns(dest=dest_spec, join=code, machine="box-b"),
                     home_b) == 0
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    for rel in (CODEX_REL, CODEX_REL2):
        landed = home_b / ".codex" / "sessions" / rel
        assert landed.is_file(), f"{rel} did not land\n{out}"
    text = (home_b / ".codex" / "sessions" / CODEX_REL).read_text()
    assert str(home_b / "code" / "app") in text, \
        "the rollout was not expanded against B's home"
    assert str(home_a) not in text, "A's home reached B's disk"
    # The Setup half travelled too, and the credential the adapter excludes
    # did not.
    assert (home_b / ".codex" / "AGENTS.md").read_text() == "Answer briefly.\n"
    assert "INVENTED-NOT-A-REAL-TOKEN" not in \
        (tmp_path / "archive").joinpath().as_posix()
    stored = [p for p in (tmp_path / "archive").rglob("*") if p.is_file()]
    assert not any(b"INVENTED-NOT-A-REAL-TOKEN" in p.read_bytes()
                   for p in stored), "auth.json reached the Archive"


def test_the_codex_uuid_is_taken_from_the_rollout_name(tmp_path):
    """The layout reads the UUID out of the filename, and a name that does
    not carry one falls back to the stem. Both spellings have to be usable as
    an Archive key, since that is what the Session hangs from."""
    home = build_codex_home(tmp_path)
    found = history.discover(home, [ADAPTERS["codex"]])

    uuids = sorted(s.uuid for s in found.sessions)
    assert uuids == sorted((CODEX_UUID, CODEX_UUID2)), uuids
    for session in found.sessions:
        assert session.project_dir == ".codex/sessions"
        assert session.main_path in (CODEX_REL, CODEX_REL2)
        assert session.files == (session.main_path,)
        assert archive.key_refusal("sessions", session.uuid) is None
    assert found.missing_cwd == (), found.missing_cwd


def test_a_rollout_whose_cwd_cannot_be_read_is_still_discovered(tmp_path):
    """A rollout the machine cannot open records no cwd, and discovery says
    so rather than raising - the guard read_recorded_cwd already carries."""
    home = build_codex_home(tmp_path)
    path = home / ".codex" / "sessions" / CODEX_REL
    path.chmod(0o000)
    try:
        found = history.discover(home, [ADAPTERS["codex"]])
    finally:
        path.chmod(0o644)

    assert len(found.sessions) == 2
    unreadable = [rel for rel, _why in found.unreadable]
    assert any(CODEX_REL in rel for rel in unreadable), found.unreadable
    assert any(CODEX_REL in rel for rel in found.missing_cwd)


def test_the_cursor_setup_travels_without_its_auth_info(tmp_path, capsys):
    """cursor carries no History at all, so the Setup half is the whole of
    it - and its one json-strip item is the only place in any adapter where
    a captured file is edited rather than copied."""
    import re
    home_a = build_cursor_home(tmp_path, "cursor_a")
    home_b = build_cursor_home(tmp_path, "cursor_b")
    (home_b / ".cursor" / "rules" / "style.md").write_text("B's own\n")
    dest_spec = str(tmp_path / "archive")

    assert sync.init(ns(dest=dest_spec, machine="mac-a"), home_a) == 0
    capsys.readouterr()
    assert sync.push(ns(apply=True), home_a) == 0
    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)
    assert sync.init(ns(dest=dest_spec, join=code, machine="box-b"),
                     home_b) == 0
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    stored = json.loads((home_b / ".cursor" / "cli-config.json").read_text())
    assert "authInfo" not in stored, out
    assert stored["version"] == 1
    assert (home_b / ".cursor" / "rules" / "style.md").read_text() == \
        "prefer prose\n"
    assert not any(b"someone@example.invalid" in p.read_bytes()
                   for p in (tmp_path / "archive").rglob("*") if p.is_file())


def test_a_cwdless_rollout_is_named_on_every_leg_and_never_raises(tmp_path,
                                                                  capsys):
    """A rollout whose meta line never made it to disk records no cwd, and a
    Session with no cwd meets three separate guards on the pull leg. All
    three name it and carry on; none of them is the raise in
    history.unpack_session, which would end a pull with Sessions already in
    $HOME.

    What it is named FOR is wrong for this layout, and that is recorded in
    this round's deviations rather than fixed here: `_codex_restore_root`
    ignores the cwd entirely - a rollout lands at ~/.codex/sessions/<rel>
    whatever cwd it recorded - so 'no local project dir can be derived' is
    true of claude-projects and false of codex-rollouts, and a Session this
    machine could restore perfectly is refused on every pull for ever.
    """
    import re
    home_a = build_codex_home(tmp_path, "codex_a")
    home_b = build_codex_home(tmp_path, "codex_b")
    no_cwd = ("2026/05/09/rollout-2026-05-09T10-00-00-"
              "019e0999-0000-7000-8000-000000000001.jsonl")
    for home, text in (
        (home_a, jline({"type": "session_meta", "payload": {"id": "x"}})
                 + jline({"type": "message", "payload": {"text": "longer"}})),
        (home_b, jline({"type": "session_meta", "payload": {"id": "x"}})),
    ):
        path = home / ".codex" / "sessions" / no_cwd
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for rel in (CODEX_REL, CODEX_REL2):
        (home_b / ".codex" / "sessions" / rel).unlink()
    dest_spec = str(tmp_path / "archive")

    assert sync.init(ns(dest=dest_spec, machine="mac-a"), home_a) == 0
    assert sync.push(ns(apply=True), home_a) == 0
    push_out = capsys.readouterr().out
    assert "recorded no cwd" in push_out, push_out
    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)
    assert sync.init(ns(dest=dest_spec, join=code, machine="box-b"),
                     home_b) == 0
    capsys.readouterr()

    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    assert "without a cwd" in out, out
    for rel in (CODEX_REL, CODEX_REL2):
        assert (home_b / ".codex" / "sessions" / rel).is_file(), \
            "the cwd-less Session took the rest of the pull with it\n" + out
    # B's own shorter copy is untouched: a pull never deletes, and nothing
    # here decided otherwise.
    assert (home_b / ".codex" / "sessions" / no_cwd).read_text() == \
        jline({"type": "session_meta", "payload": {"id": "x"}})


# =============================================================================
# 3. layout.py AND doctor UNDER HOSTILE ON-DISK SHAPES
# =============================================================================
#
# `doctor` walks the user's real agent directories, and it is the command a
# user runs when something is already wrong. It had no guard of any kind on
# that walk: capture.tree_files, history._listing and config's own read each
# say in their docstrings that $HOME is input and that a directory which will
# not list is one line rather than a traceback. This walk said it nowhere.

ERASING_NAME = "wiped\r\x1b[2K  unrecognised     : none"


def build_drifting_home(tmp_path, name="home") -> pathlib.Path:
    home = tmp_path / name
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    return home


def test_doctor_reports_a_directory_it_cannot_read(tmp_path, capsys):
    """A $HOME restored with the wrong owner, or an agent directory an agent
    wrote under sudo, leaves a mode-000 directory - which needs no attacker
    and is the ordinary reason someone runs `doctor` in the first place.
    iterdir() answered it with a PermissionError straight out of the report
    that was about to explain it."""
    home = build_drifting_home(tmp_path)
    (home / ".claude").chmod(0o000)
    try:
        report = layout.inspect(home, platform="darwin")
        text = layout.format_report(report, platform="darwin")
    finally:
        (home / ".claude").chmod(0o755)

    assert "claude-code" in report, "the agent vanished from the report"
    assert "unreadable" in report["claude-code"], report["claude-code"]
    assert "not read" in text or "permission" in text.lower(), text


def test_doctor_reports_a_home_it_cannot_look_inside(tmp_path):
    """The stat that decides an agent is installed is a syscall on a path
    this machine may refuse to answer about. pathlib swallows ENOENT,
    ENOTDIR, EBADF and ELOOP and nothing else, so EACCES came out of
    `is_installed` before `doctor` had printed a word."""
    home = build_drifting_home(tmp_path)
    home.chmod(0o000)
    try:
        report = layout.inspect(home, platform="darwin")
        layout.format_report(report, platform="darwin")
    finally:
        home.chmod(0o755)

    assert isinstance(report, dict)


def test_doctor_says_so_when_an_agent_root_is_not_a_directory(tmp_path):
    """A file, a fifo or a device standing where ~/.claude belongs is a
    layout question, and answering 'unrecognised: none' about it is the quiet
    failure this whole command exists to prevent."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude").write_text("not a directory")

    report = layout.inspect(home, platform="darwin")
    text = layout.format_report(report, platform="darwin")

    assert "claude-code" in report
    assert report["claude-code"]["unreadable"], report["claude-code"]
    assert "unrecognised     : none" not in text, text


def test_doctor_says_so_when_an_agent_root_is_a_symlink_loop(tmp_path):
    """A path this machine will not answer about is not the same as an agent
    that is not installed, and `doctor` reporting nothing at all is how a
    user learns nothing from the command they ran to learn something."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude").symlink_to(home / ".claude")

    report = layout.inspect(home, platform="darwin")
    text = layout.format_report(report, platform="darwin")

    assert "claude-code" in report, text
    assert report["claude-code"]["unreadable"], report["claude-code"]


def test_a_dangling_link_at_an_agent_root_is_still_not_installed(tmp_path):
    """The other half of the rule above: a link to nothing is an answer, and
    the answer is that the agent's directory is not there."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude").symlink_to(home / "nowhere")

    assert "claude-code" not in layout.inspect(home, platform="darwin")


def test_an_entry_name_cannot_author_a_line_of_the_doctor_report(tmp_path):
    """Every name in this report comes off the user's filesystem, and a
    filename may hold a carriage return and a CSI erase. The line naming an
    unrecognised entry IS what doctor produces, so an unescaped name rewrites
    the report it is meant to appear in - the same collision the Destination
    layer answers with `printable`."""
    home = build_drifting_home(tmp_path)
    (home / ".claude" / ERASING_NAME).write_text("x")

    report = layout.inspect(home, platform="darwin")
    text = layout.format_report(report, platform="darwin")

    assert "\r" not in text and "\x1b" not in text, repr(text)
    assert "wiped" in text, text


def test_an_entry_name_this_machine_cannot_spell_does_not_end_the_report(
        tmp_path, monkeypatch):
    """os.scandir hands back a lone surrogate for a filename that is not
    valid UTF-8, which is ordinary on Linux and cannot even be created on
    APFS - so the name reaches the report through a walk that ran somewhere
    else, and printing one raises UnicodeEncodeError. Faked at the walk
    rather than on disk, because this machine's filesystem refuses to hold
    the shape the report has to survive."""
    home = build_drifting_home(tmp_path)
    real_iterdir = pathlib.Path.iterdir

    class Surrogate:
        name = "bad\udcff\udcfename"

    def iterdir(self):
        if self.name == ".claude":
            return iter(list(real_iterdir(self)) + [Surrogate()])
        return real_iterdir(self)

    monkeypatch.setattr(pathlib.Path, "iterdir", iterdir)
    report = layout.inspect(home, platform="darwin")
    text = layout.format_report(report, platform="darwin")

    text.encode("utf-8")   # what writing it to a terminal does
    assert "bad" in text, text


def test_doctor_reads_the_home_it_is_run_under(tmp_path, monkeypatch, capsys):
    """`carryon doctor` asked layout.inspect() for its default home, which is
    bound at import time in adapters/__init__ - so the one command whose whole
    job is to describe this machine's directories was the one command no test
    could point at a directory. cmd_capture's docstring names this exact
    shape, one command over, after it had been fixed there."""
    home = build_drifting_home(tmp_path)
    (home / ".claude" / "brand-new-feature").mkdir()
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))

    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out

    assert "brand-new-feature" in out, out
    assert str(home) in out, out


# =============================================================================
# 4. pull's --map AS AN INPUT SURFACE
# =============================================================================
#
# It is user-supplied, it rewrites paths inside every restored Transcript and
# inside the restored Setup, and no round has treated it as input. It is the
# user's own flag, so the bar is report-and-refuse rather than a security
# boundary - but a traceback or a silent wrong write is a defect either way.


def two_project_home(tmp_path, name="home_a") -> pathlib.Path:
    """One machine, two Sessions in two different project directories."""
    home = tmp_path / name
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Answer briefly.\n")
    for uuid, rel in ((U1, "work/one"), (UB, "work/two")):
        cwd = str(home / rel)
        project = claude / "projects" / rekey.encode_project_dir(cwd)
        project.mkdir(parents=True)
        (project / (uuid + ".jsonl")).write_text(
            jline({"cwd": cwd, "type": "meta"})
            + jline({"type": "user", "text": f"in {cwd}"}))
    return home


def _paired(tmp_path, home_a, capsys):
    """Push home_a to a directory Destination and join an empty home_b."""
    import re
    dest_spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=dest_spec, machine="mac-a"), home_a) == 0
    assert sync.push(ns(apply=True), home_a) == 0
    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    assert sync.init(ns(dest=dest_spec, join=code, machine="box-b"),
                     home_b) == 0
    capsys.readouterr()
    return home_b


def test_a_map_writes_nowhere_but_under_the_local_home(tmp_path, capsys):
    """A --map target is a string the user chose and it reaches the value a
    project directory is derived from. It cannot reach the directory itself:
    both layouts derive the root from the cwd through their own strategy, and
    claude-projects runs it through encode_project_dir, which turns every
    non-alphanumeric into '-' and so collapses any path into one name. Asked
    here because nothing had asked it - not because it was in doubt."""
    home_a = build_claude_home(tmp_path)
    home_b = _paired(tmp_path, home_a, capsys)
    before = sorted(p for p in pathlib.Path("/etc").glob("carryon*"))

    assert sync.pull(ns(apply=True, map=["/code=/etc",
                                         "/nowhere=" + str(home_b / ".carryon")]),
                     home_b) == 0
    out = capsys.readouterr().out

    written = [p for p in home_b.rglob("*") if p.is_file()]
    assert written, out
    assert all(str(p).startswith(str(home_b)) for p in written)
    assert not [p for p in (home_b / ".carryon").rglob("*.jsonl")], \
        "a --map put a restored Transcript in carryon's own state"
    assert sorted(p for p in pathlib.Path("/etc").glob("carryon*")) == before


def test_a_map_that_collides_two_sessions_keeps_both(tmp_path, capsys):
    """Two Sessions whose cwds differ only below the mapped prefix land in
    one project directory. Each is its own file there, and ADR-0002's rule
    runs per member, so a collision is a directory two Sessions share rather
    than one Session overwriting the other."""
    home_a = two_project_home(tmp_path)
    home_b = _paired(tmp_path, home_a, capsys)

    assert sync.pull(ns(apply=True,
                        map=["/work/one=/shared", "/work/two=/shared"]),
                     home_b) == 0
    out = capsys.readouterr().out

    landed = sorted(p.name for p in (home_b / ".claude" / "projects").rglob("*")
                    if p.is_file())
    assert landed == sorted([U1 + ".jsonl", UB + ".jsonl"]), out
    dirs = {p.parent for p in (home_b / ".claude" / "projects").rglob("*.jsonl")}
    assert len(dirs) == 1, "the map was meant to collide them"


@pytest.mark.parametrize("bad", [
    "no-equals-sign",
    "=/only-a-target",
    "/only-an-old=",
    "relative=/tmp/x",             # an OLD that is not a path at all
    "/tmp/x=relative",             # a NEW that would not resolve anywhere
    "e=E",                         # the one that quietly rewrites all prose
    "~/from=/tmp/to",              # '~' is not expanded in a --map
    "/=/tmp/relocated",            # absolute, and inside every path there is
    "/tmp/from=/",                 # the same nothing on the other side
])
def test_a_map_that_is_not_two_paths_is_refused(bad, tmp_path,
                                               monkeypatch):
    """`--map OLD=NEW` moves a path outside $HOME to where it lives here, and
    the match is a plain substring over every string value in the Archive. So
    an OLD that is not an absolute path matches inside ordinary prose: one
    `--map e=E` rewrote every value of every restored Transcript AND the
    restored Setup - 'Answer briefly.' came back as 'AnswEr briEfly.' - at
    exit 0, with no line of the report mentioning a map at all.

    The home is redirected at an empty directory, so a check that stopped
    firing would meet nothing rather than the machine running the suite."""
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path))
    with pytest.raises(SystemExit) as exc:
        cli.main(["pull", "--map", bad])
    assert "--map" in str(exc.value), exc.value


def test_a_map_whose_output_another_map_rewrites_is_refused(tmp_path,
                                                           monkeypatch):
    """`--map` is documented as 'applied longest OLD first', which describes
    one rule winning over another on the same value. What it does is apply
    each rule to the last rule's OUTPUT, so '/a=/b /b=/c' sends everything
    under /a to /c, and the honest swap '/a=/b /b=/a' is a no-op. Both are
    silent, and both give a restored Transcript a path the user never named."""
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path))
    for maps in (["/data=/mnt", "/mnt=/gone"],
                 ["/data=/mnt", "/mnt=/data"]):
        with pytest.raises(SystemExit) as exc:
            cli.main(["pull"] + [arg for pair in maps
                                 for arg in ("--map", pair)])
        assert "--map" in str(exc.value), exc.value


@pytest.mark.parametrize("maps", [
    [],
    ["/data=/vol"],
    ["/data=/vol", "/data/projects=/vol2"],   # longest OLD first, no chaining
    ["/data=/data-old"],                      # a rename onto its own prefix
])
def test_a_usable_map_set_is_not_refused(maps):
    assert rekey.map_refusal(maps) is None, maps


def test_the_root_is_not_a_path_a_map_may_name(tmp_path, capsys):
    """`--map /=/tmp/relocated` is the round's own `--map e=E` finding one
    character over: '/' is an absolute path by os.path.isabs, and the chain
    rule skips a pair against itself, so one pair passed both rules. It then
    rewrote every string value of every Transcript, the derived project
    directory name, and the restored CLAUDE.md - 'and/or' came back as
    'and/tmp/relocatedor' - at exit 0.

    Driven through sync.pull rather than the CLI, because that is the second
    door: the refusal used to sit in cli.cmd_pull only, so every other caller
    of pull - this suite included - walked past it."""
    home_a = build_claude_home(tmp_path)
    home_b = _paired(tmp_path, home_a, capsys)

    with pytest.raises(SystemExit) as exc:
        sync.pull(ns(apply=True, map=["/=/tmp/relocated"]), home_b)

    assert "--map" in str(exc.value), exc.value
    landed = [p for p in (home_b / ".claude").rglob("*") if p.is_file()]
    assert not landed, "the rewrite ran before the refusal"


def test_a_home_that_will_not_resolve_is_answered_the_same_on_both_runners(
        tmp_path):
    """rekey.home_forms resolves the home to catch its second true spelling,
    and Path.resolve() is the one call the two interpreters carryon must pass
    disagree about: a symlink loop is a RuntimeError on 3.9 and the
    unresolved path on 3.13. It sits on the hot path of every re-key in both
    directions, guarded nowhere, so on 3.9 a $HOME that will not resolve was
    a traceback out of push and out of pull rather than a home with one
    spelling instead of two - external.owner_of carries this exact sentence
    about this exact call, one module over."""
    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    forms = rekey.home_forms(loop)

    assert forms == [str(loop)], forms
    text, stats = rekey.canonicalise_jsonl(
        jline({"cwd": str(loop) + "/x"}), loop)
    assert stats.rewritten_values == 1
    assert "~/x" in text


def test_a_listing_that_changes_between_two_calls_lands_the_rest(
        rclone_journey, capsys):
    """read_tree lists and then reads, and on a remote those are two answers
    about two moments. A key that was listed and is gone by the read is
    ordinary on storage somebody else writes to - a sync client mid-delete,
    a second machine pushing.

    What must hold is that the rest of the tree lands and nothing raises.
    What does NOT hold is a line about the member that vanished: base
    read_tree drops a key whose read comes back None without a word, which
    is this round's one unclosed silence and is recorded in the deviations -
    the rclone type cannot supply it, since 'absent' is also every fresh
    Archive's answer for index.enc.
    """
    fake = rclone_journey.fake
    honest = "\n".join(o.replace("archive/", "", 1)
                       for o in fake.objects()) + "\n"
    ghost = "carryon/setups/mac-a/claude/ghost.md\n"
    fake.listing((honest + ghost).encode(), honest.encode())

    dest = RcloneDestination("fakeremote:archive")
    staging = pathlib.Path(rclone_journey.tmp_path) / "staging"
    dest.read_tree("carryon/setups/mac-a", staging)
    out = capsys.readouterr().out

    landed = sorted(p.name for p in staging.rglob("*") if p.is_file())
    assert "settings.json" in landed, out
    assert "ghost.md" not in landed
    assert "Traceback" not in out


def _covered_names(adapter) -> set:
    """Top-level names under the agent root that this adapter speaks for.

    An exclusion path is a shorthand - '.codex/{cache,tmp}', a trailing '/'
    for a directory, an fnmatch pattern. Only an exclusion naming a
    TOP-LEVEL entry speaks for that entry: '.codex/skills/.system/' is about
    part of `skills` and says nothing about the rest of it, which is exactly
    how a user's own skills came to be neither carried nor mentioned.
    """
    import re as _re
    names = {item.src.split("/")[1] for item in adapter.items}
    patterns = []
    for excluded in adapter.exclude:
        path = excluded.path
        if not path.startswith(adapter.detect + "/"):
            continue        # an exclusion about somewhere else entirely
        rest = path[len(adapter.detect) + 1:].rstrip("/")
        if "/" in rest:
            continue        # about something inside an entry, not the entry
        match = _re.match(r"^\{([^}]*)\}$", rest)
        patterns += (match.group(1).split(",") if match else [rest])
    return names, patterns


@pytest.mark.parametrize("build,agent", [
    (build_codex_home, "codex"),
    (build_cursor_home, "cursor"),
])
def test_nothing_a_real_directory_holds_is_left_behind_unsaid(build, agent,
                                                              tmp_path):
    """Every entry is either carried by an item or named in an exclusion.

    `doctor` reports what no adapter has HEARD of, so it is blind to the
    third case: an entry the adapter knows about, carries nowhere, and never
    mentions. That is what Excluded exists to prevent - "an exclusion that is
    not written down reads as an oversight later, and gets 'fixed' by someone
    copying a credential onto a new machine" - and both of these adapters had
    several, `.codex/skills` (a user's own skills, silently not carried) and
    `.cursor/plugins` among them.

    Asked of these two only, because they are this round's to fix; claude-code
    has the same shape in three entries and is named in the deviations.
    """
    import fnmatch as _fnmatch
    home = build(tmp_path)
    carried, patterns = _covered_names(ADAPTERS[agent])

    unsaid = sorted(
        entry.name for entry in (home / ADAPTERS[agent].detect).iterdir()
        if entry.name not in carried
        and not any(_fnmatch.fnmatch(entry.name, p) for p in patterns))

    assert unsaid == [], (
        f"{agent} neither carries nor mentions: {', '.join(unsaid)}")


def test_list_reads_the_home_it_is_run_under(tmp_path, monkeypatch, capsys):
    """The same question as `doctor`, one command over. `list` asked
    is_installed and HOME for their defaults, both bound at import in
    adapters/__init__, so it described whatever home the process started in
    rather than the one it is running against - which is the shape this
    round exists to stop finding one place at a time."""
    home = build_codex_home(tmp_path)
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))

    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out

    assert "[x] codex" in out, out
    assert "config.toml" in out, out
    assert "[ ] claude-code" in out, "a home with no ~/.claude claimed one"


@pytest.mark.parametrize("blocked", ["home", "agent-dir"])
def test_list_answers_about_a_path_it_will_not_look_at(blocked, tmp_path,
                                                       monkeypatch, capsys):
    """`doctor` was rewritten this round to stop using the bare
    `Path.exists()` - it 'swallows exactly four errnos and raises for every
    other one' - and `list` beside it kept two of them: one inside
    adapters.is_installed and one in cli.py's own body. A mode-000 home or
    agent directory is a PermissionError out of `carryon list` where `carryon
    doctor` exits 0, on both interpreters.

    Neither needs an attacker: a $HOME restored with the wrong owner, or an
    agent that once ran under sudo."""
    home = build_claude_home(tmp_path)
    blocker = home if blocked == "home" else home / ".claude"
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))
    blocker.chmod(0o000)
    try:
        answers = [_answer_of(command) for command in ("list", "doctor")]
    finally:
        blocker.chmod(0o755)
    capsys.readouterr()

    for command, answer in zip(("list", "doctor"), answers):
        assert not isinstance(answer, OSError), (
            f"`carryon {command}` answered a path it cannot look at with a "
            f"{type(answer).__name__}")
        if isinstance(answer, SystemExit):
            assert str(answer), "SystemExit with no sentence in it"
    assert type(answers[0]) is type(answers[1]), (
        "`list` and `doctor` answer the same unreadable directory in two "
        f"different ways: {answers[0]!r} and {answers[1]!r}")


def _answer_of(command: str):
    """What `carryon <command>` does about a directory it cannot look at:
    a return code, or the exception it chose. Anything that is not one of
    those propagates."""
    try:
        return cli.main([command])
    except SystemExit as exc:
        return exc


def test_list_and_doctor_describe_the_setup_that_would_be_captured(
        tmp_path, monkeypatch, capsys):
    """`list`'s own help text is 'show detected agents and what would be
    captured', and cmd_capture's docstring has two paragraphs: pass the home
    explicitly, and read the EFFECTIVE registry - excludes applied, handpicked
    paths added (ADR-0008). The round copied the first into `list` and
    `doctor` and neither took the second, so both described a Setup that
    capture does not produce: an excluded file listed as carried, a handpicked
    path missing from the listing and reported by `doctor` as 'unrecognised'
    under the line 'Nothing unrecognised is ever captured'.

    doctor is the command a user runs to find out whether something is wrong.
    """
    home = build_claude_home(tmp_path)
    # A directory no adapter has heard of, which is what handpicking is FOR:
    # carrying a tool carryon does not know about (ADR-0008).
    (home / ".claude" / "mytool").mkdir()
    (home / ".claude" / "mytool" / "keep.json").write_text("{}")
    (home / "SECRET-IN-HOME").write_text("not an agent directory\n")
    cfg = config.default_config()
    cfg["excludes"] = [".claude/CLAUDE.md"]
    cfg["carry"] = ["~/.claude/mytool"]
    config.save(cfg, home)
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))

    assert cli.main(["list"]) == 0
    listed = capsys.readouterr().out
    assert cli.main(["doctor"]) == 0
    doctored = capsys.readouterr().out

    assert "CLAUDE.md" not in listed, (
        "list names a file the user excluded, which capture does not write:\n"
        + listed)
    assert "mytool" in listed, (
        "list omits a handpicked path capture writes:\n" + listed)
    assert "mytool" not in doctored, (
        "doctor calls a handpicked path unrecognised and then says nothing "
        "unrecognised is ever captured:\n" + doctored)
    assert "SECRET-IN-HOME" not in doctored, (
        "doctor walked $HOME itself as though it were an agent directory - "
        "the handpicked pseudo-adapter has no directory of its own:\n"
        + doctored)


@pytest.mark.parametrize("shape", ["out-is-a-file", "archive-is-a-directory",
                                   "archive-under-a-file"])
def test_capture_refuses_a_path_shaped_argument_with_a_sentence(
        shape, tmp_path, monkeypatch, capsys):
    """Naming a file where a directory belongs is the most ordinary
    user-facing error there is, and house style answers one with SystemExit.
    Both of `capture`'s path arguments answered with a raw OS exception -
    NotADirectoryError, IsADirectoryError, FileExistsError - out of the
    function whose docstring this round cites twice as its model."""
    home = build_claude_home(tmp_path)
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))
    standing = tmp_path / "a-file"
    standing.write_text("not a directory\n")
    directory = tmp_path / "a-directory"
    directory.mkdir()
    args = {
        "out-is-a-file": ["--out", str(standing), "--apply"],
        "archive-is-a-directory": ["--out", str(tmp_path / "out"), "--apply",
                                   "--archive", str(directory)],
        "archive-under-a-file": ["--out", str(tmp_path / "out"), "--apply",
                                 "--archive", str(standing / "x.tar.gz")],
    }[shape]

    with pytest.raises(SystemExit) as exc:
        cli.main(["capture"] + args)
    capsys.readouterr()

    assert not isinstance(exc.value, OSError)
    assert str(exc.value), "SystemExit with no sentence in it"


# --- the probe must not conjure a bucket (ADR-0011) --------------------------
#
# rclone's UPLOAD path creates a missing bucket - s3's prepareUpload and gcs's
# Update both reach makeBucket - so before this rule the reachability probe
# was the first write to a Destination and could create a billable resource
# with nobody asked. The Remotes the Provider flow writes pin
# no_check_bucket; a Remote the user already had, or one named in --dest, does
# not and never will. So the question is asked of the store instead, of the
# ONE component whose creation is not carryon's to make: the first one after
# the colon, which on an object store is the bucket.


def test_a_probe_refuses_to_write_into_a_bucket_that_is_not_there(
        tmp_path, monkeypatch, capsys):
    install_fake_rclone(tmp_path, monkeypatch, container=None)
    home = build_claude_home(tmp_path)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=SPEC, machine="box-a"), home)

    message = str(exc.value)
    assert "archive" in message, "the refusal does not name the container"
    assert "rclone mkdir" in message, "nothing says how to make one"
    assert keyring.fetch_master(home=home) is None
    assert not (tmp_path / "rclone-store" / "archive").exists(), \
        "the probe created the bucket it was refusing to write into"


def test_a_detected_remote_with_no_path_is_refused_by_name(tmp_path,
                                                           monkeypatch):
    """`detect_candidates` spells a configured remote 'rclone:mine:' - the
    trailing colon is rclone's, and the path half is EMPTY. The probe's key
    then starts with carryon's own prefix, so on S3 the bucket it would have
    created is one literally named 'carryon', in the user's account, for
    pressing 1 at a menu."""
    install_fake_rclone(tmp_path, monkeypatch, container=None)
    home = build_claude_home(tmp_path)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest="rclone:fakeremote:", machine="box-a"), home)

    assert "'carryon'" in str(exc.value), \
        "the refusal does not name the bucket that would have been created"
    assert not (tmp_path / "rclone-store" / "carryon").exists()


def test_an_existing_bucket_is_probed_and_the_init_completes(tmp_path,
                                                             monkeypatch):
    """The control: the rule refuses a container that is absent, not every
    rclone Destination."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)

    assert sync.init(ns(dest=SPEC, machine="box-a"), home) == 0

    assert keyring.fetch_master(home=home) is not None
    assert fake.objects() == [], "the probe was left in the Archive"


def test_a_remote_that_will_not_say_is_not_written_to(tmp_path, monkeypatch):
    """Told from an absent container, and refused the same way: carryon
    cannot tell a remote that is refusing from an Archive that is empty, and
    guessing here is guessing about somebody's bill."""
    fake = install_fake_rclone(tmp_path, monkeypatch)
    home = build_claude_home(tmp_path)
    fake.fail("lsf", code=1)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=SPEC, machine="box-a"), home)

    assert "refused" in str(exc.value) or "would not" in str(exc.value)
    assert keyring.fetch_master(home=home) is None
