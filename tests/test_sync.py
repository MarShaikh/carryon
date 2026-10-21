"""Integration: init, push, pull, pair against fake homes and a directory
Destination, at the function level.

Every home here is synthetic (the house pattern from test_capture.build_home);
nothing reads the real ~/.claude or ~/.codex, and the OS keychain is forced to
the fallback file so nothing touches the real keyring either. All transcript
content is invented for these tests.
"""

import argparse
import inspect
import json
import os
import pathlib
import re
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, cli, config, keyring, rekey, restore, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
# The one helper this suite borrows: since ADR-0014 there is no stored Setup to
# read off a Destination, and a second spelling of "unseal it and look" is a
# second thing to keep in step.
from tests.hostile_archive import reread_setup  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"   # tree; B holds a byte-prefix
UUID_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"   # codex rollout; B diverges
UUID_D = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"   # local to B only
UUID_E = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"   # B is ahead of the Archive
UUID_F = "ffffffff-ffff-4fff-8fff-ffffffffffff"   # Archive only: new to B

PROJ_REL = "code/snake_case_proj"
ROLLOUT = f"rollout-2026-07-29T10-00-00-{UUID_C}.jsonl"
FAKE_BINARY = b"\x89PNG\r\n\x1a\n" + bytes(range(256))
RECOVERY_KEY = r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}"
PAIR_CODE = r"--join (\S+)"


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


def main_a(cwd) -> str:
    return (jline({"cwd": cwd, "type": "meta"})
            + jline({"type": "user", "text": f"edit {cwd}/main.py"}))


def e_line(cwd) -> str:
    return jline({"cwd": cwd, "type": "meta", "tag": "e"})


def c_meta(cwd) -> str:
    return jline({"timestamp": "t0", "type": "session_meta",
                  "payload": {"id": UUID_C, "cwd": cwd}})


def c_event(text) -> str:
    return jline({"timestamp": "t1", "type": "event",
                  "payload": {"text": text}})


def build_home_a(tmp_path) -> pathlib.Path:
    """The pushing machine: a Setup plus four Sessions and one residue."""
    home = tmp_path / "home_a"
    cwd = str(home / PROJ_REL)

    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Global instructions.\n")

    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    (project / (UUID_A + ".jsonl")).write_text(main_a(cwd))
    sub = project / UUID_A / "subagents"
    sub.mkdir(parents=True)
    (sub / "journal.jsonl").write_text(
        jline({"step": 1, "file_path": cwd + "/out.txt"}))
    (project / UUID_A / "blob.bin").write_bytes(FAKE_BINARY)
    (project / (UUID_E + ".jsonl")).write_text(e_line(cwd))
    (project / (UUID_F + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta", "tag": "f"}))
    memory = project / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text(f"Notes live in {cwd}/notes.\n")

    codex = home / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text('model = "gpt-5"\n')
    day = codex / "sessions" / "2026" / "07" / "29"
    day.mkdir(parents=True)
    (day / ROLLOUT).write_text(c_meta(cwd) + c_event(f"working under {cwd}"))
    return home


def build_home_b(tmp_path, dotfiles=False) -> pathlib.Path:
    """The pulling machine: one prefix copy, one ahead copy, one divergent
    copy, one Session of its own - every branch of the union rule."""
    home = tmp_path / "home_b"
    cwd = str(home / PROJ_REL)

    project = home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)
    # byte-prefix of the Archive's copy (first line only): incoming is ahead
    (project / (UUID_A + ".jsonl")).write_text(jline({"cwd": cwd, "type": "meta"}))
    # ahead of the Archive's copy: an extra appended line
    (project / (UUID_E + ".jsonl")).write_text(
        e_line(cwd) + jline({"type": "note", "n": 2}))
    # local only - pull must never delete it
    (project / (UUID_D + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta", "tag": "d"}))

    day = home / ".codex" / "sessions" / "2026" / "07" / "29"
    day.mkdir(parents=True)
    (day / ROLLOUT).write_text(c_meta(cwd) + c_event("different work entirely"))

    if dotfiles:
        (home / ".claude" / "settings.json").write_text('{"model": "old"}')
        dot = home / "dotfiles"
        dot.mkdir()
        (dot / "CLAUDE.md").write_text("dotfiles owns this\n")
        (home / ".claude" / "CLAUDE.md").symlink_to(dot / "CLAUDE.md")
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    """Give a second fake home the same master key and Destination, without
    the pairing theatre (that flow has its own test)."""
    master = keyring.fetch_master(home=master_from)
    keyring.store_master(master, home=home)
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


@pytest.fixture
def pushed(tmp_path):
    """home_a initialised and fully pushed to a directory Destination."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True), home_a) == 0
    return home_a, dest_spec


# --- init and pair -----------------------------------------------------------


def test_init_writes_config_and_shows_the_recovery_key_once(tmp_path, capsys):
    home = tmp_path / "home"
    home.mkdir()
    dest_spec = str(tmp_path / "archive")

    assert sync.init(ns(dest=dest_spec, machine="laptop"), home) == 0

    cfg = config.load(home)
    assert cfg["destination"] == dest_spec
    assert cfg["machine"] == "laptop"
    assert keyring.fetch_master(home=home) is not None
    assert (home / ".carryon" / "master.key").is_file()

    out = capsys.readouterr().out
    keys = re.findall(RECOVERY_KEY, out)
    assert len(keys) == 1, "the recovery key is shown exactly once"
    assert "password manager" in out


def test_init_without_dest_and_no_candidates_asks_for_dest(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(), home)
    assert "--dest" in str(exc.value)


def test_join_requires_dest(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    # Well-formed, because the code is parsed before the Destination is
    # settled now (ADR-0011: the dialogue must not run for a typo), and
    # what this pins is the --dest refusal rather than the code check.
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join="AAAAAA-AAAAAAAAAA"), home)
    assert "--dest" in str(exc.value)


def test_pair_then_join_hands_over_the_master_key(tmp_path, capsys):
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    capsys.readouterr()

    assert sync.pair(ns(), home_a) == 0
    out = capsys.readouterr().out
    code = re.search(PAIR_CODE, out).group(1)
    assert "24" in out, "the code's 24h expiry is stated"

    dest = DirectoryDestination(tmp_path / "archive")
    assert len(dest.list("carryon/pair/")) == 1

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    assert sync.init(ns(dest=dest_spec, join=code, machine="machine-b"),
                     home_b) == 0
    out = capsys.readouterr().out
    assert not re.search(RECOVERY_KEY, out), "join mints no new recovery key"

    assert keyring.fetch_master(home=home_b) == keyring.fetch_master(home=home_a)
    assert dest.list("carryon/pair/") == [], "a pairing blob is one-time"


def test_join_rejects_an_expired_pairing_code(tmp_path, capsys, monkeypatch):
    """Codes live 24 hours, checked against created_at inside the wrapped
    payload - not just stated in pair's output text."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    sync.pair(ns(), home_a)
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    real_now = time.time()
    monkeypatch.setattr(sync.time, "time",
                        lambda: real_now + sync.PAIRING_TTL_SECONDS + 60)
    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)
    assert "expired" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None, \
        "an expired code hands over nothing"


def test_a_join_whose_blob_the_filesystem_keeps_says_the_code_is_still_live(
        tmp_path, capsys):
    """ADR-0005's one-time property through the directory type, with the
    refusal spelled the way a real machine spells it - an ACL that grants
    create and denies delete. The join must succeed (the key arrived) and
    must say the code still works, because a warning is the only thing
    standing between that state and a code that quietly works twice."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    sync.pair(ns(), home_a)
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)
    pair_dir = tmp_path / "archive" / "carryon" / "pair"
    pair_dir.chmod(0o500)

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    try:
        assert sync.init(ns(dest=dest_spec, join=code, machine="machine-b"),
                         home_b) == 0
        out = capsys.readouterr().out
    finally:
        pair_dir.chmod(0o700)

    assert keyring.fetch_master(home=home_b) == \
        keyring.fetch_master(home=home_a), "the join itself must still land"
    assert "STILL LIVE" in out, \
        f"the blob outlived its delete and the run said nothing:\n{out}"


# --- push --------------------------------------------------------------------


def test_push_twice_uploads_zero_session_objects_the_second_time(
        tmp_path, pushed, capsys):
    _, dest_spec = pushed
    dest = DirectoryDestination(tmp_path / "archive")

    session_keys = dest.list("carryon/sessions/")
    project_keys = dest.list("carryon/projects/")
    assert len(session_keys) == 4, "four Sessions on the pushing machine"
    assert len(project_keys) == 1, "one project residue"
    assert dest.list("carryon/setups/") == ["carryon/setups/machine-a.tar.enc"]
    assert dest.read("carryon/index.enc") is not None

    before = {k: dest.read(k) for k in session_keys + project_keys}
    capsys.readouterr()
    assert sync.push(ns(apply=True), pushed[0]) == 0
    out = capsys.readouterr().out

    assert dest.list("carryon/sessions/") == session_keys
    assert dest.list("carryon/projects/") == project_keys
    after = {k: dest.read(k) for k in session_keys + project_keys}
    # encryption is salted, so byte-identical objects prove nothing was
    # re-uploaded - this is ADR-0003's incrementality
    assert after == before
    assert "History: 0 Sessions pushed (4 unchanged)" in out


def test_pull_then_push_from_the_other_machine_uploads_nothing(
        tmp_path, pushed, capsys):
    """ADR-0003's incrementality is cross-machine or it is nothing: after a
    pull, a no-change push from the second machine - and then from the first -
    re-uploads zero Session objects, even though each machine's local bytes
    embed its own home."""
    home_a, dest_spec = pushed
    dest = DirectoryDestination(tmp_path / "archive")
    home_b = tmp_path / "home_b_mirror"
    home_b.mkdir()
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0

    session_keys = dest.list("carryon/sessions/")
    project_keys = dest.list("carryon/projects/")
    before = {k: dest.read(k) for k in session_keys + project_keys}

    capsys.readouterr()
    assert sync.push(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out
    assert dest.list("carryon/sessions/") == session_keys
    # encryption is salted, so byte-identical objects prove nothing was
    # re-uploaded
    assert {k: dest.read(k) for k in session_keys + project_keys} == before
    assert ("History: 0 Sessions pushed (4 unchanged), "
            "0 project memories pushed (1 unchanged)") in out

    # and the first machine still agrees: its next push is a no-op too
    capsys.readouterr()
    assert sync.push(ns(apply=True), home_a) == 0
    out = capsys.readouterr().out
    assert ("History: 0 Sessions pushed (4 unchanged), "
            "0 project memories pushed (1 unchanged)") in out
    assert {k: dest.read(k) for k in session_keys + project_keys} == before

    # pull is incremental across machines for the same reason: a second pull
    # on B recognises the residue it already holds and skips the download
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out
    assert "  residue  " not in out
    assert "4 unchanged" in out


def test_partial_category_push_keeps_the_stored_manifest_whole(
        tmp_path, pushed, capsys):
    """A --category config push must not clobber the stored MANIFEST: pull
    restores a Setup solely from what the MANIFEST names, so knowledge and
    capability entries have to survive a partial push."""
    home_a, dest_spec = pushed
    dest_root = tmp_path / "archive"

    def stored_srcs():
        """The srcs the Archive's stored MANIFEST names, read fresh.

        Through the seal since ADR-0014, and re-read rather than cached: what
        this test is about is that a second push did not drop entries from the
        stored document, so reading a copy taken before that push would be
        reading the answer it is trying to check.
        """
        stored = reread_setup(dest_root, "machine-a")
        doc = json.loads((stored / "MANIFEST.json").read_text())
        return ({i["src"] for a in doc["agents"].values() for i in a["items"]},
                stored)

    srcs, _ = stored_srcs()
    assert ".claude/CLAUDE.md" in srcs, "sanity: the full push mapped it"

    (home_a / ".claude" / "settings.json").write_text('{"model": "sonnet"}')
    capsys.readouterr()
    assert sync.push(ns(apply=True, category="config"), home_a) == 0

    srcs, stored = stored_srcs()
    assert ".claude/CLAUDE.md" in srcs, \
        "the knowledge item survives a config-only push"
    assert ".claude/settings.json" in srcs
    assert (stored / "claude" / "CLAUDE.md").is_file(), \
        "the MANIFEST still names the file and the object no longer holds it"

    home_b = tmp_path / "home_b_partial"
    home_b.mkdir()
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert (home_b / ".claude" / "CLAUDE.md").read_text() == \
        "Global instructions.\n"
    assert (home_b / ".claude" / "settings.json").read_text() == \
        '{"model": "sonnet"}'


def test_rekey_stats_are_reported_on_push_and_pull(tmp_path, capsys):
    """The shared constants say near-misses, non-UTF-8 members and bare '~'
    tokens are counted AND reported - the counts must reach the reports."""
    home_a = build_home_a(tmp_path)
    cwd = str(home_a / PROJ_REL)
    project = home_a / ".claude" / "projects" / rekey.encode_project_dir(cwd)
    # a case-variant of the home path: a near-miss, never rewritten
    (project / (UUID_A + ".jsonl")).write_text(
        main_a(cwd) + jline({"type": "note", "text": f"see {cwd.upper()}"}))
    # a home occurrence with nothing after it: becomes a bare '~' at push
    (project / "memory" / "MEMORY.md").write_text(
        f"Notes live in {cwd}/notes.\nHome is {home_a}.\n")
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home_a) == 0
    assert "Re-keying" not in capsys.readouterr().out, "--verbose detail"
    (project / (UUID_A + ".jsonl")).write_text(
        main_a(cwd) + jline({"type": "note", "text": f"see {cwd.upper()}"})
        + jline({"type": "note", "text": "again"}))
    (project / "memory" / "MEMORY.md").write_text(
        f"Notes live in {cwd}/notes.\nHome is {home_a}.\nMore.\n")
    assert sync.push(ns(apply=True, verbose=True), home_a) == 0
    out = capsys.readouterr().out
    assert ("Re-keying: 1 path matched this home folder only when ignoring "
            "case, left as written") in out
    assert "Re-keying: 1 file not UTF-8, carried unchanged" in out, \
        "blob.bin is carried unchanged and reported"
    assert "Re-keying: 1 bare '~' with nothing after it, left as written" \
        in out

    home_b = tmp_path / "home_b_stats"
    home_b.mkdir()
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out
    assert "not UTF-8" in out
    assert "bare '~'" in out


def test_a_keyless_setup_push_refuses_and_names_both_cures(tmp_path, capsys):
    """The one capability ADR-0014 takes away, asserted where it used to be
    asserted as a feature.

    This was `..._setup_only_push_needs_no_master_key_and_pull_still_finds_it`
    on ADR-0004's reasoning that only a History is encrypted. Sealing the
    Setup removes the premise: there is nothing a keyless push could write,
    so the warning it used to print becomes a refusal.

    Both cures are pinned because a refusal that names neither is how this
    decision turns into a user with no way forward - the objection ADR-0001
    raised against fail-closed and ADR-0014 answers here. `init`/`pair` gets
    the machine a key; `capture --out` gets the readable Setup that was the
    honest reason to want a keyless push, on the machine that already holds
    the secrets rather than in somebody else's storage.

    And nothing lands: a refusal that had already written the Setup half would
    leave an Archive in a state no key holder authored, which is precisely
    what sealing is for.
    """
    home = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home)
    (home / ".carryon" / "master.key").unlink()
    assert keyring.fetch_master(home=home) is None
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True, category="config"), home)

    refusal = str(exc.value)
    assert "carryon init" in refusal, "the refusal does not name the key cure"
    assert "capture --out" in refusal, \
        "the refusal does not name the readable-Setup cure"
    dest = DirectoryDestination(tmp_path / "archive")
    assert dest.list("carryon/setups/") == [], \
        "a keyless push wrote a Setup it has no key to seal"

    # A History push refused for the same reason before ADR-0014 and still
    # does; the two halves now give one answer instead of two.
    with pytest.raises(SystemExit) as exc:
        sync.push(ns(apply=True), home)
    assert "master key" in str(exc.value)


def test_push_dry_run_writes_nothing(tmp_path, capsys):
    home = build_home_a(tmp_path)
    dest_root = tmp_path / "archive"
    sync.init(ns(dest=str(dest_root), machine="machine-a"), home)
    home_before = tree_state(home)

    assert sync.push(ns(apply=False), home) == 0

    # tree_state, not exists(): init's reachability probe (ADR-0011) leaves
    # the Archive's own empty directory behind, and what a dry run must not
    # do is put CONTENT anywhere.
    assert tree_state(dest_root) == {}, "a dry-run push writes nothing anywhere"
    assert tree_state(home) == home_before


def test_push_reports_history_credentials_and_still_pushes(tmp_path, capsys):
    home = build_home_a(tmp_path)
    journal = (home / ".claude" / "projects"
               / rekey.encode_project_dir(str(home / PROJ_REL))
               / UUID_A / "subagents" / "journal.jsonl")
    journal.write_text(journal.read_text()
                       + jline({"text": "echoed ghp_FAKEFAKEFAKEFAKEFAKE1234"}))
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    capsys.readouterr()

    assert sync.push(ns(apply=True), home) == 0
    out = capsys.readouterr().out

    assert ("  possible secrets in 1 History file, carried encrypted "
            "(--verbose names them)") in out
    assert UUID_A not in out, "the History secret list is --verbose detail"
    dest = DirectoryDestination(tmp_path / "archive")
    assert len(dest.list("carryon/sessions/")) == 4, \
        "a History credential is reported and carried, never a refusal"


def test_push_reports_a_setup_credential_and_publishes_it_sealed(
        tmp_path, capsys):
    """ADR-0014's central claim, measured on the push rather than argued.

    This asserted exit 2, "REFUSED", and an empty setups/ - the posture the
    ADR retired. What it is replaced by is the comparison the ADR actually
    makes: refusing produced nothing at all, so the credential's best case was
    that it never travelled because nothing did, and sealing is strictly
    better than that. Better means the bytes cross and are unreadable where
    they land, which is the pair of facts below.

    The planted key is checked for absence in the stored object and presence
    inside the seal. Absence alone would pass against a push that dropped the
    file, and that is not the promise - a Setup carries settings.json because
    settings.json is what makes an agent yours (ADR-0014: no Adapter change
    can stop carrying it).
    """
    planted = '{"apiKey": "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED"}'
    home = build_home_a(tmp_path)
    (home / ".claude" / "settings.json").write_text(planted)
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    master = keyring.fetch_master(home=home)
    capsys.readouterr()

    code = sync.push(ns(apply=True), home)
    out = capsys.readouterr().out

    assert code == 0, "reported, not refused (ADR-0014)"
    assert ("  possible secrets in 1 file, carried encrypted:\n"
            "    .claude/settings.json (anthropic-key") in out, \
        "the credential, and what it matched, were not named"

    dest = DirectoryDestination(tmp_path / "archive")
    assert dest.list("carryon/setups/") == \
        ["carryon/setups/machine-a.tar.enc"], "the Setup was not published"
    assert planted.encode() not in dest.read("carryon/setups/machine-a.tar.enc"), \
        "the credential is readable at the Destination - the case for sealing"

    opened = tmp_path / "opened"
    archive.get_setup(dest, master, "machine-a", opened)
    assert (opened / "claude" / "settings.json").read_text() == planted, \
        "the reported file was dropped rather than carried"

    assert len(dest.list("carryon/sessions/")) == 4, \
        "the encrypted History moved too"


# --- pull: the union (ADR-0002) ----------------------------------------------


def test_pull_unions_restores_new_and_never_deletes_local(
        tmp_path, pushed, capsys):
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    cwd_b = str(home_b / PROJ_REL)
    project = home_b / ".claude" / "projects" / rekey.encode_project_dir(cwd_b)
    d_before = (project / (UUID_D + ".jsonl")).read_bytes()
    e_before = (project / (UUID_E + ".jsonl")).read_bytes()
    c_local = home_b / ".codex" / "sessions" / "2026" / "07" / "29" / ROLLOUT
    c_before = c_local.read_bytes()
    capsys.readouterr()

    # 2, not 0: C lands divergent below, and a landed divergence is
    # ADR-0012's exit code (`2 if apply else 1`).
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    # new: F restored, expanded against home_b
    f_main = project / (UUID_F + ".jsonl")
    assert f_main.is_file()
    assert json.loads(f_main.read_text().splitlines()[0])["cwd"] == cwd_b

    # prefix: A's whole tree replaced, local was behind
    a_lines = (project / (UUID_A + ".jsonl")).read_text().splitlines()
    assert len(a_lines) == 2
    assert json.loads(a_lines[1])["text"] == f"edit {cwd_b}/main.py"
    journal = project / UUID_A / "subagents" / "journal.jsonl"
    assert json.loads(journal.read_text())["file_path"] == cwd_b + "/out.txt"
    assert (project / UUID_A / "blob.bin").read_bytes() == FAKE_BINARY

    # ahead: E untouched; local-only: D untouched
    assert (project / (UUID_E + ".jsonl")).read_bytes() == e_before
    assert (project / (UUID_D + ".jsonl")).read_bytes() == d_before

    # divergent: C kept locally, incoming under conflicts
    assert c_local.read_bytes() == c_before
    conflict = home_b / ".carryon" / "conflicts" / UUID_C / "2026/07/29" / ROLLOUT
    assert conflict.is_file()
    meta_line = json.loads(conflict.read_text().splitlines()[0])
    assert meta_line["payload"]["cwd"] == cwd_b

    # residue unioned in
    memory = project / "memory" / "MEMORY.md"
    assert memory.read_text() == f"Notes live in {cwd_b}/notes.\n"

    assert "1 new" in out
    assert "1 replaced" in out
    assert "1 divergent" in out
    assert UUID_C in out


def test_pull_backs_up_the_setup_and_skips_externally_owned(
        tmp_path, pushed, capsys):
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path, dotfiles=True)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    capsys.readouterr()

    # 2: home_b's codex rollout diverges, and a landed divergence is
    # ADR-0012's exit code.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    # replaced, with the old file backed up first
    assert (home_b / ".claude" / "settings.json").read_text() == '{"model": "opus"}'
    backups = list((home_b / ".carryon" / "backups").iterdir())
    assert len(backups) == 1
    assert (backups[0] / ".claude" / "settings.json").read_text() == \
        '{"model": "old"}'

    # externally owned: skipped, named with its owner (ADR-0007)
    assert (home_b / ".claude" / "CLAUDE.md").is_symlink()
    assert (home_b / "dotfiles" / "CLAUDE.md").read_text() == "dotfiles owns this\n"
    assert ".claude/CLAUDE.md" in out
    assert "externally owned" in out
    assert "dotfiles" in out, "the report names the owner"


def test_pull_force_writes_through_an_externally_owned_path(tmp_path, pushed):
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path, dotfiles=True)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)

    # 2: the codex rollout still lands divergent - ADR-0012's exit code.
    assert sync.pull(ns(apply=True, force=True), home_b) == 2

    assert (home_b / ".claude" / "CLAUDE.md").is_symlink(), \
        "--force writes through the link, it does not replace it"
    assert (home_b / "dotfiles" / "CLAUDE.md").read_text() == \
        "Global instructions.\n"


def test_pull_reports_rather_than_dies_when_chats_are_excluded(
        tmp_path, pushed, capsys):
    """An excluded chats item (ADR-0008) must take the report-and-continue
    path, not SystemExit mid-apply with the pull half laid down."""
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    cfg = config.load(home_b)
    cfg["excludes"] = [".claude/projects"]
    config.save(cfg, home_b)
    capsys.readouterr()

    # 2: the codex Session below still lands divergent - ADR-0012's exit
    # code - while the excluded chats item stays a report line, not a raise.
    assert sync.pull(ns(apply=True), home_b) == 2
    out = capsys.readouterr().out

    assert "carries no History" in out
    assert UUID_F in out, "the skipped Session is named, not silently dropped"
    project = (home_b / ".claude" / "projects"
               / rekey.encode_project_dir(str(home_b / PROJ_REL)))
    assert not (project / (UUID_F + ".jsonl")).exists()
    # the codex Session still went through the union: divergent, kept aside
    assert "1 divergent" in out
    assert (home_b / ".carryon" / "conflicts" / UUID_C).is_dir()


def test_pull_dry_run_writes_nothing(tmp_path, pushed, capsys):
    home_a, dest_spec = pushed
    home_b = build_home_b(tmp_path, dotfiles=True)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    dest = DirectoryDestination(tmp_path / "archive")
    home_before = tree_state(home_b)
    dest_before = {k: dest.read(k) for k in dest.list("")}
    capsys.readouterr()

    # 1: the plan below shows "1 divergent", and a PLANNED divergence is
    # ADR-0012's dry-run exit code (`2 if apply else 1`).
    assert sync.pull(ns(apply=False), home_b) == 1
    out = capsys.readouterr().out

    assert tree_state(home_b) == home_before
    assert {k: dest.read(k) for k in dest.list("")} == dest_before
    assert "1 new" in out
    assert "1 divergent" in out
    assert "externally owned" in out, "the dry run still shows the full plan"


# --- cli and restore notes ---------------------------------------------------


def test_cli_gains_the_new_verbs_and_drops_the_never_chats_claim():
    parser = cli.build_parser()
    assert "Setup" in parser.description
    assert "History" in parser.description
    assert "never chats" not in parser.description

    args = parser.parse_args(["push", "--apply"])
    assert args.func is cli.cmd_push and args.apply
    args = parser.parse_args(["pull", "--map", "/data=/srv", "--force"])
    assert args.func is cli.cmd_pull
    assert args.map == ["/data=/srv"] and args.force
    args = parser.parse_args(["init", "--dest", "/x", "--machine", "m"])
    assert args.func is cli.cmd_init and args.dest == "/x"
    args = parser.parse_args(["pair"])
    assert args.func is cli.cmd_pair
    # the existing verbs survive untouched
    assert parser.parse_args(["list"]).func is cli.cmd_list
    assert parser.parse_args(["capture", "--out", "/x"]).func is cli.cmd_capture

    # retired vocabulary is gone from the whole module (CONTEXT.md)
    src = inspect.getsource(cli)
    assert "bundle" not in src
    assert "entangle" not in src
    assert "No chats or sessions" not in src, \
        "the list footer no longer denies what push now carries"


def test_restore_notes_point_at_pull_not_entangle():
    manifest = {"version": "0.1.0", "captured_at": "2026-07-29T00:00:00+00:00",
                "agents": {}}
    text = restore.build_restore(manifest)
    assert "entangle" not in text
    assert "carryon pull" in text
    assert "bundle" not in text, "retired vocabulary (CONTEXT.md)"
    assert "Install the agents and log in" in text, \
        "the agents-first ordering reasoning survives"


# --- a machine's name is a directory, so it has to be one name ---------------
#
# `--machine` takes the string half at the CLI door and its MEANING was
# recorded as sync._machine_name_refusal - a function whose only caller runs
# on the PULL leg, over names that came back off a Destination. So nothing
# settled the argument on the way in.


@pytest.mark.parametrize("name", [".", "/", "a/b", "..", "  ", "setups/../.."])
def test_init_refuses_a_machine_name_that_is_not_one_directory_name(
        name, tmp_path):
    """A name that is not one plain component puts the Setup somewhere else.

    `--machine .` and `--machine /` pushed this machine's Setup into the
    SHARED carryon/setups/ root and `--machine a/b` nested it, all at exit 0
    with no warning. Every other machine's pull then restored nothing and
    printed refusals about phantom machines called 'MANIFEST.json' and
    'RESTORE.md' - for ever, on every machine, until somebody edited the
    Destination by hand.

    Refused before the key is minted, which is the other half: `init` stores
    the master key before it writes the config, so a refusal that arrived at
    `config.save` would leave a machine holding a key for an Archive it never
    named, and a second `init` saying it already holds one.
    """
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=str(tmp_path / "archive"), machine=name), home)
    assert "machine" in str(exc.value).lower()
    assert keyring.fetch_master(home=home) is None, \
        "a refused name must not cost a recovery key"
    assert not (home / ".carryon" / "config.json").exists()


def test_init_refuses_a_bad_machine_name_before_it_burns_a_pairing_code(
        tmp_path, capsys):
    """The same refusal on the join leg, and it has to come first there too.

    `_join` reads the pairing blob, unwraps it, DELETES it (one-time, ADR-0005)
    and stores the master key, all before config.save would have looked at the
    name. A refusal after that has spent the user's pairing code on a run that
    produced nothing.
    """
    home_a, home_b = tmp_path / "home_a", tmp_path / "home_b"
    home_a.mkdir()
    home_b.mkdir()
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    sync.pair(ns(), home_a)
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    with pytest.raises(SystemExit):
        sync.init(ns(dest=dest_spec, join=code, machine="a/b"), home_b)
    assert keyring.fetch_master(home=home_b) is None

    # the control: the code is still live, so the honest join still works
    assert sync.init(ns(dest=dest_spec, join=code, machine="machine-b"),
                     home_b) == 0


def test_a_hand_edited_config_with_a_path_for_a_machine_name_is_refused(
        tmp_path):
    """The config file is the other way that name arrives, and `validate` is
    the one gate both go through - `save` on the way out, `load` on the way
    in."""
    home = tmp_path / "home"
    home.mkdir()
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    path = home / ".carryon" / "config.json"
    cfg = json.loads(path.read_text())
    cfg["machine"] = "../elsewhere"
    path.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit) as exc:
        config.load(home)
    assert "machine" in str(exc.value)
