"""History behaviour: Session discovery, packing and restore, on a fake $HOME.

The fixture Session is shaped like a real one - main Transcript at the top of
the project dir plus a <uuid>/ subtree of subagent and workflow Transcripts -
because a Session being a tree, not a file, is the fact that broke the first
design (CONTEXT.md, Session). All paths and content here are synthetic; no
real transcript material appears.
"""

import io
import json
import pathlib
import sys
import tarfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, history, rekey  # noqa: E402
from carryon.adapters import ADAPTERS  # noqa: E402
from carryon.adapters.base import HISTORY, Adapter, Item  # noqa: E402

UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
UUID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
UUID_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

# '_' in the cwd exercises the lossy encoding: '/' and '_' both become '-',
# so the local project dir name can only be re-derived from the cwd.
PROJ_REL = "code/snake_case_proj"

FAKE_BINARY = b"\x89PNG\r\n\x1a\n" + bytes(range(256))


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def build_home(tmp_path, name="home") -> pathlib.Path:
    """A fake ~ holding one realistic Claude Code project and one codex rollout."""
    home = tmp_path / name
    cwd = str(home / PROJ_REL)

    project = home / ".claude" / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)

    # main Transcript
    (project / (UUID_A + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "message": {"content": [
            {"text": f"edit {cwd}/main.py please"}]}}))
    # the subtree the same Session spawned
    sub = project / UUID_A / "subagents"
    (sub / "workflows" / "wf_1").mkdir(parents=True)
    (sub / "agent-x.jsonl").write_text(
        jline({"type": "agent", "note": f"ran in {cwd}/src"}))
    (sub / "workflows" / "wf_1" / "journal.jsonl").write_text(
        jline({"step": 1, "file_path": cwd + "/out.txt"}))
    # a non-UTF-8 artefact inside the Session tree
    results = project / UUID_A / "tool-results"
    results.mkdir()
    (results / "blob.bin").write_bytes(FAKE_BINARY)

    # a second Session whose Transcript records no cwd
    (project / (UUID_B + ".jsonl")).write_text(jline({"type": "meta"}))

    # per-project residue: memory, not part of any Session
    memory = project / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text(f"Notes live in {cwd}/notes.\n")

    # one flat codex rollout; cwd sits in the meta line's payload
    day = home / ".codex" / "sessions" / "2026" / "07" / "29"
    day.mkdir(parents=True)
    (day / f"rollout-2026-07-29T10-00-00-{UUID_C}.jsonl").write_text(
        jline({"timestamp": "2026-07-29T10:00:00Z", "type": "session_meta",
               "payload": {"id": UUID_C, "cwd": cwd}})
        + jline({"timestamp": "2026-07-29T10:00:01Z", "type": "event",
                 "payload": {"text": f"working under {cwd}"}}))
    return home


def adapters():
    return [ADAPTERS["claude-code"], ADAPTERS["codex"]]


def project_dir_rel(home) -> str:
    cwd = str(home / PROJ_REL)
    return ".claude/projects/" + rekey.encode_project_dir(cwd)


def session_by_uuid(found, uuid):
    return [s for s in found.sessions if s.uuid == uuid][0]


def tar_members(tar_bytes) -> dict:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for member in tf.getmembers():
            out[member.name] = tf.extractfile(member).read()
    return out


# --- discovery ---------------------------------------------------------------


def test_discovery_finds_the_whole_session_subtree(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())

    session = session_by_uuid(found, UUID_A)
    assert session.agent == "claude-code"
    assert session.project_dir == project_dir_rel(home)
    assert session.cwd == str(home / PROJ_REL)
    assert session.main_path == UUID_A + ".jsonl"
    assert session.files == (
        UUID_A + ".jsonl",
        UUID_A + "/subagents/agent-x.jsonl",
        UUID_A + "/subagents/workflows/wf_1/journal.jsonl",
        UUID_A + "/tool-results/blob.bin",
    ), "a Session is a tree: every Transcript beneath the uuid belongs to it"


def test_discovery_finds_the_per_project_residue(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())

    residues = [r for r in found.residues if r.agent == "claude-code"]
    assert len(residues) == 1
    residue = residues[0]
    assert residue.project_dir == project_dir_rel(home)
    assert residue.files == ("memory/MEMORY.md",)
    assert residue.cwd == str(home / PROJ_REL), \
        "residue belongs to the project, so it takes the project's cwd"


def test_a_session_with_no_recoverable_cwd_is_reported_not_guessed(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())

    session = session_by_uuid(found, UUID_B)
    assert session.cwd is None, \
        "a sibling's cwd must not be inherited - the dir name cannot confirm it"
    assert (project_dir_rel(home) + "/" + UUID_B + ".jsonl") in found.missing_cwd


def test_discovery_reads_codex_rollouts_as_flat_sessions(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())

    session = session_by_uuid(found, UUID_C)
    assert session.agent == "codex"
    assert session.project_dir == ".codex/sessions"
    assert session.cwd == str(home / PROJ_REL), \
        "codex records cwd inside the meta line's payload"
    rel = f"2026/07/29/rollout-2026-07-29T10-00-00-{UUID_C}.jsonl"
    assert session.files == (rel,)
    assert session.main_path == rel


def test_an_unknown_layout_refuses_with_the_layout_named(tmp_path):
    home = build_home(tmp_path)
    stranger = Adapter(
        key="stranger", name="Stranger", detect=".stranger",
        verified_against="never",
        items=(Item(".stranger/chats", "history/stranger", "chats", HISTORY,
                    "sessions", layout="mystery-layout"),))
    with pytest.raises(SystemExit) as exc:
        history.discover(home, [stranger])
    assert "mystery-layout" in str(exc.value)


def test_discovery_is_empty_when_the_agent_has_no_sessions(tmp_path):
    home = tmp_path / "bare"
    home.mkdir()
    found = history.discover(home, adapters())
    assert found.sessions == ()
    assert found.residues == ()
    assert found.missing_cwd == ()


# --- packing -----------------------------------------------------------------


def test_packing_canonicalises_every_member_including_nested_ones(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    tar_bytes, report = history.pack_session(session_by_uuid(found, UUID_A), home)

    members = tar_members(tar_bytes)
    home_bytes = str(home).encode("utf-8")
    for name, data in members.items():
        assert home_bytes not in data, f"{name} still names the pushing home"
    main = members[UUID_A + ".jsonl"].decode("utf-8")
    assert json.loads(main.splitlines()[0])["cwd"] == "~/" + PROJ_REL
    nested = members[UUID_A + "/subagents/workflows/wf_1/journal.jsonl"]
    assert json.loads(nested.decode("utf-8"))["file_path"] == \
        "~/" + PROJ_REL + "/out.txt"
    assert report.rewritten_values >= 4


def test_tar_paths_are_relative_to_the_project_dir_and_sorted(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    tar_bytes, _ = history.pack_session(session_by_uuid(found, UUID_A), home)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        names = [m.name for m in tf.getmembers()]
    assert names == sorted(names)
    assert names[0] == UUID_A + ".jsonl", "paths start at the project dir"
    assert not any(name.startswith((".claude", "/")) for name in names)


def test_non_utf8_members_are_carried_unchanged_and_counted(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    tar_bytes, report = history.pack_session(session_by_uuid(found, UUID_A), home)

    members = tar_members(tar_bytes)
    assert members[UUID_A + "/tool-results/blob.bin"] == FAKE_BINARY
    assert report.non_utf8 == 1


def test_residue_packs_via_the_text_walker(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    residue = [r for r in found.residues if r.agent == "claude-code"][0]
    tar_bytes, report = history.pack_session(residue, home)

    members = tar_members(tar_bytes)
    text = members["memory/MEMORY.md"].decode("utf-8")
    assert text == "Notes live in ~/" + PROJ_REL + "/notes.\n"
    assert report.text_replaced == 1


def test_a_planted_credential_is_reported_never_refused_never_redacted(tmp_path):
    home = build_home(tmp_path)
    planted = "ghp_FAKEFAKEFAKEFAKEFAKE1234"  # matches the github-token rule
    agent_x = (home / project_dir_rel(home) / UUID_A / "subagents"
               / "agent-x.jsonl")
    agent_x.write_text(agent_x.read_text()
                       + jline({"text": "echoed " + planted + " once"}))

    found = history.discover(home, adapters())
    tar_bytes, report = history.pack_session(session_by_uuid(found, UUID_A), home)

    assert report.credential_members == (UUID_A + "/subagents/agent-x.jsonl",)
    assert report.has_credentials
    members = tar_members(tar_bytes)
    assert planted.encode() in members[UUID_A + "/subagents/agent-x.jsonl"], \
        "a History is reported and encrypted, never redacted (ADR-0001)"


def test_a_clean_session_reports_no_credentials(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    _, report = history.pack_session(session_by_uuid(found, UUID_A), home)
    assert report.credential_members == ()
    assert not report.has_credentials


# --- unpack ------------------------------------------------------------------


def test_unpack_lands_in_the_locally_reencoded_project_dir(tmp_path):
    home_a = build_home(tmp_path, "home_a")
    found = history.discover(home_a, adapters())
    session = session_by_uuid(found, UUID_A)
    tar_bytes, _ = history.pack_session(session, home_a)

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    meta = {"agent": "claude-code", "cwd": "~/" + PROJ_REL}
    root, report = history.unpack_session(tar_bytes, meta, home_b)

    local_cwd = str(home_b / PROJ_REL)
    expected = home_b / ".claude" / "projects" / rekey.encode_project_dir(local_cwd)
    assert root == expected, "the dir name is re-derived from the cwd, never decoded"

    main = (expected / (UUID_A + ".jsonl")).read_text()
    assert json.loads(main.splitlines()[0])["cwd"] == local_cwd
    nested = expected / UUID_A / "subagents" / "workflows" / "wf_1" / "journal.jsonl"
    assert json.loads(nested.read_text())["file_path"] == local_cwd + "/out.txt"
    assert str(home_a) not in main
    assert (expected / UUID_A / "tool-results" / "blob.bin").read_bytes() \
        == FAKE_BINARY
    assert report.non_utf8 == 1


def test_unpack_restores_a_codex_rollout_under_its_date_tree(tmp_path):
    home_a = build_home(tmp_path, "home_a")
    found = history.discover(home_a, adapters())
    session = session_by_uuid(found, UUID_C)
    tar_bytes, _ = history.pack_session(session, home_a)

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    meta = {"agent": "codex", "cwd": "~/" + PROJ_REL}
    root, _ = history.unpack_session(tar_bytes, meta, home_b)

    assert root == home_b / ".codex" / "sessions"
    restored = (root / "2026" / "07" / "29"
                / f"rollout-2026-07-29T10-00-00-{UUID_C}.jsonl")
    assert restored.is_file()
    meta_line = json.loads(restored.read_text().splitlines()[0])
    assert meta_line["payload"]["cwd"] == str(home_b / PROJ_REL)


def test_unpack_applies_maps_to_a_cwd_outside_home(tmp_path):
    home_a = build_home(tmp_path, "home_a")
    found = history.discover(home_a, adapters())
    tar_bytes, _ = history.pack_session(session_by_uuid(found, UUID_A), home_a)

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    meta = {"agent": "claude-code", "cwd": "/data/proj"}  # verbatim, outside ~
    root, _ = history.unpack_session(tar_bytes, meta, home_b,
                                     maps=[("/data", "/srv")])
    assert root == (home_b / ".claude" / "projects"
                    / rekey.encode_project_dir("/srv/proj"))


def test_unpack_refuses_a_traversal_member_name(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("../escape.jsonl")
        data = b"{}"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(SystemExit):
        history.unpack_session(buf.getvalue(),
                               {"agent": "claude-code", "cwd": "~/p"}, home)


# --- compare_main: the ADR-0002 union primitive ------------------------------


def test_compare_main_truth_table():
    a = b'{"n":1}\n'
    ab = a + b'{"n":2}\n'
    divergent = b'{"n":9}\n'
    assert history.compare_main(a, a) == "same"
    assert history.compare_main(a, ab) == "local-prefix", "incoming is ahead"
    assert history.compare_main(ab, a) == "incoming-prefix", "local is ahead"
    assert history.compare_main(ab, divergent) == "divergent"
    assert history.compare_main(b"", a) == "local-prefix"
    assert history.compare_main(b"", b"") == "same"


# --- tree_hash ---------------------------------------------------------------


def test_tree_hash_matches_the_archive_definition(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    session = session_by_uuid(found, UUID_A)

    # A clean root holding exactly the Session's files must hash identically
    # under archive.tree_hash - same pairs, same encoding.
    clean = tmp_path / "clean"
    src = home / session.project_dir
    for rel in session.files:
        target = clean / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((src / rel).read_bytes())
    assert history.tree_hash(session, home) == archive.tree_hash(clean)


def test_tree_hash_changes_when_any_member_changes(tmp_path):
    home = build_home(tmp_path)
    found = history.discover(home, adapters())
    session = session_by_uuid(found, UUID_A)
    before = history.tree_hash(session, home)

    nested = (home / session.project_dir / UUID_A / "subagents" / "workflows"
              / "wf_1" / "journal.jsonl")
    nested.write_text(nested.read_text() + jline({"step": 2}))
    assert history.tree_hash(session, home) != before
