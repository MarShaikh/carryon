"""`carryon handover codex claude-code` (ADR-0018).

What is pinned here: a Codex rollout becomes a Claude Code Session holding
the conversation and nothing else, under the project folder the rollout
recorded; the rollout itself is never written; a second run makes no second
copy; and what carryon does not recognise is left out and named, with a
report link that carries record kinds and versions but never content.

Every home is synthetic and every rollout is invented, shaped like the ones
Codex CLI 0.128.0 writes.
"""

import argparse
import json
import os
import pathlib
import sys
import urllib.parse

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import cli, handover, rekey  # noqa: E402

CODEX_UUID = "019e071a-0017-7801-a6d4-76ade61e0a1d"
SECRET_WORDS = "the plum tree behind the shed"


def rec(kind, payload_type=None, ts="2026-05-08T10:21:16.920Z", **payload):
    if payload_type is not None:
        payload["type"] = payload_type
    return {"timestamp": ts, "type": kind, "payload": payload}


def rollout_lines(cwd, extra=()):
    return [
        rec("session_meta", id=CODEX_UUID, cwd=cwd, cli_version="0.128.0"),
        rec("turn_context", cwd=cwd),
        rec("response_item", "message", role="developer",
            content=[{"type": "input_text", "text": "system preamble"}]),
        rec("event_msg", "user_message", message="why does the build fail?"),
        rec("response_item", "message", role="user",
            content=[{"type": "input_text", "text": "why does the build fail?"}]),
        rec("response_item", "reasoning", summary=[], content=None,
            encrypted_content="gAAAA-opaque"),
        rec("event_msg", "agent_message", message="Let me run the tests."),
        rec("response_item", "function_call", name="exec_command",
            arguments=json.dumps({"cmd": "pytest -q"}), call_id="c1"),
        rec("event_msg", "exec_command_end", call_id="c1", exit_code=1),
        rec("response_item", "function_call_output", call_id="c1",
            output="1 failed\n" + "x" * 1000),
        rec("response_item", "custom_tool_call", name="apply_patch",
            call_id="c2", input="*** Begin Patch\n*** Update File: app.py\n"
                                "@@\n-a\n+b\n*** End Patch"),
        rec("response_item", "custom_tool_call_output", call_id="c2",
            output="Success."),
        rec("event_msg", "token_count", info=None),
        rec("event_msg", "agent_message", message="Fixed the import in app.py."),
        *extra,
    ]


def write_rollout(home, lines, uuid=CODEX_UUID) -> pathlib.Path:
    day = home / ".codex" / "sessions" / "2026" / "05" / "08"
    day.mkdir(parents=True, exist_ok=True)
    path = day / f"rollout-2026-05-08T11-20-05-{uuid}.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    return path


# Guards rather than skip markers: run_tests.py's pytest stub has no skipif.
HAS_TOML = handover.tomllib is not None


@pytest.fixture
def added(monkeypatch):
    """Every `claude mcp add-json` the run would have made, in place of the
    real command - which would edit this machine's ~/.claude.json."""
    calls = {}

    def fake(name, spec):
        if name in calls:
            return "already", "MCP server already exists in user config"
        calls[name] = spec
        return "added", ""
    monkeypatch.setattr(handover, "_claude_mcp_add", fake)
    return calls


@pytest.fixture
def home(tmp_path, monkeypatch, added):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / "work" / "app").mkdir(parents=True)
    monkeypatch.setattr(handover, "_claude_version", lambda: "2.1.312")
    return home


def cwd_of(home) -> str:
    return str(home / "work" / "app")


def landed(home) -> pathlib.Path:
    return (home / ".claude" / "projects"
            / rekey.encode_project_dir(cwd_of(home))
            / f"{handover.target_id(CODEX_UUID)}.jsonl")


def run(home, capsys, source="codex", target="claude-code", apply=True,
        verbose=False):
    code = handover.run(argparse.Namespace(source=source, target=target,
                                           apply=apply, verbose=verbose), home)
    return code, capsys.readouterr().out


def records(path) -> list:
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- the conversation ---------------------------------------------------------


def test_turns_alternate_from_the_user_and_carry_text_only(home):
    data = "".join(json.dumps(r) + "\n"
                   for r in rollout_lines(cwd_of(home))).encode()
    turns, meta, unknown = handover.conversation(data)
    assert [role for role, _text, _ts in turns] == ["user", "assistant"]
    assert turns[0][1] == "why does the build fail?"
    said = turns[1][1]
    assert said.startswith("Let me run the tests.")
    assert "[ran exec_command: pytest -q]\n1 failed" in said
    assert "[ran apply_patch: app.py]\nSuccess." in said
    assert said.endswith("Fixed the import in app.py.")
    assert meta["cli_version"] == "0.128.0"
    assert not unknown


def test_reasoning_and_the_preamble_stay_behind(home):
    data = "".join(json.dumps(r) + "\n"
                   for r in rollout_lines(cwd_of(home))).encode()
    text = json.dumps(handover.conversation(data)[0])
    assert "gAAAA-opaque" not in text
    assert "system preamble" not in text
    assert text.count("why does the build fail?") == 1


def test_tool_output_is_cut_short(home):
    data = "".join(json.dumps(r) + "\n"
                   for r in rollout_lines(cwd_of(home))).encode()
    said = handover.conversation(data)[0][1][1]
    assert "x" * handover.TOOL_OUTPUT_CHARS not in said
    assert " …" in said


def test_a_session_that_opens_with_the_assistant_gets_a_user_turn_first():
    data = (json.dumps(rec("event_msg", "agent_message", message="hello"))
            + "\n").encode()
    turns = handover.conversation(data)[0]
    assert [role for role, _t, _s in turns] == ["user", "assistant"]


# --- writing it ---------------------------------------------------------------


def test_apply_writes_a_session_claude_code_resumes(home, capsys):
    source = write_rollout(home, rollout_lines(cwd_of(home)))
    before = source.read_bytes()
    code, out = run(home, capsys)
    assert code == 0
    assert "Handed over 1 Codex Session(s)" in out
    lines = records(landed(home))
    session_id = handover.target_id(CODEX_UUID)
    assert [r["type"] for r in lines] == ["user", "assistant"]
    assert lines[0]["parentUuid"] is None
    assert lines[1]["parentUuid"] == lines[0]["uuid"]
    for r in lines:
        assert r["sessionId"] == session_id
        assert r["cwd"] == cwd_of(home)
        assert r["message"]["content"][0]["type"] == "text"
    assert source.read_bytes() == before


def test_a_dry_run_writes_nothing(home, capsys):
    write_rollout(home, rollout_lines(cwd_of(home)))
    code, out = run(home, capsys, apply=False)
    assert code == 0
    assert "Would hand over 1" in out and "Dry run" in out
    assert not (home / ".claude" / "projects").exists()


def test_a_second_run_makes_no_second_copy(home, capsys):
    write_rollout(home, rollout_lines(cwd_of(home)))
    run(home, capsys)
    # Claude Code appends to a Session it resumes; carryon must leave that be.
    with landed(home).open("a") as handle:
        handle.write('{"type": "user", "resumed": true}\n')
    after_resume = landed(home).read_bytes()
    code, out = run(home, capsys)
    assert code == 0
    assert "Handed over 0" in out and "1 already handed over" in out
    assert landed(home).read_bytes() == after_resume
    assert len(list(landed(home).parent.iterdir())) == 1


def test_a_rollout_with_no_project_folder_is_named_not_guessed(home, capsys):
    lines = [r for r in rollout_lines(cwd_of(home))
             if r["type"] not in ("session_meta", "turn_context")]
    write_rollout(home, lines)
    code, out = run(home, capsys)
    assert "not handed over" in out and "no project folder" in out
    assert not (home / ".claude" / "projects").exists()


def test_a_hard_link_to_carryons_state_is_not_read(home, capsys):
    state = home / ".carryon"
    state.mkdir()
    key = state / "master.key"
    key.write_text("00" * 32)
    day = home / ".codex" / "sessions" / "2026" / "05" / "08"
    day.mkdir(parents=True)
    os.link(key, day / f"rollout-2026-05-08T11-20-05-{CODEX_UUID}.jsonl")
    code, out = run(home, capsys)
    assert "not handed over" in out
    assert "00" * 32 not in out
    projects = home / ".claude" / "projects"
    assert not projects.exists() or not any(projects.rglob("*.jsonl"))


def test_a_project_folder_owned_elsewhere_is_not_written_through(
        home, tmp_path, capsys):
    write_rollout(home, rollout_lines(cwd_of(home)))
    elsewhere = tmp_path / "dotfiles"
    elsewhere.mkdir()
    (home / ".claude" / "projects").mkdir()
    landed(home).parent.symlink_to(elsewhere)
    code, out = run(home, capsys)
    assert code == 1
    assert "not handed over" in out
    assert list(elsewhere.iterdir()) == []


# --- drift ----------------------------------------------------------------------


def test_an_unknown_record_kind_is_named_and_the_link_carries_no_content(
        home, capsys):
    extra = [rec("event_msg", "brand_new_thing", message=SECRET_WORDS)]
    write_rollout(home, rollout_lines(cwd_of(home), extra))
    code, out = run(home, capsys)
    assert code == 0
    assert "event_msg/brand_new_thing (1)" in out
    link = next(line.strip() for line in out.splitlines()
                if line.strip().startswith(handover.ISSUES))
    body = urllib.parse.unquote_plus(link)
    assert "event_msg/brand_new_thing" in body and "0.128.0" in body
    assert "2.1.312" in body
    assert SECRET_WORDS not in body
    assert SECRET_WORDS not in landed(home).read_text()


def test_a_newer_agent_than_the_one_checked_is_said(home, capsys, monkeypatch):
    monkeypatch.setattr(handover, "_claude_version", lambda: "2.9.0")
    write_rollout(home, rollout_lines(cwd_of(home)))
    _code, out = run(home, capsys)
    assert "this machine has Claude Code 2.9.0" in out


def test_the_checked_versions_say_nothing(home, capsys):
    write_rollout(home, rollout_lines(cwd_of(home)))
    _code, out = run(home, capsys)
    assert "checked against" not in out


# --- the directions -------------------------------------------------------------


def test_claude_code_to_codex_points_at_codex_import(home, capsys):
    code, out = run(home, capsys, source="claude-code", target="codex")
    assert code == 0 and "/import" in out


def test_any_other_pair_is_refused(home, capsys):
    with pytest.raises(SystemExit, match="from codex to claude-code"):
        run(home, capsys, source="cursor", target="claude-code")


def test_no_claude_code_here_is_refused(home, capsys):
    (home / ".claude").rmdir()
    with pytest.raises(SystemExit, match="Claude Code is not set up"):
        run(home, capsys)


def test_the_command_line_reaches_it(home, capsys, monkeypatch):
    write_rollout(home, rollout_lines(cwd_of(home)))
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))
    assert cli.main(["handover", "codex", "claude-code", "--apply"]) == 0
    assert landed(home).is_file()


# --- the Setup ------------------------------------------------------------------


def agents_md(home, text="Prefer small commits.\n") -> pathlib.Path:
    path = home / ".codex" / "AGENTS.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_agents_md_is_imported_into_a_new_claude_md(home, capsys):
    agents_md(home)
    code, out = run(home, capsys)
    assert code == 0
    assert "now imports ~/.codex/AGENTS.md" in out
    assert (home / ".claude" / "CLAUDE.md").read_text() == \
        handover.IMPORT_LINE + "\n"


def test_an_existing_claude_md_is_kept_and_imported_from_once(home, capsys):
    agents_md(home)
    claude_md = home / ".claude" / "CLAUDE.md"
    claude_md.write_text("# Mine\nNo emojis.")
    run(home, capsys)
    assert claude_md.read_text() == \
        "# Mine\nNo emojis.\n\n" + handover.IMPORT_LINE + "\n"
    code, out = run(home, capsys)
    assert code == 0 and "already imports" in out
    assert claude_md.read_text().count(handover.IMPORT_LINE) == 1


def test_a_dry_run_leaves_claude_md_alone(home, capsys):
    agents_md(home)
    _code, out = run(home, capsys, apply=False)
    assert "would import" in out
    assert not (home / ".claude" / "CLAUDE.md").exists()


def test_a_claude_md_owned_by_a_dotfiles_repo_is_not_written(
        home, tmp_path, capsys):
    agents_md(home)
    managed = tmp_path / "dotfiles" / "CLAUDE.md"
    managed.parent.mkdir()
    managed.write_text("# managed\n")
    (home / ".claude" / "CLAUDE.md").symlink_to(managed)
    code, out = run(home, capsys)
    assert code == 1
    assert "not handed over  ~/.claude/CLAUDE.md" in out
    assert managed.read_text() == "# managed\n"


def test_an_agents_md_that_is_carryons_key_is_never_imported(home, capsys):
    state = home / ".carryon"
    state.mkdir()
    (state / "master.key").write_text("00" * 32)
    (home / ".codex").mkdir()
    os.link(state / "master.key", home / ".codex" / "AGENTS.md")
    code, out = run(home, capsys)
    assert code == 1
    assert "not handed over  ~/.codex/AGENTS.md" in out
    assert not (home / ".claude" / "CLAUDE.md").exists()


CONFIG_TOML = """model = "o4"

[mcp_servers.docs]
command = "npx"
args = ["-y", "docs-mcp"]
env = { DOCS_TOKEN = "sk-ant-api03-""" + "a1B2c3D4e5" * 4 + """" }
cwd = "/tmp"

[mcp_servers.tracker]
url = "https://tracker.example/mcp"
http_headers = { "X-Team" = "core" }
tool_timeout_sec = 30

[mcp_servers.old]
command = "old-mcp"
enabled = false

[mcp_servers.vault]
url = "https://vault.example/mcp"
bearer_token_env_var = "VAULT_TOKEN"
"""


def codex_config(home, text=CONFIG_TOML):
    path = home / ".codex" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_mcp_servers_go_through_claude_mcp_add(home, capsys, added):
    if not HAS_TOML:
        return
    codex_config(home)
    code, out = run(home, capsys)
    assert code == 1   # vault is named, not added
    assert added["docs"] == {
        "type": "stdio", "command": "npx", "args": ["-y", "docs-mcp"],
        "env": {"DOCS_TOKEN": "sk-ant-api03-" + "a1B2c3D4e5" * 4}}
    assert added["tracker"] == {"type": "http",
                                "url": "https://tracker.example/mcp",
                                "headers": {"X-Team": "core"}}
    assert set(added) == {"docs", "tracker"}
    assert "Added 2 MCP server(s)" in out
    assert "MCP server docs: left out cwd" in out
    assert "MCP server docs holds what looks like a credential" in out
    assert "a1B2c3D4e5" not in out
    assert "MCP server vault - it reads its token from the environment" in out
    assert "old" not in added


def test_an_mcp_server_claude_code_already_has_is_left_alone(
        home, capsys, added):
    if not HAS_TOML:
        return
    codex_config(home)
    run(home, capsys)
    first = dict(added)
    _code, out = run(home, capsys)
    assert "Added 0 MCP server(s) to Claude Code; 2 already there." in out
    assert added == first


def test_a_dry_run_adds_no_mcp_server(home, capsys, added):
    if not HAS_TOML:
        return
    codex_config(home)
    _code, out = run(home, capsys, apply=False)
    assert "Would add 2 MCP server(s)" in out
    assert added == {}


def test_a_name_claude_code_would_take_as_a_flag_is_refused(
        home, capsys, added):
    if not HAS_TOML:
        return
    codex_config(home, '[mcp_servers."--scope"]\ncommand = "x"\n')
    code, out = run(home, capsys)
    assert code == 1 and added == {}
    assert "Claude Code does not take that name" in out


def test_without_a_toml_reader_each_server_is_named_for_adding_by_hand(
        home, capsys, added, monkeypatch):
    monkeypatch.setattr(handover, "tomllib", None)
    codex_config(home)
    code, out = run(home, capsys)
    assert code == 1 and added == {}
    for name in ("docs", "tracker", "old", "vault"):
        assert f"MCP server {name} - reading Codex's config.toml needs " \
               "Python 3.11" in out
