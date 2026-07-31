"""Capture behaviour, exercised against a fake $HOME.

Testing against a fake home is the point: every one of these ran against a real
~/.claude first and would have been a destructive experiment there.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture  # noqa: E402
from carryon.adapters import (ADAPTERS, CATEGORIES, CONFIG, HISTORY,  # noqa: E402
                              SETUP_CATEGORIES, Item)


def build_home(tmp_path) -> pathlib.Path:
    """A minimal but realistic ~ with Claude Code and Cursor set up."""
    home = tmp_path / "home"
    claude = home / ".claude"
    (claude / "plugins").mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "plugins" / "installed_plugins.json").write_text('{"plugins": {}}')

    # a shared store plus a skills dir that links into it
    store = home / ".agents" / "skills"
    (store / "shared-skill").mkdir(parents=True)
    (store / "shared-skill" / "SKILL.md").write_text("shared")
    (home / ".agents" / ".skill-lock.json").write_text('{"version": 3}')

    skills = claude / "skills"
    skills.mkdir()
    (skills / "shared-skill").symlink_to(store / "shared-skill")
    (skills / "mine").mkdir()
    (skills / "mine" / "SKILL.md").write_text("authored here, no upstream")

    cursor = home / ".cursor"
    cursor.mkdir()
    (cursor / "cli-config.json").write_text(json.dumps({
        "editor": "vim",
        "authInfo": {"email": "someone@example.com", "teamId": "t_123"},
    }))
    return home


def run(home, out, **kw):
    return capture.run(out=out, dry=False, home=home, **kw)


def test_symlinked_skills_are_not_carried(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, manifest = run(home, out)

    assert code == 0
    assert (out / "claude/skills/mine/SKILL.md").exists()
    assert not (out / "claude/skills/shared-skill").exists()

    skills = [i for i in manifest["agents"]["claude-code"]["items"]
              if i["kind"] == "skills"][0]
    assert skills["carried"] == ["mine"]
    assert skills["re_resolvable"] == ["shared-skill"]


def test_cursor_authinfo_is_stripped(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, manifest = run(home, out)

    assert code == 0
    written = json.loads((out / "cursor/cli-config.json").read_text())
    assert "authInfo" not in written
    assert written["editor"] == "vim"

    item = [i for i in manifest["agents"]["cursor"]["items"]
            if i["kind"] == "json-strip"][0]
    assert item["stripped_keys"] == ["authInfo"]


def test_planted_credential_fails_closed(tmp_path):
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").write_text(
        '{"apiKey": "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED"}')
    out = tmp_path / "bundle"
    code, _ = run(home, out)

    assert code == 2, "a credential in the capture set must not produce a Setup"
    assert not (out / "MANIFEST.json").exists()


def test_dry_run_writes_nothing(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, _ = capture.run(out=out, dry=True, home=home)

    assert code == 0
    assert not out.exists()


def test_category_selection(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, manifest = run(home, out, want_categories={"config"})

    assert code == 0
    assert (out / "claude/settings.json").exists()
    assert not (out / "claude/skills").exists()
    kinds = {i["category"] for a in manifest["agents"].values() for i in a["items"]}
    assert kinds <= {"config"}


def test_agent_selection(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, manifest = run(home, out, want_agents={"cursor"})

    assert code == 0
    assert set(manifest["agents"]) == {"cursor"}
    assert not (out / "claude").exists()


def test_absent_agent_is_skipped_not_an_error(tmp_path):
    home = build_home(tmp_path)  # no ~/.codex
    out = tmp_path / "bundle"
    code, manifest = run(home, out)

    assert code == 0
    assert "codex" not in manifest["agents"]


def test_restore_notes_name_the_unrecoverable_skills(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    run(home, out)

    notes = (out / "RESTORE.md").read_text()
    assert "cp -R claude/skills/mine" in notes
    assert "shared-skill" not in notes.split("## 4.")[0]
    assert "does NOT redact" in notes


def test_every_adapter_declares_what_it_was_verified_against():
    for key, adapter in ADAPTERS.items():
        assert adapter.verified_against, f"{key} has no verified_against"
        assert adapter.items, f"{key} captures nothing"
        for item in adapter.items:
            assert item.category in CATEGORIES


def add_fake_session(home) -> pathlib.Path:
    """A synthetic Session tree under ~/.claude/projects. No real content."""
    project = home / ".claude" / "projects" / "-Users-someone-proj"
    project.mkdir(parents=True)
    (project / "0000-fake-uuid.jsonl").write_text('{"cwd": "/Users/someone/proj"}\n')
    return project


def test_chats_are_not_part_of_a_default_capture(tmp_path):
    home = build_home(tmp_path)
    add_fake_session(home)
    out = tmp_path / "bundle"
    code, manifest = run(home, out)

    assert code == 0
    assert not (out / "history").exists(), "a Setup must not contain Sessions"
    kinds = {i["kind"] for a in manifest["agents"].values() for i in a["items"]}
    assert "chats" not in kinds
    assert "history" not in manifest["categories"]
    assert sorted(manifest["categories"]) == sorted(SETUP_CATEGORIES)


def test_the_engine_skips_chats_even_when_history_is_in_the_wanted_set(tmp_path):
    """The kind check is a second guard, independent of category filtering."""
    home = build_home(tmp_path)
    add_fake_session(home)
    out = tmp_path / "bundle"
    cap = capture.Capture(out, dry=False, home=home)

    entry = capture._capture_agent(cap, ADAPTERS["claude-code"],
                                   set(CATEGORIES))
    assert all(i["kind"] != "chats" for i in entry["items"])
    assert not (out / "history").exists()


def test_requesting_history_from_capture_refuses_with_directions(tmp_path):
    home = build_home(tmp_path)
    with pytest.raises(SystemExit) as exc:
        capture.run(out=tmp_path / "bundle", dry=True, home=home,
                    want_categories={HISTORY})
    assert "carryon push" in str(exc.value)


def test_manifest_scope_names_the_setup_history_split(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    code, manifest = run(home, out)

    assert code == 0
    assert manifest["scope"] == ("A Setup: config + capability + knowledge. "
                                 "History travels separately, encrypted.")
    assert "history_handled_by" not in manifest


def test_a_chats_item_requires_a_layout_and_nothing_else_may_have_one():
    with pytest.raises(ValueError):
        Item("x/chats", "y", "chats", HISTORY, "no layout named")
    with pytest.raises(ValueError):
        Item("x/file", "y", "file", CONFIG, "layout on a non-chats kind",
             layout="claude-projects")
    ok = Item("x/chats", "y", "chats", HISTORY, "fine",
              layout="claude-projects")
    assert ok.layout == "claude-projects"


def test_claude_and_codex_declare_their_history():
    claude = [i for i in ADAPTERS["claude-code"].items if i.kind == "chats"]
    assert [(i.src, i.dst, i.layout, i.category) for i in claude] == \
        [(".claude/projects", "history/claude-code", "claude-projects", HISTORY)]
    assert not any(e.path.startswith(".claude/projects")
                   for e in ADAPTERS["claude-code"].exclude), \
        ".claude/projects is carried now, not excluded"

    codex = [i for i in ADAPTERS["codex"].items if i.kind == "chats"]
    assert [(i.src, i.dst, i.layout, i.category) for i in codex] == \
        [(".codex/sessions", "history/codex", "codex-rollouts", HISTORY)]


def test_success_output_keeps_setup_and_history_promises_apart(tmp_path, capsys):
    """A Setup is clean; a History is encrypted by push. The closing message
    must say exactly that - not send anyone to entangle or manual encryption,
    and not use the retired word "bundle"."""
    home = build_home(tmp_path)
    out = tmp_path / "setup"
    code, _ = run(home, out)

    assert code == 0
    text = capsys.readouterr().out
    assert "entangle" not in text.lower()
    assert "bundle" not in text.lower()
    assert "carryon push" in text


def test_refusal_output_says_setup_not_bundle(tmp_path, capsys):
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").write_text(
        '{"apiKey": "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED"}')
    code, _ = run(home, tmp_path / "setup")

    assert code == 2
    text = capsys.readouterr().out
    assert "bundle" not in text.lower()
    assert "Setup" in text


def test_symlink_outside_the_lock_store_is_not_called_re_resolvable(tmp_path):
    """A symlink is only re-resolvable if it points into the shared store.

    Dotfiles repos also symlink skills into ~/.claude/skills. Those have no
    entry in .skill-lock.json, so calling them re-resolvable would mean the
    skills installer is expected to restore something it has never heard of -
    and they would be silently lost.
    """
    home = build_home(tmp_path)
    elsewhere = tmp_path / "dotfiles" / "claude" / "skills" / "from-dotfiles"
    elsewhere.mkdir(parents=True)
    (elsewhere / "SKILL.md").write_text("managed by a dotfiles repo")
    (home / ".claude" / "skills" / "from-dotfiles").symlink_to(elsewhere)

    code, manifest = run(home, tmp_path / "bundle")
    assert code == 0

    skills = [i for i in manifest["agents"]["claude-code"]["items"]
              if i["kind"] == "skills"][0]

    assert "from-dotfiles" not in skills["re_resolvable"], \
        "a symlink outside the lock store is not re-resolvable"
    assert "from-dotfiles" in skills["external"], \
        "it must be reported as managed elsewhere, not silently dropped"
    assert "shared-skill" in skills["re_resolvable"]
