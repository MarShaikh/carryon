"""Capture behaviour, exercised against a fake $HOME.

Testing against a fake home is the point: every one of these ran against a real
~/.claude first and would have been a destructive experiment there.
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture  # noqa: E402
from carryon.adapters import ADAPTERS, CATEGORIES  # noqa: E402


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

    assert code == 2, "a credential in the capture set must not produce a bundle"
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
