"""Build the two throwaway homes demo.tape records against.

Usage: python3 seed.py ROOT

ROOT/laptop gets a Claude Code and a Codex CLI Setup and a few Sessions of
each; ROOT/desktop gets nothing but an empty ~/.claude. Nothing here is
real: no credential, no real path, no real transcript.
"""

import json
import pathlib
import re
import sys
import uuid


def jline(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


def claude_session(home, project, text):
    cwd = str(home / project)
    encoded = re.sub(r"[^A-Za-z0-9-]", "-", cwd)  # as Claude Code names it
    folder = home / ".claude" / "projects" / encoded
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{uuid.uuid4()}.jsonl").write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "text": text}))
    return folder


def codex_session(home, project, day, text):
    cwd = str(home / project)
    folder = home / ".codex" / "sessions" / "2026" / "10" / day
    folder.mkdir(parents=True, exist_ok=True)
    sid = str(uuid.uuid4())
    (folder / f"rollout-2026-10-{day}T10-00-00-{sid}.jsonl").write_text(
        jline({"timestamp": f"2026-10-{day}T10:00:00Z",
               "type": "session_meta", "payload": {"id": sid, "cwd": cwd}})
        + jline({"timestamp": f"2026-10-{day}T10:00:01Z", "type": "event",
                 "payload": {"text": text}}))


def laptop(home):
    claude = home / ".claude"
    (claude / "skills" / "release-notes").mkdir(parents=True)
    (claude / "skills" / "release-notes" / "SKILL.md").write_text(
        "---\nname: release-notes\n---\nWrite release notes from the log.\n")
    (claude / "agents").mkdir()
    (claude / "agents" / "reviewer.md").write_text("Review the diff.\n")
    (claude / "settings.json").write_text('{"model": "opus"}\n')
    (claude / "CLAUDE.md").write_text("Answer briefly.\n")

    memory = claude_session(home, "src/api", "add a /health route") / "memory"
    claude_session(home, "src/api", "why does the test hang?")
    claude_session(home, "src/site", "fix the footer on mobile")
    memory.mkdir()
    (memory / "MEMORY.md").write_text("Tests run with `make test`.\n")

    codex = home / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text('model = "gpt-5"\n')
    (codex / "AGENTS.md").write_text("Prefer small diffs.\n")
    codex_session(home, "src/api", "24", "rename the config loader")
    codex_session(home, "src/site", "25", "add dark mode")


def desktop(home):
    (home / ".claude").mkdir(parents=True)


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    laptop(root / "laptop")
    desktop(root / "desktop")
