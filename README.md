# carryon

Move an AI coding agent setup to a new machine — settings, skills, subagents,
instructions, plugin lists.

Supports Claude Code, Codex CLI, Cursor, and the `~/.agents` skills convention.
No dependencies, Python 3.9+, dry-run by default.

```bash
carryon doctor                                 # check the layout is recognised
carryon list                                   # show what would be captured
carryon capture --out ~/agent-state            # dry run
carryon capture --out ~/agent-state --apply    # write it
```

The bundle contains `MANIFEST.json` (what was taken and what was left) and
`RESTORE.md` (what to do on the new machine).

## It does not move chats

Transcripts need path re-keying and redaction, which is a separate problem.
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport) solves it.
Use `carryon` for the setup and `entangle` for the history.

Credentials are never captured. `capture` refuses to finish if it finds one.

## Install

```bash
uv tool install git+https://github.com/MarShaikh/carryon
pip install git+https://github.com/MarShaikh/carryon
```

## capture

| Flag | Effect |
| --- | --- |
| `--out DIR` | where the bundle goes (required) |
| `--apply` | actually write; without it you get a plan |
| `--agent A,B` | subset of `claude-code`, `codex`, `cursor`, `agents-convention` |
| `--category A,B` | subset of `config`, `capability`, `knowledge` |
| `--archive F.tar.gz` | also pack the bundle into one file |

Skills installed from a repo are recorded as re-resolvable and left for the
skills installer. Only skills with no upstream are carried.

## Moving the bundle

It holds no credentials — `capture` refuses to finish if it finds one — so any
private storage works. A private git repo, `--archive` onto a USB stick, or
object storage:

```bash
rclone copy ~/agent-state r2:my-bucket/agent-state    # old machine
rclone copy r2:my-bucket/agent-state ~/agent-state    # new machine
```

Works the same for R2, S3, B2, Drive or Dropbox. Keep it private: no
credentials is not the same as not personal.

An `entangle` chat bundle is a different matter — it is unredacted, so encrypt
it before it goes anywhere, or move it offline.

## Platform support

macOS is verified. Linux is expected to work and Windows is untested — the code
uses no hardcoded paths, but neither has been checked. Each adapter declares
what it was verified against, and `doctor` warns when you are outside it.

## Adding an agent

Add a module to `carryon/adapters/` defining `ADAPTER`, and list it in
`MODULES`. The engine reads the declaration.

```python
from .base import CONFIG, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="my-agent",
    name="My Agent",
    detect=".myagent",
    verified_against="My Agent 3.2, macOS 15",
    platforms=("darwin",),
    items=(
        Item(".myagent/config.json", "myagent/config.json",
             "file", CONFIG, "settings", required=True),
    ),
    exclude=(Excluded(".myagent/token", "CREDENTIAL", "log in again"),),
    known_entries=("config.json", "token", "cache"),
)
```

Set `verified_against` to a version you actually checked. `known_entries` lists
every top-level name you know about — anything else is reported by `doctor`,
which is how a layout change gets noticed.

## Tests

```bash
uv run --extra dev pytest -q
python3 run_tests.py           # no pytest required
```

## Licence

MIT. Credential detection rules ported from
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport)
(MIT, © 2026 Gowtham Sai Yadav); see `LICENSE`.
