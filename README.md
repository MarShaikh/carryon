# carryon

Carries an AI coding agent's working life between machines: the Setup that
makes an agent yours — settings, skills, subagents, instructions, plugin
lists — and the History of what you did with it.

The two halves have opposite safety properties. A Setup travels plaintext, and
carryon refuses to produce one when a credential pattern matches, when the
capture set reads carryon's own state or anything outside `$HOME`, or when it
cannot tell whether it read its own state. That is a scan and a boundary
rather than a proof — an opaque token matches no pattern — and a Setup is
personal whether or not it holds a secret, so it belongs in private storage. A
History is unredacted by nature: it is always encrypted, and a credential
found there is reported and carried, never redacted or blocked.

Supports Claude Code, Codex CLI, Cursor, and the `~/.agents` skills
convention; a History moves for Claude Code and Codex, the two whose session
layout the engine knows. No Python dependencies — encryption shells out to the
`openssl` already on the machine — and Python 3.9+. macOS only; what that is
worth is at the foot of this file.

This file is an index. The vocabulary is defined in [CONTEXT.md](CONTEXT.md)
and the reasoning behind each decision in [docs/adr/](docs/adr/).

## Install

```bash
uv tool install git+https://github.com/MarShaikh/carryon
pip install git+https://github.com/MarShaikh/carryon
```

## Commands

| Command | Effect |
| --- | --- |
| `init` | set up this machine: Destination, recovery key, config; `--join CODE` pairs with an existing Archive instead |
| `push` | push this machine's Snapshot: the Setup plaintext, the History encrypted, changed Sessions only — never one the Archive is ahead on |
| `pull` | lay the Archive down here: union the History, replace the Setup after a backup |
| `pair` | mint a one-time code that hands another machine the master key, via the Destination |
| `list` | show detected agents and what would be captured |
| `doctor` | check for layout changes: entries no adapter recognises |
| `capture --out DIR` | capture a Setup into a directory: no Destination, no key, no History |
| `encrypt` / `decrypt` | encrypt any file with a passphrase — a standalone cipher, nothing to do with an Archive |

```bash
carryon init --dest ~/Sync/carryon
carryon push --apply
# on the new machine
carryon init --dest ~/Sync/carryon --join XXXX-XXXX-XXXX-XXXX
carryon pull --apply
```

Write down the recovery key `init` prints: it is shown once, it is never
stored, and the master key that opens the Archive is derived from it. Adding a
machine uses a pairing code from `pair` instead — typing the recovery key back
in is not a command yet, so keep a paired machine while that is true.

`push`, `pull` and `capture` print a plan and change nothing without `--apply`;
`--help` on a subcommand lists its own flags (`--agent`, `--category`, `--map`,
`--force`). A pull never deletes anything under `$HOME`, and nothing carryon
writes goes through a path another tool already holds — a dotfiles symlink, a
second hard link, a name this machine will not answer about. A file like that
is skipped and named in the report; an argument that names one is refused
before the command does anything. `--force` writes through the first two on
the Setup half only; it still refuses a path no adapter here declares, one that
lands in carryon's own state, and anything that is not an ordinary file.

## Destinations

carryon holds no credentials for a Destination; it borrows whatever you
already have. A synced folder needs no account at all. The Archive's History
is encrypted wherever it lands; its Setup half is plaintext there, so the
storage still needs to be private — and a Setup pushed by a machine holding
the master key carries an authentication tag, so a pull refuses one that was
edited at the Destination. A push without a key writes no tag and says so.

| Spec | Where the Archive lives |
| --- | --- |
| `/path`, `~/path`, `dir:PATH` | a directory — including a synced one (Dropbox, Drive, Syncthing) |
| `git:URL`, `git@...`, `ssh://...`, anything ending `.git` | a private git remote |
| `rclone:remote:path` | anything rclone reaches: S3, R2, B2, ... |

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

Set `verified_against` to a version you actually checked. `known_entries`
lists every top-level name you know about — anything else is reported by
`doctor`, which is how a layout change gets noticed. An agent whose Sessions
sit in a shape the History engine has no layout for carries its Setup only;
adding that shape is engine work rather than a declaration.

## Tests, and what they are evidence of

```bash
uv run --extra dev pytest -q
python3 run_tests.py           # no pytest required
```

Both runners run the same suite and have to agree. What that evidence covers,
said plainly, because a History is your transcripts and that is not a decision
to make from a feature list. It is **macOS only**: every adapter is declared
for `darwin` and was checked there, only the `~/.agents` one also claims Linux,
nothing has been run on Linux or Windows, and `doctor` says so on a platform an
adapter does not cover. **No agent binary is involved anywhere** — the suite
builds agent directories itself and drives carryon over them, so what is
verified is carryon's behaviour against the layouts each adapter records in
`verified_against`, on the date recorded there. **The keyring is exercised
through its file backend**, with the real keychain pinned out, so `security(1)`
and `secret-tool` are covered by the arguments carryon builds for them rather
than by use. `openssl` and `git` are the real ones on the machine, and a whole
journey — init, push, pair, join, pull, push back — runs against both a
directory Destination and a bare git repository; `rclone` is a stand-in binary.
**Nothing tests two carryon runs against one Archive at the same time**: a
local Destination writes through a temp file and an atomic rename, and one
test does race a thread against the Destination walk, but concurrent pushes
from two machines are not something this suite has seen.

## Licence

MIT. Credential detection rules ported from
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport)
(MIT, © 2026 Gowtham Sai Yadav); see `LICENSE`.
