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
`openssl` already on the machine — and Python 3.9+. Run on macOS only, so far.

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
| `init` | set up this machine: Destination, recovery key, config. In a terminal it asks where the Archive should live; `--dest SPEC` says so outright, and `--join CODE` pairs with an existing Archive instead |
| `push` | push this machine's Snapshot: the Setup plaintext, the History encrypted, changed Sessions only — never one the Archive is ahead on |
| `pull` | lay the Archive down here: union the History, replace the Setup after a backup |
| `sync` | carry the History both ways in one pass: pull what the Archive has, then push what it lacks — pull first, on purpose, and it never merges a Session two machines extended at once |
| `pair` | mint a one-time code that hands another machine the master key, via the Destination |
| `list` | show detected agents and what would be captured |
| `doctor` | check for layout changes: entries no adapter recognises |
| `capture --out DIR` | capture a Setup into a directory: no Destination, no key, no History |
| `encrypt` / `decrypt` | encrypt any file with a passphrase — a standalone cipher, nothing to do with an Archive |

```bash
carryon init --dest ~/Sync/carryon    # or plain `carryon init`, which asks
carryon push --apply
# on the new machine
carryon init --dest ~/Sync/carryon --join XXXX-XXXX-XXXX-XXXX
carryon pull --apply
# from then on, on whichever machine you sit down at
carryon sync --apply
```

That loop converges only because both machines are on the same Archive —
`init --join` (with a code from `pair`) is what puts the second one there.

Write down the recovery key `init` prints: it is shown once, it is never
stored, and the master key that opens the Archive is derived from it. Adding a
machine uses a pairing code from `pair` instead — typing the recovery key back
in is not a command yet, so keep a paired machine while that is true.

`push`, `pull` and `capture` print a plan and change nothing without `--apply`;
`--help` on a subcommand lists its own flags (`--agent`, `--category`, `--map`,
`--force`).

A pull never deletes anything under `$HOME`, and carryon never writes through a
path another tool already holds — a dotfiles symlink, a second hard link, a
name this machine will not answer about. Such a path is skipped and named in
the report rather than silently overwritten. `--force` writes through a symlink
or hard link on the Setup half; it still refuses a path no adapter here
declares, one landing in carryon's own state, and anything that is not an
ordinary file.

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

With a terminal on both ends, `init` offers what it found here — synced
folders, git if it can already authenticate, rclone remotes you already have —
and a short list of services it can set one up for: Cloudflare R2, Amazon S3,
Google Cloud Storage, SFTP. It asks that service's few fields, hands them to
`rclone config create`, and offers to create the bucket, asking first because
that is a billable resource in a region and under a name carryon has no
business choosing. The credential passes through to rclone and is never kept.
Without a terminal — over SSH with no tty, in CI — `init` prints the
candidates and exits. One scripted behaviour is gone on purpose: `init` with
no `--dest` no longer adopts a lone detected candidate silently. A script
names its Destination with `--dest`.

Then it asks the Destination two questions. Whether an Archive is already
there: setting up over one without `--join` would mint a second recovery key
that does not open what is already stored, and nothing afterwards tells the two
keys apart — so it refuses and says how to pair instead. And whether
write, read and delete really work, using a probe of random bytes under a
random name that it reads back and deletes. On an rclone Destination the probe
refuses to write into a bucket that is not there rather than let the upload
create one. A directory Destination that does not exist yet is created, the
way the first push always created it — so the spelling of `--dest ~/Dropbox`
is yours to get right; a typo is a working Archive in a folder no sync client
watches. A git Destination is not probed at all: every write there is a commit
that stays in history, and git refuses a push that does not land, so the first
`carryon push` is its write test. Both questions come before a key is minted
or a config written, so a refusal costs nothing and can be re-run. Neither
says whether the storage is private — no check can, which is why that stays
your call.

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

## Platform support

Every adapter is declared for `darwin` and was checked there; only the
`~/.agents` one also claims Linux. Nothing has been run on Linux or Windows.
`doctor` tells you when you are on a platform an adapter does not cover, and an
adapter's `verified_against` records the version and OS it was actually checked
on rather than a guess.

## Tests

```bash
uv run --extra dev pytest -q
python3 run_tests.py           # no pytest required
```

Both runners run the same suite and have to agree.

A History is your transcripts, so what the suite does *not* cover is worth
knowing before you point carryon at them. No agent binary is involved anywhere:
the suite builds agent directories itself, so what is verified is carryon's
behaviour against the layouts each adapter records — not against a live agent,
and not against a vendor who has since reorganised. The keyring runs through
its file backend with the real keychain pinned out, so `security(1)` and
`secret-tool` are covered by the arguments carryon builds for them rather than
by use. `openssl` and `git` are the real binaries, and a full journey — init,
push, pair, join, pull, push back — runs against both a directory Destination
and a bare git repository; `rclone` is a stand-in, for setting a Remote up as
well as for reaching one, so the Provider flow is checked against the argv
carryon builds and against rclone's own backend source — never against a live
bucket. Two carryon runs against one Archive at the same time is not tested.

## Licence

MIT. Credential detection rules ported from
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport)
(MIT, © 2026 Gowtham Sai Yadav); see `LICENSE`.
