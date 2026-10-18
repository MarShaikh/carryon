# carryon

Carries an AI coding agent's working life between machines: the Setup that
makes an agent yours — settings, skills, subagents, instructions, plugin
lists — and the History of what you did with it.

carryon reports what it sees and encrypts what it carries. Both halves are
sealed under a master key before they leave the machine, so a credential found
in either — an API key in `settings.json`'s `env` block, a token echoed into a
transcript — is reported and carried, never redacted or blocked. The scan is a
list of shapes it recognises rather than a proof (an opaque token matches
none), which is why the promise rests on encryption and not on the scan.

What a capture may *read* is still bounded: carryon refuses a Setup whose
capture set reads its own state or anything outside `$HOME`, or when it cannot
tell whether it did. And a Setup carries what makes an agent yours, not what
built it: inside a tree an Adapter declares, development artifacts such as a
skill's test suite are left out and named, while a path you add to `carry`
yourself is carried whole.

Supports Claude Code, Codex CLI, Cursor, and the `~/.agents` skills
convention; a History moves for Claude Code and Codex, the two whose session
layout the engine knows.

The vocabulary used throughout — Setup, History, Archive, Destination,
Session — is defined in [CONTEXT.md](CONTEXT.md), and the reasoning behind each
decision is in [docs/adr/](docs/adr/).

## What you need

- **macOS.** Nothing has been run on Linux or Windows yet (see
  [Platform support](#platform-support)).
- **Python 3.9 or newer.** carryon has no Python dependencies.
- **`openssl`**, which macOS already has. Encryption shells out to it, so the
  machine you are moving *to* needs nothing installed beyond carryon itself.
- **A Destination**: somewhere both machines can reach. Any one of these:
  - a synced folder (Dropbox, Google Drive, iCloud Drive, Syncthing). No
    account beyond the one the folder already uses.
  - a private git repository you can already push to.
  - an rclone remote (S3, Cloudflare R2, B2, SFTP, ...). `init` can set one up
    for R2, S3, Google Cloud Storage or SFTP if you have `rclone` installed.
- **A password manager**, to hold the recovery key `init` prints once.

## Install

```bash
uv tool install git+https://github.com/MarShaikh/carryon
# or
pip install git+https://github.com/MarShaikh/carryon
```

Upgrade with `uv tool upgrade agent-carryon` (the package is `agent-carryon`;
the command is `carryon`). Uninstall with `uv tool uninstall agent-carryon`.
Removing the tool leaves `~/.carryon/` and your Archive where they are.

## Getting started

Every command that changes something prints a plan first and does nothing
until you add `--apply`. Run it without, read the plan, then run it again.

### 1. See what would move

```bash
carryon list
```

This shows which agents carryon detected on this machine and, for each, what
it would carry in each category: `config`, `capability` and `knowledge` make
up the Setup, and `history` is the History. Your own `excludes` and `carry` are
already applied, so the listing is what a push would really take.

### 2. Set up the first machine

```bash
carryon init                          # asks where the Archive should live
carryon init --dest ~/Dropbox/carryon # or say so outright
```

`init` checks the Destination before it commits to anything. It refuses if an
Archive is already there, and it writes, reads and deletes a probe to prove the
storage works. Then it stores a fresh master key in the macOS keychain, writes
`~/.carryon/config.json`, and prints your **recovery key**:

```
Your recovery key - shown once, never stored by carryon:

    ABCD-EFGH-JKLM-NOPQ-RSTU-VWXY-Z234-5672
```

Put it in your password manager now. The master key that opens the Archive is
derived from it. If every machine loses its key, the recovery key is the only
way back in. There is no reset.

### 3. Push

```bash
carryon push            # the plan
carryon push --apply    # do it
```

The Setup goes up as one sealed object. The History goes up as one sealed
object per Session, and only the Sessions that changed since the last push. If
the scan recognises a credential, push names the file and carries on.

### 4. Add a second machine

On the machine that is already set up:

```bash
carryon pair
```

It prints a one-time code and the exact command to run on the new machine:

```bash
carryon init --join XXXX-XXXX-XXXX-XXXX --dest ~/Dropbox/carryon
carryon pull            # the plan
carryon pull --apply    # lay the Archive down here
```

The code is good for one use within 24 hours. The master key travels through
the Destination, wrapped under that code, and lands in the new machine's
keychain without anyone typing it. Use the same Destination spec the first
machine uses.

A pull unions the History, so Sessions from both machines end up on both. It
replaces the Setup after backing up whatever it overwrites to
`~/.carryon/backups/`.

### 5. Day to day

```bash
carryon sync --apply
```

`sync` carries the History both ways in one pass: pull first, then push.
That order is deliberate, because pushing first leaves the Archive a round
behind. By default it moves only the History. Your Setup changes less often and
deserves a deliberate step:

```bash
carryon push --apply --category config,capability,knowledge  # after changing settings or skills
carryon pull --apply --category config,capability,knowledge  # to take them on another machine
```

`sync` never merges a Session that two machines extended at the same time. It
keeps your copy, files the Archive's under `~/.carryon/conflicts/`, and says
so. Running it again changes nothing until you decide.

### If a machine loses its key

A new laptop, a wiped keychain, a machine restored without its keychain: the
cure depends on whether another machine still holds the key.

- **Another machine still has it:** run `carryon pair` there and
  `carryon init --join CODE` here, as in step 4.
- **No machine has it:** type the recovery key back in.

```bash
carryon init --recover
```

carryon asks for the key at a prompt that does not echo. It never takes the key
as an argument, and without a terminal it refuses. It keeps the key only once
the key has opened the Archive's Index. A key from another Archive, or a typo
that still parses, is asked for again with nothing stored, and Ctrl-D stops. If this machine still has its
`config.json`, recovery uses that file's Destination and machine name and leaves
the file exactly as it was, your excludes and handpicked paths included.

## What moves

| Agent | Setup | History |
| --- | --- | --- |
| Claude Code (`~/.claude`) | `settings.json`, `settings.local.json`, `keybindings.json`, `CLAUDE.md`, skills, subagents, slash commands, the plugin and marketplace manifests | Sessions and per-project memory under `projects/` |
| Codex CLI (`~/.codex`) | `config.toml`, `AGENTS.md`, `memories/` | rollout transcripts under `sessions/` |
| Cursor (`~/.cursor`) | `cli-config.json` with its `authInfo` removed, rules, commands, subagents, the skills sync manifest | — |
| `~/.agents` | `.skill-lock.json` | — |

Some things are carried as a pointer rather than as the thing itself. Plugins
travel as their manifest, not as copies. Skills installed under `~/.agents`
travel as the lock file they are reinstalled from. A Claude Code skill that is
a symlink is re-resolved on the other machine, and one that is a real directory
is carried.

Some things are left out on purpose: caches, telemetry, live run state, prompt
recall (`history.jsonl`), and machine identity (`~/.claude.json`). Each one,
and the reason for it, is in the adapter under `carryon/adapters/`.
`carryon doctor` reports anything in an agent's directory that no adapter
recognises, which is how a vendor's layout change gets noticed.

The categories `--category` takes are `config`, `capability`, `knowledge`
(those three together are the Setup) and `history`.

## Choosing what moves

The defaults move everything above. To change that, edit
`~/.carryon/config.json`:

```json
{
  "version": 1,
  "destination": "~/Dropbox/carryon",
  "machine": "work-laptop",
  "excludes": [".claude/keybindings.json", ".cursor/*"],
  "carry": ["~/.config/ghostty/config", "~/bin/my-scripts"]
}
```

- **`excludes`** removes whole Items an adapter declares. Each pattern is
  matched case-sensitively against the Item's path relative to `$HOME`, as the
  adapter declares it (`.claude/keybindings.json`, `.cursor/rules`), so the
  same config excludes the same things on every machine. A pattern that
  matches nothing is reported, so a typo does not quietly exclude nothing.
- **`carry`** adds paths no adapter knows about. They always join the Setup,
  never the History, and they must sit inside `$HOME`. `~/.carryon` itself is
  refused, because the master key can live there.

carryon checks this file strictly on every command. An unknown key is an error,
not a setting that is silently ignored.

## Commands

| Command | Effect |
| --- | --- |
| `init` | set up this machine: Destination, recovery key, config. In a terminal it asks where the Archive should live; `--dest SPEC` says so outright. `--join CODE` pairs with an existing Archive instead, and `--recover` takes the recovery key back when no paired machine is left |
| `push` | push this machine's Snapshot, encrypted: the Setup as one sealed object, the History as changed Sessions only — never one the Archive is ahead on. Needs the master key |
| `pull` | lay the Archive down here: union the History, replace the Setup after a backup |
| `sync` | carry the History both ways in one pass: pull what the Archive has, then push what it lacks — pull first, on purpose, and it never merges a Session two machines extended at once |
| `resolve [PATH...]` | end a divergence in per-project memory after you have merged the Archive's filed copy by hand; with no paths, list what is filed |
| `pair` | mint a one-time code that hands another machine the master key, via the Destination |
| `list` | show detected agents and what would be captured |
| `doctor` | check for layout changes: entries no adapter recognises |
| `capture --out DIR` | capture a Setup into a local directory, in the clear, to read or diff: no Destination, no key, no History |
| `encrypt` / `decrypt` | encrypt any file with a passphrase — a standalone cipher, nothing to do with an Archive |

`push`, `pull`, `sync`, `resolve` and `capture` print a plan and change nothing
without `--apply`. `--help` on a subcommand lists its own flags (`--agent`,
`--category`, `--map`, `--force`).

`pull --map OLD=NEW` rewrites an absolute path outside `$HOME` on the way in,
for a project that lives at `/Volumes/work/...` on one machine and somewhere
else on the other. Paths under `$HOME` need no map: carryon rewrites them to a
machine-neutral form on push and expands them against the new home on pull.

## What carryon will not do to your files

A pull never deletes anything under `$HOME`, and carryon never writes through a
path another tool already holds — a dotfiles symlink, a second hard link, a
name this machine will not answer about. Such a path is skipped and named in
the report rather than silently overwritten. `--force` writes through a symlink
or hard link on the Setup half; it still refuses a path no adapter here
declares, one landing in carryon's own state, and anything that is not an
ordinary file.

Before a pull overwrites a file, it backs that file up under
`~/.carryon/backups/<timestamp>/`.

Per-project memory (`MEMORY.md` and the notes beside it) gets edited in place,
not only appended to, so carryon remembers the version of each memory file this
machine and the Archive last agreed on: its Base. If only one machine has edited
a file since then, that edit travels, on push and on pull. A pull that writes
another machine's edit over yours backs your copy up first. If both machines
edited the same file, the pull keeps yours and files the Archive's under
`~/.carryon/conflicts/<project>/`. Merge it by hand, run
`carryon resolve <path> --apply`, and the next push carries the merge. A memory
file that was edited before upgrading has no Base yet. It gets one the first
time a push or pull finds it in step with the Archive. A file still out of step
then is filed by `pull --apply`, and needs that same merge and `resolve`.

## Where carryon keeps things

On each machine, everything lives under `~/.carryon/`:

| Path | What it is |
| --- | --- |
| `config.json` | the Destination, this machine's name, `excludes` and `carry` |
| `state.json` | what this machine has seen of each Archive: the highest Index revision (so a rolled-back Archive is noticed) and each memory file's Base |
| `backups/` | every file a pull overwrote, one directory per pull |
| `conflicts/` | the Archive's copy of anything two machines changed at once, waiting for you |
| `master.key` | only on a machine with no OS keychain; on macOS the key is in the keychain under service `carryon` |

At the Destination, everything sits under `carryon/`. The Index records which
Sessions and Setups the Archive holds, Setups are kept one sealed object per
machine, and Sessions are sealed objects under names the Destination cannot
read.

## Destinations

carryon holds no credentials for a Destination; it borrows whatever you
already have. A synced folder needs no account at all. Everything in the
Archive is sealed wherever it lands — encrypted, and checked before it is
opened — so a pull refuses an object that was edited at the Destination. What
the Destination can still see is the shape: how many objects, how large, when
they changed, and the machine names in each Setup's key. A pull also refuses an
older Setup served back in place of the current one, which an encrypted object
alone cannot rule out.

An Archive pushed before the Setup was sealed holds it as a plaintext tree, and
a pull refuses that tree by name. One full `carryon push --apply` replaces it
with the sealed object and removes the plaintext files. On a git Destination
they stay in the repository's history.

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
candidates and exits. A script names its Destination with `--dest`.

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

Prefer a Destination that forgets when you have the choice. A pairing code is
deleted from the Archive once it is used, but on a git Destination that delete
is a commit, and the wrapped master key stays in the history for anyone who can
clone the repository.

## When carryon refuses

carryon would rather stop and say why than guess. Each refusal names its cure;
these are the ones a new user meets most.

| It says | What to do |
| --- | --- |
| this machine holds no master key | `carryon init --join CODE --dest SPEC` with a code from `carryon pair`, or `carryon init --recover` if no machine has the key |
| there is already an Archive at ... | you are setting up a second machine: pair it rather than starting a new Archive |
| could not read the master key via security | the keychain is locked or unreachable; the key may well still be there, so fix the keychain rather than pairing again |
| the stored master key ... is not the hex carryon wrote there | put the file back from a backup, pair again, or remove it and run `carryon init --recover` |
| wrong or expired code | the code was mistyped or is past its 24 hours; run `carryon pair` again |
| refusing to push: the Archive's Index is at revision ... | the Archive has gone backwards since this machine last saw it; restore the newer copy, or follow the message to accept it deliberately |
| a project skipped rather than overwrite the Archive's copy | `carryon pull --apply` first, then merge anything filed under `~/.carryon/conflicts/` and `carryon resolve` it |

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
