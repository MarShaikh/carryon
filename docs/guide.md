# Using carryon

The [README](../README.md) gets you from install to a first pull. This page is
everything after that. Terms are defined in [CONTEXT.md](../CONTEXT.md), and
what is encrypted and what a Destination can see is in [trust.md](trust.md).

Every command that changes something prints a plan first and does nothing
until you add `--apply`.

## What moves

`carryon list` shows which agents carryon detected on this machine and, for
each, what it would carry in each Category: `config`, `capability` and
`knowledge` make up the Setup, and `history` is the History. Your own
`excludes` and `carry` are already applied, so the listing is what a push
would really take.

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

A Setup carries what makes an agent yours, not what built it (ADR-0013).
Inside a tree an Adapter declares, development artifacts such as a skill's
test suite are left out and named, while a path you add to `carry` yourself is
carried whole.

Some things are left out on purpose: caches, telemetry, live run state, prompt
recall (`history.jsonl`), and machine identity (`~/.claude.json`). Each one,
and the reason for it, is in the adapter under `carryon/adapters/`.
`carryon doctor` reports anything in an agent's directory that no adapter
recognises, which is how a vendor's layout change gets noticed.

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

## Day to day: status and sync

```bash
carryon status
```

`status` tells you what is out of step, the way `git status` does, and moves
nothing. It reads the Archive's Index rather than downloading anything, and
each line ends with the command that closes the gap:

```
status: rclone remote carryon:carryon-archive
History: 3 to push, 2 to pull - run `carryon sync --apply`
Setup: home-mac pushed changes (2026-10-19 09:12) - run `carryon pull --apply` to bring them here
```

`in step with ...` means there is nothing to do. `--verbose` lists the Sessions
and projects behind each count. Nothing runs on its own: carryon has no
scheduler and no background process (ADR-0015).

```bash
carryon sync --apply
```

`sync` carries the History both ways in one pass: pull first, then push. That
order is deliberate, because pushing first leaves the Archive a round behind.
By default it moves only the History. Your Setup changes less often and
deserves a deliberate step:

```bash
carryon push --apply --category config,capability,knowledge  # after changing settings or skills
carryon pull --apply --category config,capability,knowledge  # to take them on another machine
```

## When two machines changed the same thing

A pull unions the History and replaces the Setup (ADR-0002). A Session belongs
to one machine at a time, so usually there is nothing to reconcile. When two
machines extended the same Session, `pull` and `sync` never merge it
(ADR-0012). They keep your copy, file the Archive's under
`~/.carryon/conflicts/`, and say so. Running them again changes nothing until
you decide.

Per-project memory (`MEMORY.md` and the notes beside it) gets edited in place,
not only appended to, so carryon remembers the version of each memory file this
machine and the Archive last agreed on: its Base. If only one machine has edited
a file since then, that edit travels, on push and on pull. A pull that writes
another machine's edit over yours backs your copy up first. If both machines
edited the same file, the pull keeps yours and files the Archive's under
`~/.carryon/conflicts/<project>/`. Merge it by hand, run
`carryon resolve <path> --apply`, and the next push carries the merge.

A memory file that was edited before upgrading has no Base yet. It gets one the
first time a push or pull finds it in step with the Archive. A file still out
of step then is filed by `pull --apply`, and needs that same merge and
`resolve`.

## Commands

| Command | Effect |
| --- | --- |
| `init` | set up this machine: Destination, recovery key, config. In a terminal it asks where the Archive should live; `--dest SPEC` says so outright. `--join CODE` pairs with an existing Archive instead, and `--recover` takes the recovery key back when no paired machine is left |
| `push` | push this machine's Snapshot, encrypted: the Setup as one sealed object, the History as changed Sessions only, never one the Archive is ahead on |
| `pull` | lay the Archive down here: union the History, replace the Setup after a backup |
| `sync` | carry the History both ways in one pass: pull what the Archive has, then push what it lacks |
| `status` | say what is out of step with the Archive and which command closes it, read off the Index without downloading anything; it moves nothing |
| `resolve [PATH...]` | end a divergence in per-project memory after you have merged the Archive's filed copy by hand; with no paths, list what is filed |
| `pair` | mint a one-time code that hands another machine the master key, via the Destination |
| `list` | show detected agents and what would be captured |
| `doctor` | check for layout changes: entries no adapter recognises |
| `capture --out DIR` | capture a Setup into a local directory, in the clear, to read or diff: no Destination, no key, no History |
| `encrypt` / `decrypt` | encrypt any file with a passphrase: a standalone cipher, nothing to do with an Archive |

`push`, `pull`, `sync`, `resolve` and `capture` print a plan and change nothing
without `--apply`. `--help` on a subcommand lists its own flags (`--agent`,
`--category`, `--map`, `--force`, `--verbose`). `--verbose` lists each file
and Session behind a summary.

`pull --map OLD=NEW` rewrites an absolute path outside `$HOME` on the way in,
for a project that lives at `/Volumes/work/...` on one machine and somewhere
else on the other. Paths under `$HOME` need no map: carryon rewrites them to a
machine-neutral form on push and expands them against the new home on pull
(ADR-0006).

## Destinations

| Spec | Where the Archive lives |
| --- | --- |
| `/path`, `~/path`, `dir:PATH` | a directory, including a synced one (Dropbox, Drive, iCloud Drive, Syncthing) |
| `git:URL`, `git@...`, `ssh://...`, anything ending `.git` | a private git remote |
| `rclone:remote:path` | anything rclone reaches: S3, R2, B2, SFTP, ... |

With a terminal on both ends, `init` offers what it found here (synced
folders, git if it can already authenticate, rclone remotes you already have)
and a short list of services it can set one up for: Cloudflare R2, Amazon S3,
Google Cloud Storage, SFTP. It asks that service's few fields, hands them to
`rclone config create`, and offers to create the bucket, asking first because
that is a billable resource in a region and under a name carryon has no
business choosing (ADR-0011). Without a terminal (over SSH with no tty, in CI)
`init` prints the candidates and exits, and a script names its Destination
with `--dest`.

Then it asks the Destination two questions, before a key is minted or a config
written, so a refusal costs nothing and can be re-run:

- **Is an Archive already there?** Setting up over one without `--join` would
  mint a second recovery key that does not open what is already stored, so it
  refuses and says how to pair instead.
- **Do write, read and delete really work?** It writes a probe of random bytes
  under a random name, reads it back and deletes it. On an rclone Destination
  the probe refuses to write into a bucket that is not there rather than let
  the upload create one. A directory Destination that does not exist yet is
  created, so the spelling of `--dest ~/Dropbox` is yours to get right; a typo
  is a working Archive in a folder no sync client watches. A git Destination
  is not probed, because every write there is a commit that stays in history;
  the first `carryon push` is its write test.

Neither question says whether the storage is private; see
[trust.md](trust.md#what-a-destination-can-and-cannot-do).

### Cloudflare R2 through rclone

R2 has no egress fees and 10 GB of free storage. You need
[rclone](https://rclone.org/install/) on both machines (`brew install rclone`,
or your distribution's package).

In the Cloudflare dashboard, under R2 Object Storage:

1. Create a bucket, for example `carryon-archive`. Creating it here rather
   than from `init` lets you keep the token below to this one bucket.
2. Under **Manage API tokens**, create a token with **Object Read & Write**,
   applied to that bucket only. Note the access key ID and the secret
   access key. The secret is shown once.
3. Note your account ID, which is on the R2 overview page.

On the first machine, run `carryon init` with no `--dest`. It asks, in order:

- where the Archive should live: pick *a cloud service*;
- which service: pick *Cloudflare R2*;
- a name for the rclone remote (`carryon` unless you already have one);
- your account ID, access key ID and secret access key (not echoed);
- the bucket: `carryon-archive`;
- whether to create the bucket: answer no, since it exists.

The keys go into rclone's config (`~/.config/rclone/rclone.conf`), not
carryon's. carryon stores only the spec, `rclone:carryon:carryon-archive`.
Then `carryon push --apply` and `carryon pair` as usual.

On the second machine, run `carryon init --join CODE` with no `--dest`, and
answer the same questions with the same keys and bucket. That creates the
same rclone remote there before the code is used. If rclone already has a
remote for the bucket, name it instead:
`carryon init --join CODE --dest rclone:REMOTE:carryon-archive`.

Amazon S3 and Google Cloud Storage go the same way, with their own
questions. Backblaze B2 is not in `init`'s list, because rclone's upload to
B2 creates a missing bucket, so a `push` could re-create one you deleted. A
B2 remote you set up yourself still works as `rclone:REMOTE:BUCKET`.

## Where carryon keeps things

On each machine, everything lives under `~/.carryon/`:

| Path | What it is |
| --- | --- |
| `config.json` | the Destination, this machine's name, `excludes` and `carry` |
| `state.json` | what this machine has seen of each Archive: the highest Index revision (so a rolled-back Archive is noticed) and each memory file's Base |
| `backups/` | every file a pull overwrote, one directory per pull |
| `conflicts/` | the Archive's copy of anything two machines changed at once, waiting for you |
| `master.key` | only on a machine with no OS keychain, or one set up with `init --key-file`; elsewhere the key is in the keychain under service `carryon` |

At the Destination, everything sits under `carryon/`. The Index records which
Sessions and Setups the Archive holds, Setups are kept one sealed object per
machine, and Sessions are sealed objects under names the Destination cannot
read.

## When carryon refuses

carryon would rather stop and say why than guess. Each refusal names its cure;
these are the ones a new user meets most.

| It says | What to do |
| --- | --- |
| this machine holds no master key | `carryon init --join CODE --dest SPEC` with a code from `carryon pair`, or `carryon init --recover` if no machine has the key |
| there is already an Archive at ... | you are setting up a second machine: pair it rather than starting a new Archive |
| could not read the master key via security | the keychain is locked or unreachable; the key may well still be there, so fix the keychain rather than pairing again |
| could not read the master key via secret-tool | as above; on a server with no keyring running, run `carryon init` in a terminal and answer yes, or pass `--key-file` |
| the stored master key ... is not the hex carryon wrote there | put the file back from a backup, pair again, or remove it and run `carryon init --recover` |
| wrong or expired code | the code was mistyped or is past its 24 hours; run `carryon pair` again |
| refusing to push: the Archive's Index is at revision ... | the Archive has gone backwards since this machine last saw it; restore the newer copy, or follow the message to accept it deliberately |
| Skipped ... rather than overwrite the Archive's copy | `carryon pull --apply` first, then merge anything filed under `~/.carryon/conflicts/` and `carryon resolve` it |

## Installing and removing

```bash
pipx install agent-carryon       # or: uv tool install agent-carryon
pipx upgrade agent-carryon       # or: uv tool upgrade agent-carryon
pipx uninstall agent-carryon     # or: uv tool uninstall agent-carryon
```

The package is `agent-carryon`, because the bare name belongs to an unrelated
project on PyPI; the command is `carryon`. Removing the tool leaves
`~/.carryon/` and your Archive where they are.
