# carryon

Carries an AI coding agent's working life between machines: the
[Setup](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) that makes an agent yours (settings, skills, subagents,
instructions, plugin lists) and the [History](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) of what you did with
it. Both are encrypted before they leave the machine.

Works with Claude Code, Codex CLI, Cursor and the `~/.agents` skills
convention. A History moves for Claude Code and Codex.

![Two machines, five commands: init, push and pair on a laptop, then init --join and pull on a desktop](https://raw.githubusercontent.com/MarShaikh/carryon/main/docs/demo/demo.gif)

## Install

```bash
pipx install agent-carryon
```

`uv tool install agent-carryon` works too. The package is `agent-carryon`; the
command is `carryon`. You need macOS or Linux, Python 3.9 or newer, and
`openssl`, which both already have. carryon has no Python dependencies.

## Two machines, five commands

You also need a [Destination](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md): somewhere both machines can reach.
A synced folder (Dropbox, Google Drive, iCloud Drive, Syncthing) is the
simplest. A private git repository works too, and so does anything rclone
reaches: `init` can set up Cloudflare R2, Amazon S3, Google Cloud Storage or
SFTP for you. See [Cloudflare R2 through rclone](https://github.com/MarShaikh/carryon/blob/main/docs/guide.md#cloudflare-r2-through-rclone).

Every command that changes something prints a plan first and does nothing
until you add `--apply`. Run it without, read the plan, then run it again.

### On the first machine

```bash
carryon init --dest ~/Dropbox/carryon
```

`init` checks the Destination works, stores a new master key in the OS
keychain, and prints your recovery key once:

```
Your recovery key - shown once, never stored by carryon:

    R5EB-RK4X-YNQE-L2UN-2IFV-4F76-HWQY-KCDW
```

Put it in your password manager now. If every machine loses its key, it is the
only way back into your [Archive](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md). There is no reset.

```bash
carryon push --apply
```

This seals your Setup and every [Session](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) into the Archive at the
Destination. If the scan recognises a credential, push names the file and
carries it encrypted:

```
Setup: pushed, encrypted (Claude Code)
  possible secrets in 1 file, carried encrypted:
    .claude/settings.json (anthropic-key)
History: 24 Sessions pushed (0 unchanged), 8 project memories pushed (0 unchanged)
```

```bash
carryon pair
```

`pair` prints a one-time code and the command to run on the other machine.

### On the second machine

```bash
carryon init --join PRET-805J-98XQ-2NVD --dest ~/Dropbox/carryon
carryon pull --apply
```

Joining takes the master key from the Destination, wrapped under the code, so
you never type or copy the key itself. The code works once, within 24 hours.

`pull` adds the Archive's Sessions to this machine's and replaces the Setup,
backing up anything it overwrites to `~/.carryon/backups/`. It never deletes
anything, and it skips a file another tool owns, such as a dotfiles symlink,
and tells you which.

## After that

```bash
carryon status          # what is out of step, and the command that fixes it
carryon sync --apply    # carry the History both ways: pull, then push
```

Nothing runs on its own; carryon has no background process. `sync` moves only
the History. After changing settings or skills, push the Setup deliberately
with `carryon push --apply`, and take it on the other machine with
`carryon pull --apply`.

If you lose a machine's key, run `carryon pair` on another machine and join
again. If no machine has the key, `carryon init --recover` takes the recovery
key.

## Why carryon

Other tools carry a coding agent between machines. Most carry Claude Code
only, or carry Sessions only. As of October 2026:

| Tool | Agents | What moves | Where it goes | Encryption |
| --- | --- | --- | --- | --- |
| carryon | Claude Code, Codex CLI, Cursor, `~/.agents` | chat sessions and project memory for Claude Code and Codex; settings, skills and instructions for all four | a synced folder, git, or rclone (R2, S3, GCS, SFTP, ...) | always; the key moves by a one-time code, with a recovery key |
| [claude-sync](https://github.com/tawanorg/claude-sync) | Claude Code | Sessions and memory, and by default settings, skills, agents and plugins | R2, S3, GCS, S3-compatible, WebDAV | always (age); the same passphrase on each machine, or a copied key file |
| [claude-code-sync](https://github.com/perfectra1n/claude-code-sync) | Claude Code | History, settings, skills, agents, memory | git | not built in |
| [claude-brain](https://github.com/toroleapinc/claude-brain) | Claude Code (a plugin) | memory, skills, agents, rules, settings; not transcripts | git | optional (age) |
| [codex-claude-transfer](https://github.com/ahmojo/codex-claude-transfer) | Claude Code, Codex | Sessions; memory if asked | a bundle file you copy, or LAN sync | optional (age) |
| [entangle](https://github.com/gowtham-sai-yadav/entangle) | Claude Code, Codex, opencode | one Session to anyone; a whole machine for Claude Code only | a direct transfer by a three-word code, or a file | in transit; likely secrets scrubbed |

What carryon does that these do not, together:

- One Archive holds the chat sessions and project memory of Claude Code and
  Codex CLI, and the settings, skills and instructions of those two, Cursor
  and `~/.agents`.
- No passphrase to choose and no key file to copy. `pair` hands the key over
  under a one-time code.
- Project memory that two machines both changed is kept aside for
  `carryon resolve`, not overwritten.
- Paths under `$HOME` need no mapping. They are rewritten to a neutral form on
  push and expanded against the new home on pull.
- Every change is a plan first, and nothing happens without `--apply`.

What it does not do: it never syncs on its own (claude-sync and claude-brain
can, through hooks), it does not hand a live Session to someone else
(entangle does), and it does not turn a Codex Session into a Claude Code one
(codex-claude-transfer does).

## More

- [docs/trust.md](https://github.com/MarShaikh/carryon/blob/main/docs/trust.md): what is encrypted, what a Destination can
  and cannot see or do, the recovery key, and pairing.
- [docs/guide.md](https://github.com/MarShaikh/carryon/blob/main/docs/guide.md): what moves for each agent, choosing what
  moves, every command, Destinations, conflicts, and what each refusal means.
- [docs/development.md](https://github.com/MarShaikh/carryon/blob/main/docs/development.md): tests, adding an agent,
  platform support, releasing.
- [CONTEXT.md](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) defines the terms, and [docs/adr/](https://github.com/MarShaikh/carryon/tree/main/docs/adr)
  records the reasoning behind each decision.

## Licence

MIT. Credential detection rules ported from
[entangle](https://github.com/gowtham-sai-yadav/entangle)
(MIT, © 2026 Gowtham Sai Yadav); see `LICENSE`.
