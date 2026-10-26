# carryon

Carries an AI coding agent's working life between machines: the
[Setup](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) that makes an agent yours (settings, skills, subagents,
instructions, plugin lists) and the [History](https://github.com/MarShaikh/carryon/blob/main/CONTEXT.md) of what you did with
it. Both are encrypted before they leave the machine.

Works with Claude Code, Codex CLI, Cursor and the `~/.agents` skills
convention. A History moves for Claude Code and Codex.

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
simplest. A private git repository or an rclone remote works too.

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
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport)
(MIT, © 2026 Gowtham Sai Yadav); see `LICENSE`.
