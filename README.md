# carryon

Move an AI coding agent setup to a new machine.

Your agents accumulate a setup — settings, skills, subagents, instructions,
plugin lists. None of it is in the cloud. Copying the folders across does not
work, and copying them *carelessly* is worse, because those folders also hold
credentials and machine identity.

`carryon` takes the part that should travel, refuses to take anything that
looks like a credential, and writes down what it deliberately left behind.

```bash
carryon doctor                                   # is my layout still recognised?
carryon list                                     # what would be captured
carryon capture --out ~/agent-state              # dry run, writes nothing
carryon capture --out ~/agent-state --apply      # write it
```

No dependencies. Python 3.9+. Dry-run by default.

## What it does not do

It does not move chats, sessions or transcripts.

That is a genuinely different problem — transcripts have the old machine's
absolute paths written inside them, and they record everything ever printed to
your terminal, which sooner or later includes a token. It needs path re-keying
and redaction, and [entangle](https://github.com/gowtham-sai-yadav/claude-teleport)
already does it well across Claude Code, Codex and opencode.

Use both. `carryon` for the setup, `entangle` for the history. The generated
`RESTORE.md` gives you the order, including the part that bites: if you also
restore curated memory from somewhere else, run entangle **first**, or its
verbatim copy overwrites your curated one.

## Install

```bash
pip install agent-carryon        # the command is still `carryon`
```

Or run it from a clone — there are no dependencies:

```bash
git clone https://github.com/marshaikh/carryon && cd carryon
python3 -m carryon.cli doctor
```

## Commands

### `doctor` — check before you migrate

```
$ carryon doctor
Layout check on darwin

  Claude Code  (claude-code)
    verified against : Claude Code 2.1.220, macOS 15
    platform         : darwin, verified
    unrecognised     : 1 entries
                       brand-new-feature
```

`doctor` reports anything in an agent's directory that no adapter describes.
That is how a vendor's layout change first becomes visible — a new directory
appears, and you find out *before* you migrate rather than after.

Nothing unrecognised is ever captured. An unknown entry is a prompt to update
the adapter, not a failure.

### `list` — what would be captured

```
$ carryon list
  [x] claude-code          Claude Code
        config      settings.json
        capability  skills, installed_plugins.json, known_marketplaces.json
  [x] codex                OpenAI Codex CLI
        config      config.toml
```

### `capture` — build the bundle

```bash
carryon capture --out ~/agent-state --apply
carryon capture --out ~/agent-state --apply --archive ~/agent-state.tar.gz
carryon capture --out ~/b --agent claude-code,codex --category knowledge --apply
```

| Flag | Effect |
| --- | --- |
| `--out DIR` | where the bundle goes (required) |
| `--apply` | actually write; without it you get a plan |
| `--agent A,B` | only these agents |
| `--category A,B` | only these categories |
| `--archive F.tar.gz` | also pack the bundle into one file |

The bundle contains `MANIFEST.json` (what was taken, what was left, and why)
and `RESTORE.md` (the order to do things on the new machine).

## The categories

They need genuinely different handling, which is why this is a taxonomy and not
a list of paths with include/exclude flags:

| Category | Examples | Treatment |
| --- | --- | --- |
| `config` | model, permissions, hooks, keybindings | copy |
| `capability` | skills, plugins, subagents, commands | prefer re-resolving from upstream over copying bytes |
| `knowledge` | global instructions, memories, rules | copy — this is the irreplaceable part |
| — | sessions, transcripts, prompt history | not this tool's job |
| — | auth tokens, machine ids, caches | never migrated |

## Re-resolve, don't copy

A skill installed from a repo should be re-installed on the new machine, not
copied — copying pins a stale version and re-imports whatever was already
broken. A skill you wrote yourself has no upstream and is the only thing a
mistake destroys permanently.

`carryon` tells them apart structurally. In `~/.claude/skills`, entries that
are symlinks into the shared `~/.agents/skills` store are recorded as
re-resolvable; real directories are carried. On the machine this was built
against that was 11 re-resolvable and 3 that existed nowhere else.

## Secrets

The scanner does not mask, it **refuses**. A config bundle should contain no
credentials at all, so a hit means the capture list is wrong — and a bundle
that needs cleaning up afterwards is one you will eventually forget to clean.

`tests/test_secrets.py` plants 18 fake credentials and asserts every one is
caught, then asserts 12 documentation placeholders are not. Both halves matter:
a scanner that fires on every `api_key=os.environ["KEY"]` in an SDK doc is one
you learn to click through, and that is how a real key eventually gets out.

Two fixtures exist because the first version got them wrong.
`client_secret=exampleXK92mfQ7zLpR4` and `API_KEY=os.environ_backup_KEY_9f8e`
were being suppressed as placeholders by a prefix match. The suppression now
uses `fullmatch`.

## Moving the bundle to the other machine

The bundle is small — 31K on the machine this was built against — and contains
no credentials by construction, because `capture` refuses to finish if it finds
one. So it is safe to put in a **private git repo**:

```bash
carryon capture --out ~/agent-state --apply
cd ~/agent-state
git init && git add -A && git commit -m "agent setup"
git remote add origin git@github.com:you/agent-state.git   # private
git push -u origin main
```

Then on the new machine:

```bash
git clone git@github.com:you/agent-state.git
cd agent-state && cat RESTORE.md
```

Or skip git and move one file:

```bash
carryon capture --out ~/agent-state --apply --archive ~/carryon.tar.gz
# AirDrop / USB / scp it, then:
tar xzf carryon.tar.gz && cat agent-state/RESTORE.md
```

**Private, not public.** Nothing in the bundle is a credential, but it is still
your settings, your instructions and your hand-written skills.

**Never do either of these with the entangle chat bundle.** `entangle export`
does not redact — only `share` and `send` do — so the `.tgz` it produces holds
raw transcripts. Move that one by USB or `entangle send`, and delete it after
import.

## Platform support

The code is platform-neutral: `Path.home()` and paths relative to it, no
hardcoded roots. What is *verified* is narrower, and each adapter declares it:

| Platform | Status |
| --- | --- |
| macOS | verified — every adapter was built against a real setup |
| Linux | unverified, expected to work; agents use the same `~/.claude` style paths |
| Windows | unverified. Paths are probably right; the symlink split degrades to carrying everything, which loses nothing but copies more |

`doctor` tells you when you are on a platform an adapter has not been checked
on. If you run it somewhere new and it works, a PR updating `platforms=` is the
most useful thing you can send.

## Adding an agent

Drop a module in `carryon/adapters/` defining `ADAPTER`, and list it in
`MODULES`. No engine changes — the capture logic reads the declaration.

```python
from .base import CONFIG, KNOWLEDGE, Adapter, Excluded, Item

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
    exclude=(
        Excluded(".myagent/token", "CREDENTIAL", "log in again"),
    ),
    known_entries=("config.json", "token", "cache"),
)
```

Three fields carry the weight:

- **`verified_against`** — the version and OS you actually checked. An adapter
  written against a guess is worse than no adapter: it fails silently, and the
  user finds out on the machine they have already migrated to. This is how
  Mackup died — it symlinked app-support directories wholesale and broke as
  formats and sandboxing changed underneath it.
- **`required=True`** — for paths an installed agent should always have. If one
  goes missing, `capture` reports layout drift instead of quietly capturing
  less than you expect.
- **`known_entries`** — every top-level name you know about, captured or not.
  Anything else shows up in `doctor`. fnmatch patterns work, so `daemon*`
  covers a family.

Verified adapters: Claude Code, Codex CLI, Cursor, and the `~/.agents`
cross-agent skills convention.

## Tests

```bash
python3 -m pytest tests/ -q     # if you have pytest
python3 run_tests.py            # if you do not - a fresh Mac has neither
```

24 tests. Capture, layout and transport tests run against a fake `$HOME` built
in a temp directory, which is the only sane way to test a tool whose failure
mode is damaging a real one.

## Licence

MIT. The credential detection rules in `carryon/secrets.py` are ported from
[entangle](https://github.com/gowtham-sai-yadav/claude-teleport) (MIT, © 2026
Gowtham Sai Yadav) — see `LICENSE` for the notice.
