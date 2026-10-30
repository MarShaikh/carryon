# A Handover goes where no vendor importer does, and carries the conversation

Everything carryon does so far moves one agent's working life between machines.
The other move people ask for is between agents on one machine: someone who has
done six months of work in Codex wants to open Claude Code and carry on. An
earlier version of this idea was dropped because vendors reorganise their
directories without notice, and a tool that hard-codes two layouts breaks
whenever either one moves.

Two things have changed since. Codex now ships an importer of its own, and an
experiment on a real machine showed the other direction is far smaller than it
looked.

## What is already covered

Codex's `/import` (CLI 0.140 and later; `externalAgentConfig/detect` and
`externalAgentConfig/import` on its app-server) takes a Claude Code install
apart and rebuilds it: instruction files into `AGENTS.md`, `settings.json` into
`config.toml`, skills, slash commands, MCP servers, hooks, subagents, project
memories, and up to fifty chats from the last thirty days, each resumable with
`codex resume`. It is code inside Codex, not the model, and OpenAI keeps it in
step with Claude Code's format because winning Claude Code users is the point
of it.

Nothing goes the other way. Anthropic ships no importer, and the published
migration guides for Codex to Claude Code all end in the same place: copy
`AGENTS.md` across by hand and rewrite what the sessions decided.

## The experiment

Two Codex rollouts from this machine (CLI 0.128.0; 96 and 587 lines) were
converted into Claude Code Sessions and resumed with `claude -p --resume <id>`
on Claude Code 2.1.312. Each was asked, with tools off, something only the
original conversation could answer, and each answered it: what the user was
building, what had gone wrong, what had been reverted. Both resumed under the
UUID written for them.

What was written is the oldest and plainest part of Claude's format and nothing
else: user and assistant records alternating, each with `uuid`, `parentUuid`,
`sessionId`, `timestamp`, `cwd`, and one text block. None of the twenty-odd
fields a live Claude record carries — `requestDigest`, `shapeHash`,
`serverClassifierRequest` — was needed, and none of the record types that are
not conversation at all.

Codex's tool calls became lines of text inside the assistant's turn — `[ran
exec_command: pytest]` and the first few hundred characters of output — and its
reasoning was dropped, because Codex stores it as `encrypted_content` and there
is nothing to carry.

## The decision

A **Handover** carries a Setup or a Session from one agent to another on the
same machine. carryon builds one only in a direction no vendor importer
covers, and for the directions one does, it names the importer and stops.
Today that means Codex to Claude Code is carryon's, and Claude Code to Codex is
`/import`'s.

A handed-over Session is a **new Session in the target agent**, written as
conversation only. It is lossy on purpose. A Transcript that replayed Codex's
`function_call` records as Claude `tool_use` blocks would show the model results
from tools it does not have, under ids it never issued, and would lean on the
part of the format that changes most. Text is what both agents agree a
conversation is. The source is read and never written; the Codex rollout is
still there, still resumable in Codex, afterwards.

A handed-over Setup goes through the target agent's own front door wherever it
has one. An MCP server is added with `claude mcp add`, not by editing
`~/.claude.json`, which is Claude Code's state file and not carryon's to
rewrite. Instructions are added beside what is there and never replace it: a
`CLAUDE.md` that already exists is the user's, so a Codex `AGENTS.md` is
reached from it by an `@AGENTS.md` line rather than pasted over it. That is
ADR-0007's rule reached by a different route. Something already holds the
name, so carryon defers to it.

## Layout drift is the safety net, not a state file

Detecting what a vendor moved needs no new mechanism. Every Adapter already
records what it was `verified_against`, and `doctor` already reports
**Layout drift** when an install holds something its Adapter has never heard
of. A Handover records two more versions: the source's session format it was
checked against, and the target's. Faced with a record type it does not know,
it carries the conversation it does know, names what it left out, and does not
guess. Faced with a target version it was not checked against, it says so
before writing, the same way `doctor` treats a platform it was not verified on.

When it does break, the report names both agent versions and the record that
stopped it, and prints a link to open an issue with that text already filled
in. It never includes the Transcript, which is the user's History and goes
nowhere they did not send it.

## Considered options

**Discover the layout at run time by matching directories.** Both agents keep
a base directory and both keep their sessions in JSONL, so match
`~/.codex/sessions` to `~/.claude/projects` by shape. Rejected because finding
the files was never the hard part — both locations are already in the Adapters
— and the hard part is what is inside them. A guessed mapping that writes a
Session Claude opens with the wrong content is worse than one that refuses,
which is ADR-0001's reasoning about a Setup applied to a Transcript.

**An agent skill that does the Handover.** Ship a `SKILL.md` and let whichever
agent the user is in read `~/.codex` and rebuild what it finds. It adapts to
drift for free, which is its whole appeal. Rejected as the mechanism because
two of its jobs are rules, not judgement: never copy `auth.json`, and never
overwrite a file the user owns. A skill states a rule; it cannot hold one. It
also writes a different `CLAUDE.md` each run. A skill may still be a front end
that calls carryon, which is a separate decision.

**Report breakage to infrastructure that spins up an agent to fix it.** It
answers the right worry — layouts will change — with machinery sized for a
problem that arrives a few times a year. A prefilled issue reaches the same
people with nothing to run.

**Summaries instead of Sessions.** Write each Codex Session out as a markdown
note Claude Code reads at start. Robust against any format change, and the
fallback if the target ever stops accepting a written Session. Rejected as the
default because the experiment showed a resumable Session costs almost nothing
more and keeps the turn-by-turn record a summary throws away.

**A shared memory layer both agents read over MCP.** Products like MemoryLake
store decisions once and serve them to every agent. That answers the question
after a switch, not the switch itself: it reads neither agent's Sessions, so the
history the user has already built stays where it is.

## Consequences

`carryon` gains a move that needs no Destination, no key and no network, and
nothing leaves the machine. Encryption has nothing to protect here, so a
Handover is the one carryon move that does not seal anything. The credential
scanner still runs over what a Handover writes into a Setup, and still
*reports* rather than refuses, as ADR-0014 settled for both halves.

A handed-over Session is an ordinary Claude Code Session from then on, so the
next `push` carries it like any other. The Archive will hold the Codex original
and its Claude copy as two Sessions. That duplicates content, encrypted, and is
correct: they are two Sessions in two agents, and either can be extended
without the other.

Handing the same Session over twice must not make two copies. The target
Session's UUID is derived from the source's, so a second Handover lands on the
same name and the write refuses it. Nothing records what was handed over, so
there is no record to lose. (The first draft of this ADR kept such a record
beside the High-water mark; the derived name made it unnecessary.) The target
file is the target agent's once written, because resuming it appends to it,
and carryon never writes it again.

Like everything since ADR-0015, a Handover runs when the user asks for one and
never on its own.

This commits carryon to tracking one vendor format it did not before: Codex's
rollout records, read-only. The commitment is narrow. It reads four record
kinds and writes the plainest records Claude Code has, and Layout drift tells
the user and the maintainer the day either one moves. If Anthropic ships an
importer, this direction becomes `/import`'s too, and carryon names it and
stops.
