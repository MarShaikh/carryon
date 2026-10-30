# A session end pushes the History, and nothing else runs on its own

ADR-0015 turned automation down. A scheduled `sync` would break in places the
user cannot see, and a run that needs a person has no way to reach one. What
was built instead was `carryon status`. That left the most common complaint in
the sync requests on Claude Code's tracker
([anthropics/claude-code#22648](https://github.com/anthropics/claude-code/issues/22648))
standing: syncing happens only when you remember to. The tools people build
instead sell exactly that, a push when a session ends.

So carryon gains an opt-in `carryon hooks install`. It registers two Claude
Code hooks. When a session ends, carryon pushes the History. When a session
starts, it prints one line to the person if something is waiting. That is the
one exception to plan-then-`--apply`, and this record sets its limits. It was
grilled on 2026-10-30 (#36).

## Why a hook is not the schedule ADR-0015 rejected

A hook fires because a person just closed their own agent session, on a
machine they are logged in to, from a process started from their own shell.
Most of what sank the schedule does not arise:

- `PATH` is the agent's, which is the person's. It is not a LaunchAgent's
  `/usr/bin:/bin:/usr/sbin:/sbin`.
- The keychain is unlocked, because someone is at the machine.
- There is no clock. Nothing runs while nobody is using an agent.

What ADR-0015 said still holds. A run that needs a person has no channel to
one, and two runs can overlap. The rest of this record answers those two.

## Only the History, only a push

A session end runs `push --category history --apply`, the whole History. It
does not push only the Session that ended. Sessions are only ever added, and a
push skips a Session the Archive is ahead on or that diverged, so the
unattended push writes nothing a typed one would not.

It never pushes the Setup, because a Setup push publishes this machine's
configuration to every other machine. It never pulls, because a pull replaces
the Setup (ADR-0002). Both stay deliberate steps.

## Session end starts a detached push and returns

Claude Code gives a `SessionEnd` hook 1.5 seconds by default and cancels it
after that. Codex allows 1 second, 3 at most, and Cursor does not wait at all.
A push cannot finish in that time. So `carryon hook session-end` starts the
push as a fully detached process with its own timeout of about two minutes,
and returns at once. The agent's budget never decides whether a push finishes
halfway.

It hooks `SessionEnd` for every reason, since `/clear` and `/resume` also end
a Session. It does not hook `Stop`, which fires after every turn. A push after
every turn would need a debounce, and a debounce is a timer. The docs do not
say whether a session end fires when a terminal closes. A Session missed that
way goes with the next session end or a typed `sync`, and `status` shows it
meanwhile.

## The lock ADR-0015 promised

ADR-0015 said that if anything ran carryon on its own, a lock would come with
it. Two sessions ending close together start two detached pushes, and a hook
can fire while someone types `sync`. Either could write the Index and the
High-water mark out of order.

So every command that writes to the Archive takes one lock in `~/.carryon/`.
A hook that finds it held exits quietly, and the next session end pushes. A
typed command waits a few seconds, then refuses with a sentence naming the
lock, because a person who typed a command should hear why it did not run.

## Failure is silent where it happens and reported where someone looks

A hook must never block or slow the agent. It always exits 0, never prompts,
and gives up at its timeout. Being offline, an unreachable Destination, a
locked keychain and a missing config all end the same way: no output to the
agent and one line in `~/.carryon/hook.log`.

A failure nobody hears about is ADR-0012's report nobody reads. So `status`,
and the session-start line, say when the last automatic push failed and why.

## Session start reads what the last session end recorded

A live `status` at session start costs a round trip to the Destination, and
Claude Code holds the model's first reply until the hook finishes. ADR-0015
deferred this hook on exactly that cost. So after its push, the detached
session-end job runs the `status` check and records the result in
`~/.carryon/`. At `startup` and `resume`, the hook reads that record and
touches no network. The cost is staleness: a push from another machine since
the last session end goes unseen until the next one.

The line goes to the person through `systemMessage`, never to the model.
Plain stdout from a `SessionStart` hook enters the model's context, and an
agent told that a Setup is waiting could run `pull --apply` itself. That would
undo the one thing this record keeps deliberate.

## Installing edits a file carryon carries

`hooks install` writes into `~/.claude/settings.json`. That is new for carryon:
until now it owned nothing in an agent's configuration (ADR-0011). So it
behaves like every other command. It prints the change and writes only with
`--apply`. It merges into whatever hooks are there and keeps every other key,
and it finds its own entries by their command, so installing twice changes
nothing and `uninstall` removes only those.

The Setup carries `settings.json`, so the hook travels: opting in on one
machine opts in wherever that Setup is pulled. Nothing is special-cased at
capture, for the reason ADR-0012 gave about `settings.local.json`. One file
should not mean two things depending on the command. Uninstalling and then
pushing the Setup opts out everywhere. Because the hook travels, its command
cannot hold an absolute path, and on a machine without carryon it must stay
quiet:

```
command -v carryon >/dev/null 2>&1 && carryon hook session-end || true
```

## Consequences

**`status` says the Setup changed here right after an install,** because it
did. `hooks install --apply` says to push the Setup so the hook reaches the
other machines.

**Claude Code first.** Codex has the same two events and a user-facing
message, but caps a session end at 3 seconds, asks the person to trust each
new hook, and keeps hooks in a file carryon does not carry unless they are
written inline in `config.toml` (#44). Cursor has the events, but no
documented way to show the person a line at start (#45).

**A Session can wait one session to be pushed.** An end that never fires
(terminal closed, a crash) costs nothing but delay, and `status` reports it.

**The session-start line can be stale.** It is as fresh as the last session
end on this machine, never fresher.

**Nothing else runs on its own.** The rest of ADR-0015 stands. There is no
schedule, no daemon, no relay, and no unattended pull or Setup push.
