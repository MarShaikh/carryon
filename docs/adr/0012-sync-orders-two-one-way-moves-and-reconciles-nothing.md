# sync orders two one-way moves and reconciles nothing

Two machines used in turn — a work one and a home one — need the same two
commands in the same order every day, and the order is not obvious. Push
first and a Session the Archive is ahead on is skipped as BEHIND
(`_push_skip_reason`); the pull that follows unions it, and the merged copy
this machine now holds does not reach the Archive until the *next* push. So
push-then-pull leaves the Archive a round stale, silently, and the user who
typed both commands has every reason to think they are done.

`sync` is that order, made not-a-choice: pull, then push. It is a
convenience in the way a seatbelt is.

## It is not a convergence protocol, and ADR-0002 stands

ADR-0002 opens by saying carryon carries state one way and that there is
deliberately no convergence protocol. `sync` does not add one. It supplies no
merge rule, negotiates nothing, and each half keeps the granularity ADR-0002
already gave it. What makes a loop of two one-way moves converge at all is a
fact recorded in CONTEXT.md rather than any new machinery: **a Session belongs
to one machine at a time**. Two machines produce two sets of UUIDs, a union by
UUID has nothing to reconcile, and continuing your own Session on the other
machine is the byte-prefix case the union rule was written for.

Where that fact does not hold, `sync` does not help and must not pretend to.
Resume one Session on both machines at once and neither transcript is a prefix
of the other: pull files the Archive's copy under `~/.carryon/conflicts/` and
keeps yours, push then skips it as DIVERGENT, and running `sync` a hundred
times changes nothing. That is ADR-0002's missing protocol, still missing, on
purpose. The help text says so, because a command called sync that quietly
fails to converge is worse than no command.

## A History by default, because the Setup half is the out-of-scope one

ADR-0002's Consequences already rule on carrying a Setup both ways: protecting
machine-specific tweaks means per-machine overrides, "which is two-way sync in
everything but name and is out of scope". A `sync` defaulting to everything
would put that in a loop and run it daily.

The damage is narrower than it first looks — `_setup_writes` emits one write
per stored file, so a restore overwrites same-named files and adds new ones
and sweeps nothing (CONTEXT.md's "Replace" ambiguity is about exactly this
misreading). But narrower is not nothing, and the sharpest instance is a file
carryon carries on purpose: `.claude/settings.local.json`, declared in the
adapter as *local overrides*. Two machines have it under one name by
definition, so a wide sync flattens the file whose whole job is to differ,
every run, in whichever direction pushed last.

A History has no such problem: union by UUID, union again per member, nothing
under `$HOME` unlinked, and a real divergence set aside rather than resolved.
So `sync` defaults to `--category history` — the loop that is safe to run ten
times a day — and widening it is something a person types.

What `sync` does **not** do is special-case anything inside a category it was
given. If it excluded `settings.local.json` while `pull` carried it, one
question would have two answers depending on which command you typed, which is
the shape ADR-0010 exists to prevent. `sync` differs from its two halves in
exactly one respect: its default.

`all` is taught to the shared category parser rather than to `sync`, so
`--category all` means the same thing to all three commands and `sync` grows
no vocabulary of its own.

## A divergence is an exit code now

`pull` returned non-zero only when the Setup was denied. A divergent Session —
the one outcome that genuinely needs a person, because only they can decide
what two transcripts of one conversation mean — printed a line and exited 0.
That was survivable while pull was something you watched. It is not survivable
under a command built to be run in a loop, and it is exactly wrong for the
scheduled runs `sync` invites next: a report nobody reads is not a report.

So a landed divergence makes `pull` non-zero, and `sync` inherits it by
propagation rather than by inventing a channel of its own. The exit code's
meaning does not change — it has always been "something landed that a person
has to deal with" — only the set of things that qualify. The cost is a
user-visible contract change and every assertion that pinned `pull(...) == 0`
while meaning "the pull worked"; each had to say which it meant - the ones in
divergence scenarios now assert the new code, and the union-only ones keep
their 0 with the meaning stated.

Between the halves, `sync` carries on past a non-zero **return** and never
past a **raise**. The distinction is already load-bearing everywhere else in
this package: a refusal raises `SystemExit`, and a thing-to-look-at comes back
as a code. Stopping on a conflict would let one divergent Session block the
publication of everything else, which is the opposite of what the user wants
from the command; stopping on an unreachable Destination is not a decision
anyone has to write, because the exception ends the command.

## Consequences

**There is no "remote" precondition, because there is no such axis.** A plain
directory is a first-class Destination and always has been (ADR-0011: carryon
can remove the second tool, not the storage). The real preconditions — a
configured Destination and a master key — are enforced already by
`_open_destination` and `_require_master`, with the sentences a user needs.
Requiring an Archive to pre-exist was considered and rejected: the first
`sync` on the founding machine is what creates one.

**Stale things still accumulate.** Rename a skill on one machine and the old
name survives on the other, for ever. `sync` runs the union more often, so it
reaches that state sooner. The cure remains `--mirror`, still deferred by
ADR-0002 and still gated behind ADR-0010's removal scanner.

**Automation is now the obvious next request and is not this decision.**
Running unattended raises questions this ADR does not settle — what may run
with nobody at the checkpoint, and whether a conflict should notify rather
than merely exit non-zero. The exit code above is the groundwork for it and
not the thing itself.
