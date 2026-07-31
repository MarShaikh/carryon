# Pull unions a History and replaces a Setup

carryon carries state one way: a machine publishes, another lays it down. There
is deliberately no convergence protocol. But "the newest push wins" is only
unambiguous when the receiving machine is empty, which is true for a migration
and false for every use after it. Applied at whole-snapshot granularity it would
destroy sessions the receiving machine had and the snapshot didn't.

So `pull` resolves at different granularity per part, and the granularity is
the rule rather than a detail of it. A **History** is unioned by Session UUID,
and within a Session it is unioned again, **member by member**. A Session is a
tree and not a file (CONTEXT.md) — the main Transcript plus the dozens of
subagent transcripts and workflow journals beneath it — so each member is
compared with the file it is about to land on, and that comparison decides that
member and nothing else: the incoming file replaces the local one only when the
local file is a byte-prefix of it — the append-only case — or when there is
nothing there at all; where the local file is the longer of the two it stays,
and the incoming bytes are already inside it; and where neither extends the
other both are kept, the incoming copy under `~/.carryon/conflicts/` where
discovery will not mistake it for a Session of its own, and the collision
reported. A member only this machine holds is not a collision at all and is
left where it is. Nothing under `$HOME` is unlinked by a pull.

The rule is asked per member and never per tree, and that sentence is the point
of this ADR rather than a refinement of it. Asked of the main Transcript and
then acted on across thirty files, it answers a question nobody put: two
machines resuming one Session each grow Transcripts the other never saw while
their mains stay in a clean prefix relation, which is the ordinary shape and
not the corner, so a main that is behind says nothing about whether the subtree
is a subset. Stated at tree granularity the rule reads exactly the same and
permits deleting a journal only one machine ever had.

The main Transcript still decides one thing above the members: when the two
mains have *diverged* the incoming tree is not laid over the local one at all.
The whole of it goes to `~/.carryon/conflicts/<uuid>/` and the local Session is
left untouched, because a Session whose main conversations have forked is two
Sessions sharing a UUID rather than one that grew. Every other case lays the
tree down and asks the rule of each member in it. The per-project memory that
accretes beside a project's Transcripts is part of a History too (CONTEXT.md),
and takes the same rule per file.

A **Setup** is replaced item by item: every file the stored MANIFEST names is
overwritten, after a copy of what was there goes to a timestamped backup under
`~/.carryon/backups/`, and a file the MANIFEST does not name is left alone.
Wholesale is what a Setup *means* — the newest desired state wins — and not
what a pull does to a directory, since removing what the Archive no longer
carries is `--mirror`'s job on this half as well. Items some other tool owns
(ADR-0007) and items a stored MANIFEST names that this machine will not take
(ADR-0009) come out of that set too, and are reported rather than written.

The asymmetry is deliberate and is not inconsistency. A Setup is a *desired
state*, so the newest one legitimately wins. A History is an *accumulation*, and
nothing about a Transcript being older makes it less true.

The union rule is not pull's alone: it governs push too, and the symmetry is
plain — the Archive's copy of a Session is replaced only when the local one is
strictly ahead of it. Ahead is asked of the tree there, member by member and
over the same canonical bytes pull compares: every member the Archive holds
must be present here, and this machine's copy of each must begin with the
stored bytes. It is settled over the tree because the tree is what push
replaces — an Archive object is one sealed tar (ADR-0003), so there is no
member to write in isolation and no way to be ahead on part of it. A machine
that never pulled, or pulled long ago, is *behind*, and letting its push win
would overwrite the longer Transcript with the shorter one in the only copy
that is not on the other machine. Behind and divergent are both skips,
reported by name and never raised, with the same cure — pull first: a machine
that is behind catches up, after which its pushes go through again, while a
divergent pull lands the Archive's copy in the conflicts directory and keeps
the local one put, so neither copy ever overwrites the other.

A project's residue takes that same rule on the way out, and for the same
reason rather than as a courtesy extended to it: the memory that accretes
beside a project's Transcripts is part of a History, so it accumulates, and a
machine holding a byte-prefix of what the Archive has — the textbook behind
case the Session beside it is protected from — must not truncate it there. It
is asked the way a Session is asked, over the tree and member by member,
because a residue is one sealed object too: every member the Archive holds has
to be here and to be extended here, or the push skips it by name with the same
cure.

## Consequences

**Pull never deletes, and "never" is per member.** A Transcript this machine
holds and the Archive does not survives a pull, and so does one this machine is
ahead on; both are named in the report rather than left to be inferred from the
absence of a line. Rename a skill on one machine and pull to another, and the
old name survives there. Divergence accumulates quietly. The cure is a
`--mirror` mode that does delete, deliberately not built yet — and the one case
that genuinely wants it, a member the Archive now carries under a new name, is
exactly the case a union cannot tell apart from an addition.

**Machine-specific Setup tweaks are lost on pull**, recoverably from the backup,
for each file the stored MANIFEST names. Protecting them properly means
per-machine overrides, which is two-way sync in everything but name and is out
of scope.
