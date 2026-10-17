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

## An edit is judged against the Base

> Amendment, 2026-10-17.

The prefix rule assumes a file only grows. Transcripts do. Per-project memory
does not: an agent rewrites a line of `MEMORY.md` in place as often as it adds
one. Under the prefix rule, that edit became a divergence the moment it was
made, and the divergence never ended. Push skipped the project and said "pull
first". Pull filed the Archive's copy as a conflict and kept the local one. The
next push compared against the same stored copy and skipped again. This
happened on the first real Archive: a project's memory stayed frozen at its
first push while the skip line kept naming a cure that could not work.
Mirrored, the same bug is worse: another machine's in-place edit reached this
one only as a filed conflict, and the stale local copy stayed put.

So each per-project memory file has a **Base**. That is the canonical hash of
the version this machine and the Archive last agreed on, kept in
`~/.carryon/state.json` beside the High-water mark and keyed by Destination,
project and file. Compared with its Base, a file can be in one of three states.
If only this machine has moved off the Base, this machine's copy wins: push
replaces the stored copy, and pull keeps the local one. If only the Archive has
moved, the Archive's copy wins: pull writes it, and push skips the project,
because push replaces the stored tree whole. This time "pull first" works:
the pull lays the other machine's edit down, and the push after it goes
through. If
both have moved, the file has diverged: the prefix rule runs as before, and a
conflict stays a conflict. A file with no Base, whether recorded or readable,
gets exactly the old prefix rule. A missing Base can only make carryon more
cautious.

The Base is asked first, and the prefix rule only when the Base does not
decide. Suppose another machine deletes the last line of a file. Its copy is
now a byte-prefix of this machine's. The prefix rule alone calls that 'this
machine is ahead', so pull keeps the old copy. Then this machine's push finds
that the Archive has moved and skips. Nothing would ever change, because each
leg would be applying a different rule to the same file.

A Base is recorded only with `--apply`, and only after the write it describes
has succeeded: on push once the Destination holds the file, and on pull once the
file is laid down or found the same or ahead. Pull never records one for a
conflict. A push or pull that finds a project's whole tree the same as the
Index records a Base for every file in it. That is how a machine that pushed
before the Base existed gets Bases before its first edit, rather than meeting
the bare prefix rule again. Pairing hands over no Bases, because a joining machine holds none of
the files. If `state.json` will not read, that is the High-water mark's rule:
one warning, and no Bases for that run.

It is per file rather than per project tree, although the Index already records
a hash per tree, because two machines that edit different files of one project
are the ordinary case. With a per-tree Base, one machine's added note would turn
the other machine's in-place edit into a divergence.

It covers per-project memory only. Transcripts are append-only, every divergence
seen in one so far was a genuine fork, and a Base for every member of every
Session would cost thousands of entries to answer a question nobody has hit. The
Base lives only on this machine, so adding it for Sessions later changes nothing
stored in the Archive.

Deletions are out of scope. A file missing locally while the Archive holds it
stays a skip, and here "pull first" does cure it: pull writes the file back.
Making a deletion stick needs `--mirror`, which is deferred for the reason given
under Consequences.

**The fetched residue must be the one the Index names.** A label binds which
object a blob is, not which version. Before the Base, an earlier authentic
residue served back was harmless: its files were prefixes of the local ones, or
conflicts, so pull kept the local copies. Under the Base it would win. The local
copy equals the Base and the replayed one does not, so pull would write
superseded memory over current memory at exit 0. So on both legs a fetched
residue's members are hashed and compared with the Index entry's `tree_hash`
before anything acts on them. A mismatch refuses that project by name and writes
nothing. This is `_main_mismatch` for a tree with no main Transcript. Keeping
the Index itself current is the High-water mark's job.

**A pull that writes over a local file backs it up first.** Under the prefix
rule a History pull never lost a byte, because the local file was inside the
incoming one. A Base-write replaces the local copy with another machine's edit,
and once that machine's push replaced the stored copy, the local version exists
nowhere else. It goes under the same `~/.carryon/backups/<stamp>/` as that
pull's Setup backup, and the report names it.

**A divergence ends when the user Resolves it.** Filing a conflict and keeping
it filed forever leaves the user with nothing to do. `carryon resolve <path>`
takes the local path of a memory file whose Archive copy was filed. It makes
the filed copy that file's Base, then removes the filed copy. Specifically, it
makes Base the hash that pull recorded, at filing time, of the canonical bytes
it compared. It does not re-derive the hash from the filed file, because the
file is expanded for this machine, possibly under `--map`, and expansion does
not always run backwards. The Base is written before the filed copy is
removed, and if it cannot be written nothing is removed. With no paths it lists the residue conflicts still filed. Without
`--apply` it only plans. The user is saying "my copy now includes theirs", which
in three-way terms means "theirs is my Base". The next push carries the merge.
If the Archive has moved again since the conflict was filed, the Base is stale:
the next run files a fresh conflict, and nothing is lost. Treating a filed copy
that has disappeared as resolved was rejected, because an accidental
`rm -rf ~/.carryon/conflicts` would then read as a merge of everything. So was
seeding Bases from the Index's `machine` field, because a machine name is
config, not identity. A filed Session conflict is refused by name, because
Sessions have no Base.

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
