# carryon defers to whatever already owns a path

A pull replaces a Setup (ADR-0002), and plenty of people symlink their agent
config out of a dotfiles repo — stow, chezmoi, yadm, a bare git checkout. Copying
onto an already-symlinked path writes *through* the link and silently edits that
repo, surfacing only as an unexplained dirty tree much later.

So restore treats any path something else already holds as **externally owned**:
it is skipped and named in the report, never written. A symlink to somewhere
carryon does not manage is the case this was written for, but the question is
who else holds the name, and a symlink is only one way to hold it. A second
hard link to the same inode is not a symlink, resolves to itself, sits
comfortably under `$HOME`, and truncating it rewrites the file the other name
belongs to — verbatim the harm above by the one route the link check does not
see — so `st_nlink` is asked beside it. A path this machine will not answer
about at all, a symlink loop or a name it cannot spell, is treated as held for
the same reason: that is the fail-closed direction for a write. Reading is
unaffected and still goes through the link, so nothing is missing from the
Archive; it is writing that defers, wherever the writing happens. Restore is
where that was first written, and it is not the only leg with a write:
`capture --out` lands a Setup in a directory the user names and carryon does
not own the inside of, so a link planted at an item's landing path is this
document's harm by this document's own route. Both go through one writer
(ADR-0010), and the argument naming the output directory is asked the same
question one call earlier, because a root is the one thing a walk downward
from it cannot see.

`--force` overrides on the Setup leg, for people who mean it. A restored
History gets no such flag. `--force` says "write through a link I own" about
paths this machine's Adapters declare, and a Session's members are named by the
incoming tar instead — so nothing about pulling a Transcript is a decision to
edit whichever repository a link in a project directory happens to point at.
The report says as much on every deferred member, rather than leaving a user
who has just watched the flag work on the Setup leg to go hunting for it here.

This generalises behaviour carryon already had in one place. `do_skills` classifies
a symlink pointing outside the shared skills store as *external*, on the reasoning
that whatever owns it will restore it but the skills installer will not, so it
"must be named rather than quietly counted as handled." That reasoning was never
specific to skills.

## Consequences

Restore order between carryon and a dotfiles manager stops being load-bearing.
The overlap was hazardous because both tools claimed the same files and whichever
ran last won; deferring to the owner removes the race without having to assign a
single owner per file — and it works for tools carryon has never heard of.

A user whose entire Setup is symlinked will see a pull that writes almost nothing
and reports almost everything. That is correct, and the report has to make it
obvious rather than reading like a failure.
