# Handpicking is a config file, and user-added paths join the Setup only

The default has to be effortless, but people need to pick exactly what moves. That
lives in a config file written by `init`, with the existing `--agent` and
`--category` flags as one-off overrides. Not an interactive picker: carryon's job
routinely runs on a machine being driven over SSH, in CI, or freshly imaged, and
an interactive-first tool is useless in all three.

The config can exclude anything an Adapter declares, and can add paths no Adapter
knows about — which is what lets someone carry a tool carryon has never heard of
without writing an Adapter for it.

**A user-added path always joins the Setup, never the History.** A Setup is
fail-closed, so adding `~/.ssh` or `~/.aws` makes capture refuse and name the
file; the existing safety property protects the user for free. The same path in a
History would only be *reported* (ADR-0001), which is the right posture for
Transcripts an Adapter vouched for and the wrong one for a directory the user
pointed at by hand.

That protection has a limit, and the first version leaned on it past the
limit. carryon's own state directory holds the fallback master key as bare
hex, which matches no credential pattern — the scanner is tuned for keys that
announce themselves, and a random 256-bit value announces nothing — so the
fail-closed capture this ADR leans on would have carried the key that decrypts
the Archive's History into the Archive's plaintext half without a murmur.
`~/.carryon` is therefore unreachable by construction rather than guarded by
scanning: a handpicked path is resolved before it is judged, every symlink on
the way followed and case folded per component, so neither a link that lands
in `~/.carryon` nor `~/.Carryon` — the same directory under another spelling
on APFS and NTFS — reaches the key. A path that will not resolve at all is
treated as landing there, and the Setup's restore leg consults the same
function, so the two legs cannot drift into disagreeing about what
`~/.carryon` is. The History's restore leg asks a lexical version of the same
question, and the difference is who wrote the name it is judging rather than a
second opinion about the directory: ADR-0009 has why.

The rule is asked per member, not once per name. A handpicked path is a tree,
expanded after the judgment, and the capture engine reads a member link
through to its target — so an innocent `~/.mytool` with a link to the master
key planted inside it is the same leak one level down, and an adapter-declared
tree is as open to it as a handpicked one. Push walks the expansion, asks
again for every link it finds, and a hit refuses the whole Setup before
anything is copied anywhere — ADR-0001's posture, not a per-item skip, because
half a Setup published beside the master key is not a better outcome than
none.

Every rule above answers about a *name*, which is one alias short. A hard link
is a second directory entry for the same content: `ln ~/.carryon/master.key`
into a captured tree is not a symlink, resolves to itself, sits under `$HOME`
and nowhere near `.carryon`, and satisfies every path check on the way to
copying the key verbatim. What the two names share is the inode, so the walk
compares each file it is about to read against the identities of everything
under `~/.carryon`. A path rule cannot see an alias; only identity can, and
every future way to alias a file lands on the same check.

Where those rules live turned out to matter as much as the rules. Each
paragraph above was written after a defect, closed on the leg that was under
review, and found again on the leg beside it — the Setup leg asked the path
question and the identity question together while the History engine beside it
asked only the path one, so a hard link to the master key inside a Session tree
was packed and laid down in every pulling machine's project directory. So the
questions are one function now, `carry_refusal`, and there is one way to obtain
a user file's bytes: `read_carryable`, which asks it and then asks identity
again on the descriptor it actually reads from. Setup capture, handpicked
trees, Session trees and project residue all come through there, so no leg
keeps a weaker spelling of the rule, and where Python cannot enforce that the
package's own syntax tree is walked in the tests. The identity half rests on a
walk of `~/.carryon`, so a walk that could not list a directory answers *cannot
tell* rather than *no* — which for a Setup is ADR-0001's refusal, naming the
directory that would not list and why. ADR-0010 has the shape and what it cost
to learn.

## Consequences

A user-added path has no Adapter behind it, so nothing knows what it is for: no
`verified_against`, no layout-drift detection, no exclusions. The manifest marks
it unvouched-for so it does not read like supported agent coverage.
