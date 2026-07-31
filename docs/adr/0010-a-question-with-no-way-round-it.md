# A question with no way round it

Six rounds of review said the same sentence about every defect they found: a
rule closed where it was reviewed and open where it was not. The last one was
explicit that both of its findings "arrived by asking one already-closed
question in a second place". Patching those two would have produced a seventh
round with two more, so this round is not about them. It is about the shape
that keeps producing them.

The shape is a question that has one answer and several askers. Every fix so
far has ended by writing the answer down in one function and then trusting each
leg to call it: `config.carry_refusal` for what a file may be read for,
`external.owner_of` for who holds a path, `config.state_write_path` for the
directories carryon makes under its own state. Each of those is right, and each
of them is one review away from a leg that does not call it.

The Destination layer is the counter-example this codebase already has. Its
four verbs are concrete on the base class and a type supplies only the private
halves, so a new type cannot forget the guard — and the verifiers stopped
finding anything there. ADR-0009 records why that mattered: "directory and git
each followed links in their own separately written walk". The move this round
makes is that one, applied to the two questions that still had askers.

## The question and the operation are one call

`config.read_carryable` was already this: it asks and it reads, so a leg that
wants bytes has necessarily asked. The write side was the other arrangement —
four functions that answer, and five call sites that answer and then call
`Path.write_bytes` a syscall later.

That interval is not academic. Three places in this codebase already say a
check and its use must be one syscall — ADR-0009's openat walk,
`destinations/base._local_write`, `config.write_state_bytes` — and the reason
given is measured: renaming a directory to a symlink mid-walk won a read
outside the root about once in 150 tries. A Session's project directory is
exactly that kind of place. The ownership answer was about the path as it was a
syscall ago, and then `write_bytes` followed whatever was at the name.

So there is one writer now, `external.write_owned`, and it answers twice
because the two answers are blind to each other:

- **the ancestors**, with `owner_of` from the caller's own root. Only a path
  walk learns that a directory two components up is a link into somebody's
  repository, and no descriptor can be asked about it.
- **the leaf**, on the descriptor the bytes are about to go to. `O_NOFOLLOW`,
  then `fstat`: `st_nlink` for a second name for the same file, `S_ISREG`
  because a named pipe answers `open()` by waiting for the other end.

A leg may still ask `owner_of` for itself — a skip line needs to name what
holds the path, and the ownership question has to be settled *before* the union
rule reads anything, since a broken link reads as "nothing here yet" while the
write that followed would create the file at the other end. What no leg does
any more is ask and then write. That pair is what the enforcement suite
forbids, by name, in the package's own syntax tree.

`--force` is untouched and deliberately so: it means "write through the link I
own" (ADR-0007), so the two checks that are about a link stand down with it —
the `O_NOFOLLOW` on the open, and the `st_nlink` on the descriptor. Half a
`--force` would refuse the dotfiles-managed `settings.json` the flag exists
for. What does not stand down is `S_ISREG`: a named pipe or a device is not a
link anybody owns, and nothing the flag says is about writing into one.

## What it refuses, it has not already destroyed

`Path.write_bytes` opens with `O_TRUNC`: the file at the name is gone before
anything has established that carryon may write there. ADR-0002's first
Consequence is that a pull never deletes, and a write that truncates and then
refuses has shortened a Transcript nothing agreed to replace.

The truncate happens after both answers now, which is the rule
`config.write_state_bytes` already spelled for carryon's own state and nothing
else inherited. A refusal costs the file nothing.

The same question one direction over: the union rule reads the local copy to
decide whether the incoming one extends it, and that read had no question in
front of it at all. A `mkfifo` where a Transcript belongs — no key, no
Destination access, one command from anybody with an account on the machine —
blocked that open for ever, so the pull never returned and printed nothing. It
now opens the way every other read in the package does, and "absent" and "there
and this machine will not read it" have stopped being one answer: the first
writes, the second is a *conflict*, because neither copy has been shown to
extend the other and ADR-0002 already says what to do then. No new outcome, no
new report line, and the local copy survives.

CONTEXT.md's definition of *externally owned* already covered the fifo — "a
path this machine will not answer about counts the same way" — and the
ownership question had never been asked it.

## An answer nobody could give was being read as "no"

The identity half of the read gate is the only half a hard link cannot defeat,
and it rests on a walk of `~/.carryon` collecting `(st_dev, st_ino)`. That walk
swallowed every error and answered with an empty set, and an empty set read as
"this file is not carryon's state".

Mode 0300 is the reachable spelling: a directory you may enter and may not
list. carryon opens its own `config.json` and its own `master.key` by name and
neither notices; the push runs normally, the report says nothing, and a hard
link to that key in a Session tree is packed and laid down in every pulling
machine's project directory. A botched `chmod` and a backup restored with the
wrong modes both produce one, which are the two causes `layout.py` already
calls ordinary and needing no attacker.

"Found nothing" and "could not look" are different answers and only the first
one means no. The walk carries which of the two it is, the refusal has a
sentence of its own — carryon does not assert that somebody's notes *are* its
state, only that it cannot tell — and both askers get it from one function. It
fails closed, which for a Setup is ADR-0001's refusal naming the cure, and for
a History is a withheld member named in the report.

Every other walk in this package already reports a directory it could not list:
`capture.tree_files`, `history._listing`, `layout._entries`,
`destinations/base._local_keys`. This was the last one that did not, and it was
the one whose silence costs the trust root.

## "They are carryon's own files, not a user's"

The review that followed this work found nothing inside any of the gates above.
Not one finding on a Session tree, a Setup item, an Archive object or an Index
field — which is this document's prediction holding on every surface the
chokepoints cover. What it found was on the two surfaces they had never been
pointed at, and each of those was left out for a reason somebody wrote down at
the time. The reasons are the part worth recording: a defect gets fixed once,
and a reason gets repeated.

The first was that `~/.carryon/config.json`, `~/.carryon/state.json` and
`~/.carryon/master.key` are carryon's own. Every user path went through
`read_carryable` and every Destination object through the Destination base
class, while these three were read with a bare `Path.read_text()` behind
whatever guard each reader had thought to write for itself, on the reasoning
that carryon wrote them and there is nobody else in the question.

carryon does write them, and that is not what a gate is about. The boundary is
not who authored the bytes but whether this process computed them in this run,
which ADR-0009 states in as many words, in a paragraph about `config.json`:
*anything this process did not compute in this run is input, and that includes
the file carryon itself wrote last month into a `$HOME` that came back from a
backup*. So the sentence was already written, one document over, about one of
these three files — and what it produced there was a better hand-written guard
in that one reader rather than a gate. A rule spelled per reader is a rule the
readers beside it never get, and it is not even the whole rule where it is
spelled: a guard wrapped around a read still answers about the name a syscall
ago. "carryon's own" is what made a gate feel unnecessary, and it sounds like
a property of the file when it is a claim about a moment.

Nothing it cost needs an attacker. A `state.json` that is not UTF-8 — a
truncated write, a synced folder's conflict copy, a restored backup, the three
causes that reader's own docstring calls ordinary — came out of both `push` and
`pull` as a bare `UnicodeDecodeError`, because that leg guarded the decode
around the parse, where it cannot fire, while `config.load` beside it guarded
the same exception in the block where it can. A named pipe at either name
blocked `open()` for ever, so `list`, `doctor`, `push`, `pull`, `capture` and
`pair` printed nothing and never returned — worse than a crash, because there
is nothing to read and nothing to report. And a dangling symlink answers
ENOENT, which both readers spell "not there": `config.load` ran the defaults
and reported no Destination on a machine that has one, and `fetch_master`
answered "this machine holds no key", after which `init` mints a fresh recovery
key and orphans the Archive that the key still sitting at that name opens.

`read_state_bytes` is the gate — the type settled before the open and again on
the descriptor the bytes come from, `O_NONBLOCK` on the way in, and a refusal
returned rather than raised, because the three callers need opposite things
from one: the config's is the SystemExit that ends a command every subcommand
depends on, the key's is the one that must not read as "no key", and the
high-water mark's is a warning line, since that mark is deliberately never a
gate. `read_state_json` is one caller of it, and settles only what the bytes
mean.

That split is the second half of the lesson and it was learnt inside the same
round. The first pass gated the two JSON files and left `master.key` out on a
narrower excuse — it holds bare hex rather than a document, so the gate's shape
did not fit it — and the excuse went into the read allowlist as a written,
reasoned entry, where it read as settled. An allowlist can do one thing a
reviewer cannot, which is make an open defect look approved. The file it was
approved about is the one that opens the Archive.

## "It is only argument parsing"

The second surface runs upstream of every guard in the package, and it was left
out because it does not look like an operation: normalisation opens nothing,
writes nothing and decides nothing, it only tidies what the user typed into a
`Path`. The tidying is the problem. Each step of it picks a path, and a guard
downstream that is correct about the path it is handed is correct about a path
the user never named.

`cmd_capture` called `.expanduser().resolve()` on `--out` and `--archive`, and
`resolve()` follows a symlink. So `external.write_owned` — the writer this
document is about, which asks twice precisely because a name is not the content
behind it — was handed the link's target and answered correctly about that.
`--out` at a link into a dotfiles repository filled the repository, at exit 0,
with nothing in the report about a link; `--archive` at one overwrote the file
at the other end; a dangling `--out` link had its target created, a directory
carryon was never pointed at, made from a name something else had put there.
The guard was present, it was correct, and it was about the wrong path.
`resolve()` costs more than the links: `--out ''` is `Path('')`, whose
`resolve()` is the working directory, and it captured a plaintext Setup into
this project's own tree while the fix was being written.

So there is one door, `cli._named_path`, and no subcommand normalises anything
for itself. The spelling first — an argument that is empty, blank or holds a
NUL is not a path, and a NUL is not even the same `ValueError` on the two
interpreters carryon must pass. Then `~` against the home the command is
running under, and no further: expanding is what the user asked for, resolving
answers about a different path than the one they named. Then whether the path
can be used for what the subcommand needs, and whether something else already
holds the name.

The door's ownership question does not replace the writer's, and both are
needed. The answer about a name is only true until the next syscall, so
`write_owned` still asks on the descriptor. What the door has that no writer
can get at is the root: `--out` names the directory every later question is
asked *from*, and no walk downward from a root sees the root itself. It is
asked from `$HOME` down, which is where the tools ADR-0007 is about put their
links, and outside `$HOME` the named path is judged alone — walking the chain
from the filesystem root would refuse `--out /tmp/x` on every mac, where `/tmp`
is itself a link.

The other half is the enumeration, and it is the half that stops the next one.
`tests/test_cli_arguments.py` reads every argument of every subcommand off the
parser and requires each to sit in one of three tables: path-valued and settled
by the door; text that becomes a filesystem name somewhere else, which takes
the spelling half here while the one function that owns its meaning settles the
rest; or answered by a door of its own, as a pairing code is. An argument added
to a subcommand fails a test until somebody has said which of the three it is.
The middle table is not a loophole, and writing it out is what found the last
of these: a Destination spec must not be expanded here, since it is stored
verbatim and expanded against each machine's own home, which is what keeps an
Archive machine-neutral — but `--machine` had never been asked anything at all
on the way in, and `--machine .` put this machine's Setup into the shared
`setups/` root at exit 0, after which every other machine's pull restored
nothing and reported phantom machines named `MANIFEST.json` and `RESTORE.md`
for ever. That question was recorded as settled in a function whose only caller
runs on the pull leg, over names that came back off a Destination.

## Consequences

A leg that wants to put bytes at a path carryon does not own has one way to do
it and no argument to make. The write allowlist in
`tests/test_state_chokepoint.py` lost every entry whose reason was "asked
immediately above the call" — that sentence was the gap being approved — and
what remains writes into an Archive, into a directory this process just made,
or is the chokepoint itself.

Removals are enumerated too, which they never were. Both existing scanners
watch bytes arriving, and two of the three properties they guard are promises
that something *survives*: the sweep that unlinked a machine's own workflow
journals made no write at all and would have passed both. Nothing under `$HOME`
appears in that list and nothing may; a stale member that genuinely ought to go
is `--mirror`, which ADR-0002 defers on purpose.

A machine whose `~/.carryon` cannot be listed now refuses to capture and
withholds its History, where before it pushed happily. That is a real cost and
it is the right one: what carryon cannot answer about is the file that opens
the Archive, and the cure is one `chmod` on the directory the refusal names.

A state file that is there and will not read is a sentence naming the file,
where it used to be a default: a machine that has a Destination no longer
reports that it has none, and `init` on a machine whose `master.key` is a
directory, a named pipe or a dangling link stops rather than minting a fresh
recovery key over one it merely could not read. The high-water mark is the one
that stays a warning and a zero, because it exists to make carryon notice more
and must never become a way to stop a machine working.

`--out` and `--archive` are no longer resolved, so a user whose `~/Dropbox` is
itself a symlink has to spell out where it points or capture somewhere else.
That is ADR-0007's cost charged one call earlier, and a Destination stays
exempt from it: a spec is not a path argument, carryon never writes through one
with an ownership question of its own, and ADR-0009 has already said a
Destination is quite reasonably a link. A hostname this machine cannot write
out, or one holding a `/`, refuses `init` with a sentence rather than pushing a
Setup where no reader looks — and `config.validate` puts the same question to a
hand-edited `config.json`, so a machine that already has one stops rather than
seeding phantom machines into every other machine's pull.

## What eight rounds taught

For several rounds the answer was that a guard is not finished when the case
that prompted it is closed — write down the question, find every place it
arises, put the rule where it can be answered. That was right and it was not
enough, because "every place it arises" is a list somebody maintains by
reading.

The correction is that the answer and the act should be the same call. A
question a caller must remember to ask is a question some caller will not ask,
and no amount of care about the list changes that; what changes it is having
nowhere else to go. Where the language cannot enforce it — nothing in Python
takes `write_bytes` away from a leg — the package's own syntax tree is walked
and the pair "asks, then writes" is a failing test rather than a reviewer's
attention.

The two surfaces above add the other half of it, which the correction does not
supply by itself: a chokepoint has an edge, and the edge is a sentence about
what the gate is *for* — "a user's file", "what a Destination serves",
"content carryon writes". Both surfaces sat outside every one of those
sentences by construction, and neither exclusion was an oversight. Both were
argued, and one of them was argued inside an allowlist, where being written
down made it look decided. So the question to put to a gate is not only
whether every leg goes through it, but what the sentence defining it excludes,
and whether each exclusion is a fact about the operation or a fact about who
happens to own the file. The excluded set is where the next findings are, and
it is a far shorter list to read than every call site.
