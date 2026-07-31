# What comes back from a Destination is input, not carryon's own output

carryon has always called a Destination untrusted, and ADR-0003 encrypts a
History before it goes to one. A security review of the built code found three
places where that posture stopped at the encryption boundary and the code went
on to trust what came back: restore drove its writes from paths read out of a
stored MANIFEST, a pairing object was named by a hash of the very secret that
wrapped it, and an Archive object's ciphertext carried no statement of which
object it was. All three were reproduced against the real code.

The rule the fixes share is one sentence. Nothing read back from a Destination
is treated as carryon's own output, however carryon-shaped it looks: it is
checked against something this machine knows independently, and refused by name
when it fails. The rule reaches below the objects, too — a local Destination is
a filesystem somebody else writes to, and what a filesystem can serve is not
only files.

## A stored MANIFEST is attacker-authored

The Setup half of an Archive is plaintext and unauthenticated on purpose —
`push --category config` needs no master key at all (ADR-0004), which is what
makes a git Destination worth having — so anybody with write access can put a
MANIFEST there. Restore then took `src` and `dst` from it and joined them onto
local roots, and two ordinary Python facts turn that into a write anywhere on
the machine: `home / src` silently *becomes* `src` when `src` is absolute, and
enough `..` segments climb out of any root.

So restore validates both fields of every item before a byte moves, refuses
whole items rather than repairing them, and names each refusal in the report —
a silently skipped item reads as a successful restore that is quietly missing a
file. `dst` has to stay lexically inside the stored Setup, and every member of a
stored tree is re-checked rather than trusted because its root passed. `src` has
to be relative, under `$HOME`, outside carryon's own state, and — the check that
also holds under `--force` — a path some Adapter on this machine already
declares.

That last one is load-bearing. `$HOME` is not a boundary worth having: it holds
`~/.zshrc`, `~/.ssh/authorized_keys`, and everything else some program runs at
next login. What the local Adapters declare is a boundary, because it is the set
of paths this machine already decided to carry — ADR-0008's effective registry,
exclusions applied and handpicked paths added. A restore fills those in and
invents nothing.

## A pairing code is a locator and a secret, drawn separately

The pairing blob used to sit at `sha256(code)[:16]`. Naming an object after a
digest of its own wrapping secret hands that secret to anyone who can list the
directory — unsalted, one iteration — which bypasses the 600,000-iteration wrap
completely. The truncation to 64 bits was no help: it still pins a unique
preimage. Recovering a 40-bit code that way is roughly 55 GPU-seconds, and the
code it recovers opens the wrap.

A code is now two halves drawn independently from a 32-character unambiguous
alphabet: six characters of **locator**, which names the object and is published
as a filename, and ten characters of **secret**, which is the only thing the
key-wrapping KDF ever sees. Thirty bits in public guarding nothing, fifty bits
behind PBKDF2 — about 1.3e21 SHA-256 compressions, some 2000 GPU-years. The two
are kept apart by a type rather than by convention, so neither can be passed
where the other belongs.

## An Archive object says which object it is

The Index says which key holds a Session, but the Destination decides what comes
back from that key, and AES-CBC is malleable besides. So an object is
encrypt-then-MAC, and the MAC covers a *label* — the object's logical identity,
a Session's UUID, a project's cwd, the Index — rather than the storage key it
happens to sit at, which is the untrusted party's choice. Authentication runs in
constant time, before openssl sees the ciphertext.

That turns the cheapest attacks available to honest-but-curious storage into
authentication failures instead of quiet successes: serving one Session's
ciphertext under another Session's key, replaying a superseded object, passing
the Index off as a Session, flipping a byte to see what changes. Labels carry a
domain prefix, so a Session UUID and a project path that happened to be equal as
strings could not be substituted for one another. The key that authenticates and
the key that names are each derived from the master key rather than being it, so
no single value does two of those three jobs.

The wrapped pairing blob is the one object with no tag and stays that way — the
machine reading it holds no master key to check one with. It is guarded instead
by requiring the unwrapped bytes to parse into a payload carrying a 32-byte key,
and that check happens before the one-time delete, so a tampered blob cannot
burn a code that would have worked.

## Nothing found on a Destination's filesystem is followed

A directory Destination and a git clone are local trees anyone with write
access can plant a symlink in, and `is_file()` follows one — so a planted link
was enumerated as an Archive object and its target's bytes read as though they
had been pushed there: any file the pulling user can read, served into a
restore. carryon follows no symlink it finds on a Destination. On a read the
link is skipped and reported by name; on a write it is refused outright, with
the key named, because unlike a read there is no attacker-chosen object to
skip — only the blob carryon itself is pushing, and a push that quietly did
not happen is worse than one that stops with a sentence. A hard link is
refused for the same reason one syscall over — `link()` needs no read
permission on its target, so on a shared machine it is the same exfiltration
without the link bit — and a fifo, a device, or a directory standing where a
blob should be is a report line, never a raise: one planted object that raises
is a permanent abort on every pull from every machine.

The check and the use are one syscall where the platform has one. A walk that
inspects each component and then opens the whole path answers about the path
it saw and opens the path that is there now, and on storage somebody else
writes to those are two different paths often enough to measure — renaming a
directory to a symlink mid-walk won a read outside the root about once in 150
tries. So every component below the root is opened refusing links, and the
read happens inside the directory descriptor the walk ended on. The root
itself is exempt: the user chose it, and a Destination is often `~/Dropbox`,
which is quite reasonably a link. Everything beneath the root is whatever the
untrusted party put there. The guards live in the base every Destination type
is written over; a type supplies only the primitives beneath them and never
spells the public read or write, so it cannot forget the rule — which is how
the hole survived a round of fixes in the first place: directory and git each
followed links in their own separately written walk.

## A tag that is there must be answered for

The rule above — a missing SETUP.mac never decides anything, because the file
sits where an attacker can delete it — was written and read as the whole of it.
It is half. The other half is that a tag which *is* there is a statement only a
master key holder can make, and the pull leg used to walk past one without
opening it whenever the Index did not call the Setup authenticated.

That is reachable with no key at all. Delete `index.enc` and every encrypted
object, and the Archive is a plaintext Setup tree and nothing else — which is
also what ADR-0004's keyless push leaves, and no rule over what the Destination
serves separates the two. The separation carryon had was local: this machine's
high-water mark, written at every moment it could have learnt the Archive has
an Index. A machine that holds no mark — paired by a carryon that predates the
revision in the pairing payload, or one whose `$HOME` came back from a backup —
restored the tree unverified behind two notes, at exit 0, edits included.

The tell was in the tree. A SETUP.mac is written only by a push holding the
master key, and that same push records the tree in the encrypted Index and
seals it: one branch writes both, so they cannot come apart at the source. A
stored tree carrying a tag while the Index does not record it is therefore the
Index being served not being the one that push wrote. A keyless push leaves no
tag whatsoever, so the honest unverifiable Archive is not touched by this and
keeps restoring with its warning.

A tag that does not verify takes the same refusal. The difference between the
two is a directory renamed at the Destination — the label binds the machine
name, so `setups/mac-a` served as `setups/mac-A` verifies under neither — a
forged tag, or a tree lifted from another Archive; and treating "it does not
verify" as a reason to carry on would hand the check back to whoever can
rename a directory.

The push leg already refused on exactly this, one function over, and that was
no evidence at all about the pull leg. It is the recurring shape: a rule closed
where it was reviewed and open where it was not.

## A field's shape is checked where it is indexed

"Refused by name" is a promise about the sentence, and a traceback is not one.
It names a Python type instead of a file, it carries no cure, and on the pull
leg it lands after the History has begun writing into `$HOME` — a half-restored
home and a stack trace about `str.replace`. Every rule above says what carryon
*decides* about hostile input. This one is about whether it decides anything at
all before the interpreter answers first.

The Index is sealed, so a master key holder wrote it — which is not the same as
its fields holding the shapes the two legs index out of them. The guards that
existed stopped at the container: the catalogue is an object, and every entry
in it is an object. Then a leg reached inside the entry and handed `cwd` to
`str.replace` and `main_path` to `tarfile.getmember`, each a bare
AttributeError out of a pull that had already laid Sessions down. A guard that
stops one level above where the code indexes is a guard with a hole in it
exactly one level wide, and the same hole let out both.

So the check descends to the field it is about. Every field a leg takes out of
an entry and hands to something that only accepts a string is confirmed to be
one where the Index is opened, and a failure refuses that entry — see the
section below, which corrects what this one first said about how much a
failure refuses. Absent is allowed, and so is null: carryon writes one, for a
Transcript that recorded no cwd, and every reader already treats missing as
"not recorded". What is refused is a field holding some other type, because
that is the shape no reader can answer about — and the check is about the
fields these legs index, never about the shape as a whole, since an Index
written by a later carryon is an honest Index and refusing it for being
unfamiliar would be the same fault pointing the other way.

What the check is *about* and where it physically sits are separate questions,
and only the first one is the rule. The Index's string fields are settled once
at the door, because every reader of them is downstream of that one open and a
rule spelled there does not depend on each room remembering it. A field whose
answer belongs to one reader — is this a usable Destination key — is settled
at that reader instead, where the question can actually be asked. What is
forbidden is neither of those: a check whose subject is the container while
the code's subject is the field.

The same shape one document over needs no master key at all. A stored
MANIFEST's agent entries were guarded as objects and then subscripted for
`items`, `excluded`, `kind`, `dst` and `src`, so one key left out of a planted
entry was a KeyError straight out of `push --category config` on a machine that
holds no key. And a string is not the end of the question; a string this
machine can *write* is. A lone surrogate is legal JSON, legal in a Python
`str`, and pure ASCII on the Destination as the six characters `\ud800` — every
`isinstance` between there and the write says yes, and the write raises
UnicodeEncodeError. So an entry that has to ride back out into a rendered
document is asked whether it can be encoded as well as whether it is shaped
right, and one that cannot is dropped and named: a partial push carries a
stored agent forward for every later pull to restore, so dropping one silently
is a Setup that goes mysteriously short an agent.

None of this needs an attacker either. The Index is sealed and the MANIFEST
beside it is not, but both reach the same code from an honest Archive written
by a carryon whose shape this one does not know. The rule's boundary is the
reader rather than the Destination: anything this process did not compute in
this run is input, and that includes the file carryon itself wrote last month
into a `$HOME` that came back from a backup. `~/.carryon/config.json` is read
by every subcommand before any of them has decided anything, so the read is the
guard rather than an `exists()` ahead of it — a directory standing there, a
file this user cannot read, a symlink loop — for the same reason the walk above
opens rather than inspects: two syscalls answer about two different paths. What
that produced here was a guard around this one reader rather than a gate, so it
reached neither of the two state files beside it nor the shapes a stat before
the open answers — a fifo, a dangling link. ADR-0010 has both, and why the
reasoning stopped at the word "own".

## The name an entry hangs from is a string too

Three rounds walked this Index down a level at a time — the catalogue is an
object, each entry in it is an object, each field a leg indexes out of an entry
is a string — and each of them kept its subject where the round before had left
it. The key the entry hangs from was never in scope, and it is not a lesser
string than the fields beside it: it is what the object is sealed under, what
the object is named after, and for a Session it is a directory this machine has
to be able to make. A lone surrogate there is legal JSON, six ASCII characters
on the Destination, and a UnicodeEncodeError out of the label encode, raised
mid-pull with Sessions already in `$HOME`.

Asking it where an Index is read is half an answer, and the wrong half to stop
at. carryon does not mint these names — the claude-projects layout takes the
stem of a file the agent wrote, so a transcript called `...jsonl` is a Session
named `..` — and a name no machine can restore under goes up at exit 0 and
seals a catalogue that every machine, including the one that wrote it, declines
from then on. The reader's refusal names a cure that has stopped existing by
the time anyone reads it: push again from a machine whose Index is intact, when
the poisoned Index *is* the current one. So the question is asked in the three
places it arises — where a name is taken off the filesystem, where an Index
becomes bytes, and where one comes back — out of one function, and on the push
leg the answer is a Session left behind with a report line, which is what every
other push skip already is.

## A stored tar is answered for whole, where it is opened

The seal proves a master key holder wrote an object's bytes. It does not prove
those bytes are a tar, and nothing about an attacker is needed to make them not
be one: a disk that lost a block, a synced folder's conflict copy, a carryon
whose shape this one does not know. That failure was refused by name at one of
the four places carryon opened a stored tar — the one that had been reviewed —
and left bare at the other three, across two modules and both legs, so which
branch a run happened to reach first decided whether the user got a sentence or
a traceback over a half-written tree. A call site does not get to spell the open
now; it asks for the members and takes the refusal with them.

Then the same rule one level in. A tar that opens perfectly can hold a member
named `../../../escape.txt`, and that was answered from inside the loop that
writes, by each of the two callers that write, with the tree's earlier members
already under `$HOME` — the harm the first fix was written to end, reached
through the door it left open. What a member is called is a property of the
object rather than of the caller acting on it, so the object is refused whole
and before the first member is handed out. Refused, not repaired: the seal
makes a key holder's damaged Archive the honest reading, and one damaged object
has never been a reason to abandon the rest of a pull.

## A refusal is the size of the damage

Each check above descended a level into the Index — catalogue, entry, field,
key — and each one inherited the answer written for the one before it: refuse
the Index. That was right where it was first written — a catalogue that is a
list cannot be read entry by entry, so there is nothing to set aside and
nothing to carry forward — and it was carried down two levels past the case it
argued. One entry, out of a catalogue of hundreds, with a key holding a lone
surrogate or a `cwd` that is a list, took every Session, every residue and
every Setup with it, on both legs, on every machine, until somebody found an
older copy of the Archive. Which is the permanent Archive-wide abort this
document already ruled out for the objects an Archive holds — *one planted
object that raises is a permanent abort on every pull from every machine* —
reached through the Index instead of through an object, and needing no attacker
to reach it: the Index is sealed, so damage there is a key holder's own
Archive, or carryon's own bug.

So the unit refused is the unit the damage is in. An entry a leg cannot act on
is dropped from the catalogue the legs read, named in the report and counted
towards the exit status, and everything undamaged still moves — the same answer
`ObjectRefused` already gave for an object. The rule the two levels share: a
check descending a level without its remedy is not a smaller failure than no
check at all, it is the same failure with a sentence in front of it.

Two things follow, and neither is optional. A record set aside is still a
record, so a push may not read it as *no record*: the union rule (ADR-0002) is
asked only where an entry exists, and a Session whose entry was dropped would
take the branch that writes without comparing — a machine one turn behind
overwriting the Archive's longer copy, which is the loss the union rule exists
to prevent. And the entry itself is carried through the next seal untouched: it
is the only record of which object holds that Session and its key is the only
name that object was sealed under, so a push that dropped it would delete a key
holder's record of a Session still sitting in the Archive, at exit 0. The
damage stays visible on every run until a machine that still holds the Session
pushes a fresh entry — and a fresh entry wins, or the cure the report names
would be a no-op for ever.

## Consequences

A refusal is now an ordinary line in a restore report rather than a sign of an
attack. A Setup captured on a machine whose Adapters or handpicked paths this
one does not have will lay down less than it holds and say which items it
declined; the cure is to declare the path here (ADR-0008), not to loosen the
check.

`--force` no longer means "write it anyway". It still discards ADR-0007's
deference to whatever owns a path, which is what it was for, but it cannot turn
a `src` no Adapter declares into a write.

## What the rounds taught

Every round turned up one defect in different clothes. A rule was closed where
it was reviewed and open where it was not: at an item's root but not its
members, on the push leg but not on the capture leg, at a container but not at
the key it hangs its entries from, at one of the four places a stored tar is
opened and not at the other three, on one Destination type but not on the
other written beside it. Not one of them was a wrong rule, not one was a
missing idea, and not one was found by doubting the rule — each was found by
asking where else the same question gets put. The last review said it of both
its findings at once: they arrived by asking one already-closed question in a
second place.

Writing the question down and then hunting for every place it arises was the
answer here for several rounds. It was right and it was not enough: "every
place it arises" is a list somebody maintains by reading, and the reading is
the part that keeps failing. What ends it is one place that answers the
question, and no way to perform the operation without going through that
place. The proof is already in this repository: the Destination layer's four
verbs are concrete on the base class and a type supplies only the private
halves beneath them, so a type cannot forget the guard — and reviews stopped
finding anything there while they were still finding things everywhere else.
`config.read_carryable` (ADR-0008) is that move for reading a user's file,
`external.write_owned` (ADR-0010) for writing one, `config.read_state_bytes`
for reading one of carryon's own, `cli._named_path` for turning a command-line
argument into a path at all, and `archive.tar_members` for opening a stored
tree: in each, the call that asks and the call that acts are one call.

So when you add a guard here, write down the question it answers and then make
it impossible to do the thing without asking. If the answer and the act can be
one call, make them one call — a check and a use separated by a syscall are
answers about two different paths, which this document has already measured.
Where the language cannot take the bare verb away, and Python cannot, the
enumerations in `tests/test_state_chokepoint.py`,
`tests/test_write_chokepoint.py` and `tests/test_cli_arguments.py` stand in for
it: they walk the package's own syntax tree and the parser's own arguments, so
a leg that reads, writes or removes outside the gate — or an argument nobody
has said which door settles — fails a test rather than passing a reviewer.
Route a new call through the gate, or put it in those lists with the reason it
needs none. An entry is a decision under review and not a place to park one:
the last of these excused the file that opens the Archive, in a sentence that
read as approved because somebody had written it down. Give the refusal the
size of the damage it is about, because a check that descends a level while its
remedy stays at the level above is how a rule written to protect one Session
came to refuse an Archive. And when a fix comes up for review, review its
boundary rather than its instance.
