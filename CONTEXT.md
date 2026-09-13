# carryon

Carries an AI coding agent's working life between machines: the setup that makes
an agent yours, and the history of what you did with it. Agent vendors do not
offer this, and the two halves have opposite safety properties, so the language
below keeps them apart.

## Language

### What gets carried

**Snapshot**:
What one push contributes — the state of one machine at one moment. Has exactly
two parts, a Setup and a History.
_Avoid_: bundle, backup, export

**Archive**:
What a Destination accumulates: every Session anyone has ever pushed there, plus
the most recent Setup from each machine. Outlives any single Snapshot and is
never overwritten wholesale.
_Avoid_: backup, remote, bucket

**Setup**:
The part of a Snapshot that makes an agent yours rather than freshly installed —
settings, skills, subagents, slash commands, standing instructions, plugin
lists. Carried encrypted, like a History (ADR-0014); a credential found in one
is named, not refused.
_Avoid_: config (it is one of three categories inside a Setup, not the whole),
clean (retired — see Flagged ambiguities)

**History**:
The part of a Snapshot that records what you actually did — transcripts, and the
per-project memory that accretes alongside them. Unredacted by nature.
_Avoid_: chats (a chat is one conversation; History is all of them), sessions

**Session**:
One continuous piece of work with an agent, identified by a UUID the agent
assigns, and the smallest thing carryon moves as a unit. A Session belongs to
one machine at a time. On disk it is a *tree*, not a file: the main Transcript
plus everything the work spawned beneath it. Moves as a unit is not decides as
a unit — a Session travels as one sealed tree, and what happens to each
Transcript inside it when it lands is settled member by member.

**Transcript**:
One participant's record within a Session — the main conversation, or a
subagent's, or a workflow's journal. A single Session routinely holds dozens;
one workflow run alone produced 27. All of them record absolute paths and all of
them need Re-keying.
_Avoid_: treating "the transcript" as the whole Session

**Category**:
A slice of a Snapshot the user can select: config, capability, knowledge — which
make up a Setup — and history.

### How it is described

**Adapter**:
A per-agent declaration of where that agent keeps its data and which of it is
worth carrying. Holds no logic. Adding an agent means writing one of these and
nothing else — unless its Sessions sit in a shape the History engine has no
layout for, which is the one thing a declaration cannot supply.

**Item**:
One thing an Adapter declares worth carrying, with a kind that tells the engine
how to handle it.

**Vouched**:
What an Adapter does for a declaration it makes on the user's behalf: it names a
directory the user never named, and stands behind what is in it. A handpicked
path is the opposite and deliberately so — unvouched, but named by the person
whose machine it is. The distinction decides who may narrow what a tree carries:
carryon may leave Development artifacts out of a vouched tree, because the
Adapter chose the whole directory and nobody asked for its contents one by one.
It may not narrow a path the user named.
_Avoid_: trusted (nothing here is about trusting the user), verified (that is
Layout drift's word, about a vendor version)

**Development artifact**:
Content inside a carried tree that belongs to making the thing rather than to
using it — a test suite, its fixtures, a build cache. A Setup carries what makes
an agent yours, so a skill belongs in one and the tests that prove the skill
works do not. Not a judgement about worth: they are worth keeping, and keeping
them is a backup's job rather than a Snapshot's.
_Avoid_: junk, cruft (they are neither), residue (taken — that is per-project
memory in a History)

**Layout drift**:
An Adapter expecting a path the agent no longer uses. The early warning that a
vendor has reorganised, and the reason Adapters record what version they were
checked against.

### Moving it

**Destination**:
Somewhere a Snapshot can be put and later fetched. Carryon stores no credential
for one. It borrows a tool that already holds them — git's keys, rclone's
config — and where it helps set that tool up, the credential passes straight
through and is never kept.

**Provider**:
A storage service carryon knows how to set a Remote up for: which handful of
fields that service needs, and nothing else about it. Knowing a Provider is not
speaking its protocol — rclone does that.

**Remote**:
rclone's stored definition of how to reach a Provider. It belongs to rclone and
lives in rclone's config; carryon can create one and never reads it back.
_Avoid_: using "remote" for the Destination — a Destination names a Remote and a
path within it, and the same Remote can hold Archives that are nothing to do
with each other

**Probe**:
The random bytes under a random name `init` writes, reads back and deletes to
prove a Destination works before anything is minted. It is the one thing
carryon writes in the clear, and it has no choice: it runs before any master
key exists, so there is nothing to seal it with. That is why it carries no
machine name, no home path and no timestamp — it is content chosen to mean
nothing to whoever reads it. Passing it means write, read and delete work,
nothing about whether the storage is private, which no probe can answer.
_Avoid_: health check, ping (a Probe moves real bytes through the real verbs);
"the Archive's plaintext half" for where it lands — after ADR-0014 there is no
such half, only this one deliberate exception

**Sync**:
Carrying a History both ways in one step: what the Archive holds and this
machine does not is laid down, what this machine holds and the Archive does not
is published. It converges two machines that take turns, because a Session
belongs to one machine at a time — there is nothing to reconcile, only things
to carry. It never deletes, and it does not merge a Session two machines
extended at once; that divergence is filed, reported, and stays.
_Avoid_: "sync state" for the High-water mark; "two-way sync" for the
per-machine Setup merge ADR-0002 puts out of scope

**Re-keying**:
Rewriting the absolute paths recorded inside a History so they do not belong to
the machine that wrote them. Happens on the way out, leaving the Archive
machine-neutral, and is reversed against the local home on the way in. Without
it a restored Transcript refers to directories that do not exist and will not
resume.

**Externally owned**:
A path some other tool already holds — a dotfiles symlink, most often; a second
hard link to the same file, or a path this machine will not answer about, count
the same way. A named pipe, a socket or a device counts as the last of those:
carryon cannot say who is at the other end and must not wait to find out.
carryon reads through it happily but never writes to it, because writing
through it edits a repository carryon does not own.

Asked of the path *and* of the descriptor the bytes go to. The answer about a
name is only true until the next syscall, and the two questions see different
things: only a walk from the caller's own root finds a link two directories up,
and only the open finds what is at the name right now. Neither sees a link *at*
the root the walk starts from, so an argument that names one — the directory a
capture is written into — is asked about before the walk has a root to start
from.

**Index**:
The encrypted catalogue at the head of an Archive: for every Session, where it
came from and what state it was in. Read first on every pull, so a machine can
decide what it needs without downloading or decrypting the rest.

**High-water mark**:
How far into an Archive this machine has already read, kept here rather than
there. An Index served from an old copy is authentic — a key holder sealed it —
so nothing in the Archive separates a superseded one from the current one; what
this machine has already seen is the one side of that comparison a Destination
cannot author. Pairing hands a new machine the mark the pairing machine had.
_Avoid_: version, sync state (it records how far this machine has got, nothing
about what was pushed)

**Authenticated**:
Retired by ADR-0014. It named a Setup a master key holder had pushed, as
against one anybody could have — a distinction that existed because a keyless
push could write a Setup at all. Once a Setup is sealed there is nothing to
write without the key, so every Setup in an Archive is the first kind and the
word divides nothing. What outlived it is the Index's record of **which tree is
current**, which was always a separate question: a seal says a key holder wrote
these bytes at some time, and a versioned Destination keeps every sealed tree it
has ever held, all of which open. Say _current_ for that, and say _sealed_ for
what a seal proves.
_Avoid_: authenticated, unauthenticated (both retired), verified, signed
(nothing here is a signature; one key both writes and checks)

**Pairing**:
Giving a new machine the master key by way of a short one-time code, so nobody
has to type the recovery key. Travels through the Destination, not between the
machines directly. The code has two halves that never do each other's job — a
Locator and a Pairing secret.

**Locator**:
The half of a pairing code that names the wrapped key's object in the Archive.
Not a secret: it is published as a filename on untrusted storage, and guards
nothing.
_Avoid_: calling it "the code" — it is the half that gives nothing away

**Pairing secret**:
The other half, which wraps the master key and is the only part any key
derivation ever sees. Never written anywhere the Destination can read; a
pairing is only as private as this half.

**Recovery key**:
The high-entropy secret that opens an Archive, generated once and kept by the
user. The root of trust and the last resort; lose it and the History is gone.

### Handling credentials

**Reports**:
What carryon does when it finds a credential in either half — names it, carries
on, encrypts. One posture, in a Setup and a History alike (ADR-0014). It is not
a judgement that the credential is harmless: it is carryon declining to manage
somebody's secrets for them, having first made sure nothing crosses in the
clear.
_Avoid_: refuses (that was the Setup's posture until ADR-0014, and it is not a
word about credentials any more)

## Flagged ambiguities

**"Bundle"** appears throughout the current code and README meaning "a Setup".
It is retired: a Snapshot is the whole, a Setup and a History are its parts.

**"Scan"** meant two different things depending on where it ran. Since ADR-0014
it means one — it *reports*, everywhere. Say *reports*, and never let "the scan
passed" stand in for a promise about the bytes: it is a list of shapes it
recognises, not a proof of what is absent.

**"Clean"** is retired entirely (ADR-0014). It was an absolute, then briefly a
word about the Setup alone, and it never was a proof: it said only that the scan
matched no credential shape it knows. A secret that announces nothing —
carryon's own master key is bare hex — was always invisible to it, so *clean*
named the scan's coverage while reading as a guarantee about the bytes. There is
one promise now and it is about storage, not content: everything carryon carries
is encrypted. Say *encrypted*, and say what the scan reported separately.

**"Refused"** no longer covers credentials at all (ADR-0014) — those are
*reported*, in both halves. What remains refused is what a Destination serves —
this object, this catalogue entry, this stored item — named in the report while
the rest of the run carries on, and what a capture may read at all, which is
ADR-0008's rule and stops a whole capture. Those two still differ in size, and
the unit is the whole difference between a pull that skips a Session and a pull
that abandons an Archive, so say which one is meant.

**"Memory"** names things in both halves, with opposite safety properties. The
per-project notes that accrete beside a project's Transcripts are a History:
unioned per file, never deleted, and a divergence is filed rather than
resolved. An agent that keeps its memories in one install-wide tree instead —
partitioned by a path recorded inside each file rather than by directory — has
them in its Setup, where a pull overwrites any file of the same name from
whichever machine's Setup was chosen and leaves the rest. The word says nothing
about which, so say the per-project ones or the install-wide ones, and never
"memories" unqualified when the difference decides whether something can be
lost.

**"Replace"** is a word about one file and gets read as a word about a
directory. A pull replaces a Transcript; it does not replace a Session tree,
and it does not replace a Setup directory. Name the unit every time — per
member, per item — because the rule that destroyed a user's workflow journals
was true of the one Transcript it was written about and false of the thirty
files it was applied to.

## Example dialogue

> **Dev:** If I push from my laptop, does my API key go up?
>
> **Domain expert:** Yes, and sealed either way. If it's in your settings it
> travels in the Setup; if you echoed it in a terminal six weeks ago it's in
> your History. carryon names what it recognised in both, then encrypts the lot
> and pushes.
>
> **Dev:** It doesn't stop me?
>
> **Domain expert:** It used to, for the Setup, and that only worked while the
> Setup went up in the clear. Both halves are encrypted now, so there is nothing
> left to protect you from by refusing — it would just be carryon deciding how
> you may store your own keys.
>
> **Dev:** So it's safe.
>
> **Domain expert:** It's encrypted. That's not the same word. All of it is only
> as safe as your recovery key — and a quiet report means no shape it knows, not
> that there was nothing there.
>
> **Dev:** And when I pull it down on the desktop?
>
> **Domain expert:** Nothing to translate by then — Re-keying already happened
> on the way out, so what's sitting in the Archive doesn't mention your laptop's
> home at all. The desktop just expands it against its own.
>
> **Dev:** Even though one's `/Users/you` and the other's `/home/you`?
>
> **Domain expert:** That's the whole reason it's done that way. If the Archive
> held your laptop's paths, every machine that ever pulled would need to know
> where your laptop kept its home.
>
> **Dev:** And my settings.json is a symlink into my dotfiles repo.
>
> **Domain expert:** Then it's externally owned and pull won't touch it. It'll
> say so. Your dotfiles put it there; carryon writing through that link would
> quietly edit the repo.
