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
lists. Contains no credentials, and carryon refuses to produce one that does.
_Avoid_: config (it is one of three categories inside a Setup, not the whole)

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

**Layout drift**:
An Adapter expecting a path the agent no longer uses. The early warning that a
vendor has reorganised, and the reason Adapters record what version they were
checked against.

### Moving it

**Destination**:
Somewhere a Snapshot can be put and later fetched. Carryon holds no credentials
for one: it borrows whatever the user already has.

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
What a machine's Setup is once a master key holder has pushed it: a tag over
the whole plaintext tree, with the Index recording that the tag exists and
which tree is current. The record lives in the Index because the tag itself
sits where an attacker can strip it — a tag that can be stripped is not a
guard. A keyless push produces an unauthenticated Setup, and warns.
_Avoid_: verified, signed (nothing here is a signature; one key both writes
and checks)

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

**Refuses**:
What carryon does when it finds a credential in a Setup — stops, names the file,
produces nothing. A hit there means the Adapter is wrong, and that is fixable.

**Reports**:
What carryon does when it finds a credential in a History — names the count,
carries on, encrypts. A hit there means something was echoed to a terminal in
the past. The user cannot fix it retroactively, so blocking them would be an
obstacle rather than a safeguard.

## Flagged ambiguities

**"Bundle"** appears throughout the current code and README meaning "a Setup".
It is retired: a Snapshot is the whole, a Setup and a History are its parts.

**"Scan"** now means two different things depending on where it runs. Say
*refuses* or *reports* instead, never "the scan" unqualified.

**"Clean"** was an absolute — carryon either produced a credential-free artifact
or nothing. It now applies only to a Setup. A History is never clean; it is
encrypted. These are different promises and must not be blurred in user-facing
text. Nor is *clean* a proof: it says the scan matched no credential shape it
knows and the capture set read nothing it must not. A secret that announces
nothing — carryon's own master key is bare hex — is invisible to it, which is
why what a Setup may read is a rule of its own and not a question put to the
scanner.

**"Refused"** now covers two different sizes. A credential in a Setup refuses
the whole capture and nothing is produced. What a Destination serves is refused
one thing at a time — this object, this catalogue entry, this stored item —
named in the report while the rest of the run carries on. Both are the same
posture, fail closed and say so, and the unit is the whole difference between a
pull that skips a Session and a pull that abandons an Archive, so say which one
is meant.

**"Replace"** is a word about one file and gets read as a word about a
directory. A pull replaces a Transcript; it does not replace a Session tree,
and it does not replace a Setup directory. Name the unit every time — per
member, per item — because the rule that destroyed a user's workflow journals
was true of the one Transcript it was written about and false of the thirty
files it was applied to.

## Example dialogue

> **Dev:** If I push from my laptop, does my API key go up?
>
> **Domain expert:** Depends which half. If it's sitting in your Setup, carryon
> refuses to push at all — that's an adapter bug, we shouldn't have been reading
> that file. If you echoed it in a terminal six weeks ago it's in your History,
> and carryon will tell you how many transcripts look like that, then encrypt
> the lot and push it.
>
> **Dev:** So it's safe.
>
> **Domain expert:** It's encrypted. That's not the same word. Your Setup is
> clean; your History is only as safe as your recovery key.
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
