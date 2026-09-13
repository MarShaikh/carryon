# Encrypt both halves, and refuse nothing

> Status: supersedes the Setup half of ADR-0001. That ADR's History posture is
> unchanged and was re-measured while this was decided.

ADR-0001 split the posture by half: refuse a credential in a Setup, report one in
a History. The asymmetry rested on a difference in what could be done about a
hit — an Adapter reading a file it shouldn't is fixable, a credential echoed to a
terminal last March is not — and on a difference in storage that document did not
have to state, because it was true either way: a History is encrypted and a Setup
is written to the Archive in the clear.

Two things found on the way to the first real cloud push undo that split.

The first is that the fixable/unfixable line does not hold. `.claude/settings.json`
carries an `env` block; that block is where an `ANTHROPIC_API_KEY` or an MCP
server's token goes; and that file is a `CONFIG` Item — as unambiguously part of a
Setup as anything carryon carries. No Adapter change fixes that, because the
Adapter is right to carry the file. ADR-0001's cure ("a hit means the Adapter is
wrong, and that is fixable") has no purchase on it, and ADR-0013 could only remove
the *observed* cause while recording that this case had no answer.

The second is what the split actually costs. Refusing produces nothing at all,
which for a user whose settings hold a key means carryon simply does not work —
the same sentence ADR-0001 used to reject fail-closed for a History, "would block
a push the user has no way to unblock", arriving in the other half by a different
route.

## The decision

Both halves are encrypted, and the scan refuses in neither. It names what it
found, in a Setup exactly as it already does in a History, and the push carries
on.

This is not a relaxation. Today a Setup goes into the Archive in the clear, so
the only thing standing between somebody's `env` block and a readable object in a
bucket is a refusal that stops the whole push. After this, that key crosses the
network and sits at the Destination sealed under the master key — which is
strictly better than the status quo's best case, where the credential never
travelled because nothing did.

It is also less to explain. carryon had two promises and a paragraph in
CONTEXT.md about not blurring them. It now has one: **carryon reports what it
sees and encrypts what it carries.**

## encrypt_all becomes the behaviour, not a knob

`config.py` has declared, defaulted and validated `encrypt_all` since it was
written, and nothing has ever read it. The intent was recorded and never wired
up. It is now the behaviour, and the knob is removed rather than defaulted on.

A knob that can be turned off is the plaintext-credential case restored, and it
would restore it for exactly the user who turned it off — which is ADR-0001's own
argument about an option people learn to click through, one layer up. The reason
to want a readable Setup is real, and it already has a home that is not somebody
else's storage: `carryon capture --out DIR` writes the whole thing to a local
directory, in the clear, for reading and diffing. Plaintext belongs on the machine
that already has the secrets, not in the Archive.

## Sealed as one object per machine

"Encrypted" leaves the shape open, and the shape decides what the Destination
still learns. A Setup becomes a single sealed object — `setups/<machine>.tar.enc`
— which is what a Session already is, so the Archive grows no second idea of what
sealed storage looks like.

The alternative was to seal each file where it stands and keep the tree. It
keeps a partial push cheap, which is the honest argument for it, and it leaves
the names in the clear: today's Destination can read that this machine has a
skill called `job-application-agent` and a file in it called `secret-store.mjs`.
That is a weaker promise than the one this ADR makes, and it would have to be
explained every time someone asked why the contents are hidden and the shape is
not. The cost is paid by `push --category config`, which now rewrites the whole
object rather than the files it changed — 280K on the machine this was decided
on, and a Session tar is already larger.

## What sealing deletes, and the one thing it must not

`SETUP.mac` exists only because a plaintext tree could not be sealed.
`crypto.py` says so in its own words — "the plaintext Setup cannot be sealed
without giving up ADR-0004, so it gets the MAC without the encryption" — and
`archive.py` repeats it over the tag. A seal is an HMAC over the object's label
and then the ciphertext, so once the Setup is sealed the tag is a second answer
to a question already answered, and a second answer is what ADR-0010 exists to
prevent. It goes, and `setup_tree_manifest` with it.

Two of `authentication.py`'s guards go the same way, and for a better reason
than redundancy: they stop being reachable. `_vouch_for_stored_manifest` closes
a signing oracle in the partial push — the stored `MANIFEST.json` is read back
off the Destination, merged, and then MACed with the user's own key, so an
attacker who edits that one file gets their JSON signed. When the stored
manifest arrives out of a sealed object, it was written by a key holder or it
does not unseal; there is nothing to vouch for it against because there is no
longer a way for the Destination to have authored it. `_carried_setup_files`
answers the same question for the other files and goes with it.

**`_stale_stamp` stays, and nothing about this makes it less necessary.** A
sealed object is as replayable as a plaintext one: a versioned Destination keeps
every `<machine>.tar.enc` it has ever held, and every one of them unseals
correctly for ever. The seal says a key holder wrote these bytes at some time,
which is not "this is the Setup a key holder means you to have now" — that
sentence has only ever been the Index's to say, and it still is. The temptation
this ADR creates is to read "it unsealed" as "it is current", which is precisely
the confusion `_stale_stamp`'s own docstring was written against after one
ordinary `push --category config` laundered a replayed tree.

## A keyless push refuses, and the recovery key waits

Settled: a push needs a master key. There is nothing to write without one, so
`push --category config` on a keyless machine refuses and names the two cures —
`init` or `pair` for a key, `capture --out DIR` for a readable Setup on the
machine that already has the secrets.

This withdraws something ADR-0004 stated as a fairness property: "the burden
falls on people who opt into carrying History, not everyone". It now falls on
everyone, and that is the price of one promise instead of two.

What it does not do is answer the case that made keyless push worth having — a
machine whose keychain entry is gone. That machine must re-pair from one that
still holds the key, exactly as it must for a History today, because nothing in
the CLI takes a recovery key back; ADR-0004 records that absence and it is
unchanged here. Building that command is the better answer and it is deliberately
not in this decision's scope.

## Retiring a setting is not deleting a line

`encrypt_all` cannot simply leave `default_config`. `config.validate` refuses
any key it does not know AND any known key that is missing — a deliberate
posture, because "a typo that validation shrugs at is a setting silently not
applied". So deleting the declaration turns every config.json that has ever been
written by `carryon init` into `'encrypt_all' is not a carryon setting`, on every
command, including the one the user would run to fix it.

The loader therefore learns what a retired setting is: a name that was once real,
is dropped on read, and is named once so the user knows their file has something
in it that no longer does anything. That is a third category beside known and
unknown, and it is worth the line it costs — the alternative is a tool that
breaks its own installs whenever a decision is reversed, which would make every
future reversal more expensive than the decision deserves.

## Consequences

A Setup can no longer be read at the Destination. `carryon/setups/<machine>/` was
browsable with nothing but Destination access, and that was occasionally useful
and is now gone. `pull` and `capture --out` are the ways to look at one.

The scanner keeps its whole job and loses its veto. It still runs over everything
captured, still names files, and what it produces is a report line in both halves.
Nothing about it may become load-bearing for secrecy — encryption is what protects
the bytes, and a scanner that misses a secret announcing nothing (carryon's own
master key is bare hex, as ADR-0001 notes) was never the thing keeping them safe.

**A keyless push can no longer produce a Setup.** Today an unauthenticated Setup
is a real state — it warns and proceeds. With the Setup sealed under the master
key there is nothing to write without one, so that path becomes a refusal. This
is the one place this decision takes a capability away rather than adding one;
it is settled above rather than left open, and what it leaves unanswered — a
machine that has lost its key — is named there too.

**"Unauthenticated" stops naming anything.** The word distinguished a Setup a
key holder pushed from one anybody pushed, and after this every Setup in the
Archive is the first kind. It goes out of the vocabulary rather than staying on
as a state nothing can reach; what survives is the Index's record of which tree
is current, which was never the same question.

The README states the two halves apart, on ADR-0001's instruction, and that
instruction is withdrawn — the Setup is no longer *clean*, it is encrypted, like
everything else. `cli.py`'s own description ("the Setup in the clear and checked
for credentials, the History always encrypted") says the retired thing too. The
README is maintained by hand and is not this ADR's to rewrite.

ADR-0013 is unaffected. It was argued from what a Setup *is* rather than from the
scanner, so a Setup still carries a capability and not the workshop that built
it, whether or not a credential would have been refused.
