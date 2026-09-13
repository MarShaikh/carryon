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
is the one place this decision takes a capability away rather than adding one,
and it needs its own answer before implementation.

The README states the two halves apart, on ADR-0001's instruction, and that
instruction is withdrawn — the Setup is no longer *clean*, it is encrypted, like
everything else. `cli.py`'s own description ("the Setup in the clear and checked
for credentials, the History always encrypted") says the retired thing too. The
README is maintained by hand and is not this ADR's to rewrite.

ADR-0013 is unaffected. It was argued from what a Setup *is* rather than from the
scanner, so a Setup still carries a capability and not the workshop that built
it, whether or not a credential would have been refused.
