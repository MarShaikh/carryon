# Refuse credentials in a Setup, report them in a History

carryon was built on a fail-closed credential scanner: a hit stops the capture
and produces nothing, on the reasoning that a Setup should contain no
credentials at all, so a hit means the Adapter is reading a file it shouldn't.
That reasoning does not transfer to a History. A credential in a Transcript
means something was echoed to a terminal in the past; no Adapter change can fix
it, and measuring the current scanner against 56 real transcripts had 26% of
them tripping it. Fail-closed there would block a push the user has no way to
unblock.

So the posture is now category-dependent. In a Setup the scanner **refuses** —
unchanged. In a History it **reports** a count and carries on, and the History is
encrypted unconditionally regardless of Destination.

## Considered options

**Redact the credentials out of the History**, as `entangle share` does by
default. Rejected: a Transcript that has been rewritten may not resume, which
destroys the thing being carried. And the rule responsible for all 26% is a
keyed-secret heuristic tuned to be noisy-safe across a hundred small config
files — pointing it at tens of megabytes of terminal history and then editing
whatever it flags would corrupt mostly false positives.

**Block unless the user opts in.** Rejected: an opt-in the user must click every
time becomes reflexive. `secrets.py` already argues this in its own comments —
a scanner people learn to click through is how a real key eventually gets out.

**Skip scanning a History entirely.** Rejected: carryon would ship credentials
to third-party storage and never mention it. Reporting costs one pass over data
already being read.

## Consequences

carryon can no longer make a single promise about what it produces. A Setup is
*clean*; a History is *encrypted*. Those are different guarantees and
user-facing text must not blur them — see the flagged ambiguities in
`CONTEXT.md`. In particular, any claim that a carried artifact contains no
credentials is true only of a Setup, which is why the README states the two
halves apart rather than making one promise about a push.

*Clean* is also the scanner's verdict over the credential shapes it knows,
which is weaker than the sentence above reads. A secret that announces nothing
— a random token, or carryon's own fallback master key, which is bare hex —
matches no rule here and never will, so the promise a Setup carries no
credential rests on the capture list being right rather than on this pass
catching what it should not have read. That is why what a Setup may read at
all became a rule of its own (ADR-0008) instead of a question put to the
scanner, and why user-facing text says what was checked rather than what is
absent.
