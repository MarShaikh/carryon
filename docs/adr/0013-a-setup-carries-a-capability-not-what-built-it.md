# A Setup carries a capability, not what built it

The first `push` ever aimed at a real cloud Destination refused its Setup half.
The file was a skill's test suite, and what it matched was the jwt.io example
token — `{"alg":"HS256"}` over `{"sub":"1234567890"}`, the most published dummy
credential there is — beside an `access-token=` whose value was the alphabet.
The scan was right about the bytes and the refusal was right to fire. What had
no answer was the sentence the refusal ends on: fix the capture list, and re-run.

ADR-0001 delegates that cure deliberately — the promise "rests on the capture
list being right rather than on this pass catching what it should not have
read", which is why what a Setup may read became ADR-0008's rule instead of a
question put to the scanner. ADR-0008 then scopes the config's reach: it can
exclude "anything an Adapter declares". An Adapter declares `.claude/skills`;
the scanner reports one file inside it. So the cure exists at the granularity of
the declaration and the complaint arrives at the granularity of a file, and
between those two the user has nothing to write down. `.claude/skills` matches
and takes all fifteen skills with it, four of which exist nowhere else;
`.claude/skills/job-application-agent/tests/*` matches nothing and is reported
back as a typo.

ADR-0001 rejected fail-closed for a History because it "would block a push the
user has no way to unblock". That condition had arrived in the Setup, by a route
that ADR did not have to consider.

## What the measurement said

ADR-0001 settled the History posture by counting: 26% of 56 real transcripts
tripped the scanner. The same count over this machine's capture set puts the two
halves side by side for the first time.

| Half | Files | With a hit | Rate |
| --- | --- | --- | --- |
| Setup | 40 | 1 | **2.5%** |
| History | 370 | 102 | **27.6%** |

The History figure reproduces ADR-0001's on a corpus it never saw, which is the
strongest evidence that document could have hoped for. The Setup figure is the
new one, and it points the other way from where this started. The Setup scanner
is not noisy. It fired once in forty files, and the one file it fired on is a
test suite for a credential detector — a file that must contain credential
shapes to do its job at all.

So the problem was never that the gate is too tight. It is that a Setup was
carrying something a Setup is not for. `secrets.py` says so in its first
paragraph and has since it was written: a hit means the capture list is wrong.
The capture list was wrong. Eleven of the thirty-three files under the carried
skills — a third of them, 125K of 320K — are a test tree, and a machine that
pulls this Setup needs none of it to have the skill.

## The decision

A tree an Adapter declares is **vouched**: the Adapter named a directory the
user never named, on their behalf, and stands behind its contents. carryon may
leave **Development artifacts** out of a vouched tree, because nobody chose them
one by one and a Setup is not a backup — the glossary refuses that word for both
a Snapshot and an Archive.

A handpicked path is the opposite and deliberately so. ADR-0008 says a user-added
path always joins the Setup, and `config.py`'s pseudo-Adapter records it as
"user-supplied - unvouched". The user named that path. Nothing here narrows it,
and a `carry` entry pointing at a directory called `tests` is carried as a
directory called `tests`.

That is the whole rule, and it turns on a distinction the codebase already draws
rather than on a flag somebody has to remember to set.

## Considered options

**Let an exclude reach inside a declared Item.** The smallest change, and it
keeps the user in charge. Rejected because it moves ADR-0008's boundary to buy
a cure for a problem that should not exist: the config would gain the power to
carve up a declaration, and every user of every Adapter would have to know to
use it. A pattern that goes stale then shrinks a Setup silently, and nothing
says it went stale.

**Acknowledge a known-safe hit, pinned to a content hash.** The only option that
also covers a credential shape inside a file that genuinely belongs in a Setup.
Rejected for now on two documented grounds and one absence. ADR-0001 rejected the
opt-in because "a scanner people learn to click through is how a real key
eventually gets out" — weaker here than there, since 2.5% is not "every time",
but not nothing. ADR-0010 is the harder one: "an allowlist can do one thing a
reviewer cannot, which is make an open defect look approved", written about the
file that opens the Archive. And the absence: there is no observed case. Every
hit measured was either a History file, where ADR-0001 already reports and
carries on, or a Development artifact this ADR removes. Building an escape hatch
against two recorded warnings, for a case nobody has seen, is how the warnings
get spent.

**Teach the scanner that the jwt.io token is not a credential.** `secrets.py`
already suppresses indirections, but only for `keyed-secret` — the `jwt` rule has
no suppression path at all. Rejected as the primary answer because at a 2.5% base
rate the scanner is not the thing that is wrong, and suppressing this token fixes
one file rather than the class. Worth doing on its own merits; it is not this
decision.

## Consequences

A Setup gets smaller and truer. The skills a machine pulls are the skills, not
the skills plus the workshop, and the one file that has ever refused a real push
stops being captured at all — not excused, not acknowledged, just no longer
something a Setup was ever for.

**This does not close the seam in general, and that is deliberate.** If a
credential shape ever lands in a file that genuinely belongs in a Setup — a
settings file with an example token in a comment — the user will still have no
cure to write down, and this ADR will not have helped them. That case is real
but unobserved, and the two rejected options above are both available when it
turns up. What changes is that it would then be a decision made against evidence
rather than against a hypothetical.

`doctor` gains something to say. A Development artifact left out of a vouched
tree is not layout drift and must not be reported as it — it is carryon
declining to carry something, which is the same class of thing as an exclude and
belongs wherever those are named.

The prune list is a list, and ADR-0010 is explicit about what those cost:
"'every place it arises' is a list somebody maintains by reading". This one is
small, it is about the shape of software rather than about any vendor, and it
fails in the safe direction — an unrecognised development directory is carried,
which is the status quo, rather than a needed one being dropped. It is not a
gate and must never become one: nothing about credentials may depend on it,
because the scanner still runs over everything that survives it.
