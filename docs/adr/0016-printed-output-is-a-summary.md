# Printed output is a summary, and the reasoning stays here

By 2026-10-21 carryon's output had grown to explain itself. A routine
`sync --apply` printed a `keep … ahead` line ending in "(ADR-0002)" and a
sentence about `--mirror` being deliberately not built. A `push --apply`
printed capture's whole report: the staging directory, "Wrote 299 files …
to staging", and a paragraph warning that the Setup was in the clear and only
as private as the directory it sat in. That paragraph is `capture --out`'s,
and inside a push it is wrong, because a push publishes a sealed Setup. About
57 printed strings cited an ADR. Read in a real terminal, the reasoning drowned
out what had happened.

## The rule

Every message a user sees, meaning a command's report, its hints and its
refusals, says what happened and what to do next. It cites no ADR and gives no
design reasoning. One line of why is allowed, and only when the user needs it
to act. The test before a sentence ships is to ask whether a user would
benefit from knowing the design decision behind it. Usually they would not,
and a user who is curious reads the ADRs. Code comments, docstrings and these
records keep the reasoning, because that is where it belongs.

## A summary by default, detail behind `--verbose`

`push`, `pull` and `sync` gain `--verbose`, which `status` already has
(ADR-0015). The default report always keeps what a user acts on:

- counts
- anything not carried, or carried differently from what was asked
- Setup files holding possible secrets, by name, because a user can move a key
  out of a file
- the next command

What only describes the work moves behind `--verbose`: per-item capture lines,
the folders that recorded no working directory, the Sessions behind a
History's secrets count (a transcript is not something a user edits), and
the re-keying counts.

A dry run prints the same summary as `--apply`, changing only its verbs and
its last line.

## Push reports its own Setup

`capture.run` is split into a step that collects a capture's findings and a
step that prints them. `capture --out` does both. `push` collects only, and
words the findings in its own report, so none of capture's lines about the
staging directory reach a push.

## Consequences

- Each command is rewritten on its own, `push` first, then `pull`, `sync` and
  `status`, then the rest. Every changed sentence keeps an assertion that pins
  it, and the README's examples follow.
- One test asserts that a push never prints capture's in-the-clear paragraph
  or its staging lines. Whole-output comparisons were rejected, because they
  break on every later rewording.
- Lines are gated where they are printed. A report object built first and
  rendered after was rejected for now. It would pay off only for machine-
  readable output, which nobody has asked for.
