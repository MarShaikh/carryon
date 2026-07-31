# Re-key to a canonical form at push, by walking JSON string values

A Transcript records absolute paths, so a History restored on another machine
refers to directories that do not exist and will not resume. Re-keying could run
when a Session is pulled, translating the source machine's home to the local
one, or when it is pushed, storing a canonical `~`-relative form that each pull
expands.

carryon canonicalises at push. The Archive is then machine-neutral: a third
machine needs to know nothing about where the first one kept its home, and the
work happens once per push rather than once per pull per machine.

## What gets rewritten

Every occurrence of the home path *inside a JSON string value* — never in keys,
never at byte level. Occurrences are mid-string, not prefixes: paths appear in
running prose as often as in fields.

Enumerating the fields that carry paths was rejected. A single real Transcript
held them in six distinct shapes (`cwd`, `message.content[].input.file_path`,
`toolUseResult.file.filePath`, `toolUseResult.filePath`,
`message.content[].content`, and a bare `toolUseResult` string), and any list
would silently fall behind a vendor schema change. Walking string values costs
nothing extra and cannot fall behind.

Confining rewrites to string values bounds the worst case to a semantic one — a
Transcript that discussed the old path as data now reads slightly wrong — rather
than a structural one. It cannot produce a file that will not parse.

## The project directory name is derived, never decoded

Claude Code names a project directory after its path with **every
non-alphanumeric character replaced by `-`**, so `/Users/x/CUDA_course/practicals`
becomes `-Users-x-CUDA-course-practicals`. A `/`, a `_` and a space all become
`-`, and a `-` already in the path stays one, so several characters collapse
into one and the name cannot be decoded back. It is therefore re-derived from
the `cwd` recorded inside the Session, which is authoritative, and re-encoded
for the target.

This makes the encoding itself a form of layout drift: if a vendor changes it,
re-keyed Sessions land in a directory the agent will not look in. Adapters
record the version they were verified against for exactly this reason.

## Every absolute path in a Setup, not the one field that named the home

Re-keying reads as a History concern, and the Setup half was first handled one
field at a time: the MANIFEST field that obviously named the source home. That
is the enumerate-the-fields mistake rejected above, one layer up: capture
records the home it read from *and* the resolved target of every externally
owned symlink, and a later Adapter or item kind will record another without
anyone revisiting that code. So a MANIFEST is walked the way a Transcript line
is — every string value, keys untouched — and so is the content of every UTF-8
file in the staged Setup, because a hook command or a standing instruction
spells a home out as readily as a manifest field does. That is also what makes
a restored hook path work on a machine whose home is somewhere else.

Rewriting cannot cover all of it. A value still shaped like an absolute path
after the home has been rewritten names some directory on the source machine
that `~` cannot express — another volume, a team share, a spelling of the home
differing only by case, which the no-case-folding rule forbids collapsing. Those
are **withheld**: replaced by a note saying a path was there, and counted in the
push report. The name of the thing survives; the path it had on that machine is
not something an Archive gets to carry.

A staged file that does not decode as UTF-8 is withheld from the Archive
outright, and named in the push report. carryon cannot read one to tell whether
it spells this machine's home out, so carrying it would put a value in the
Archive's one plaintext half that this rule exists to keep out; nothing here
can tell an image in a skill from a latin-1 note or a log with one stray byte
in it, and the two cannot have different answers. The file stays on the machine
that holds it and a pull elsewhere lands without it, which is a real cost and
the reason the report names each one rather than counting them.

RESTORE.md is re-rendered from the neutralised MANIFEST rather than scrubbed on
its own. It is a rendering of that MANIFEST, and the two being written from
different sources is exactly how resolved symlink targets reached a Destination
once already.

## Details

Paths outside `$HOME` cannot be derived from the home mapping and need
`--map OLD=NEW`, a flag adopted from entangle. Matching is exact, with no case
folding — macOS being case-insensitive means `/users/alice` can occur, but
folding case would rewrite things it should not, so near-misses are reported
rather than guessed at.
