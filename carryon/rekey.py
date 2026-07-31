"""Re-keying: the path rewriting that makes an Archive machine-neutral.

A Transcript records absolute paths, so a History restored elsewhere refers to
directories that do not exist and will not resume. Per ADR-0006 the rewrite
happens once, at push - every occurrence of the home path inside a JSON string
value becomes '~' - and each pull expands '~' against its own home. Keys are
never touched, and matching never folds case: a case-insensitive-only hit is a
near-miss, reported and left alone.

The one non-obvious decision: a line that needs no rewrite (or does not parse)
passes through byte-identical, and only changed lines are re-serialised. Pull's
union rule compares Transcript bytes prefix-wise; re-serialising every line
would make each machine's copy of the same Session look divergent.

Standalone on purpose: imports nothing from the rest of carryon, so the push
and pull pipelines can both lean on it without ordering their imports.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
import unicodedata

HOME_TOKEN = "~"


def _names_a_directory(value: str) -> bool:
    """Whether an absolute path names something below the root.

    '/', '//' and '/////' are absolute and name the root itself, which is not
    a directory a --map can move: it is a substring of every path in the
    Archive, so replacing it rewrites all of them and their prose with them.
    """
    return bool([part for part in value.split("/") if part])


def map_refusal(pairs):
    """Why this set of `--map OLD=NEW` arguments cannot be applied, or None.

    `--map` is the one thing a user hands the re-keying engine, and it had
    never been treated as input. What it does is a plain substring replace
    over every string value of every restored Transcript and over the
    restored Setup besides, so an OLD that is not a path matches inside
    ordinary prose: `--map e=E` turned 'Answer briefly.' into 'AnswEr
    briEfly.' in a restored CLAUDE.md, and every value of every Transcript
    with it, at exit 0 and without one line of the report mentioning a map.
    The flag is the user's own, so the bar is report-and-refuse rather than a
    security boundary - but a silent wrong write is a defect at either bar.

    Two rules, and each is the flag's own documentation made checkable.
    Both sides are absolute paths, because the flag exists for "a path
    outside $HOME" and a Transcript records nothing but absolute paths -
    which also refuses `~/from=...`, since nothing expands a '~' on this
    side of the rewrite and it would be matched literally.

    Absolute is not enough on its own, and the round that wrote the rule
    found that out one character later. `os.path.isabs('/')` is True and the
    chain rule below skips a pair against itself, so `--map /=/tmp/relocated`
    passed both and rewrote every string value of every Transcript, the
    derived project-directory name and the restored CLAUDE.md: 'and/or' came
    back as 'and/tmp/relocatedor'. That is `--map e=E` in the one spelling
    the rule as written could not see. So a side has to name something BELOW
    the root as well as start at it - '/' is the one absolute path that is a
    substring of every other, and it names no directory to move.

    And no pair's NEW may contain another pair's OLD. "Applied longest OLD
    first" describes one rule winning over another on the same value, which
    is what a user reads it as; what the code does is apply each rule to the
    previous rule's OUTPUT, so '/a=/b' with '/b=/c' sends everything under
    /a to /c and the honest swap '/a=/b' with '/b=/a' is a no-op. A pair
    whose NEW contains its own OLD is fine and stays allowed - str.replace
    does not re-scan what it just wrote, so '/data=/data-old' is the ordinary
    rename it looks like.

    Stated here because this is the module both spellings of the rewrite live
    in, and returned rather than raised so the caller decides where the
    refusal lands - which has to be before anything is read, not from inside
    the loop that writes.
    """
    maps = []
    for raw in pairs or []:
        if "=" not in raw:
            return f"--map {raw!r}: expected OLD=NEW"
        old, new = raw.split("=", 1)
        if not old or not new:
            return f"--map {raw!r}: OLD and NEW must be non-empty"
        for side, value in (("OLD", old), ("NEW", new)):
            if not os.path.isabs(value) or not _names_a_directory(value):
                return (
                    f"--map {raw!r}: {side} is not an absolute path naming a "
                    "directory. A --map moves a path the Archive recorded "
                    "outside $HOME to where it lives here, and the match is a "
                    "plain substring over every value in every Transcript - "
                    "so anything shorter than a path rewrites prose, and '/' "
                    "is inside every path there is. Nothing expands a '~' "
                    "here either; spell the directory out.")
        maps.append((old, new))
    for index, (_old, new) in enumerate(maps):
        for other, (old, _new) in enumerate(maps):
            if other != index and old in new:
                return (
                    f"--map: {_old!r} maps onto {new!r}, which {old!r} then "
                    "rewrites again. Each pair is applied to what the pair "
                    "before it produced, so a chain moves paths somewhere "
                    "neither pair names and a swap cancels itself out. Do it "
                    "in one pass, or in two pulls.")
    return None


@dataclasses.dataclass(frozen=True)
class RekeyStats:
    """What one pass over one JSONL file did, for the push/pull reports."""
    lines: int = 0
    rewritten_values: int = 0   # string values changed, not occurrences
    malformed: int = 0          # lines that did not parse, passed through
    near_misses: int = 0        # case-insensitive-only matches, never rewritten


@dataclasses.dataclass(frozen=True)
class TextRekeyStats:
    """What one pass over one non-JSONL text file did.

    bare_tokens is the round-trip gap made countable: canonicalise reports
    home occurrences that became a bare '~' (nothing but '/' after them
    expands), expand reports the '~' it left alone. Pull reports the number
    instead of the asymmetry hiding in a docstring.
    """
    replaced: int = 0           # occurrences rewritten
    near_misses: int = 0        # case-insensitive-only matches, never rewritten
    bare_tokens: int = 0        # ambiguous bare '~': created at push, kept at pull


def _home_str(home) -> str:
    return str(home).rstrip("/")


def home_forms(home) -> list:
    """Every spelling of one home a captured value may carry, longest first.

    A Transcript records whatever the process that wrote it saw, and one
    directory has more than one true name. The CLI hands push an unresolved
    `Path.home()` while a shell prints the resolved path, so any $HOME with a
    symlink in it - /home/x pointing at /export/home/x, a macOS home on an
    external volume, an automounted one - reaches the Archive in two
    spellings. macOS stores filenames in NFD while a shell or a Python
    literal usually produces NFC, which is a third.

    Longest first is not cosmetic. Rewriting '/var/.../x' before
    '/private/var/.../x' leaves '/private~', which is neither the path that was
    recorded nor a machine-neutral one, and expands on the receiving machine
    into a directory that cannot exist.

    A home that will not resolve has one spelling, which is the answer this
    returns. The guard is not decoration: resolve() is the call the two
    interpreters carryon must pass answer differently - a symlink loop is a
    RuntimeError on 3.9 and the unresolved path on 3.13 - and this sits on
    the hot path of every re-key in both directions, so on one runner an
    unresolvable $HOME was a traceback out of push and out of pull.
    external.owner_of says the same sentence about the same call.
    """
    forms = []
    try:
        resolved = pathlib.Path(home).resolve()
    except (OSError, RuntimeError, ValueError):
        resolved = home
    for base in (home, resolved):
        text = _home_str(base)
        for form in (text, unicodedata.normalize("NFC", text),
                     unicodedata.normalize("NFD", text)):
            if form and form not in forms:
                forms.append(form)
    return sorted(forms, key=len, reverse=True)


def _ordered(maps) -> list:
    # Longest OLD first, so "/data/projects" beats "/data" on the same value.
    return sorted(maps, key=lambda pair: len(pair[0]), reverse=True)


def apply_maps(text: str, maps) -> tuple:
    """(text, replaced, near_misses) after every --map pair, longest OLD first.

    One implementation, because there are three callers and there were three
    copies: a Transcript's string values (expand_jsonl), a text file's whole
    body (expand_text) and the Index's recorded cwd, which the History engine
    expands one module over. Three sequential replace loops is how two of them
    come to disagree about what a set of maps does - and `map_refusal` is
    written about THIS loop's semantics, so a caller with its own copy is a
    caller the refusal is not quite about.
    """
    replaced = near = 0
    for old, new in _ordered(maps):
        near += _near_misses(text, old)
        hits = text.count(old)
        if hits:
            replaced += hits
            text = text.replace(old, new)
    return text, replaced, near


def _near_misses(text: str, needle: str) -> int:
    # Occurrence-wise: case-variant hits minus exact hits, so an exact hit in
    # the same value never swallows a variant one. Both directions count this
    # way on purpose.
    folded = text.lower().count(needle.lower())
    exact = text.count(needle)
    return folded - exact if folded > exact else 0


def _walk(node, value_fn):
    """Rewrite string values throughout a parsed line.

    Returns (new_node, values_changed, near_misses). Dict keys are passed
    through untouched - a pathlike key is data about the old machine, and
    rewriting it could collide with a sibling key.
    """
    if isinstance(node, str):
        new, changed, near = value_fn(node)
        return new, (1 if changed else 0), near
    if isinstance(node, dict):
        out, changed, near = {}, 0, 0
        for key, val in node.items():
            out[key], sub_changed, sub_near = _walk(val, value_fn)
            changed += sub_changed
            near += sub_near
        return out, changed, near
    if isinstance(node, list):
        out, changed, near = [], 0, 0
        for val in node:
            new, sub_changed, sub_near = _walk(val, value_fn)
            out.append(new)
            changed += sub_changed
            near += sub_near
        return out, changed, near
    return node, 0, 0


def _rewrite_jsonl(text: str, value_fn):
    lines = text.split("\n")
    out = []
    seen = rewritten = malformed = near = 0
    for index, line in enumerate(lines):
        if line == "" and index == len(lines) - 1:  # trailing newline artefact
            out.append(line)
            continue
        seen += 1
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            # RecursionError beside ValueError because json.loads answers
            # nesting past the interpreter's limit with a RuntimeError, and a
            # guard naming only ValueError walks past the one line that costs
            # nothing to write: 200 KB of '[' in one local Transcript ended a
            # whole push. A line nested too deep is a line that will not
            # parse, which is what this branch already exists for.
            malformed += 1
            out.append(line)
            continue
        new_obj, changed, line_near = _walk(obj, value_fn)
        rewritten += changed
        near += line_near
        if changed:
            out.append(json.dumps(new_obj, ensure_ascii=False,
                                  separators=(",", ":")))
        else:
            out.append(line)
    return "\n".join(out), RekeyStats(seen, rewritten, malformed, near)


def canonicalise_jsonl(text: str, home) -> tuple:
    """Rewrite `home` to '~' inside string values, line by line.

    Occurrences are mid-string, not prefixes: paths appear in running prose
    as often as in fields (ADR-0006). Every spelling of the home goes, longest
    first (see home_forms): one machine's home is one directory however the
    process that wrote the line happened to name it.
    """
    forms = home_forms(home)

    def canon(value: str):
        near = 0
        changed = False
        for form in forms:
            near += _near_misses(value, form)
            if form in value:
                value = value.replace(form, HOME_TOKEN)
                changed = True
        return value, changed, near

    return _rewrite_jsonl(text, canon)


def expand_jsonl(text: str, home, maps=()) -> tuple:
    """Expand '~' against the local home, then apply --map OLD=NEW pairs.

    maps is a sequence of (old, new) pairs for paths outside $HOME, which the
    Archive stores verbatim; they are pull-side only and applied longest-OLD-
    first. Matching is exact - a case-insensitive-only hit is a near-miss.
    """
    home = _home_str(home)

    def expand(value: str):
        if value == HOME_TOKEN:
            new = home
        else:
            new = value.replace(HOME_TOKEN + "/", home + "/")
        new, _replaced, near = apply_maps(new, maps)
        return new, new != value, near

    return _rewrite_jsonl(text, expand)


def canonicalise_text(text: str, home) -> tuple:
    """Plain textual replace for non-JSONL UTF-8 files (markdown memory etc.).

    Returns (text, TextRekeyStats). Near-misses are counted here too - a
    memory file is prose about the same paths a Transcript records, and gets
    the same report. bare_tokens counts home occurrences not followed by '/',
    which expand_text will not restore. Every spelling of the home is
    rewritten, longest first, on the same grounds as canonicalise_jsonl.
    """
    replaced = near = bare = 0
    for form in home_forms(home):
        near += _near_misses(text, form)
        hits = text.count(form)
        if not hits:
            continue
        replaced += hits
        bare += hits - text.count(form + "/")
        text = text.replace(form, HOME_TOKEN)
    return text, TextRekeyStats(replaced=replaced, near_misses=near,
                                bare_tokens=bare)


def expand_text(text: str, home, maps=()) -> tuple:
    """Reverse of canonicalise_text, plus --map pairs longest-OLD-first.

    Only '~/' is expanded here: in free text a bare '~' is as likely to mean
    "approximately" as it is to mean home. Every '~' left standing is counted
    in bare_tokens so pull can report the gap. Returns (text, TextRekeyStats).
    """
    home = _home_str(home)
    replaced = text.count(HOME_TOKEN + "/")
    out = text.replace(HOME_TOKEN + "/", home + "/")
    out, mapped, near = apply_maps(out, maps)
    return out, TextRekeyStats(replaced + mapped, near,
                               out.count(HOME_TOKEN))


def apply_to_bytes(data: bytes, rewrite) -> tuple:
    """Run a text rewrite over raw bytes, refusing to guess at encodings.

    `rewrite` is text -> (text, stats). Non-UTF-8 data comes back unchanged
    with is_utf8 False and stats None, so the caller can count and report it
    rather than corrupt it.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, None, False
    new_text, stats = rewrite(text)
    return new_text.encode("utf-8"), stats, True


def read_cwd(jsonl_path) -> str | None:
    """First 'cwd' value recorded in a Transcript, or None.

    The recorded cwd is authoritative for where a Session belongs; the project
    directory name is derived from it, never decoded (ADR-0006). Lines that do
    not parse are skipped, not fatal - a Transcript can be truncated mid-write.

    RecursionError is in that guard for the reason it is in _rewrite_jsonl's:
    it is how json.loads answers a line nested past the interpreter's limit,
    it is a RuntimeError rather than a ValueError, and skipping the line is
    what this loop already does for every other line it cannot read.
    """
    with pathlib.Path(jsonl_path).open("r", encoding="utf-8",
                                       errors="replace") as handle:
        for line in handle:
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(obj, dict) and isinstance(obj.get("cwd"), str):
                return obj["cwd"]
    return None


_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")


def encode_project_dir(cwd: str) -> str:
    """Claude Code's dashed directory name for a cwd.

    Verified read-only against a live ~/.claude/projects on 2026-07-29 (dir
    names plus the first recorded cwd per dir, six pairs): '/', '_' and ' '
    each become '-', a literal '-' survives, and letter case survives. No
    observed special character survived, so the rule is every non-alphanumeric
    to '-'. Three characters collapse into one, which is why the name is
    derived from the recorded cwd and never decoded back (ADR-0006) - and why
    a vendor changing this encoding is layout drift.
    """
    return _NON_ALNUM.sub("-", cwd)
