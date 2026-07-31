"""A Setup on the way out - made machine-neutral, merged, overlaid and sealed.

What leaves this machine for the Archive's one plaintext half. ADR-0006 says an
Archive names no machine, and that is a whole-tree promise rather than a
manifest-field one: a hook command in settings.json spells the home out as
readily as `source_home` does, so the neutralising runs over every file in the
staged tree and the two generated documents are re-rendered from the result.
What a rewrite cannot reach - a path outside $HOME, a spelling that differs
only by case, a file that does not decode - is withheld and named rather than
carried, because ADR-0006 forbids folding case and nothing here can tell a PNG
from a note.

The one non-obvious thing: a partial push MERGES onto what the Archive already
holds, so a document the Destination authored is an input to a document a key
holder then signs. Pull restores a Setup solely from what the MANIFEST names,
so what the merge carries forward is a field this carryon writes holding a
shape this carryon produces - everything else is dropped, and named in the
report, because an agent dropped silently here is an agent no later pull lays
down.

Sits above authentication (what the previous tag vouched for) and stored_setup
(what the Destination serves as a MANIFEST); the way-in leg imports neither of
this module's names, which is the point of the split.
"""

from __future__ import annotations

import json
import pathlib
import re

from . import archive, rekey, restore
from .authentication import _carried_setup_files, _vouch_for_stored_manifest
from .destinations.base import join_prefix, printable
from .stored_setup import _stored_setup_manifest


# --- how the Setup half spells this machine's home ---------------------------


def _home_forms(home) -> list:
    """Every spelling of this machine's home a captured value may carry.

    rekey owns the rule; this is here so the Setup half spells it the same
    way. The two did drift - the History half knew one spelling and turned a
    Transcript's '/private/var/.../home' into '/private~/...' - which is why
    the definition lives in one place now rather than two that agree by
    review.
    """
    return rekey.home_forms(home)


def _canon_home(value, home):
    """A single value in the Archive's machine-neutral form (ADR-0006).

    Every occurrence, not just a leading one: rekey.canonicalise_text rewrites
    the home wherever it sits in a value, because paths turn up in running
    prose as often as in fields. Two rewriters promising different things is
    how a leak survives the fix for it.
    """
    if value is None:
        return None
    for form in _home_forms(home):
        if value == form:
            return rekey.HOME_TOKEN
        value = value.replace(form, rekey.HOME_TOKEN)
    return value


def _home_near_misses(text: str, home) -> int:
    """Hits that match the home case-insensitively only.

    ADR-0006 never folds case when rewriting - on a case-sensitive filesystem
    two spellings are two directories - so these are counted and reported
    rather than rewritten. rekey owns the counting rule; a second copy of it
    here would drift from the one the History half reports.
    """
    return sum(rekey._near_misses(text, form) for form in _home_forms(home))


# --- merging a partial capture onto what the Archive already holds -----------


# What a MANIFEST holds at the top level. A stored one can hold anything -
# the file is plaintext on untrusted storage - and a partial push writes its
# merge back into the Archive, so a key the capture engine never produces is
# dropped here rather than accumulated, signed and served on.
_MANIFEST_FIELDS = ("tool", "version", "captured_at", "source_home",
                    "categories", "scope", "agents")


def _renderable(value) -> bool:
    """Whether every string anywhere inside `value` can be written to a file.

    A partial push re-renders RESTORE.md out of the merged MANIFEST, and
    write_text encodes strictly - so a lone surrogate, which is legal in JSON
    and legal in a Python str, is a UnicodeEncodeError at the write. It
    reaches here as pure ASCII on the Destination ('\\ud800' is six ordinary
    characters in a JSON file) and every guard between there and the write
    asks isinstance(x, str), which it answers yes to.

    NOT config.spellable, which is the same question about a different
    destination: that one encodes with surrogateescape because it is asking
    whether a syscall will look at a path, and surrogateescape accepts the
    \\udc80-\\udcff range by design. This asks whether the string can be
    written into a document, and the answer there is strict UTF-8 or nothing.

    Iterative rather than recursive because the document is untrusted and
    arbitrarily deep: json.loads has already refused anything past the
    recursion limit (_JSON_REFUSALS), and a checker that added its own frames
    on top of a document that only just parsed would be a second limit, hit
    later and reported worse.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return True


def _carryable_item(raw):
    """One stored item, or None when it is not one this carryon would have
    written. Fields it does not know ride along untouched - so the whole item
    is asked the renderability question, not just the three named fields."""
    if not isinstance(raw, dict):
        return None
    if not all(isinstance(raw.get(field), str)
               for field in ("src", "dst", "kind")):
        return None
    if not isinstance(raw.get("carried", []), list):
        return None
    if not isinstance(raw.get("external", {}), dict):
        return None
    if not _renderable(raw):
        return None
    return raw


def _carryable_agent(raw):
    """A stored agent entry with the fields a MANIFEST is rendered from made
    recognisable, or None when it is not an entry at all.

    A partial push carries forward agents it did not capture, and the keyless
    path (ADR-0004) has no tag to check them against, so their shape is
    checked rather than assumed. restore.build_restore subscripts
    agent['excluded'], agent['items'] and each item's 'kind', 'dst' and 'src'
    with no guard at all, so one key left out of a planted entry was a
    KeyError straight out of `carryon push --category` - a traceback where
    ADR-0009 asks for a sentence, from a document the Destination authored.

    "Recognisable" now includes writable-back-out. Every check here was an
    isinstance against str, and a string is not the same thing as a string
    this machine can put in a file: the same push that could not subscript a
    missing key could not encode a lone surrogate either, and the second one
    survived the fix for the first. The whole entry is asked, once, after the
    per-field repairs - fields this carryon does not know ride along into the
    document, so they have to be able to ride along out of it.
    """
    if not isinstance(raw, dict):
        return None
    agent = dict(raw)
    if not isinstance(agent.get("name"), str):
        agent["name"] = "(a stored entry naming no agent)"
    items = agent.get("items")
    agent["items"] = ([i for i in items if _carryable_item(i) is not None]
                      if isinstance(items, list) else [])
    excluded = agent.get("excluded")
    agent["excluded"] = ([e for e in excluded
                          if isinstance(e, dict)
                          and all(isinstance(e.get(f), str)
                                  for f in ("path", "what", "why"))]
                         if isinstance(excluded, list) else [])
    if not _renderable(agent):
        return None
    return agent


def _merge_setup_manifest(stored: dict, fresh: dict, pushed_categories,
                          dropped=None) -> dict:
    """The stored MANIFEST with a freshly captured slice layered in.

    Per agent, fresh items replace stored items in the pushed categories only;
    agents not captured this time (absent here, or filtered by --agent) carry
    over. This matters because pull restores a Setup solely from what the
    MANIFEST names: overlaying the files while writing the partial capture's
    manifest as-is would silently drop every unselected item from all
    subsequent pulls until the next full push.

    Nothing is taken from `stored` unchecked, because `stored` came back from
    the Destination and is the attacker's to author (ADR-0009). It used to
    start from dict(stored), which carried every top-level key and every
    uncaptured agent whole into a document the key holder then signed. What
    survives now is a field this carryon writes, holding a shape this carryon
    produces: a set union over the integer 7 raised TypeError, sorting
    categories mixed with non-strings raised another, and an agent missing a
    key was a KeyError out of the renderer - none of them a shape to repair,
    all of them a shape to ignore.

    `dropped` collects a sentence per stored entry ignored, because ignoring
    one is not nothing: pull restores a Setup solely from what the MANIFEST
    names, so an agent dropped here is an agent no later pull lays down. It
    was a silent decision and the report the caller prints is the whole of
    the difference between a partial push that declined something and one
    that is mysteriously short an agent."""
    if dropped is None:
        dropped = []
    merged = {key: value for key, value in stored.items()
              if key in _MANIFEST_FIELDS and _renderable(value)}
    for key in ("tool", "version", "captured_at", "source_home", "scope"):
        if key in fresh:
            merged[key] = fresh[key]
    known = stored.get("categories")
    merged["categories"] = sorted(
        {c for c in (known if isinstance(known, list) else [])
         if isinstance(c, str) and _renderable(c)}
        | {c for c in fresh.get("categories", []) if isinstance(c, str)})
    stored_agents = stored.get("agents")
    agents = {}
    if isinstance(stored_agents, dict):
        for key, stored_agent in stored_agents.items():
            name = printable(str(key))
            if not isinstance(key, str) or not _renderable(key):
                dropped.append(
                    f"the stored agent keyed {name} is not named by anything "
                    "this machine can write back out")
                continue
            agent = _carryable_agent(stored_agent)
            if agent is None:
                dropped.append(
                    f"stored agent {name} is not an entry this carryon could "
                    "write back out, so it is not carried into the merged "
                    "MANIFEST and no later pull will restore it")
                continue
            was = stored_agent.get("items")
            lost = (len(was) - len(agent["items"])
                    if isinstance(was, list) else 0)
            if lost:
                dropped.append(
                    f"stored agent {name} carried {lost} item(s) this "
                    "carryon could not write back out; the rest of the entry "
                    "is merged as usual")
            agents[key] = agent
    for key, fresh_agent in fresh.get("agents", {}).items():
        stored_agent = agents.get(key)
        if stored_agent is None:
            agents[key] = fresh_agent
            continue
        kept = [item for item in stored_agent["items"]
                if item.get("category") not in pushed_categories]
        replacement = dict(fresh_agent)
        replacement["items"] = kept + list(fresh_agent.get("items", []))
        agents[key] = replacement
    merged["agents"] = agents
    return merged


# --- making the staged tree machine-neutral ----------------------------------


# Anything still shaped like a filesystem root after the home has been
# rewritten names some directory on this machine - a team share, a volume, a
# case-variant home resolve() would not normalise. An Archive names no
# machine, so those are withheld rather than published.
_ABSOLUTE = re.compile(r"^(?:/|\\\\|[A-Za-z]:[\\/])")
WITHHELD = "(withheld: a path on the machine this Setup came from)"


def _neutralise_manifest(manifest: dict, home) -> tuple:
    """(manifest, withheld): a MANIFEST with no local path left in it.

    The guarantee is per string value, not per field: the capture engine
    records the home it read from *and* the resolved target of every
    externally owned skill symlink - a dotfiles repo, typically - and an
    adapter or item kind added later can record another without anyone
    revisiting this function. That is right for a local `carryon capture`
    directory and wrong for the Archive, which is machine-neutral by ADR-0006
    and whose setups/ tree is its one plaintext half.

    Two steps, because rewriting alone cannot cover the second: a value under
    the home becomes '~', and a value that is still absolute afterwards is
    withheld. That closes the cases a rewrite has to leave alone - a target
    outside $HOME entirely, and a spelling of the home that differs only by
    case, which ADR-0006 forbids folding.
    """
    # rekey._walk is the recursion canonicalise_jsonl already runs over a
    # parsed Transcript line: string values only, keys untouched (ADR-0006).
    # Reaching for a private helper beats a third path-rewriter that would
    # then have to be kept in step with the other two.
    withheld = []

    def canon(value: str) -> tuple:
        new = _canon_home(value, home)
        if _ABSOLUTE.match(new):
            withheld.append(new)
            new = WITHHELD
        return new, new != value, 0

    neutral, _, _ = rekey._walk(manifest, canon)
    return neutral, len(withheld)


def _neutralise_staged_setup(staging, manifest: dict, home) -> tuple:
    """The whole staged Setup made machine-neutral.
    (manifest, withheld, near, undecodable).

    Not just the two files carryon generates: a Setup carries the CONTENT of
    settings.json, CLAUDE.md and every skill, and a hook command or an
    instruction line spells the home out as readily as a manifest field does.
    CONTEXT.md's promise - what sits in the Archive does not mention your
    laptop's home at all - is a whole-tree promise, and re-keying the Setup
    the way ADR-0006 already re-keys a History is also what makes a restored
    hook path work on a machine whose home is somewhere else.

    RESTORE.md is re-rendered from the neutralised MANIFEST rather than
    scrubbed on its own. It is a rendering of that MANIFEST, and the two being
    written from different sources is exactly how resolved symlink targets
    reached a Destination while this was reported closed.

    A file that does not decode as UTF-8 is withheld and named, not carried.
    This used to be a skip, justified in a comment by images in a skill - but
    it was decided by the decoder rather than by intent, so it also covered
    every latin-1 note, every truncated log and every file with one stray
    byte in it, any of which can spell the home out and did travel verbatim
    into the one plaintext half of the Archive. Nothing here can tell a PNG
    from a note, and a Setup that names this machine is what ADR-0006 rules
    out, so the file stays here and the push report names it. Deleting it
    from the staging tree is what withholds it: a full push mirrors that tree
    onto the Archive, so one also clears a file an earlier version published.
    """
    staging = pathlib.Path(staging)
    generated = {staging / "MANIFEST.json", staging / "RESTORE.md"}
    near = 0
    undecodable = []
    for path in sorted(p for p in staging.rglob("*")
                       if p.is_file() and not p.is_symlink()):
        if path in generated:
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            undecodable.append(path.relative_to(staging).as_posix())
            path.unlink()
            continue
        near += _home_near_misses(text, home)
        neutral_text = _canon_home(text, home)
        if neutral_text != text:
            path.write_bytes(neutral_text.encode("utf-8"))

    neutral, withheld = _neutralise_manifest(manifest, home)
    path = staging / "MANIFEST.json"
    if path.is_file():
        path.write_text(json.dumps(neutral, indent=2))
        (staging / "RESTORE.md").write_text(restore.build_restore(neutral))
    return neutral, withheld, near, undecodable


# --- overlaying a partial Setup onto the Archive -----------------------------


def _push_partial_setup(dest, master, machine, staging, manifest,
                        pushed_categories, withheld=(),
                        index_entry=None, pushed_at="",
                        stamp="") -> None:
    """Overlay a partial capture onto the Archive's Setup, MANIFEST included.

    Files not selected this time survive because an overlay never deletes;
    the MANIFEST and RESTORE.md are regenerated from the merged view so they
    keep describing the whole stored tree, not just this push's slice.

    Withheld files are the one thing an overlay does delete, and that is the
    point: withholding is done by removing the file from the staging tree,
    which only a FULL push turns into a deletion in the Archive (put_setup
    sweeps stale keys). On a partial push the file an earlier version
    published stayed there, with the source machine's home inside it, while
    the report said it had not gone - so the deletion is spelled out here
    rather than left to the mirror that does not run.

    With a master key the overlay is authenticated: the new SETUP.mac joins
    fresh hashes for this push's slice onto the entries the previous verified
    manifest vouched for, minus the withheld. The carry-forward is resolved -
    and the stored MANIFEST proved to be the one it vouches for - BEFORE a
    byte is written, so either refusal leaves the Archive untouched.

    What the merge could not carry is printed rather than raised. The keyless
    path (ADR-0004) is the one that meets an attacker-authored MANIFEST with
    nothing to check it against, and stopping there would hand anyone with
    write access to the Destination a permanent `push --category config` on
    every keyless machine - so the entry is dropped, named, and the rest of
    the push carries on. A stored document that will not PARSE is still a
    stop one function up, because there is no rest of the push to carry on
    with: the merge would be built from nothing.
    """
    prefix = archive.setup_prefix(machine)
    raw = dest.read(prefix + "/MANIFEST.json")
    carried = {}
    if master is not None:
        carried = _carried_setup_files(dest, master, machine, prefix,
                                       index_entry or {})
        _vouch_for_stored_manifest(raw, carried, prefix)
    stored = _stored_setup_manifest(raw, prefix)
    staging = pathlib.Path(staging)
    if stored is not None:
        dropped = []
        merged = _merge_setup_manifest(stored, manifest, pushed_categories,
                                       dropped)
        for why in dropped:
            print(f"  drop     {printable(prefix)}/MANIFEST.json - {why}")
        (staging / "MANIFEST.json").write_text(json.dumps(merged, indent=2))
        (staging / "RESTORE.md").write_text(restore.build_restore(merged))
    if master is not None:
        files = dict(carried)
        files.update(archive.setup_tree_manifest(staging))
        for rel in withheld:
            files.pop(rel, None)
        (staging / archive.SETUP_MAC_NAME).write_bytes(
            archive.seal_setup_manifest(master, machine, files, pushed_at,
                                        stamp))
    dest.write_tree(prefix, staging)
    for rel in withheld:
        dest.delete(join_prefix(prefix, rel))
