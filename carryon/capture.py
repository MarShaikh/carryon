"""The capture engine.

Interprets adapter declarations. Knows nothing about any particular agent - if
you find yourself adding an `if key == "cursor"` here, it belongs in the
adapter or in a new item kind.

The one rule the engine applies for itself is what it may read at all: no path
it walks may land in carryon's own state (~/.carryon), or outside $HOME. That
check used to sit in `sync.push`, the caller that happened to have been
reviewed, so `carryon capture --out DIR --apply` - which reaches this same
engine over the same trees, and writes a plaintext Setup the README calls safe
for a private git repo - copied the fallback master key out through a symlink
and reported 'SECRET SCAN: clean' over it, because a key is bare hex no
credential pattern matches. A guard in one caller is a guard the next caller
does not have.

So it is asked twice, from one place. `run` refuses the whole capture up front
over anything in the declared set that reads what a Setup may not carry
(ADR-0001's posture), and every read the handlers then make goes through
`config.read_carryable`, which asks the same question of the file it actually
opens. `run` is the only way in - the handlers below need an Item and an
already-opened output root - so a fifth caller gets the up-front refusal
whether or not its author knew to ask for one, and `_read` is the only way to
bytes, so a sixth handler gets the per-file one. The rule itself is in
config.py, in one function, because the History engine needs the same answer
and two spellings of it is what put a hard link to the master key in a Session
tar while this leg refused the same file.

The second rule is that a walk reports rather than raises. Every read here is
of a path some other program owns and can change between one syscall and the
next: an everyday dotfiles link whose target moved, a mode-000 file, a FIFO,
a transcript rotated out from under the walk. Each of those used to leave a
traceback and a half-written Setup with no verdict printed at all - and worse,
the scanning walk and the copying walk disagreed about what a file was, so the
credential scan covered a set the copier did not. There is one list now, built
once, and everything not on it is named in the report - and one READ, so the
bytes the scanner saw are the bytes that are written rather than a second
read of the same name.

The third rule is about the other end. `--out` is a required argument holding
whatever path the user typed; carryon makes it, never clears it, and has no
idea what else is in it. It was excused in the write allowlist as "carryon's
own capture output directory", which is the same sentence that was true of
nothing: a link planted at an item's landing path - `out/claude/settings.json`
pointing into a dotfiles repo - was followed, that repo's file overwritten and
then chmodded to match. So every write this engine makes goes through
`_write_owned`, which asks `external.owner_of` about the tree the user named,
exactly as the restore leg asks it about $HOME. One writer, so the archive
and the manifest cannot answer differently from the items.

That fix asked the question and then wrote, which is the gap the round after
it closed: the answer was about the path a syscall ago, and the `copymode`
after the write was a second follow of the same name. `_write_owned` is one
call into `external.write_owned` now - the package's one writer, which asks
again on the descriptor the bytes go to and sets the mode there.

And `write_archive` used to hand the whole `--out` tree to `tar.add`, which
turns a directory into content in one call that meets no gate at all: a second
name for ~/.carryon/master.key sitting in that directory went into
setup.tar.gz verbatim, at exit 0, under 'SECRET SCAN: clean'. The archive is
built from members read through `config.read_carryable` now, like everything
else this engine reads.
"""

from __future__ import annotations

import io
import json
import pathlib
import tarfile
from datetime import datetime, timezone

from . import __version__, config, external
from .adapters import ADAPTERS, HISTORY, HOME, SETUP_CATEGORIES, is_installed
from .config import state_identities, unsafe_reads
from .destinations.base import printable
from .restore import build_restore
from .secrets import scan


def _why(exc: OSError) -> str:
    return exc.strerror or str(exc)


def tree_files(root: pathlib.Path) -> tuple:
    """(files, skipped): every ordinary file under `root` that this machine
    will actually hand over, and (path, why) for everything else.

    One list, because there used to be two. `tree_files` filtered on
    `is_file()` and `copy_tree` copied everything `not is_dir()`, so the set
    the credential scanner read and the set the engine copied were different
    sets: a broken link was scanned by neither and handed to copy2, which
    raised FileNotFoundError out of an apply that had already written earlier
    items; a FIFO was handed to copy2, which blocks on one forever. Whatever
    widens the gap next widens it silently, so there is no gap.

    is_file() swallows ENOENT, ENOTDIR, EBADF and ELOOP and re-raises
    everything else, EACCES included, so the questions are asked inside a
    guard. A directory that will not list is one skip line rather than a
    traceback out of `push`.
    """
    files, skipped = [], []
    try:
        entries = sorted(root.rglob("*"))
    except OSError as exc:
        return [], [(root, f"this machine would not list it ({_why(exc)})")]
    for path in entries:
        if ".git" in path.parts:
            continue
        try:
            if path.is_dir():
                continue
            if path.is_symlink() and not path.exists():
                skipped.append((path, "a link whose target is not there"))
                continue
            if not path.is_file():
                skipped.append(
                    (path, "not an ordinary file - a socket, a device or a "
                           "named pipe"))
                continue
        except OSError as exc:
            skipped.append((path, f"this machine would not look at it "
                                  f"({_why(exc)})"))
            continue
        files.append(path)
    return files, skipped


def _size(path: pathlib.Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _write_owned(target: pathlib.Path, data: bytes, root: pathlib.Path,
                 mode_from: pathlib.Path = None):
    """None once `data` is at `target`, or why carryon would not write there.

    The engine's ONE write, and it is now one call into the package's one
    writer rather than an ownership question with a Path.write_bytes after it.
    `--out` is a path the user names and carryon does not own the inside of; a
    link planted at an item's landing path is ADR-0007's harm by ADR-0007's
    own route, and this used to follow whatever was at the name by the time
    the write happened - then chmod the same name a second time, with
    `shutil.copymode`, which is the follow this function's own docstring ruled
    out. The mode goes on the descriptor now, where nothing can have swapped
    the file underneath it (external.write_owned).
    """
    return external.write_owned(target, data, root, mode_from=mode_from)


def copy_tree(src: pathlib.Path, dst: pathlib.Path, members, root) -> tuple:
    """Write exactly `members` - (path, bytes) pairs - into `dst` under their
    path relative to `src`.

    The BYTES are passed in, not just the list, and that is the whole of this
    function's remaining job. It used to take paths and hand each to
    shutil.copy2, which is a second read of a file the caller had already read
    for the credential scan - so the scanner and the copier answered about two
    different reads of the same name, and a project tree is a place where the
    file behind a name changes. Now the bytes that were scanned are the bytes
    that are written, and the only read of a user's file in this engine is
    config.read_carryable.

    `root` is the capture output directory, which is what the ownership
    question below is asked from - see `_write_owned`, the one write in this
    engine.
    """
    skipped = []
    copied = total = 0
    for path, data in members:
        target = dst / path.relative_to(src)
        why = _write_owned(target, data, root, mode_from=path)
        if why is not None:
            skipped.append((path, why))
            continue
        copied += 1
        total += len(data)
    return copied, total, skipped


class Capture:
    """Copies what an adapter declares, and records any credential it meets."""

    def __init__(self, out: pathlib.Path, dry: bool, home: pathlib.Path = HOME):
        self.out = out
        self.dry = dry
        self.home = home
        # carryon's own state inodes, collected once for the whole capture and
        # handed to every read (config.carry_refusal). Same collection
        # state_reads makes for the walk that runs before this one, for the
        # same reason: the answer is identical for every file and this runs on
        # every push.
        self.identities = state_identities(home)
        self.findings = []
        self.files = 0
        self.bytes = 0
        # Paths this machine would not hand over, named as they are met and
        # counted at the end. Not the same thing as a credential finding: this
        # capture is still clean, it just covers less than the adapters
        # declare, and a user who is not told reads it as covering more.
        self.skipped = []

    def _check(self, label: str, data: bytes) -> None:
        hits = scan(data)
        if hits:
            self.findings.append((label, hits))

    def _write(self, dst: pathlib.Path, data: bytes, label: str = "") -> bool:
        """One file into the capture output, through the engine's one write.

        False when nothing was written, which the caller turns into the same
        answer it gives for an item it could not READ: named where it was met,
        and recorded as absent rather than as an item. A MANIFEST entry for a
        file that was never written is a restore that refuses it later
        (_capture_agent says so about the read side), and an item this machine
        would not write is no more present than one it would not read.
        """
        if self.dry:
            return True
        why = _write_owned(dst, data, self.out)
        if why is not None:
            print(f"        -- {printable(label or str(dst))}  not written: "
                  f"{why}")
            self.skipped.append(label or str(dst))
            return False
        self.files += 1
        self.bytes += len(data)
        return True

    def _report_skipped(self, skipped) -> None:
        """Name every path the walk would not take. Silence here reads as a
        capture that covered more than it did, which is the failure the whole
        report exists to prevent."""
        for path, why in skipped:
            try:
                rel = str(path.relative_to(self.home))
            except ValueError:
                rel = str(path)
            print(f"        -- {printable(rel)}  skipped: {why}")
            self.skipped.append(rel)

    def _read(self, path):
        """One user file's bytes, or (None, why) - the engine's only read.

        config.read_carryable asks the gate and reads in one call, so nothing
        in this engine can obtain a user's bytes without having asked whether
        they may leave the machine (config.py). `state_reads` has already
        refused the whole capture over anything the walk would meet, which is
        ADR-0001's posture and the reason a hit here is impossible in a still
        filesystem; this is the same question asked of the file that is
        actually opened, in a tree other programs are writing to.

        The refusals it returns cover what used to be a traceback as well: a
        path the adapter names is still somebody else's file, mode 000 raises
        EACCES and a link whose target moved raises ENOENT, and both used to
        end `capture` and `push` with earlier items already written.
        """
        return config.read_carryable(path, self.home, self.identities)

    def do_file(self, src, dst, item):
        """One declared file. None when this machine will not hand it over."""
        data, why = self._read(src)
        if data is None:
            print(f"      !!  {item.src:<46} skipped: {why}")
            self.skipped.append(item.src)
            return None
        print(f"      {item.src:<46} {len(data)/1024:>7.1f}K  {item.note}")
        self._check(item.src, data)
        if not self._write(dst, data, item.src):
            return None
        return {}

    def do_tree(self, src, dst, item):
        files, skipped = tree_files(src)
        size = sum(_size(p) for p in files)
        print(f"      {item.src:<46} {len(files):>3} files {size/1024:>6.1f}K  {item.note}")
        readable = []
        for path in files:
            data, why = self._read(path)
            if data is None:
                skipped.append((path, why))
                continue
            self._check(str(path.relative_to(self.home)), data)
            readable.append((path, data))
        if not self.dry and readable:
            copied, written, failed = copy_tree(src, dst, readable,
                                                self.out)
            self.files += copied
            self.bytes += written
            skipped += failed
        self._report_skipped(skipped)
        return {}

    def do_json_strip(self, src, dst, item):
        data, why = self._read(src)
        if data is None:
            print(f"      !!  {item.src:<46} skipped: {why}")
            self.skipped.append(item.src)
            return None
        try:
            raw = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            # A config file half-written by a crashed editor is ordinary, and
            # a capture that dies on one has said nothing about the rest.
            print(f"      !!  {item.src:<46} skipped: it is not the JSON this "
                  f"item strips keys from ({exc})")
            self.skipped.append(item.src)
            return None
        if not isinstance(raw, dict):
            print(f"      !!  {item.src:<46} skipped: it holds no JSON object")
            self.skipped.append(item.src)
            return None
        strip = set(item.strip)
        removed = sorted(k for k in raw if k in strip)
        body = json.dumps({k: v for k, v in raw.items() if k not in strip},
                          indent=2).encode()
        suffix = f" [stripped: {', '.join(removed)}]" if removed else ""
        print(f"      {item.src:<46} {len(body)/1024:>7.1f}K  {item.note}{suffix}")
        self._check(item.dst + " (after strip)", body)
        if not self._write(dst, body, item.src):
            return None
        return {"stripped_keys": removed}

    def do_skills(self, src, dst, item):
        """Sort a skills directory into three groups.

        re-resolvable  a symlink into the shared store, recorded in a lock file
                       with its upstream, so the new machine re-installs it
        external       a symlink somewhere else - typically a dotfiles repo.
                       Whatever owns it will restore it, but the skills
                       installer will not, so it must be named rather than
                       quietly counted as handled
        carried        a real directory. No upstream: if it is not copied here,
                       it is gone

        resolve() is inside the guard because it answers a symlink loop with a
        RuntimeError on Python 3.9 and with the unresolved path on 3.13, and
        this code has to behave the same on both.
        """
        store = (self.home / item.resolvable_via).resolve() if item.resolvable_via else None

        resolvable, external, owned = [], {}, []
        skipped = []
        try:
            entries = sorted(src.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            entries = []
            skipped.append((src, f"this machine would not list it "
                                 f"({_why(exc)})"))
        for path in entries:
            try:
                if path.is_symlink():
                    target = path.resolve()
                    if store and store in target.parents:
                        resolvable.append(path.name)
                    else:
                        external[path.name] = str(target)
                elif path.is_dir():
                    owned.append(path)
            except (OSError, RuntimeError, ValueError) as exc:
                skipped.append((path, f"this machine would not look at it "
                                      f"({exc})"))

        print(f"      {item.src:<46} {len(owned):>3} carried, "
              f"{len(resolvable)} re-resolvable, {len(external)} external")
        for path in owned:
            print(f"        + {path.name}  (no upstream - lost if not carried)")
            files, bad = tree_files(path)
            skipped += bad
            readable = []
            for f in files:
                data, why = self._read(f)
                if data is None:
                    skipped.append((f, why))
                    continue
                self._check(str(f.relative_to(self.home)), data)
                readable.append((f, data))
            if not self.dry:
                copied, written, failed = copy_tree(path, dst / path.name,
                                                    readable, self.out)
                self.files += copied
                self.bytes += written
                skipped += failed
        for name, target in external.items():
            print(f"        ~ {name}  managed elsewhere: {target}")
        self._report_skipped(skipped)

        return {"carried": [p.name for p in owned],
                "re_resolvable": resolvable,
                "external": external}


HANDLERS = {
    "file": "do_file",
    "tree": "do_tree",
    "json-strip": "do_json_strip",
    "skills": "do_skills",
}


def _capture_agent(cap: Capture, adapter, want_categories: set) -> dict:
    entry = {
        "name": adapter.name,
        "verified_against": adapter.verified_against,
        "platforms": list(adapter.platforms),
        "items": [],
        "absent": [],
        "layout_drift": [],
        "excluded": [{"path": e.path, "what": e.what, "why": e.why}
                     for e in adapter.exclude],
    }

    for item in adapter.items:
        # A chats item names where the History lives; it moves through the
        # push pipeline, encrypted. The Setup engine never copies one, whatever
        # categories were asked for - a Setup is clean, a History never is.
        if item.kind == "chats":
            continue
        if item.category not in want_categories:
            continue
        src = cap.home / item.src
        try:
            present = src.exists()
        except OSError:
            present = False
        if not present:
            entry["absent"].append(item.src)
            # A path the adapter says should always be there, missing, usually
            # means the agent moved it. Say so rather than quietly capturing
            # less than the user expects.
            if item.required:
                entry["layout_drift"].append(item.src)
            continue
        if item.kind == "tree":
            files, skipped = tree_files(src)
            if not files and not skipped:
                entry["absent"].append(item.src + " (empty)")
                continue

        # None from a handler means this machine would not hand the item over
        # - unreadable, not the shape the item declares, or a landing path
        # inside `out` that something else holds. It is named where it was met
        # and recorded as absent, because a MANIFEST entry for a file that was
        # never written is a restore that refuses it later.
        extra = getattr(cap, HANDLERS[item.kind])(src, cap.out / item.dst, item)
        if extra is None:
            entry["absent"].append(
                item.src + " (this machine would not hand it over)")
            continue
        record = {"src": item.src, "dst": item.dst, "kind": item.kind,
                  "category": item.category, "note": item.note}
        record.update(extra)
        entry["items"].append(record)

    if not entry["items"]:
        print("      (nothing in the selected categories)")
    for missing in entry["layout_drift"]:
        print(f"      !!  {missing} is missing - {adapter.name} may have moved it")
    return entry


def state_reads(want_agents, want_categories, home) -> list:
    """(item src, the path it reads, why) for every path this capture would
    read that a Setup must not carry. Empty is clean.

    Asked over the selection `run` is about to walk - its categories, its
    --agent filter, never a chats item - minus the is_installed test, which is
    deliberate: a wider question here can only name a path the engine would
    not have read anyway, and an adapter that is not set up has no files for
    this to find. `config.unsafe_reads` expands each Item and asks again per
    member, because the rule has to cover a tree rather than only its name,
    and it compares file identity as well as spelling, because a hard link is
    a second name for the same bytes (config.py).

    The state directory's identities are collected once here and handed to
    every Item, rather than re-walked per Item: the answer is the same for all
    of them and this runs on every push.
    """
    identities = state_identities(home)
    found = []
    for key, adapter in sorted(ADAPTERS.items()):
        if want_agents and key not in want_agents:
            continue
        for item in adapter.items:
            if item.kind == "chats" or item.category not in want_categories:
                continue
            for rel, why in unsafe_reads(item.src, home, identities,
                                         item.kind):
                found.append((item.src, rel, why))
    return found


def _refuse_state_reads(found: list, dry: bool) -> int:
    """ADR-0001's posture over what a Setup may read: name every offending
    path and produce nothing, rather than skip the item and carry on.

    A hit means the capture set is wrong - a link or a hard link planted in a
    captured directory, or a handpicked path that should never have been one -
    and half a Setup published alongside the key that decrypts the same
    Archive's History is not a better outcome than none. Names go through
    `printable`: a filename may hold a newline or a CSI escape, and the line
    naming the refusal is the whole safety property here.
    """
    print("CAPTURE REFUSED: a path in the capture set reads what a Setup may "
          "not carry\n")
    for src, rel, why in found:
        print(f"  !! ~/{printable(src)}")
        print(f"     ~/{printable(rel)} - {why}")
    print("\nThe fallback master key under ~/.carryon is bare hex that no")
    print("credential pattern matches, and the config beside it names the")
    print("Destination - so a Setup carrying either would hand both to")
    print("wherever this directory ends up; a file from outside $HOME is one")
    print("this machine never agreed to publish. Remove the link, or drop the")
    print("path from `carry` (ADR-0008). Nothing was captured.")
    return 1 if dry else 2


def run(out: pathlib.Path, dry: bool, want_agents=None, want_categories=None,
        home: pathlib.Path = HOME, archive: pathlib.Path = None) -> tuple:
    """Capture into `out`, optionally also writing a .tar.gz.

    Returns (exit_code, manifest).

    The state check runs before the first adapter rather than over the
    manifest afterwards, so on a hit the key is never copied anywhere at all -
    not into `out`, which a refusal deliberately leaves in place for
    inspection, and not into the staging tree a push would go on to publish.
    """
    if want_categories and HISTORY in want_categories:
        raise SystemExit("history is pushed, not captured - use carryon push")
    want_categories = set(want_categories or SETUP_CATEGORIES)
    cap = Capture(out, dry, home)

    manifest = {
        "tool": "carryon",
        "version": __version__,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_home": str(home),
        "categories": sorted(want_categories),
        "scope": "A Setup: config + capability + knowledge. "
                 "History travels separately, encrypted.",
        "agents": {},
    }

    print(f"{'PLAN (dry run)' if dry else 'CAPTURING'} -> {out}")
    print(f"categories: {', '.join(sorted(want_categories))}\n")

    found = state_reads(want_agents, want_categories, home)
    if found:
        return _refuse_state_reads(found, dry), manifest

    if not dry:
        # Naming a file where a directory belongs is the most ordinary
        # user-facing error there is, and house style answers one with a
        # SystemExit. `--out /dev/null --apply` and `--out <an existing file>`
        # were a NotADirectoryError out of the first item's write, three
        # printed lines into a capture - which is a Python type where a
        # sentence belongs, and it named the item rather than the argument.
        #
        # After the refusal above and not before it, so a capture that reads
        # something a Setup may not carry still leaves nothing behind at all -
        # not even the empty directory it would have written into.
        try:
            pathlib.Path(out).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SystemExit(
                f"--out {out}: carryon cannot capture into that ({_why(exc)}) "
                "- it needs a directory it can make or write in, and "
                "something else is standing at that name")

    for key, adapter in ADAPTERS.items():
        if want_agents and key not in want_agents:
            continue
        if not is_installed(key, home):
            print(f"  --  {adapter.name}: not set up here, skipped")
            continue
        print(f"  {adapter.name}  ({key})")
        manifest["agents"][key] = _capture_agent(cap, adapter, want_categories)
        print()

    return _finish(cap, manifest, out, dry, archive)


def write_archive(out: pathlib.Path, archive: pathlib.Path,
                  home: pathlib.Path = HOME, identities=None) -> list:
    """Pack the Setup into a single .tar.gz for a USB stick or AirDrop.
    Returns (path, why) for everything it would not pack.

    Everything is nested under one top-level directory so that unpacking on the
    other machine cannot scatter files across $HOME.

    It was one call - `tar.add(out, arcname=out.name)` - and that call is the
    eighth leg the state gate did not cover. `add` walks a directory and turns
    every file in it into content, `--out` is a path the user names and carryon
    never clears, and tarfile stores the first occurrence of an inode as an
    ordinary file: so `ln ~/.carryon/master.key out/notes.md` put the key's
    bytes in setup.tar.gz verbatim, at exit 0, under 'SECRET SCAN: clean' and
    a closing line saying private storage of any kind will do. Neither
    enforcement scanner could see it either - `add` was in no verb set, and an
    `open` on tarfile was excused wholesale.

    So the members are read through `config.read_carryable` like everything
    else this engine reads, and added from bytes. That also settles what a
    member IS: the walk is `tree_files`, so a fifo or a dangling link in the
    output directory is a named skip rather than something tarfile blocks on.

    The tar is built in memory and written through `_write_owned`, the one
    write in this engine, because the archive is a second path the user named
    and a link standing at it is the same edit of somebody else's tree.
    """
    home = pathlib.Path(home)
    if identities is None:
        identities = state_identities(home)
    files, skipped = tree_files(out)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in files:
            data, why = config.read_carryable(path, home, identities)
            if data is None:
                skipped.append((path, why))
                continue
            info = tarfile.TarInfo(
                f"{out.name}/{path.relative_to(out).as_posix()}")
            info.size = len(data)
            try:
                info.mode = path.stat().st_mode & 0o777
            except OSError:
                pass
            tar.addfile(info, io.BytesIO(data))
    why = _write_owned(archive, buffer.getvalue(), archive.parent)
    if why is not None:
        raise SystemExit(f"{archive}: {why}")
    return skipped


def _finish(cap: Capture, manifest: dict, out: pathlib.Path, dry: bool,
            archive: pathlib.Path = None) -> tuple:
    print("-" * 74)
    if cap.findings:
        print("SECRET SCAN: FAILED - do not commit or transfer this Setup\n")
        for label, hits in cap.findings:
            print(f"  !! {label}\n     matched: {', '.join(hits)}")
        print("\nThis is fail-closed on purpose. A Setup should contain no")
        print("credentials, so a hit means the capture list is wrong. Fix it, re-run.")
        if not dry:
            print("\nRefusing to finalise. Written files left in place for inspection.")
            return 2, manifest
        return 1, manifest

    print("SECRET SCAN: clean - no credential patterns in the captured set")

    if cap.skipped:
        # Beside the scan verdict rather than folded into it: the Setup is
        # still clean, and what this says is that it covers less than the
        # adapters declare. A user who is not told reads it as covering more.
        print(f"\n{len(cap.skipped)} path(s) NOT captured - this machine would "
              "not read them (named above)")

    drift = {key: agent["layout_drift"] for key, agent in manifest["agents"].items()
             if agent["layout_drift"]}
    if drift:
        print("\nLAYOUT DRIFT: paths an adapter expects are missing")
        for key, paths in drift.items():
            for path in paths:
                print(f"  ?? {key}: {path}")
        print("Run `doctor` to see what is there instead. The capture below is")
        print("still valid - it just may cover less than you expect.")

    if dry:
        print("\nDry run. Re-run with --apply to write.")
        return 0, manifest

    # Through the same writer as every item, because these two say what the
    # capture was: a MANIFEST written through a link edits the tree the link
    # points at, and one that did not get written at all is a directory a
    # restore cannot read. Counted apart from the items, which is what the
    # line below has always meant and what the two lines under it explain.
    items_written, items_bytes = cap.files, cap.bytes
    cap._write(out / "MANIFEST.json", json.dumps(manifest, indent=2).encode(),
               "MANIFEST.json")
    cap._write(out / "RESTORE.md", build_restore(manifest).encode(),
               "RESTORE.md")
    print(f"\nWrote {items_written} files, {items_bytes/1024:.0f}K to {out}")
    print("  MANIFEST.json   what was taken, and what was deliberately left")
    print("  RESTORE.md      the order to do things on the new machine")

    if archive:
        # The archive is packed from what is in `out` now, which includes
        # whatever was already there - so its members go through the gate
        # (write_archive) and what it would not pack is named here beside
        # everything else this capture left behind.
        cap._report_skipped(write_archive(out, archive, cap.home,
                                          cap.identities))
        print(f"  {archive}  ({archive.stat().st_size/1024:.0f}K)")

    print("\nThis Setup passed the credential scan, so private storage of any")
    print("kind will do. Your History is not in it - `carryon push` carries")
    print("that separately and encrypts it unconditionally.")
    return 0, manifest
