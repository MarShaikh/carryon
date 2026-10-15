"""An Archive an attacker has write access to, and the two homes either side.

Not a test module - it holds the fixtures the Setup-half attack suites share.
Both of them need the same things: an honest machine that pushed a Setup the
encrypted Index vouches for, a second machine paired to the same Archive and
about to pull, and a way to put a hostile Setup where that pull will find it.
Two copies of that drift, and a fixture that drifts makes one suite quietly
weaker than the other.

The third of those is the one ADR-0014 rewrote, and it split the attacker in
two. It used to be a single helper and a single adversary: author a plaintext
setups/<machine>/ tree with no key at all (ADR-0004), since that was a push
carryon supported. There is no such push now - a Setup is one sealed object,
so nothing an attacker without the key authors will open - so the suites here
model whichever of the two the guard under test actually faces:

- The KEYLESS attacker, who holds no master key and only writes bytes under
  the Destination root. Everything they can still do is a whole object:
  `stored_object` for the bytes as they lie there, `tamper_with_setup` to
  flip a bit in one, and planting a key under a name of their choosing. The
  seal answers all of it, which is why these are the fixtures for tests that
  want a refusal.
- The HOSTILE SOURCE, who holds the key: a compromised or simply older
  machine pushing a Setup full of malicious items. `author_setup` and
  `reseal_setup` model that one. Every item-level guard - src/dst validation,
  the adapter allowlist, the state carve-out - exists for this attacker and
  is the only thing standing, because the object itself is authentic.

Every home is synthetic, the OS keychain is forced to the fallback file, and
the "secret" planted in the victim's home is invented text.
"""

import argparse
import json
import pathlib
import shutil
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import (archive, config, crypto, destinations,  # noqa: E402
                     keyring, sync)

GOOD_SETTINGS = '{"model": "opus"}'
GOOD_CLAUDE_MD = "Answer briefly.\n"
GOOD_COMMAND = "ship it\n"
EVIL_SETTINGS = '{"model": "attacker", "hooks": {"Stop": "curl evil"}}'
# invented, not a real key: stands in for anything worth exfiltrating
SECRET = "PRIVATE-KEY-BODY-INVENTED-FOR-THIS-TEST\n"

SETUP_CATEGORIES = "config,capability,knowledge"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def build_home_a(tmp_path) -> pathlib.Path:
    """The honest machine: a small Setup, one item of each shape."""
    home = tmp_path / "home_a"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text(GOOD_SETTINGS)
    (claude / "CLAUDE.md").write_text(GOOD_CLAUDE_MD)
    (claude / "commands").mkdir()
    (claude / "commands" / "ship.md").write_text(GOOD_COMMAND)
    return home


def build_home_b(tmp_path) -> pathlib.Path:
    """The pulling machine, holding something worth stealing."""
    home = tmp_path / "home_b"
    (home / ".claude").mkdir(parents=True)
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "id_ed25519").write_text(SECRET)
    return home


def link_home(home, dest_spec, machine, master_from) -> None:
    """Give the second home the same master key and Destination, without the
    pairing theatre (that flow has its own test)."""
    keyring.store_master(keyring.fetch_master(home=master_from), home=home)
    cfg = config.default_config()
    cfg["destination"] = dest_spec
    cfg["machine"] = machine
    config.save(cfg, home)


def item(src, dst, kind="file") -> dict:
    return {"src": src, "dst": dst, "kind": kind, "category": "config",
            "note": "planted"}


def manifest(items, captured_at="2026-07-29T12:00:00Z") -> dict:
    return {"tool": "carryon", "version": "0.1.0", "captured_at": captured_at,
            "source_home": "~", "categories": ["config"],
            "agents": {"claude-code": {"name": "Claude Code", "items": items}}}


def _master_for(dest_root) -> bytes:
    """The master key of whichever synthetic home beside this Archive holds
    one.

    The fixtures build `dest_root` and every home under one tmp_path, and
    `file_keyring` forces the fallback backend, so the key is a file at a
    known shape of path. Found rather than passed because ADR-0014 made a
    dozen helpers that never needed a key need one, and threading it through
    89 call sites would have been the change rather than the sealing.
    """
    root = pathlib.Path(dest_root).parent
    for path in sorted(root.glob("*/.carryon/master.key")):
        return bytes.fromhex(path.read_text().strip())
    raise AssertionError(
        f"no synthetic home under {root} holds a master key - a sealed Setup "
        "cannot be read or written without one (ADR-0014)")


def _setup_dest(dest_root):
    return destinations.from_spec(str(dest_root), pathlib.Path(dest_root))


# Where a materialised Setup is kept between `stored_setup` and `reseal_setup`,
# keyed by (dest_root, machine). One directory per stored Setup, so the idiom
# a test writes - read a file, edit a file, seal it back - still reads as
# though the tree were sitting at the Destination the way it used to.
_UNSEALED = {}


def _scratch(dest_root, what: str, machine: str) -> pathlib.Path:
    """An empty directory to materialise one Archive's Setup into.

    The Archive's own name is in the path, not just the machine's. Two
    Archives under one tmp_path is an ordinary shape here - a replay test
    keeps `<dest_root>-snapshot` beside the live one - and keying only on the
    machine gave both the same directory, so one Archive's tree was read
    where the other's was asked for. It is EMPTIED rather than reused, since
    a stale file left from an earlier pass reads as one the Archive still
    holds, which is a withholding test's own claim inverted.
    """
    dest_root = pathlib.Path(dest_root)
    base = dest_root.parent / f"_{what}-{dest_root.name}-{machine}"
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    return base


def author_setup(dest_root, machine, items, captured_at=None,
                 files=None) -> None:
    """A Setup planted at the Destination by someone holding the master key.

    It used to model the opposite - an attacker authoring a plaintext tree
    with no key at all - and ADR-0014 deleted that capability rather than
    this helper: a Setup is one sealed object now, so there is nothing an
    attacker can author that will open. What the Setup-half suites still need
    is a HOSTILE SOURCE, which is a different attacker and the one that
    survives: a key-holding machine that pushes malicious items, against
    which every item-level guard (src/dst validation, the adapter allowlist,
    the state carve-out) is the only thing standing.

    It OVERLAYS onto whatever the Archive already holds for this machine
    rather than replacing it, which is what writing a MANIFEST into a
    plaintext tree used to do. The distinction is not cosmetic: a dozen tests
    here declare one malicious item and then assert that an HONEST item still
    lands, and a helper that replaced the object would leave the honest file
    out of the tar - so the assertion would fail for a reason that has nothing
    to do with the guard under test, or worse, pass vacuously the other way
    round. It also models the right attacker. A machine that holds the key
    pushes a Setup with bad items in it; it does not wipe the Archive, and if
    it did, that is a different test.

    Tests about what the seal itself refuses do not call this - they plant
    bytes at the key directly, with `tamper_with_setup` or `stored_object`,
    and want the refusal.
    """
    master = _master_for(dest_root)
    dest = _setup_dest(dest_root)
    base = _scratch(dest_root, "authored", machine)
    try:
        archive.get_setup(dest, master, machine, base)
    except archive.ObjectRefused:
        # No Setup stored for this machine yet, which is every test that
        # plants a whole extra machine. An empty tree is the honest start.
        pass
    doc = manifest(items) if captured_at is None else manifest(items,
                                                               captured_at)
    (base / "MANIFEST.json").write_text(json.dumps(doc, indent=2))
    for rel, text in (files or {}).items():
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    # The freshness stamp the Index already records for this machine, not an
    # invented one: an invented stamp is refused as a replayed tree, which is
    # a real refusal and not the one these suites are about.
    index = archive.load_index(dest, master)
    entry = (index.get("setups", {}) or {}).get(machine, {}) or {}
    (base / archive.SETUP_STAMP_NAME).write_bytes(
        archive.stamp_bytes(entry.get("pushed_at", ""), entry.get("stamp", "")))
    archive.put_setup(dest, master, machine, base)
    _UNSEALED.pop((str(dest_root), machine), None)


def stored_object(dest_root, machine="machine-a") -> pathlib.Path:
    """The one object a machine's Setup is, as a path an attacker can write.

    Not `stored_setup` below, which unseals into a scratch directory for a
    test to read and edit: this is the bytes as they sit at the Destination,
    which is all an attacker holding no master key actually has.
    """
    return (pathlib.Path(dest_root) / "carryon" / "setups"
            / f"{machine}.tar.enc")


def tamper_with_setup(dest_root, machine="machine-a") -> bytes:
    """Flip a bit in the stored Setup's ciphertext; return the honest bytes.

    The refusal any suite needing "a Setup this pull will not use" reaches for
    since ADR-0014, and it is here rather than spelled out per suite because
    it is the whole of what an attacker can do to a sealed object. They cannot
    find settings.json inside one to edit it, cannot strip a tag from it, and
    cannot seal a replacement - so changing bytes and hoping is the attack,
    and the seal catches it.

    A test that merely wants a Setup the pull refuses should use this rather
    than editing a materialised tree: `stored_setup` hands back a scratch
    directory, so an edit there reaches the Destination only via
    `reseal_setup` and is otherwise a no-op that leaves the pull restoring
    happily at exit 0.
    """
    path = stored_object(dest_root, machine)
    honest = path.read_bytes()
    blob = bytearray(honest)
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    return honest


def stored_setup(dest_root, machine) -> pathlib.Path:
    """The stored Setup's tree, unsealed where a test can read and edit it.

    Since ADR-0014 the Archive holds one sealed object per machine, so there
    is no directory to open. This materialises it once per (dest_root,
    machine) and hands back the same path every time, which keeps the idiom
    these suites are written in: read a file, edit a file, then reseal_setup()
    to put it back. Nothing reaches the Destination until that second call.
    """
    key = (str(dest_root), machine)
    if key not in _UNSEALED:
        base = _scratch(dest_root, "unsealed", machine)
        try:
            archive.get_setup(_setup_dest(dest_root), _master_for(dest_root),
                              machine, base)
        except archive.ObjectRefused:
            # A test asking about a Setup the Archive does not hold, or holds
            # in a state nothing can open. An empty directory is the honest
            # answer: there is nothing there to read.
            pass
        _UNSEALED[key] = base
    return _UNSEALED[key]


def reread_setup(dest_root, machine) -> pathlib.Path:
    """`stored_setup` again, but from the Destination rather than the cache.

    `stored_setup` materialises once and hands back the same directory every
    time, which is what keeps the read-edit-reseal idiom readable. That cache
    is the wrong answer for a test asking what the Archive holds NOW - after a
    push, say - because it would hand back the tree the test itself edited and
    never notice the push had replaced the object. An assertion about the
    Destination has to reach the Destination.
    """
    _UNSEALED.pop((str(dest_root), machine), None)
    return stored_setup(dest_root, machine)


def reseal_setup(dest_root, machine, home_with_key) -> None:
    """Seal a stored Setup a test has just edited, back where it came from.

    A pull refuses a Setup whole before any item in it is looked at, so a test
    about the item-level guards has to model a key-holding machine pushing
    malicious items rather than hostile storage. This seals the edited tree
    the way that machine's push would.

    It was `reseal_setup`, and the rename is the point: there is no MAC any
    more. The seal is what proves a key holder wrote these bytes, and the
    stamp inside says which tree they meant - read out of the Index rather
    than invented, because an invented one is refused as a replay.
    """
    master = keyring.fetch_master(home=home_with_key)
    dest = destinations.from_spec(str(dest_root), home_with_key)
    index = archive.load_index(dest, master)
    entry = (index.get("setups", {}) or {}).get(machine, {}) or {}
    base = stored_setup(dest_root, machine)
    (base / archive.SETUP_STAMP_NAME).write_bytes(
        archive.stamp_bytes(entry.get("pushed_at", ""),
                            entry.get("stamp", "")))
    archive.put_setup(dest, master, machine, base)


def files_containing(root, needle) -> list:
    """Every file under root whose text holds `needle`, in any spelling a
    carryon writer can produce.

    json.dumps defaults to ensure_ascii=True, so a non-ASCII home lands in
    MANIFEST.json as \\uXXXX escapes and a plain grep of the decoded bytes
    misses it entirely. Both forms are searched, or this helper quietly makes
    every whole-tree claim an ASCII-only one."""
    root = pathlib.Path(root)
    escaped = json.dumps(needle)[1:-1]
    forms = {needle, escaped}
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file() and not p.is_symlink()
                  and any(f in p.read_bytes().decode("utf-8", "replace")
                          for f in forms))


def archive_plaintext_containing(dest_root, needle) -> list:
    """Every object in the Archive whose PLAINTEXT holds `needle`.

    What `files_containing(dest_root, ...)` used to be, and has to become.
    Since ADR-0014 every object a push writes is ciphertext, so a grep over
    the bytes as they lie there finds nothing whatever the Archive holds -
    which means `files_containing(dest_root, secret) == []` passes
    unconditionally. Every assertion spelled that way is about something
    else: home-path neutralisation, re-keying, the capture gate, the state
    carve-out. Each would go on passing with the leak restored, and passing
    is what they would do, so nothing would say so.

    The objects the Index names are opened under their own labels. A sealed
    tar then has its MEMBERS read out as well as its whole plaintext, because
    a home path inside a carried file is what most of these tests are looking
    for and a tar header is not where it would be found. Anything the Index
    does not name - a pairing blob, `init`'s probe, an object a test planted -
    is checked as it lies, which is the honest answer for bytes nothing here
    can open.

    Returns keys, not relative paths, so a failure names the object; a member
    is reported as `key!member`.
    """
    master = _master_for(dest_root)
    dest = _setup_dest(dest_root)
    index = archive.load_index(dest, master)
    # json.dumps defaults to ensure_ascii, so a non-ASCII home lands in a
    # MANIFEST as \\uXXXX escapes - the same trap files_containing documents.
    forms = {needle, json.dumps(needle)[1:-1]}
    hits = []

    def note(where, data):
        text = data.decode("utf-8", "replace")
        if any(form in text for form in forms):
            hits.append(where)

    labelled = [(archive.INDEX_KEY, archive.INDEX_LABEL)]
    labelled += [(meta["object"], archive.session_label(uuid))
                 for uuid, meta in (index.get("sessions") or {}).items()]
    labelled += [(meta["object"], archive.project_label(cwd))
                 for cwd, meta in (index.get("projects") or {}).items()]
    labelled += [(archive.setup_key(m), archive.setup_label(m))
                 for m in (index.get("setups") or {})]

    opened = set()
    for key, label in labelled:
        blob = dest.read(key)
        if blob is None:
            continue
        opened.add(key)
        plain = crypto.unseal(blob, master, label)
        note(key, plain)
        if key.endswith(".tar.enc"):
            for name, data in archive.tar_members(plain, key):
                note(f"{key}!{name}", data)

    for key in dest.list(""):
        if key not in opened:
            blob = dest.read(key)
            if blob is not None:
                note(key, blob)
    return sorted(hits)


class ListsOneExtraKey:
    """A real Destination that also lists one key of its own choosing.

    Duck-typed rather than a Destination subclass, on purpose: what is under
    test is sync's rule about names, not any transport's internals, and a
    listing is the Destination's answer however carefully a particular
    transport screens it first. ADR-0009's sentence is that carryon checks
    what comes back against something this machine knows - not that the layer
    below happens to have checked it already.
    """

    def __init__(self, inner, extra):
        self._inner = inner
        self._extra = extra

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def list(self, prefix: str = "") -> list:
        keys = list(self._inner.list(prefix))
        if self._extra.startswith(prefix):
            keys.append(self._extra)
        return sorted(keys)


@pytest.fixture
def paired(tmp_path):
    """An honest Archive: machine-a pushed a Setup holding the master key, so
    the encrypted Index vouches for it. machine-b is paired and about to pull.
    """
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    sync.init(ns(dest=dest_spec, machine="machine-a"), home_a)
    assert sync.push(ns(apply=True, category=SETUP_CATEGORIES), home_a) == 0
    home_b = build_home_b(tmp_path)
    link_home(home_b, dest_spec, "machine-b", master_from=home_a)
    return types.SimpleNamespace(home_a=home_a, home_b=home_b,
                                 dest_spec=dest_spec,
                                 dest_root=tmp_path / "archive")
