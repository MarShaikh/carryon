"""The capture engine.

Interprets adapter declarations. Knows nothing about any particular agent - if
you find yourself adding an `if key == "cursor"` here, it belongs in the
adapter or in a new item kind.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import tarfile
from datetime import datetime, timezone

from . import __version__
from .adapters import ADAPTERS, CATEGORIES, HOME, is_installed
from .restore import build_restore
from .secrets import scan

ENTANGLE = "https://github.com/gowtham-sai-yadav/claude-teleport"


def tree_files(root: pathlib.Path) -> list:
    return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def copy_tree(src: pathlib.Path, dst: pathlib.Path) -> tuple:
    files = total = 0
    for path in sorted(src.rglob("*")):
        if path.is_dir() or ".git" in path.parts:
            continue
        target = dst / path.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        files += 1
        total += path.stat().st_size
    return files, total


class Capture:
    """Copies what an adapter declares, and records any credential it meets."""

    def __init__(self, out: pathlib.Path, dry: bool, home: pathlib.Path = HOME):
        self.out = out
        self.dry = dry
        self.home = home
        self.findings = []
        self.files = 0
        self.bytes = 0

    def _check(self, label: str, data: bytes) -> None:
        hits = scan(data)
        if hits:
            self.findings.append((label, hits))

    def _write(self, dst: pathlib.Path, data: bytes) -> None:
        if self.dry:
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        self.files += 1
        self.bytes += len(data)

    def do_file(self, src, dst, item) -> dict:
        data = src.read_bytes()
        print(f"      {item.src:<46} {len(data)/1024:>7.1f}K  {item.note}")
        self._check(item.src, data)
        self._write(dst, data)
        return {}

    def do_tree(self, src, dst, item) -> dict:
        files = tree_files(src)
        size = sum(p.stat().st_size for p in files)
        print(f"      {item.src:<46} {len(files):>3} files {size/1024:>6.1f}K  {item.note}")
        for path in files:
            self._check(str(path.relative_to(self.home)), path.read_bytes())
        if not self.dry and files:
            copied, written = copy_tree(src, dst)
            self.files += copied
            self.bytes += written
        return {}

    def do_json_strip(self, src, dst, item) -> dict:
        raw = json.loads(src.read_text())
        strip = set(item.strip)
        removed = sorted(k for k in raw if k in strip)
        body = json.dumps({k: v for k, v in raw.items() if k not in strip},
                          indent=2).encode()
        suffix = f" [stripped: {', '.join(removed)}]" if removed else ""
        print(f"      {item.src:<46} {len(body)/1024:>7.1f}K  {item.note}{suffix}")
        self._check(item.dst + " (after strip)", body)
        self._write(dst, body)
        return {"stripped_keys": removed}

    def do_skills(self, src, dst, item) -> dict:
        """Split a skills dir into re-resolvable links and must-carry originals.

        A symlinked skill points into a shared store and is recorded in a lock
        file with its upstream, so the new machine re-installs it. A real
        directory has no upstream: if it is not carried here, it is gone.
        """
        linked = sorted(p.name for p in src.iterdir() if p.is_symlink())
        owned = sorted((p for p in src.iterdir()
                        if not p.is_symlink() and p.is_dir()), key=lambda p: p.name)
        print(f"      {item.src:<46} {len(owned):>3} carried, "
              f"{len(linked)} re-resolvable  {item.note}")
        for path in owned:
            print(f"        + {path.name}  (no upstream - lost if not carried)")
            for f in tree_files(path):
                self._check(str(f.relative_to(self.home)), f.read_bytes())
            if not self.dry:
                copied, written = copy_tree(path, dst / path.name)
                self.files += copied
                self.bytes += written
        return {"carried": [p.name for p in owned], "re_resolvable": linked}


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
        if item.category not in want_categories:
            continue
        src = cap.home / item.src
        if not src.exists():
            entry["absent"].append(item.src)
            # A path the adapter says should always be there, missing, usually
            # means the agent moved it. Say so rather than quietly capturing
            # less than the user expects.
            if item.required:
                entry["layout_drift"].append(item.src)
            continue
        if item.kind == "tree" and not tree_files(src):
            entry["absent"].append(item.src + " (empty)")
            continue

        extra = getattr(cap, HANDLERS[item.kind])(src, cap.out / item.dst, item)
        record = {"src": item.src, "dst": item.dst, "kind": item.kind,
                  "category": item.category, "note": item.note}
        record.update(extra)
        entry["items"].append(record)

    if not entry["items"]:
        print("      (nothing in the selected categories)")
    for missing in entry["layout_drift"]:
        print(f"      !!  {missing} is missing - {adapter.name} may have moved it")
    return entry


def run(out: pathlib.Path, dry: bool, want_agents=None, want_categories=None,
        home: pathlib.Path = HOME, archive: pathlib.Path = None) -> tuple:
    """Capture into `out`, optionally also writing a .tar.gz.

    Returns (exit_code, manifest).
    """
    want_categories = set(want_categories or CATEGORIES)
    cap = Capture(out, dry, home)

    manifest = {
        "tool": "carryon",
        "version": __version__,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_home": str(home),
        "categories": sorted(want_categories),
        "scope": "config + capability + knowledge. Never chats or sessions.",
        "history_handled_by": f"entangle - {ENTANGLE}",
        "agents": {},
    }

    print(f"{'PLAN (dry run)' if dry else 'CAPTURING'} -> {out}")
    print(f"categories: {', '.join(sorted(want_categories))}\n")

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


def write_archive(out: pathlib.Path, archive: pathlib.Path) -> None:
    """Pack the bundle into a single .tar.gz for a USB stick or AirDrop.

    Everything is nested under one top-level directory so that unpacking on the
    other machine cannot scatter files across $HOME.
    """
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(out, arcname=out.name)


def _finish(cap: Capture, manifest: dict, out: pathlib.Path, dry: bool,
            archive: pathlib.Path = None) -> tuple:
    print("-" * 74)
    if cap.findings:
        print("SECRET SCAN: FAILED - do not commit or transfer this bundle\n")
        for label, hits in cap.findings:
            print(f"  !! {label}\n     matched: {', '.join(hits)}")
        print("\nThis is fail-closed on purpose. A config bundle should contain no")
        print("credentials, so a hit means the capture list is wrong. Fix it, re-run.")
        if not dry:
            print("\nRefusing to finalise. Written files left in place for inspection.")
            return 2, manifest
        return 1, manifest

    print("SECRET SCAN: clean - no credential patterns in the captured set")

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

    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    (out / "RESTORE.md").write_text(build_restore(manifest))
    print(f"\nWrote {cap.files} files, {cap.bytes/1024:.0f}K to {out}")
    print("  MANIFEST.json   what was taken, and what was deliberately left")
    print("  RESTORE.md      the order to do things on the new machine")

    if archive:
        write_archive(out, archive)
        print(f"  {archive}  ({archive.stat().st_size/1024:.0f}K)")

    print("\nThis bundle passed the credential scan, so it is safe to put in a")
    print("private git repo. The chat bundle from entangle is not - keep that")
    print("one off any remote.")
    return 0, manifest
