"""Detect that an agent has changed its on-disk layout.

Vendors move files without notice. When that happens a path-driven tool has two
options: fail loudly, or quietly copy less than the user thinks. Mackup chose
the second by accident and broke for years before anyone could say exactly how.

`inspect` answers two questions per installed agent:
  - is anything here that this adapter has never heard of?
  - is this platform one the adapter was actually verified on?

Run it before a migration, not after.
"""

from __future__ import annotations

import fnmatch
import pathlib
import sys

from .adapters import ADAPTERS, HOME, is_installed


def _is_known(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def inspect(home: pathlib.Path = HOME, platform: str = None) -> dict:
    """Report unknown entries and platform coverage for each installed agent."""
    platform = platform or sys.platform
    report = {}

    for key, adapter in ADAPTERS.items():
        if not is_installed(key, home):
            continue

        root = home / adapter.detect
        unknown = []
        if root.is_dir():
            unknown = sorted(entry.name for entry in root.iterdir()
                             if not _is_known(entry.name, adapter.known_entries))

        report[key] = {
            "name": adapter.name,
            "root": str(root),
            "verified_against": adapter.verified_against,
            "platforms": list(adapter.platforms),
            "platform_verified": platform in adapter.platforms,
            "unknown": unknown,
        }
    return report


def format_report(report: dict, platform: str = None) -> str:
    platform = platform or sys.platform
    lines = [f"Layout check on {platform}", ""]

    if not report:
        lines.append("  No supported agents found.")
        return "\n".join(lines)

    drifting = False
    for key, info in report.items():
        lines.append(f"  {info['name']}  ({key})")
        lines.append(f"    verified against : {info['verified_against']}")

        if info["platform_verified"]:
            lines.append(f"    platform         : {platform}, verified")
        else:
            drifting = True
            lines.append(f"    platform         : {platform} - NOT verified "
                         f"(adapter covers {', '.join(info['platforms'])})")

        if info["unknown"]:
            drifting = True
            lines.append(f"    unrecognised     : {len(info['unknown'])} entries")
            for name in info["unknown"]:
                lines.append(f"                       {name}")
        else:
            lines.append("    unrecognised     : none")
        lines.append("")

    if drifting:
        lines += [
            "Unrecognised entries are not an error. They mean this agent has",
            "something the adapter does not describe - usually a feature added",
            "since it was written. Check whether it is worth carrying, then add",
            "it to the adapter's items or exclude list so it stops being a",
            "surprise. Nothing unrecognised is ever captured.",
        ]
    else:
        lines.append("Everything on disk is accounted for by an adapter.")
    return "\n".join(lines)
