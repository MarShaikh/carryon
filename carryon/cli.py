"""Command line entry point."""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import __version__, capture, layout
from .adapters import ADAPTERS, CATEGORIES, HOME, is_installed


def _parse_subset(value: str, known, label: str) -> set:
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    unknown = chosen - set(known)
    if unknown:
        raise SystemExit(
            f"unknown {label}: {', '.join(sorted(unknown))}\n"
            f"known {label}s: {', '.join(known)}")
    return chosen


def cmd_list(args) -> int:
    print("Agents detected on this machine:\n")
    for key, adapter in ADAPTERS.items():
        present = is_installed(key)
        print(f"  [{'x' if present else ' '}] {key:<20} {adapter.name}")
        if not present:
            continue
        for category in CATEGORIES:
            names = [item.src.split("/")[-1] for item in adapter.items
                     if item.category == category and (HOME / item.src).exists()]
            if names:
                print(f"        {category:<11} {', '.join(names)}")
    print("\nNo chats or sessions are included in any of the above - see README.md.")
    return 0


def cmd_doctor(args) -> int:
    """Report anything on disk this tool does not recognise."""
    print(layout.format_report(layout.inspect()))
    return 0


def cmd_capture(args) -> int:
    agents = _parse_subset(args.agent, ADAPTERS, "agent") if args.agent else None
    categories = (_parse_subset(args.category, CATEGORIES, "category")
                  if args.category else None)
    code, _ = capture.run(
        out=pathlib.Path(args.out).expanduser().resolve(),
        dry=not args.apply,
        want_agents=agents,
        want_categories=categories,
        archive=pathlib.Path(args.archive).expanduser().resolve() if args.archive else None,
    )
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="carryon",
        description="Move an AI coding agent setup to a new machine. "
                    "Config, capability and knowledge - never chats.")
    parser.add_argument("--version", action="version",
                        version=f"carryon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show detected agents and what would be captured")
    listing.set_defaults(func=cmd_list)

    doctor = sub.add_parser(
        "doctor",
        help="check for layout changes: entries no adapter recognises")
    doctor.set_defaults(func=cmd_doctor)

    cap = sub.add_parser("capture", help="capture portable state into a directory")
    cap.add_argument("--out", required=True, help="destination directory")
    cap.add_argument("--apply", action="store_true",
                     help="actually write (default: dry run)")
    cap.add_argument("--agent", metavar="A,B",
                     help=f"subset of: {', '.join(ADAPTERS)}")
    cap.add_argument("--category", metavar="A,B",
                     help=f"subset of: {', '.join(CATEGORIES)}")
    cap.add_argument("--archive", metavar="FILE.tar.gz",
                     help="also pack the bundle into a single file")
    cap.set_defaults(func=cmd_capture)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
