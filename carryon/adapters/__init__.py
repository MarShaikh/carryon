"""Adapter registry.

To add an agent: drop a module in this package that defines `ADAPTER`, and add
it to MODULES below. Nothing else changes - the capture engine reads the
declaration.

Please fill in `verified_against` with the version and OS you actually checked.
An adapter written against a guess is worse than no adapter: it fails silently,
and the user finds out on the machine they just migrated to.
"""

from __future__ import annotations

import importlib
import pathlib

from .base import (CAPABILITY, CATEGORIES, CONFIG, HISTORY, KNOWLEDGE,
                   SETUP_CATEGORIES, Adapter, Excluded, Item)

HOME = pathlib.Path.home()

MODULES = (
    "claude_code",
    "codex",
    "cursor",
    "agents_dir",
)


def _load() -> dict:
    found = {}
    for name in MODULES:
        module = importlib.import_module(f".{name}", __package__)
        adapter = module.ADAPTER
        if adapter.key in found:
            raise ValueError(f"duplicate adapter key {adapter.key!r} in {name}")
        found[adapter.key] = adapter
    return found


ADAPTERS = _load()


def present(path) -> bool:
    """Whether something is at `path`, for a caller that has no better answer
    than no.

    Path.exists() swallows exactly four errnos - ENOENT, ENOTDIR, EBADF,
    ELOOP - and raises every other one, EACCES included. A mode-000 $HOME or
    agent directory needs no attacker (a backup restored with the wrong owner,
    an agent that once ran under sudo) and it came out of `carryon list` as a
    PermissionError before a word had been printed, while `doctor` beside it
    answered the same directory with a report line. layout.py's docstring
    already spells this out for its own walk; this is the same sentence for
    the two callers that were left holding the bare call.

    A path this machine will not answer about is not installed and holds no
    item: that is the fail-closed direction for a question about what to
    CARRY, and the command whose job is to say what is wrong (`doctor`) has
    its own walk that reports the reason rather than the answer.
    """
    try:
        return pathlib.Path(path).exists()
    except (OSError, ValueError):
        return False


def is_installed(key: str, home: pathlib.Path = HOME) -> bool:
    return present(pathlib.Path(home) / ADAPTERS[key].detect)


def installed(home: pathlib.Path = HOME) -> list:
    return [key for key in ADAPTERS if is_installed(key, home)]


__all__ = [
    "ADAPTERS", "Adapter", "Item", "Excluded", "CATEGORIES", "SETUP_CATEGORIES",
    "CONFIG", "CAPABILITY", "KNOWLEDGE", "HISTORY", "HOME",
    "is_installed", "installed", "present",
]
