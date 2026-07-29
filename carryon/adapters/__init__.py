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

from .base import (CAPABILITY, CATEGORIES, CONFIG, KNOWLEDGE, Adapter,
                   Excluded, Item)

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


def is_installed(key: str, home: pathlib.Path = HOME) -> bool:
    return (home / ADAPTERS[key].detect).exists()


def installed(home: pathlib.Path = HOME) -> list:
    return [key for key in ADAPTERS if is_installed(key, home)]


__all__ = [
    "ADAPTERS", "Adapter", "Item", "Excluded", "CATEGORIES",
    "CONFIG", "CAPABILITY", "KNOWLEDGE", "HOME", "is_installed", "installed",
]
