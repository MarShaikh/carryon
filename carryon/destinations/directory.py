"""A Destination that is just a path.

This one module covers a USB stick, iCloud Drive, Dropbox, Google Drive,
OneDrive, Syncthing and a mounted NAS alike: each is a directory something
else keeps in sync, and carryon needs no credentials and no client library to
use one - the sync client owns the transport.

The non-obvious decision: nothing about walking, reading, writing or deleting
the root is this module's. All four are LocalTreeDestination's, because a
synced folder is exactly the kind of Destination somebody else can write to,
and every rule that follows from that - carryon follows no symlink it finds
there, reads no hard link, and lands every blob through a tmp file plus an
atomic rename so a sync client never uploads half a blob - has to be the same
rule the git clone gets. This module is the spec and the four verbs.
"""

from __future__ import annotations

import pathlib

from .base import TMP_PREFIX, LocalTreeDestination  # noqa: F401 (re-exported)


class DirectoryDestination(LocalTreeDestination):

    def __init__(self, root):
        self.root = pathlib.Path(root).expanduser()

    def _read_blob(self, key: str):
        return self._local_bytes(key)

    def _write_blob(self, key: str, data: bytes) -> None:
        self._local_write(key, data)

    def _delete_blob(self, key: str) -> None:
        self._local_delete(key)

    def _list_keys(self, prefix: str) -> list:
        return self._local_keys(prefix)

    def describe(self) -> str:
        return f"directory {self.root}"
