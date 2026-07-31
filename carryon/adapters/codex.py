"""OpenAI Codex CLI - ~/.codex"""

from .base import CONFIG, HISTORY, KNOWLEDGE, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="codex",
    name="OpenAI Codex CLI",
    detect=".codex",
    # Checked read-only on 2026-07-31, names and structure only, never file
    # contents: every top-level entry below is one this list accounts for,
    # every file under ~/.codex/sessions/ was
    # sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl, and ~/.codex/skills
    # held nothing but .system. The state_N.sqlite trio (plus -shm and -wal)
    # is what a running Codex leaves, which is what the pattern below covers.
    verified_against="macOS 15, ~/.codex layout as of 2026-07-31",
    platforms=("darwin",),
    items=(
        Item(".codex/config.toml", "codex/config.toml",
             "file", CONFIG, "config", required=True),
        Item(".codex/AGENTS.md", "codex/AGENTS.md",
             "file", KNOWLEDGE, "global instructions"),
        Item(".codex/memories", "codex/memories",
             "tree", KNOWLEDGE, "memories"),
        Item(".codex/sessions", "history/codex",
             "chats", HISTORY, "rollout transcripts, one flat Session each",
             layout="codex-rollouts"),
    ),
    exclude=(
        Excluded(".codex/auth.json", "CREDENTIAL",
                 "log in again on the new machine"),
        Excluded(".codex/installation_id", "machine identity",
                 "regenerated on install"),
        # The WHOLE directory, not just .system - which is what it said
        # before, and that reads as "everything else here is carried" when
        # nothing here is: this adapter declares no skills item at all, and
        # the engine's `skills` kind carries every real directory it finds
        # with no way to leave one out, so declaring one would carry .system
        # too. An exclusion that is not written down reads as an oversight
        # later (adapters/base.Excluded says so), and a Codex user's own
        # skills going nowhere is exactly the thing that must not be silent.
        Excluded(".codex/skills/", "vendor skills under .system, and any of "
                                   "your own beside them",
                 "the vendor ones are recreated by the install and carrying "
                 "them pins a stale version; carryon has no way yet to take "
                 "your own without them, so none of this directory travels - "
                 "copy it by hand if you keep skills here"),
        Excluded(".codex/{state_*.sqlite*,logs_*.sqlite}",
                 "opaque local state", "not portable"),
        Excluded(".codex/{cache,tmp,.tmp,log,logs,shell_snapshots,"
                 "models_cache.json}", "caches and machine-local scratch",
                 "regenerated"),
        Excluded(".codex/version.json", "the installed Codex version",
                 "written by the install; the new machine's own is the true one"),
        Excluded(".codex/history.jsonl", "prompt history",
                 "prompt-box recall, not a Transcript - not part of the History"),
        Excluded(".codex/.personality_migration", "one-time migration marker",
                 "written by the install; means nothing on a fresh machine"),
    ),
    known_entries=(
        "config.toml", "AGENTS.md", "memories", "skills",
        "auth.json", "sessions", "installation_id", "version.json",
        "state_*.sqlite*", "logs_*.sqlite", "models_cache.json",
        "cache", "tmp", "log", "logs", "shell_snapshots", "history.jsonl",
        ".personality_migration", ".tmp", ".DS_Store",
    ),
)
