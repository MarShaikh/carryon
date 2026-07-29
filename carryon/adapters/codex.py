"""OpenAI Codex CLI - ~/.codex"""

from .base import CONFIG, KNOWLEDGE, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="codex",
    name="OpenAI Codex CLI",
    detect=".codex",
    verified_against="macOS 15, ~/.codex layout as of 2026-07",
    platforms=("darwin",),
    items=(
        Item(".codex/config.toml", "codex/config.toml",
             "file", CONFIG, "config", required=True),
        Item(".codex/AGENTS.md", "codex/AGENTS.md",
             "file", KNOWLEDGE, "global instructions"),
        Item(".codex/memories", "codex/memories",
             "tree", KNOWLEDGE, "memories"),
    ),
    exclude=(
        Excluded(".codex/auth.json", "CREDENTIAL",
                 "log in again on the new machine"),
        Excluded(".codex/sessions/", "chats", "use entangle"),
        Excluded(".codex/installation_id", "machine identity",
                 "regenerated on install"),
        Excluded(".codex/skills/.system/", "vendor skills",
                 "recreated by the install; carrying them pins a stale version"),
        Excluded(".codex/{state_*.sqlite*,logs_*.sqlite}",
                 "opaque local state", "not portable"),
        Excluded(".codex/{cache,tmp,log,models_cache.json}", "caches", "regenerated"),
        Excluded(".codex/history.jsonl", "prompt history", "entangle carries this"),
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
