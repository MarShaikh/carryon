"""Cursor - ~/.cursor

Only the CLI side. Cursor's editor state lives elsewhere and is
platform-specific (on macOS, ~/Library/Application Support/Cursor/User/).
That is deliberately out of scope: it is editor configuration rather than
agent state, and it is large, opaque and re-createable.
"""

from .base import CAPABILITY, CONFIG, KNOWLEDGE, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="cursor",
    name="Cursor",
    detect=".cursor",
    verified_against="macOS 15, ~/.cursor layout as of 2026-07",
    platforms=("darwin",),
    items=(
        Item(".cursor/cli-config.json", "cursor/cli-config.json",
             "json-strip", CONFIG, "authInfo (email, team and user ids) removed",
             strip=("authInfo",), required=True),
        Item(".cursor/rules", "cursor/rules", "tree", KNOWLEDGE, "rules"),
        Item(".cursor/commands", "cursor/commands", "tree", CAPABILITY, "commands"),
        Item(".cursor/agents", "cursor/agents", "tree", CAPABILITY, "subagents"),
        Item(".cursor/skills-cursor/.sync-manifest.json",
             "cursor/skills-cursor.sync-manifest.json",
             "file", CAPABILITY,
             "inventory only; Cursor re-syncs the skills themselves"),
    ),
    exclude=(
        Excluded(".cursor/extensions/", "editor extensions, often 300M+",
                 "re-install from the marketplace"),
        Excluded(".cursor/projects/", "chat and session state",
                 "no tool re-keys it"),
        Excluded(".cursor/skills-cursor/*/", "vendor-synced skills",
                 "Cursor re-syncs them; the manifest is kept to check against"),
        Excluded(".cursor/{ide_state.json,ai-tracking,blocklist}",
                 "machine-local", "regenerated"),
        Excluded("~/Library/Application Support/Cursor/", "editor state",
                 "out of scope - editor config, not agent state"),
        Excluded(".cursor/.gitignore", "Cursor-managed ignore rules",
                 "Cursor rewrites it; note that its existence means Cursor "
                 "expects people to version-control ~/.cursor"),
    ),
    known_entries=(
        "cli-config.json", "rules", "commands", "agents", "skills-cursor",
        "plugins", "extensions", "projects", "ide_state.json", "ai-tracking",
        "blocklist", "argv.json", "unified_repo_list.json",
        ".gitignore", ".DS_Store",
    ),
)
