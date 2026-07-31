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
    # Checked read-only on 2026-07-31, names and structure only, never file
    # contents: every top-level entry below is one this list accounts for,
    # skills-cursor held .sync-manifest.json beside one directory per
    # vendor-synced skill, and plugins held nothing but `local`. `rules` and
    # `commands` were absent there, which is what leaving them not-required
    # is for.
    verified_against="macOS 15, ~/.cursor layout as of 2026-07-31",
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
        # Written down rather than left out. Both were in known_entries and
        # in neither items nor exclude, which is the shape `doctor` cannot
        # see - it reports what no adapter has heard of, and these are heard
        # of and carried by nothing. An exclusion nobody wrote down reads as
        # an oversight later (adapters/base.Excluded).
        Excluded(".cursor/plugins/", "installed CLI plugins",
                 "Cursor resolves these itself; a copied plugin tree pins a "
                 "stale version and carries whatever it was built against"),
        Excluded(".cursor/{argv.json,unified_repo_list.json}",
                 "launcher flags and the local repo list",
                 "both name paths and hardware on the old machine"),
        Excluded("~/Library/Application Support/Cursor/", "editor state",
                 "out of scope - editor config, not agent state"),
        Excluded("~/Library/Application Support/Cursor/User/workspaceStorage/",
                 "chat state",
                 "lives in app storage as opaque per-workspace databases, not "
                 "as transcripts under ~/.cursor - no History is carried for "
                 "this agent"),
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
