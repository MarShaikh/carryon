"""The cross-agent skills convention - ~/.agents

Not an agent, but the shared store that many agents install skills into. Its
lock file records each skill's upstream repo and hash, which is what makes the
skills re-installable on the new machine rather than something to copy.
"""

from .base import CAPABILITY, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="agents-convention",
    name="Cross-agent skills (~/.agents)",
    detect=".agents",
    verified_against=".skill-lock.json version 3",
    platforms=("darwin", "linux"),
    items=(
        Item(".agents/.skill-lock.json", "agents/.skill-lock.json",
             "file", CAPABILITY,
             "upstream repo and hash per skill - the re-resolve source of truth",
             required=True),
    ),
    exclude=(
        Excluded(".agents/skills/", "skills with a recorded upstream",
                 "re-installed from .skill-lock.json rather than copied"),
    ),
    known_entries=(".skill-lock.json", "skills", "agents", ".DS_Store"),
)
