# Developing carryon

Terms are defined in [CONTEXT.md](../CONTEXT.md), and the reasoning behind each
decision is in [docs/adr/](adr/).

## Tests

```bash
uv run --extra dev pytest -q
python3 run_tests.py           # no pytest required
```

Both runners run the same suite and have to agree. CI runs both on macOS and
Ubuntu for every pull request, and fails if they ran different numbers of
tests in any module. `run_tests.py` works from a hand-written module list, so a
new `tests/test_*.py` goes into its `MODULES`; `tests/test_harness.py` fails
until it does.

What the suite does and does not exercise is in
[trust.md](trust.md#what-the-tests-do-not-cover).

## Adding an agent

Add a module to `carryon/adapters/` defining `ADAPTER`, and list it in
`MODULES`. The engine reads the declaration.

```python
from .base import CONFIG, Adapter, Excluded, Item

ADAPTER = Adapter(
    key="my-agent",
    name="My Agent",
    detect=".myagent",
    verified_against="My Agent 3.2, macOS 15",
    platforms=("darwin",),
    items=(
        Item(".myagent/config.json", "myagent/config.json",
             "file", CONFIG, "settings", required=True),
    ),
    exclude=(Excluded(".myagent/token", "CREDENTIAL", "log in again"),),
    known_entries=("config.json", "token", "cache"),
)
```

Set `verified_against` to a version you actually checked. `known_entries`
lists every top-level name you know about; anything else is reported by
`doctor`, which is how a layout change gets noticed. An agent whose Sessions
sit in a shape the History engine has no layout for carries its Setup only;
adding that shape is engine work rather than a declaration.

## Platform support

Every adapter is declared for `darwin` and was checked there; only the
`~/.agents` one also claims Linux. The test suite runs on macOS and Ubuntu in
CI, which shows carryon itself works on Linux. It does not show where an agent
keeps its files there, which is what an adapter's platform claim is about.
Nothing has been run on Windows.

`doctor` tells you when you are on a platform an adapter does not cover, and an
adapter's `verified_against` records the version and OS it was actually checked
on rather than a guess.

## Releasing

Bump `__version__` in `carryon/__init__.py` and merge it. Then the maintainer
pushes a matching tag from `main`:

```bash
git fetch origin && git tag vX.Y.Z origin/main && git push origin vX.Y.Z
```

`.github/workflows/release.yml` runs the full suite, checks the tag matches the
version, builds and installs the wheel, then publishes `agent-carryon` to PyPI
through trusted publishing.
