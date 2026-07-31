"""Layout drift: what happens when an agent moves its files.

This is the failure mode that killed Mackup. It symlinked app-support
directories wholesale, vendors changed their layouts, and it broke quietly.
The defence here is that drift must be LOUD:

  - an item an adapter says should always exist, going missing, is a warning
  - an entry the adapter has never heard of is reported by `doctor`

Both of these fire before a migration, not after one.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, layout  # noqa: E402
from carryon.adapters import ADAPTERS  # noqa: E402


def build_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home"
    claude = home / ".claude"
    (claude / "plugins").mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "skills").mkdir()
    return home


# --- required items ---------------------------------------------------------

def test_missing_required_item_is_reported_not_silent(tmp_path):
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").unlink()  # the agent moved it

    code, manifest = capture.run(out=tmp_path / "b", dry=True, home=home)

    drift = manifest["agents"]["claude-code"]["layout_drift"]
    assert ".claude/settings.json" in drift, \
        "a required path going missing must be surfaced, not silently skipped"


def test_missing_optional_item_is_not_drift(tmp_path):
    home = build_home(tmp_path)
    # keybindings.json is genuinely optional - most people have none
    code, manifest = capture.run(out=tmp_path / "b", dry=True, home=home)

    drift = manifest["agents"]["claude-code"]["layout_drift"]
    assert ".claude/keybindings.json" not in drift
    assert ".claude/keybindings.json" in manifest["agents"]["claude-code"]["absent"]


def test_capture_still_succeeds_despite_drift(tmp_path):
    """Drift is a warning, not a failure. The user may still want the capture."""
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").unlink()

    code, _ = capture.run(out=tmp_path / "b", dry=True, home=home)
    assert code == 0


# --- unknown entries (the doctor) -------------------------------------------

def test_doctor_flags_an_entry_the_adapter_has_never_heard_of(tmp_path):
    home = build_home(tmp_path)
    (home / ".claude" / "brand-new-feature").mkdir()

    report = layout.inspect(home)
    unknown = report["claude-code"]["unknown"]

    assert "brand-new-feature" in unknown, \
        "an unrecognised entry is how a layout change first shows up"


def test_doctor_is_quiet_about_entries_the_adapter_knows(tmp_path):
    home = build_home(tmp_path)
    (home / ".claude" / "cache").mkdir()      # known, deliberately excluded
    (home / ".claude" / "projects").mkdir()   # known, entangle's job

    report = layout.inspect(home)
    unknown = report["claude-code"]["unknown"]

    assert "cache" not in unknown
    assert "projects" not in unknown
    assert "settings.json" not in unknown


def test_doctor_skips_agents_that_are_not_installed(tmp_path):
    home = build_home(tmp_path)  # no ~/.codex
    report = layout.inspect(home)
    assert "codex" not in report


def test_every_adapter_accounts_for_what_it_captures():
    """An adapter must not capture something it does not also declare known.

    Otherwise doctor would report the tool's own captures as unrecognised.
    """
    for key, adapter in ADAPTERS.items():
        known = set(adapter.known_entries)
        for item in adapter.items:
            top = item.src.split("/")[1]  # ".claude/skills" -> "skills"
            assert top in known, f"{key}: captures {top!r} but does not list it as known"


# --- platform ---------------------------------------------------------------

def test_every_adapter_declares_its_verified_platforms():
    for key, adapter in ADAPTERS.items():
        assert adapter.platforms, f"{key} declares no platforms"
        for plat in adapter.platforms:
            assert plat in ("darwin", "linux", "win32"), f"{key}: odd platform {plat}"


def test_unverified_platform_is_flagged(tmp_path):
    home = build_home(tmp_path)
    report = layout.inspect(home, platform="win32")
    assert report["claude-code"]["platform_verified"] is False

    report = layout.inspect(home, platform="darwin")
    assert report["claude-code"]["platform_verified"] is True
