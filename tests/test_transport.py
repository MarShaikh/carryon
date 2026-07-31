"""Getting a captured Setup to the other machine by hand.

Two routes, and the difference matters:

  - a directory, which is safe to commit to a private git repo, because the
    scanner refuses to produce one containing a credential
  - a single .tar.gz, for a USB stick or AirDrop

Neither is encrypted, and neither needs to be: a Setup holds config and
skills, not secrets. A History is the opposite - always encrypted - and
travels via push/pull, never these routes.
"""

import pathlib
import sys
import tarfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture  # noqa: E402


def build_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "skills").mkdir()
    (claude / "skills" / "mine").mkdir()
    (claude / "skills" / "mine" / "SKILL.md").write_text("authored here")
    return home


def test_archive_contains_the_bundle(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "bundle"
    archive = tmp_path / "bundle.tar.gz"

    code, _ = capture.run(out=out, dry=False, home=home, archive=archive)
    assert code == 0
    assert archive.exists()

    with tarfile.open(archive) as tar:
        names = tar.getnames()
    assert any(n.endswith("MANIFEST.json") for n in names)
    assert any(n.endswith("claude/settings.json") for n in names)
    assert any(n.endswith("claude/skills/mine/SKILL.md") for n in names)


def test_archive_is_not_written_on_a_dry_run(tmp_path):
    home = build_home(tmp_path)
    archive = tmp_path / "bundle.tar.gz"

    code, _ = capture.run(out=tmp_path / "b", dry=True, home=home, archive=archive)
    assert code == 0
    assert not archive.exists()


def test_archive_is_not_written_when_a_credential_is_found(tmp_path):
    """A failed scan must not leave a shippable artefact lying around."""
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").write_text(
        '{"key": "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED"}')
    archive = tmp_path / "bundle.tar.gz"

    code, _ = capture.run(out=tmp_path / "b", dry=False, home=home, archive=archive)
    assert code == 2
    assert not archive.exists(), "a refused capture must not produce an archive"


def test_archive_entries_are_contained_under_one_top_level_dir(tmp_path):
    """So `tar xzf` on the other machine cannot scatter files across $HOME."""
    home = build_home(tmp_path)
    archive = tmp_path / "bundle.tar.gz"
    capture.run(out=tmp_path / "bundle", dry=False, home=home, archive=archive)

    with tarfile.open(archive) as tar:
        names = tar.getnames()
    tops = {n.split("/")[0] for n in names}
    assert len(tops) == 1, f"archive spreads across {tops}"
    assert not any(n.startswith("/") or ".." in n for n in names)
