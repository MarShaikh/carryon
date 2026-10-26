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


def test_a_credential_is_named_over_an_archive_that_is_still_written(tmp_path,
                                                                     capsys):
    """This one pinned "a failed scan must not leave a shippable artefact
    lying around", and ADR-0014 took the failure away rather than the concern.

    The concern was a plaintext tarball with a credential in it, and what
    answers it now is not a refusal but where the tarball is: `capture` writes
    in the clear on the machine that already holds the secrets, and `push`
    seals. So the artefact is written, and what has to hold is that the run
    says both things - what it matched, and that these bytes are not sealed.

    Asserted on the closing sentence rather than just the exit code, because
    an archive written silently is the outcome ADR-0014 would be wrong to
    allow: this is the one path where the plaintext is deliberate, and a user
    who is not told that is a user who mails it somewhere.
    """
    home = build_home(tmp_path)
    (home / ".claude" / "settings.json").write_text(
        '{"key": "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED"}')
    archive = tmp_path / "bundle.tar.gz"

    code, _ = capture.run(out=tmp_path / "b", dry=False, home=home, archive=archive)

    printed = capsys.readouterr().out
    assert code == 0, "reported, not refused (ADR-0014)"
    assert archive.exists(), "the archive ADR-0014 goes on writing"
    assert "settings.json" in printed, "the credential was not named"
    assert capture.NOT_ENCRYPTED in printed, \
        "a plaintext artefact was written without saying it is plaintext"


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
