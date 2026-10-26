"""The refusals, hints and documents ADR-0016's first round left: `init`,
`pair`, `resolve`, `list`, a retired setting, and the RESTORE.md a Setup
carries (ADR-0016's 2026-10-26 amendment).

Each test pins the sentence a user reads. The last one is the guard for the
whole rule: no string carryon could print cites an ADR.
"""

import argparse
import ast
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, cli, config, crypto, keyring  # noqa: E402
from carryon import prompting, resolve, sync  # noqa: E402
from tests.test_capture import build_home  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, recover=False, machine=None,
                apply=False, agent=None, category=None, force=False,
                paths=[], verbose=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def bare(tmp_path, name="home") -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    return home


def refusal(call) -> str:
    with pytest.raises(SystemExit) as exc:
        call()
    return str(exc.value)


# --- init, join, recover ------------------------------------------------------


def test_a_keyless_push_points_at_capture(tmp_path):
    message = refusal(lambda: sync._require_master(bare(tmp_path),
                                                   for_push=True))
    assert message.endswith(
        ". For an unencrypted copy of this Setup instead, run `carryon "
        "capture --out DIR --apply`"), message
    assert "keyless push" not in message and "Everything carryon" not in message


def test_init_on_a_machine_with_a_key(tmp_path):
    home = bare(tmp_path)
    keyring.store_master(b"\x01" * crypto.MASTER_BYTES, home=home)
    message = refusal(lambda: sync.init(ns(dest=str(tmp_path / "a")), home))
    assert message == (
        "this machine already holds a master key, so it is already set up. "
        "To start over, remove the key from the keychain (service 'carryon') "
        "first."), message


def test_recover_without_a_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(prompting, "available", lambda: False)
    message = refusal(lambda: sync.init(
        ns(recover=True, dest=str(tmp_path / "a")), bare(tmp_path)))
    assert message == ("--recover needs a terminal, because the recovery key "
                       "is typed at a prompt. Nothing was stored."), message


def test_recover_over_objects_with_no_index(tmp_path, monkeypatch, capsys):
    from tests.test_recover import a_terminal, founded_archive
    from carryon import archive, destinations
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare(tmp_path, "home_b")
    dest = destinations.from_spec(spec, home)
    dest.write(archive.PREFIX + "/setups/machine-a.tar.enc", b"sealed")
    dest.delete(archive.INDEX_KEY)
    a_terminal(monkeypatch, key)
    message = refusal(lambda: sync.init(
        ns(recover=True, dest=spec, machine="machine-b"), home))
    assert message == (
        f"there is no Index at {dest.describe()}, but there are carryon "
        "objects there, so the recovery key can't be checked. Restore an "
        "earlier copy of the Archive (a git Destination keeps one in its "
        "history), then run `carryon init --recover` again. Nothing was "
        "stored."), message


def test_join_without_dest_or_terminal(tmp_path, monkeypatch):
    monkeypatch.setattr(prompting, "available", lambda: False)
    message = refusal(lambda: sync.init(
        ns(join=sync.new_pairing_code()), bare(tmp_path)))
    assert message == ("--join needs --dest: name the Destination the paired "
                       "machine uses. Nothing was stored, and the code is "
                       "still good."), message


# --- pair ----------------------------------------------------------------------


def pair_output(tmp_path, capsys, spec) -> str:
    home = bare(tmp_path)
    assert sync.init(ns(dest=spec, machine="machine-a"), home) == 0
    capsys.readouterr()
    assert sync.pair(ns(), home) == 0
    return capsys.readouterr().out


def test_pair_closes_in_one_line(tmp_path, capsys):
    out = pair_output(tmp_path, capsys, str(tmp_path / "archive"))
    assert out.splitlines()[-1] == "Use it once, within 24 hours.", out
    assert "ADR-" not in out and "git repository" not in out, out


def test_pair_over_git_says_keep_the_code_private(tmp_path, capsys):
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)],
                   check=True)
    out = pair_output(tmp_path, capsys, f"git:{origin}")
    assert out.splitlines()[-1] == (
        "This Destination is a git repository, so a used code can still be "
        "read from its history - keep the code private."), out
    assert "Rotate" not in out and "ADR-" not in out, out


# --- resolve, list, config --------------------------------------------------------


def test_resolve_on_a_transcript(tmp_path):
    from tests.test_residue_base import UUID_1, build_home as residue_home
    from tests.test_residue_base import project_dir
    home = residue_home(tmp_path, "home_a")
    sync.init(ns(dest=str(tmp_path / "archive"), machine="machine-a"), home)
    transcript = project_dir(home) / (UUID_1 + ".jsonl")
    message = refusal(lambda: resolve.run(ns(paths=[str(transcript)]), home))
    assert message == (
        f"refusing to resolve {transcript}: it belongs to Session {UUID_1}, "
        "and only per-project memory can be resolved. A divergent Transcript "
        "stays filed under ~/.carryon/conflicts/<uuid>/."), message


def test_list_closes_in_one_plain_line(tmp_path, monkeypatch, capsys):
    home = build_home(tmp_path)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)
    assert cli.cmd_list(ns()) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[-1] == ("All of this is the Setup. `carryon push` "
                                    "encrypts it, along with the History."), out
    assert "ADR-" not in out, out


def test_a_retired_setting_says_why_plainly():
    assert config.RETIRED["encrypt_all"] == ("carryon always encrypts, so "
                                             "the setting does nothing")


# --- RESTORE.md ---------------------------------------------------------------------


def test_restore_notes_are_plain(tmp_path):
    home = build_home(tmp_path)
    dotfiles = home / "dotfiles" / "linked-skill"
    dotfiles.mkdir(parents=True)
    (home / ".claude" / "skills" / "linked-skill").symlink_to(dotfiles)
    (home / ".claude" / "skills" / "mine" / "tests").mkdir()
    (home / ".claude" / "skills" / "mine" / "tests" / "t.py").write_text("x")
    out = tmp_path / "setup"
    assert capture.run(out=out, dry=False, home=home)[0] == 0
    text = (out / "RESTORE.md").read_text()
    for gone in ("ADR-", "Two things", "their business", "deliberate",
                 "capability, not what built it"):
        assert gone not in text, f"RESTORE.md still says {gone!r}:\n{text}"
    for kept in (
            "This Setup holds no login credentials, so log in again.",
            "Re-install from it to get current versions rather than a stale "
            "copy.",
            "Then copy the skills with no upstream. They exist only in this "
            "Setup:",
            "Some skills are symlinks managed elsewhere, most likely by a "
            "dotfiles repo.",
            "A target under `~` is the path on the machine this Setup came "
            "from.",
            "This Setup holds no History. Bring it down from the Archive with "
            "`carryon pull`:",
            "- The History is carried unredacted, credentials included, so "
            "keep your recovery key safe.",
            "- `.claude/skills/mine/tests` - development artifact: a Setup "
            "carries the skill, not its tests, caches or installed packages"):
        # Compared with the line wrapping taken out: the document wraps at
        # 80 columns, and where it breaks is not the sentence.
        assert kept in " ".join(text.split()), \
            f"RESTORE.md lacks {kept!r}:\n{text}"


# --- the guard ------------------------------------------------------------------------


def _docstrings(tree) -> set:
    """Every bare string statement: module, class and function docstrings,
    and the attribute docstrings dataclasses use."""
    return {id(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)}


def test_no_string_carryon_can_print_cites_an_adr():
    """Comments and docstrings keep the reasoning; a string constant is
    something a user may read, so none names an ADR."""
    found = []
    for path in sorted((ROOT / "carryon").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = _docstrings(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and "ADR-" in node.value and id(node) not in docs):
                found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not found, found
