"""The Setup mark: which Setup this machine last sealed or laid down, and what
it held (ADR-0015, CONTEXT **Setup mark**).

The Index's entry for a Setup holds a random stamp, not a digest, so nothing in
the Archive says whether a Setup changed. A pull restores the newest Setup any
vouched machine pushed, so a Setup can be behind as well as ahead. `push` and
`pull` therefore keep this record, and `carryon status` reads it. Every test
here drives the commands and reads `state.json` for what they left.

Every home is synthetic (test_sync's builders); nothing reads the real
~/.claude, and the OS keychain is forced to the fallback file.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, keyring, setup_mark, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from tests.test_sync import build_home_a, link_home, ns  # noqa: E402

SETUP = "config,capability,knowledge"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def state(home) -> dict:
    path = pathlib.Path(home) / ".carryon" / "state.json"
    return json.loads(path.read_text()) if path.exists() else {}


def mark(home, spec):
    return state(home).get("setup_marks", {}).get(spec)


def index_stamp(home, spec, machine) -> str:
    index = archive.load_index(DirectoryDestination(pathlib.Path(spec)),
                               keyring.fetch_master(home=home))
    return index["setups"][machine]["stamp"]


def here(home) -> str:
    effective = sync._effective_adapters(config.load(home), home)
    return setup_mark.digest_here(home, effective)


@pytest.fixture
def home_a(tmp_path):
    home = build_home_a(tmp_path)
    spec = str(tmp_path / "archive")
    sync.init(ns(dest=spec, machine="machine-a"), home)
    return home, spec


def test_a_full_push_records_the_stamp_it_sealed_and_a_digest(home_a):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    recorded = mark(home, spec)
    assert recorded["stamp"] == index_stamp(home, spec, "machine-a")
    assert isinstance(recorded["digest"], str) and len(recorded["digest"]) == 64
    # A push's real capture and status's dry one must agree on an unchanged
    # home, or every status after a push would say "changed here".
    assert recorded["digest"] == here(home)


def test_a_dry_run_push_leaves_no_mark(home_a):
    home, spec = home_a
    assert sync.push(ns(apply=False), home) == 0
    assert mark(home, spec) is None


def test_a_history_only_push_leaves_the_mark_alone(home_a):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    before = mark(home, spec)
    assert sync.push(ns(apply=True, category="history"), home) == 0
    assert mark(home, spec) == before


def test_a_partial_setup_push_clears_the_mark(home_a):
    """A subset push seals a new stamp over part of the Setup, so the digest
    no longer describes what the Archive holds for this machine."""
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    assert sync.push(ns(apply=True, category="config"), home) == 0
    assert mark(home, spec) is None


def test_the_digest_is_the_same_for_an_unchanged_home(home_a):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    first = mark(home, spec)["digest"]
    assert sync.push(ns(apply=True), home) == 0
    assert mark(home, spec)["digest"] == first


def test_the_digest_moves_when_a_setup_file_changes(home_a):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    first = mark(home, spec)["digest"]
    (home / ".claude" / "CLAUDE.md").write_text("Different instructions.\n")
    assert sync.push(ns(apply=True), home) == 0
    assert mark(home, spec)["digest"] != first


def test_a_full_pull_records_the_source_stamp_and_the_setup_now_here(
        home_a, tmp_path):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    link_home(home_b, spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0
    recorded = mark(home_b, spec)
    assert recorded["stamp"] == index_stamp(home, spec, "machine-a")
    # The mark describes this machine's Setup as the pull left it, which is
    # what a later `status` captures and compares.
    assert recorded["digest"] == here(home_b)


def test_a_dry_run_pull_and_a_history_only_pull_leave_no_mark(
        home_a, tmp_path):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    link_home(home_b, spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=False), home_b) == 0
    assert sync.pull(ns(apply=True, category="history"), home_b) == 0
    assert mark(home_b, spec) is None


def test_a_partial_setup_pull_clears_the_mark(home_a, tmp_path):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    home_b = tmp_path / "home_b"
    (home_b / ".claude").mkdir(parents=True)
    link_home(home_b, spec, "machine-b", master_from=home)
    assert sync.pull(ns(apply=True), home_b) == 0
    assert sync.pull(ns(apply=True, category="config"), home_b) == 0
    assert mark(home_b, spec) is None


def test_a_mark_that_cannot_be_written_is_a_warning_not_a_raise(
        home_a, capsys):
    home, spec = home_a
    assert sync.push(ns(apply=True), home) == 0
    state_path = home / ".carryon" / "state.json"
    state_path.chmod(0o400)
    (home / ".carryon").chmod(0o500)
    try:
        (home / ".claude" / "CLAUDE.md").write_text("Changed.\n")
        assert sync.push(ns(apply=True), home) == 0
    finally:
        (home / ".carryon").chmod(0o700)
        state_path.chmod(0o600)
    assert "could not record the Setup mark" in capsys.readouterr().out
