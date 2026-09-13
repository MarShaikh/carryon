"""A Setup carries a capability, not what built it (ADR-0013).

A tree an Adapter declares is VOUCHED: the Adapter named a directory the user
never named, on their behalf, and stands behind its contents - so carryon may
leave Development artifacts out of it. A handpicked path is the opposite and
deliberately so. ADR-0008 says a user-added path always joins the Setup, and a
`carry` entry pointing at a directory called `tests` is carried as a directory
called `tests`.

The distinction is the whole of this file. Every test below is either "the
vouched side drops it" or "the handpicked side keeps it", and the two must
never be answered by the same code path.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, config, development, layout, sync  # noqa: E402
from carryon.adapters import ADAPTERS  # noqa: E402

# The jwt.io example token: {"alg":"HS256"} over {"sub":"1234567890"}, the most
# published dummy credential there is, and the one that refused the first push
# carryon ever aimed at a real cloud Destination. It lives in a test suite
# because a credential detector's tests must contain credential shapes to do
# their job at all.
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def build_home(tmp_path) -> pathlib.Path:
    """A ~ with Claude Code set up and one authored skill that has tests."""
    home = tmp_path / "home"
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')

    skills = claude / "skills"
    (skills / "mine").mkdir(parents=True)
    (skills / "mine" / "SKILL.md").write_text("this is the capability")
    (skills / "mine" / "tests").mkdir()
    (skills / "mine" / "tests" / "test_it.py").write_text("assert True\n")
    (skills / "mine" / "tests" / "fixtures").mkdir()
    (skills / "mine" / "tests" / "fixtures" / "case.json").write_text("{}")
    return home


def run(home, out, **kw):
    return capture.run(out=out, dry=False, home=home, **kw)


def with_config(home, **cfg_kw):
    """Capture through the EFFECTIVE registry - excludes applied, handpicked
    paths added - which is the registry push and capture both read."""
    cfg = config.default_config()
    cfg.update(cfg_kw)
    return sync._swapped_registry(sync._effective_adapters(cfg, home))


# --- the rule itself --------------------------------------------------------

def test_the_top_most_development_directory_is_the_one_named():
    """A tests tree with its own fixtures under it is ONE decline, named at
    the top. Reporting every file under it turns a single sentence the user
    can act on into a wall they scroll past."""
    rel = pathlib.PurePosixPath("mine/tests/fixtures/case.json")

    assert development.workshop_prefix(rel) == \
        pathlib.PurePosixPath("mine/tests")


def test_a_nested_second_hit_does_not_move_the_name():
    rel = pathlib.PurePosixPath("mine/tests/data/__pycache__/x.pyc")

    assert development.workshop_prefix(rel) == \
        pathlib.PurePosixPath("mine/tests")


def test_a_file_that_happens_to_be_called_tests_is_a_file():
    """The rule is about directories on the way to a file. A skill whose whole
    content is a file named `tests` still has that file carried."""
    assert development.workshop_prefix(pathlib.PurePosixPath("mine/tests")) \
        is None


def test_the_name_is_matched_whatever_its_case():
    """macOS folds case, so `Tests` and `tests` are one directory there and
    two on Linux. They are the same thing either way."""
    assert development.workshop_prefix(
        pathlib.PurePosixPath("mine/Tests/test_it.py")) == \
        pathlib.PurePosixPath("mine/Tests")


def test_an_unrecognised_directory_is_carried():
    """The list fails in the safe direction: what it does not recognise is
    carried, which is the status quo, rather than dropped."""
    assert development.workshop_prefix(
        pathlib.PurePosixPath("mine/references/style.md")) is None


# --- the vouched side: a declared tree drops them ---------------------------

def test_a_vouched_skill_leaves_its_test_tree_behind(tmp_path):
    home = build_home(tmp_path)
    out = tmp_path / "setup"

    code, manifest = run(home, out)

    assert code == 0
    assert (out / "claude/skills/mine/SKILL.md").exists(), \
        "the capability itself must still be carried"
    assert not (out / "claude/skills/mine/tests").exists(), \
        "a Setup carries a capability, not the workshop that built it"


def test_a_vouched_tree_leaves_them_behind_too(tmp_path):
    """`skills` is one kind and `tree` is another, and both are vouched. The
    rule belongs to the declaration, not to the handler that happens to walk
    it."""
    home = build_home(tmp_path)
    agents = home / ".claude" / "agents"
    (agents / "reviewer").mkdir(parents=True)
    (agents / "reviewer" / "AGENT.md").write_text("the subagent")
    (agents / "reviewer" / "__pycache__").mkdir()
    (agents / "reviewer" / "__pycache__" / "x.cpython-313.pyc").write_bytes(b"\x00")
    out = tmp_path / "setup"

    code, _ = run(home, out)

    assert code == 0
    assert (out / "claude/agents/reviewer/AGENT.md").exists()
    assert not (out / "claude/agents/reviewer/__pycache__").exists()


# --- the handpicked side: the user named it, so it is carried --------------

def test_a_handpicked_tree_keeps_the_tests_inside_it(tmp_path):
    """ADR-0008: a user-added path always joins the Setup. Nothing here
    narrows what the user named."""
    home = build_home(tmp_path)
    tool = home / ".mytool"
    (tool / "tests").mkdir(parents=True)
    (tool / "tests" / "test_it.py").write_text("assert True\n")
    (tool / "conf.json").write_text("{}")
    out = tmp_path / "setup"

    with with_config(home, carry=["~/.mytool"]):
        code, _ = run(home, out)

    assert code == 0
    assert (out / "handpicked/.mytool/tests/test_it.py").exists(), \
        "carryon narrowed a path the user named"


def test_a_handpicked_path_that_is_itself_a_test_tree_is_carried_as_named(
        tmp_path):
    """The sharpest case: the `carry` entry IS the directory called tests."""
    home = build_home(tmp_path)
    tool = home / ".mytool" / "tests"
    tool.mkdir(parents=True)
    (tool / "test_it.py").write_text("assert True\n")
    out = tmp_path / "setup"

    with with_config(home, carry=["~/.mytool/tests"]):
        code, _ = run(home, out)

    assert code == 0
    assert (out / "handpicked/.mytool/tests/test_it.py").exists()


# --- what the user is told --------------------------------------------------

def test_the_manifest_names_what_was_declined(tmp_path):
    """A decline that is not written down reads as an oversight later, and
    gets 'fixed' by someone copying the workshop onto a new machine."""
    home = build_home(tmp_path)
    out = tmp_path / "setup"

    _, manifest = run(home, out)

    excluded = manifest["agents"]["claude-code"]["excluded"]
    declined = [e for e in excluded if ".claude/skills/mine/tests" == e["path"]]
    assert len(declined) == 1, \
        f"the declined tree is named nowhere in {excluded}"
    assert all(isinstance(declined[0][field], str)
               for field in ("path", "what", "why")), \
        "it has to survive setup_out._carryable_agent to reach a MANIFEST"


def test_a_decline_is_not_a_skip(tmp_path, capsys):
    """A skip is 'this machine would not hand it over' - a shortfall the user
    may want to fix. A decline is carryon choosing, and the two must not read
    as one thing."""
    home = build_home(tmp_path)
    out = tmp_path / "setup"

    run(home, out)

    printed = capsys.readouterr().out
    for line in printed.splitlines():
        if "tests" in line:
            assert "skipped" not in line, \
                f"a declined tree was reported as a shortfall: {line!r}"


def test_a_decline_is_not_layout_drift(tmp_path):
    """doctor's unrecognised list is the early warning that a vendor has
    reorganised. A Development artifact is not that, and must never be counted
    as it."""
    home = build_home(tmp_path)

    report = layout.inspect(home, platform="darwin")

    assert "tests" not in report["claude-code"]["unknown"]
    assert any("tests" in str(entry)
               for entry in report["claude-code"]["declined"]), \
        "doctor has nothing to say about what a capture would leave out"


def test_doctor_says_what_it_would_decline(tmp_path):
    home = build_home(tmp_path)

    text = layout.format_report(layout.inspect(home, platform="darwin"),
                                platform="darwin")

    assert "skills/mine/tests" in text


# --- the gate this must never become ---------------------------------------

def test_the_scanner_still_reads_everything_that_survives(tmp_path):
    """Positive control. Nothing about credentials may depend on the prune
    list: the scan runs over everything left, and a hit in a carried file is
    still a hit."""
    home = build_home(tmp_path)
    (home / ".claude" / "skills" / "mine" / "SKILL.md").write_text(
        f"token: {JWT}\n")
    out = tmp_path / "setup"

    code, _ = run(home, out)

    assert code == 2, "a credential in a carried file still fails the scan"


def test_the_state_gate_does_not_consult_the_prune_list(tmp_path):
    """The same rule from the other side. `state_reads` runs over everything
    DECLARED, this list included, so a second name for the master key parked
    in a test tree refuses the whole capture even though the tree would not
    have been carried.

    Wider than it needs to be, and deliberately so: a gate that asked the
    prune list first would be a gate whose coverage depended on a directory
    name being on that list, which is exactly the list ADR-0010 says nobody
    can keep complete."""
    home = build_home(tmp_path)
    (home / ".carryon").mkdir()
    (home / ".carryon" / "master.key").write_text("0123456789abcdef")
    (home / ".claude" / "skills" / "mine" / "tests" / "notes.md").symlink_to(
        home / ".carryon" / "master.key")
    out = tmp_path / "setup"

    code, _ = run(home, out)

    assert code == 2, "a path into carryon's own state must refuse the capture"
    assert not out.exists(), "a refused capture leaves nothing behind at all"


def test_the_declined_tree_stops_being_captured_rather_than_excused(tmp_path):
    """The whole of ADR-0013's answer to the refusal that produced it. The
    file is not acknowledged and not allowlisted - it is no longer something
    a Setup was ever for, so there is nothing for the scanner to meet."""
    home = build_home(tmp_path)
    (home / ".claude" / "skills" / "mine" / "tests" / "test_it.py").write_text(
        f"token = {JWT!r}\n")
    out = tmp_path / "setup"

    code, manifest = run(home, out)

    assert code == 0, "the push that ADR-0013 exists to unblock"
    assert not (out / "claude/skills/mine/tests").exists()
