"""Config behaviour, exercised against a fake $HOME.

The two properties worth pinning are ADR-0008's: an exclude pattern that
matches nothing must be reported rather than silently ignored, and a
handpicked path must land in the Setup where the fail-closed credential
scanner guards it for free.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import capture, config  # noqa: E402
from carryon.adapters import CAPABILITY, CONFIG, Adapter, Item  # noqa: E402


def build_home(tmp_path) -> pathlib.Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def write_config(home, cfg) -> pathlib.Path:
    path = home / ".carryon" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg))
    return path


# --- load / save / validate ------------------------------------------------

def test_missing_file_yields_defaults(tmp_path):
    home = build_home(tmp_path)
    cfg = config.load(home=home)

    assert cfg["version"] == 1
    assert cfg["destination"] == ""
    assert cfg["machine"], "machine must default to a hostname, not empty"
    assert cfg["excludes"] == []
    assert cfg["carry"] == []
    assert cfg["encrypt_all"] is False


def test_save_then_load_round_trips(tmp_path):
    home = build_home(tmp_path)
    cfg = config.load(home=home)
    cfg["destination"] = "rclone:remote:carryon"
    cfg["excludes"] = [".claude/keybindings.json"]
    cfg["carry"] = ["~/.mytool"]

    config.save(cfg, home=home)

    assert (home / ".carryon" / "config.json").is_file()
    assert config.load(home=home) == cfg


def test_partial_file_gains_defaults(tmp_path):
    """An older or hand-written config with keys missing still loads."""
    home = build_home(tmp_path)
    write_config(home, {"version": 1, "destination": "~/archive"})

    cfg = config.load(home=home)
    assert cfg["destination"] == "~/archive"
    assert cfg["carry"] == []
    assert cfg["machine"]


def test_invalid_json_names_the_file(tmp_path):
    home = build_home(tmp_path)
    path = home / ".carryon" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")

    with pytest.raises(SystemExit) as exc:
        config.load(home=home)
    assert "config.json" in str(exc.value)


def test_unknown_key_is_refused_and_named(tmp_path):
    """A typoed key that validation ignores is a setting silently not applied."""
    home = build_home(tmp_path)
    write_config(home, {"version": 1, "excldues": []})

    with pytest.raises(SystemExit) as exc:
        config.load(home=home)
    assert "excldues" in str(exc.value)


@pytest.mark.parametrize("bad, key", [
    ({"version": 2}, "version"),
    ({"destination": 7}, "destination"),
    ({"machine": ""}, "machine"),
    ({"excludes": ".claude/*"}, "excludes"),
    ({"carry": [1]}, "carry"),
    ({"encrypt_all": "yes"}, "encrypt_all"),
])
def test_wrong_value_names_the_offending_key(bad, key):
    cfg = config.default_config()
    cfg.update(bad)
    with pytest.raises(SystemExit) as exc:
        config.validate(cfg)
    assert key in str(exc.value)


def test_save_refuses_an_invalid_config(tmp_path):
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["encrypt_all"] = "yes"

    with pytest.raises(SystemExit):
        config.save(cfg, home=home)
    assert not (home / ".carryon" / "config.json").exists()


# --- apply_excludes (ADR-0008) ---------------------------------------------

def fake_adapters() -> dict:
    return {"fake": Adapter(
        key="fake", name="Fake", detect=".fake",
        verified_against="test fixture",
        items=(
            Item(".fake/settings.json", "fake/settings.json",
                 "file", CONFIG, "settings"),
            Item(".fake/skills", "fake/skills", "tree", CAPABILITY, "skills"),
        ),
    )}


def test_apply_excludes_removes_matching_items():
    adapters = fake_adapters()
    filtered, unmatched = config.apply_excludes(adapters, [".fake/skills"])

    assert [i.src for i in filtered["fake"].items] == [".fake/settings.json"]
    assert unmatched == []
    # a filtered *copy*: the registry the caller handed in is untouched
    assert len(adapters["fake"].items) == 2


def test_apply_excludes_takes_glob_patterns():
    filtered, unmatched = config.apply_excludes(fake_adapters(), [".fake/*"])
    assert filtered["fake"].items == ()
    assert unmatched == []


def test_a_typoed_pattern_is_reported_not_silent():
    filtered, unmatched = config.apply_excludes(fake_adapters(), [".fake/skils"])
    assert unmatched == [".fake/skils"]
    assert len(filtered["fake"].items) == 2


def test_exclude_matching_is_case_sensitive():
    """fnmatch.fnmatch case-folds on darwin, so the same config would exclude
    different things on different machines. The exact variant does not."""
    _, unmatched = config.apply_excludes(fake_adapters(), [".Fake/*"])
    assert unmatched == [".Fake/*"]


# --- user_adapter (ADR-0008) -----------------------------------------------

def test_user_adapter_describes_handpicked_paths(tmp_path):
    home = build_home(tmp_path)
    (home / ".mytool").mkdir()
    (home / ".mytool" / "conf.json").write_text("{}")
    (home / ".mytoolrc").write_text("colour=on")
    cfg = config.default_config()
    cfg["carry"] = ["~/.mytool", ".mytoolrc"]

    adapter = config.user_adapter(cfg, home=home)

    assert adapter.key == "handpicked"
    assert adapter.name == "Handpicked paths"
    assert adapter.detect == ""
    assert adapter.verified_against == "user-supplied - unvouched"

    by_src = {i.src: i for i in adapter.items}
    assert by_src[".mytool"].kind == "tree"
    assert by_src[".mytoolrc"].kind == "file"
    for item in adapter.items:
        assert item.category == CONFIG, \
            "a handpicked path joins the Setup, never the History"
        assert item.note == "handpicked - no adapter vouches for this"


def test_user_adapter_relativises_an_absolute_path_under_home(tmp_path):
    home = build_home(tmp_path)
    (home / ".mytoolrc").write_text("x")
    cfg = config.default_config()
    cfg["carry"] = [str(home / ".mytoolrc")]

    adapter = config.user_adapter(cfg, home=home)
    assert [i.src for i in adapter.items] == [".mytoolrc"]


@pytest.mark.parametrize("raw", ["~", "~/", "/", "//", "~/.", "."])
def test_user_adapter_refuses_the_entire_home(tmp_path, raw):
    """'/' and '.' reduce to an empty relpath after normalising, and
    home/'' *is* $HOME - which would capture the whole home directory as a
    plaintext Setup tree."""
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = [raw]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "home" in str(exc.value)


def test_user_adapter_refuses_home_spelled_absolutely(tmp_path):
    home = build_home(tmp_path)
    for raw in (str(home), str(home) + "/", str(home) + "/."):
        cfg = config.default_config()
        cfg["carry"] = [raw]
        with pytest.raises(SystemExit) as exc:
            config.user_adapter(cfg, home=home)
        assert "home" in str(exc.value), raw


@pytest.mark.parametrize("raw", [
    "~/.carryon", ".carryon", "~/.carryon/master.key",
])
def test_user_adapter_refuses_carryons_own_state(tmp_path, raw):
    """The fallback master.key is bare hex, which no scanner pattern matches,
    so a Setup holding ~/.carryon would carry the key that decrypts the same
    Archive's History. A Setup contains no credentials (ADR-0004)."""
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = [raw]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    msg = str(exc.value)
    assert ".carryon" in msg
    assert "master key" in msg


def test_user_adapter_refuses_a_path_outside_home(tmp_path):
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = ["/etc/hosts"]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "carry" in str(exc.value)


def test_user_adapter_refuses_a_path_that_escapes_home_via_dotdot(tmp_path):
    """`home / src` with a `..` inside would read outside $HOME."""
    home = build_home(tmp_path)
    cfg = config.default_config()
    cfg["carry"] = ["../otherhome/.ssh"]

    with pytest.raises(SystemExit) as exc:
        config.user_adapter(cfg, home=home)
    assert "carry" in str(exc.value)


def test_handpicked_paths_feed_the_fail_closed_scanner(tmp_path):
    """The point of ADR-0008: a handpicked ~/.aws-alike goes through the
    existing Setup engine, so a credential in it makes capture refuse."""
    home = build_home(tmp_path)
    (home / ".mytool").mkdir()
    (home / ".mytool" / "creds").write_text(
        "sk-ant-api03-PLANTEDPLANTEDPLANTEDPLANTED")
    cfg = config.default_config()
    cfg["carry"] = ["~/.mytool"]

    adapter = config.user_adapter(cfg, home=home)
    cap = capture.Capture(tmp_path / "out", dry=False, home=home)
    entry = capture._capture_agent(cap, adapter, {CONFIG})

    assert cap.findings, "a credential in a handpicked path must be caught"
    assert entry["items"], "the engine must have actually visited the path"
