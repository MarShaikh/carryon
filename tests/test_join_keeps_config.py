"""Joining keeps the config (ADR-0005's 2026-10-18 amendment).

`init --join` used to write a fresh config over whatever this machine had.
The usual joining machine is one whose keychain entry is gone and whose
config.json is not, so that undid its handpicks and, under a hostname that
differs from its chosen name, made it a new machine in the Archive. It now
follows `--recover`'s rule. A valid config is kept. A `--dest` or `--machine`
that disagrees with it is refused. A config with no Destination is built on.
A config that will not load is refused.

The code is one-time, so the other half of every refusal here is that it
leaves the code unspent. "Code intact" is asserted the way a user would find
it: the same code then joins. "Nothing stored" is no master key, and
config.json and state.json exactly as they were before the run.

Every home is a temp dir, and the keychain is forced to the fallback file.
"""

import argparse
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import cli, config, destinations, keyring, prompting  # noqa: E402
from carryon import sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402

PAIR_CODE = re.compile(r"--join ([A-Z0-9]{4}(?:-[A-Z0-9]{4}){3})")


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


@pytest.fixture(autouse=True)
def no_terminal(monkeypatch):
    """No terminal unless a test says otherwise: a prompt is a failure."""
    monkeypatch.setattr(prompting, "available", lambda: False)


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, recover=False, machine=None,
                apply=False, agent=None, category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def paired_archive(tmp_path, capsys):
    """An Archive founded by machine A, with a fresh pairing code minted.
    Returns machine A's home, the spec and the code."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=spec, machine="machine-a"), home_a) == 0
    capsys.readouterr()
    sync.pair(ns(), home_a)
    code = PAIR_CODE.search(capsys.readouterr().out).group(1)
    return home_a, spec, code


def bare_home(tmp_path, name="home_b") -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    return home


def kept_config(home, spec, machine="laptop-name"):
    """The config a machine keeps after its keychain entry is gone, with a
    handpick in it that a fresh config would not have."""
    cfg = config.default_config()
    cfg["destination"] = spec
    cfg["machine"] = machine
    cfg["excludes"] = ["skills/private-*"]
    config.save(cfg, home)
    return config.config_path(home).read_bytes()


def snapshot(home):
    def bytes_of(path):
        return path.read_bytes() if path.exists() else None
    return (bytes_of(config.config_path(home)),
            bytes_of(sync._state_path(home)),
            bytes_of(keyring._fallback_path(home)))


def assert_nothing_stored(home, before):
    assert snapshot(home) == before, "a refused join stored something"


def assert_code_intact(tmp_path, spec, code, home_a):
    """The code still joins, on a machine with nothing in the way."""
    home = bare_home(tmp_path, "home_check")
    assert sync.init(ns(join=code, dest=spec, machine="checker"), home) == 0
    assert keyring.fetch_master(home=home) == \
        keyring.fetch_master(home=home_a)


def destination_reads(monkeypatch):
    reads = []
    real = DirectoryDestination.read

    def recording(self, key):
        reads.append(key)
        return real(self, key)
    monkeypatch.setattr(DirectoryDestination, "read", recording)
    return reads


def a_terminal(monkeypatch):
    prompts = []

    def no_answer(prompt):
        prompts.append(prompt)
        raise EOFError
    monkeypatch.setattr(prompting, "available", lambda: True)
    monkeypatch.setattr(prompting, "_read_line", no_answer)
    monkeypatch.setattr(prompting, "_read_secret", no_answer)
    return prompts


# --- J1-J5: a kept config ----------------------------------------------------


def test_a_kept_config_is_used_and_left_byte_for_byte(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    original = kept_config(home, spec)

    assert sync.init(ns(join=code), home) == 0
    out = capsys.readouterr().out

    assert config.config_path(home).read_bytes() == original
    assert keyring.fetch_master(home=home) == keyring.fetch_master(home=home_a)
    assert "paired as 'laptop-name'" in out
    assert f"kept the existing config at {config.config_path(home)}" in out


def test_the_kept_name_wins_over_a_hostname_no_machine_may_be(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    original = kept_config(home, spec)
    monkeypatch.setattr(config, "default_config",
                        lambda _real=config.default_config:
                            dict(_real(), machine="bad/name"))

    assert sync.init(ns(join=code), home) == 0
    assert config.config_path(home).read_bytes() == original


def test_the_high_water_mark_is_recorded_under_the_configs_spelling(
        tmp_path, monkeypatch, capsys):
    """Marks are keyed by spec string, and every later push and pull looks
    one up by the config's spelling, not the one pasted after --dest."""
    _, spec, code = paired_archive(tmp_path, capsys)
    home = tmp_path  # so that '~/archive' is the founded Archive
    kept_config(home, "~/archive")

    assert sync.init(ns(join=code, dest=spec), home) == 0
    assert sync._seen_revision(home, "~/archive") >= 1
    assert sync._seen_revision(home, spec) == 0


def test_without_a_terminal_or_dest_a_kept_config_is_enough(
        tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)

    assert sync.init(ns(join=code), home) == 0
    assert "needs --dest" not in capsys.readouterr().out


def test_a_kept_config_asks_nothing_even_at_a_terminal(
        tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    prompts = a_terminal(monkeypatch)

    assert sync.init(ns(join=code), home) == 0
    assert not prompts, "the config already answers the Destination question"


# --- J6-J8: flags against a kept config --------------------------------------


def test_a_dest_that_disagrees_is_refused_and_the_code_survives(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    before = snapshot(home)
    elsewhere = str(tmp_path / "elsewhere")
    reads = destination_reads(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code, dest=elsewhere), home)

    message = str(exc.value)
    assert "--dest" in message and elsewhere in message and spec in message
    assert str(config.config_path(home)) in message
    assert "drop --dest" in message
    assert "Nothing was stored" in message and "code" in message
    assert not reads, "a refusal read the Destination"
    assert_nothing_stored(home, before)
    assert_code_intact(tmp_path, spec, code, home_a)


def test_a_machine_that_disagrees_is_refused_and_the_code_survives(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    before = snapshot(home)
    reads = destination_reads(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code, machine="other-name"), home)

    message = str(exc.value)
    assert "--machine" in message and "other-name" in message
    assert "laptop-name" in message and "drop --machine" in message
    assert not reads, "a refusal read the Destination"
    assert_nothing_stored(home, before)
    assert_code_intact(tmp_path, spec, code, home_a)


def test_agreeing_flags_are_fine(tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    original = kept_config(home, spec)

    assert sync.init(ns(join=code, dest=spec, machine="laptop-name"),
                     home) == 0
    assert config.config_path(home).read_bytes() == original
    assert keyring.fetch_master(home=home) == keyring.fetch_master(home=home_a)


def test_a_dest_spelt_differently_but_naming_the_same_place_agrees(
        tmp_path, monkeypatch, capsys):
    """`carryon pair` prints the paired machine's spelling, and a shell
    expands '~' before carryon sees it, so the pasted command routinely
    spells the kept Destination another way."""
    _, spec, code = paired_archive(tmp_path, capsys)
    home = tmp_path  # so that '~/archive' is the Archive
    original = kept_config(home, "~/archive")

    assert sync.init(ns(join=code, dest=spec), home) == 0
    assert config.config_path(home).read_bytes() == original


# --- J9-J10: a config with no Destination ------------------------------------


def test_a_config_with_no_destination_is_built_on(
        tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    cfg = config.default_config()
    cfg["machine"] = "chosen-name"
    cfg["excludes"] = [".cursor/*"]
    config.save(cfg, home)

    assert sync.init(ns(join=code, dest=spec), home) == 0
    out = capsys.readouterr().out

    after = config.load(home)
    assert after["destination"] == spec
    assert after["excludes"] == [".cursor/*"]
    assert after["machine"] == "chosen-name"
    assert "paired as 'chosen-name'" in out
    assert sync._seen_revision(home, spec) >= 1


def test_a_config_with_no_destination_takes_a_given_machine(
        tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    cfg = config.default_config()
    cfg["machine"] = "chosen-name"
    cfg["excludes"] = [".cursor/*"]
    config.save(cfg, home)

    assert sync.init(ns(join=code, dest=spec, machine="new-name"), home) == 0
    after = config.load(home)
    assert after["machine"] == "new-name"
    assert after["excludes"] == [".cursor/*"]


def test_a_bad_hostname_is_still_refused_before_the_code_is_spent(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    real = config.default_config
    monkeypatch.setattr(config, "default_config",
                        lambda: dict(real(), machine="bad/name"))

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code, dest=spec), home)

    assert "machine name" in str(exc.value)
    assert_nothing_stored(home, before)
    monkeypatch.setattr(config, "default_config", real)
    assert_code_intact(tmp_path, spec, code, home_a)


# --- J11: a config that will not load ----------------------------------------


def test_a_config_that_will_not_load_says_to_fix_or_remove_it(
        tmp_path, monkeypatch, capsys):
    home_a, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    path = config.config_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"version": 1, "destination": "%s", "machine": "a/b", '
                    '"excludes": [], "carry": []}\n' % spec)
    before = snapshot(home)
    reads = destination_reads(monkeypatch)
    prompts = a_terminal(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code, machine="good"), home)

    message = str(exc.value)
    assert str(path) in message
    assert "init --join" in message and "remove" in message.lower()
    assert "Nothing was stored" in message
    assert not prompts and not reads
    assert_nothing_stored(home, before)
    monkeypatch.setattr(prompting, "available", lambda: False)
    assert_code_intact(tmp_path, spec, code, home_a)


# --- J12-J13: order -----------------------------------------------------------


def test_a_malformed_code_still_fails_first(tmp_path, monkeypatch):
    """The code parse is a pure string check; it goes ahead of the config,
    so a broken config does not hide a typo in the code."""
    home = bare_home(tmp_path)
    path = config.config_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json")

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join="ABCD-EFGH"), home)
    assert "pairing code" in str(exc.value)


def test_a_config_that_cannot_be_written_leaves_no_key(
        tmp_path, monkeypatch, capsys):
    """A key with no config is a machine every later `init` refuses as
    already holding one. A config with no key is one a fresh code joins on
    the kept-config path. So the config goes first, as for --recover."""
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)

    def full_disk(cfg, home):
        raise SystemExit("could not write config.json: disk full")
    monkeypatch.setattr(config, "save", full_disk)

    with pytest.raises(SystemExit):
        sync.init(ns(join=code, dest=spec, machine="machine-b"), home)

    assert keyring.fetch_master(home=home) is None


# --- J14-J15: unchanged ------------------------------------------------------


def test_with_no_config_join_writes_a_fresh_one(tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)

    assert sync.init(ns(join=code, dest=spec, machine="machine-b"), home) == 0
    out = capsys.readouterr().out

    after = config.load(home)
    assert after["destination"] == spec and after["machine"] == "machine-b"
    assert f"config written to {config.config_path(home)}" in out


def test_plain_init_still_writes_a_fresh_config(tmp_path, monkeypatch, capsys):
    """Out of scope on purpose (the amendment's last paragraph)."""
    home = bare_home(tmp_path)
    cfg = config.default_config()
    cfg["destination"] = str(tmp_path / "old")
    cfg["excludes"] = [".cursor/*"]
    config.save(cfg, home)

    assert sync.init(ns(dest=str(tmp_path / "new"), machine="m"), home) == 0
    after = config.load(home)
    assert after["destination"] == str(tmp_path / "new")
    assert after["excludes"] == []


# --- J16: the help -----------------------------------------------------------


def test_init_help_says_a_kept_config_names_the_destination(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["init", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "An existing config's Destination and name are used" in text
    assert "a config that names no Destination" in text, \
        "a config with no Destination does not answer the question (finding 10)"


# --- review round ------------------------------------------------------------


def test_a_mark_ahead_of_the_pairing_revision_is_warned_about(
        tmp_path, monkeypatch, capsys):
    """Finding 1. The pairing machine read the Index when it minted the code,
    so a mark this machine kept that is ahead of it is a rollback - an
    Archive lost and begun again at the same place. --recover warns there,
    and the next push refuses; the join should not be the silent step."""
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    sync._record_revision(home, spec, 50)

    assert sync.init(ns(join=code), home) == 0
    out = capsys.readouterr().out
    assert "warning:" in out and "revision 50" in out


def test_no_blob_at_a_kept_destination_names_the_config(
        tmp_path, monkeypatch, capsys):
    """Finding 2. The user typed no spec, so a refusal that says the code
    was mistyped, or to check the spec, points away from the cause: the
    config names another Archive."""
    _, _, code = paired_archive(tmp_path, capsys)
    other_home = bare_home(tmp_path, "home_other")
    other = str(tmp_path / "other-archive")
    assert sync.init(ns(dest=other, machine="other"), other_home) == 0
    sync.pair(ns(), other_home)  # so that Archive holds objects of its own
    home = bare_home(tmp_path)
    kept_config(home, other)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code), home)

    message = str(exc.value)
    assert "no pairing blob" in message
    assert str(config.config_path(home)) in message and other in message


def test_no_archive_at_a_kept_destination_names_the_config(
        tmp_path, monkeypatch, capsys):
    _, _, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    kept_config(home, str(empty))

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code), home)

    message = str(exc.value)
    assert "no Archive at" in message
    assert str(config.config_path(home)) in message


def test_needs_dest_says_the_code_is_still_good(tmp_path, monkeypatch,
                                                 capsys):
    """Finding 4. Every other refusal ahead of the spend says so."""
    _, _, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code), home)

    message = str(exc.value)
    assert "needs --dest" in message
    assert "the code is still good" in message


# --- the verdict (ADR-0011's 2026-10-19 amendment) ---------------------------


def test_a_good_code_says_so_before_anything_else(tmp_path, monkeypatch,
                                                  capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)

    assert sync.init(ns(join=code, dest=spec, machine="machine-b"), home) == 0
    out = capsys.readouterr().out

    where = destinations.from_spec(spec, home).describe()
    accepted = ("pairing code accepted: it unwrapped the key the paired "
                f"machine left at {where}.")
    assert accepted in out
    assert out.index(accepted) < out.index("Destination checked")
    assert out.index("Destination checked") < out.index("paired as")
    assert "paired as 'machine-b': this machine now opens the Archive\n" in out
    assert "storage is private" not in out


def test_an_expired_code_never_says_accepted(tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    # A lifetime below zero rather than a clock moved for the whole process.
    monkeypatch.setattr(sync, "PAIRING_TTL_SECONDS", -1)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=code, dest=spec, machine="machine-b"), home)
    assert "expired" in str(exc.value)
    assert "accepted" not in capsys.readouterr().out


def test_a_code_that_will_not_unwrap_never_says_accepted(
        tmp_path, monkeypatch, capsys):
    _, spec, code = paired_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    wrong = code[:-1] + ("A" if code[-1] != "A" else "B")

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join=wrong, dest=spec, machine="machine-b"), home)
    assert "wrong or expired code" in str(exc.value)
    assert "accepted" not in capsys.readouterr().out
