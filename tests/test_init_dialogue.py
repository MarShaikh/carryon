"""`init` asks, with a terminal on both ends - and only then (ADR-0011).

Nothing is decided for the user, including the case where there is one
obvious answer: the silent single-candidate pick is gone, and a machine with
~/Dropbox gets a prompt with that candidate offered, which costs one
keypress and puts a person behind the decision.

Without a terminal, `init` prints the candidates and exits exactly as it
always did - the non-tty tests here are the regression tests for the
deleted silent pick, because "behaves as today" now excludes it.

The provider flow is driven through the same public seam every dialogue
test uses (`prompting._read_line` / `_read_secret`), with the two rclone
verbs recorded rather than run - their own behaviour has its own file
(test_provider_setup.py).
"""

import argparse
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import choosing, config, keyring, prompting, sync  # noqa: E402
from carryon.destinations import rclone_setup  # noqa: E402

RECOVERY_KEY = r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}"
PAIR_CODE = r"--join (\S+)"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def a_terminal(monkeypatch, *answers):
    """A terminal on both ends, holding these answers in order."""
    queue = list(answers)
    prompts = []

    def next_answer(prompt):
        prompts.append(prompt)
        if not queue:
            raise EOFError
        return queue.pop(0)

    monkeypatch.setattr(prompting, "available", lambda: True)
    monkeypatch.setattr(prompting, "_read_line", next_answer)
    monkeypatch.setattr(prompting, "_read_secret", next_answer)
    return prompts


class RcloneCalls:
    """What the dialogue asked rclone to do, without an rclone."""

    def __init__(self, monkeypatch, make_place_why=None):
        self.created = []
        self.made = []
        monkeypatch.setattr(
            rclone_setup, "create_remote",
            lambda name, rclone_type, pairs:
                self.created.append((name, rclone_type, list(pairs))))
        monkeypatch.setattr(
            rclone_setup, "make_place",
            lambda target, flags=():
                self.made.append((target, tuple(flags))) or make_place_why)


# --- one candidate is a question now, not an answer ---------------------------


def test_one_candidate_is_offered_not_taken(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    (home / "Dropbox").mkdir(parents=True)
    prompts = a_terminal(monkeypatch, "1")

    assert sync.init(ns(machine="laptop"), home) == 0
    out = capsys.readouterr().out

    assert prompts, "the lone candidate was taken without a question"
    assert "Dropbox" in out
    assert config.load(home)["destination"] == "~/Dropbox"
    assert keyring.fetch_master(home=home) is not None
    assert re.search(RECOVERY_KEY, out)


def test_without_a_terminal_one_candidate_is_a_listing_and_an_exit(
        tmp_path, monkeypatch):
    """The deleted silent pick, pinned. Non-tty `init` with no --dest lists
    what it found and exits - it no longer chooses for the machine."""
    home = tmp_path / "home"
    (home / "Dropbox").mkdir(parents=True)
    monkeypatch.setattr(prompting, "available", lambda: False)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(machine="laptop"), home)

    message = str(exc.value)
    assert "--dest" in message and "Dropbox" in message
    assert keyring.fetch_master(home=home) is None, \
        "a listing that also minted a key decided after all"
    assert config.load(home)["destination"] == ""


def test_a_typed_spec_reaches_init_like_a_dest_argument(tmp_path, monkeypatch,
                                                        capsys):
    """The 'somewhere else' door: what is typed is a spec, and lands in the
    config verbatim the way --dest does."""
    home = tmp_path / "home"
    home.mkdir()
    dest = tmp_path / "archive"
    # no candidates at all -> the menu is providers-or-spec
    a_terminal(monkeypatch, "2", str(dest))

    assert sync.init(ns(machine="laptop"), home) == 0

    assert config.load(home)["destination"] == str(dest)
    assert "write, read and delete" in capsys.readouterr().out


def test_a_typed_spec_with_a_nul_is_refused_at_the_question(tmp_path,
                                                            monkeypatch):
    """The same rule cli._spelling applies to --dest, asked at this door:
    a NUL stored now is a ValueError out of a push two commands later."""
    home = tmp_path / "home"
    home.mkdir()
    a_terminal(monkeypatch, "2", "/tmp/a\x00b", str(tmp_path / "archive"))

    assert sync.init(ns(machine="laptop"), home) == 0, \
        "the re-ask after the refusal did not continue the dialogue"
    assert config.load(home)["destination"] == str(tmp_path / "archive")


def test_cancelling_the_dialogue_costs_nothing(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Dropbox").mkdir(parents=True)
    a_terminal(monkeypatch)  # ^D at the first question

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(machine="laptop"), home)

    assert "cancelled" in str(exc.value)
    assert keyring.fetch_master(home=home) is None
    assert config.load(home)["destination"] == ""


# --- the provider flow ---------------------------------------------------------


def provider_menu_position(key) -> str:
    from carryon.destinations.providers import PROVIDERS
    return str([p.key for p in PROVIDERS].index(key) + 1)


def test_the_provider_flow_creates_a_remote_and_offers_the_bucket(
        tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    calls = RcloneCalls(monkeypatch)
    a_terminal(monkeypatch,
               "1",                          # a cloud service
               provider_menu_position("r2"),  # Cloudflare R2
               "",                           # remote name -> default carryon
               "acct42",                     # account ID
               "AKID",                       # access key id
               "SEKRIT",                     # secret access key (unechoed)
               "my-bucket",                  # bucket
               "y")                          # create it

    spec = choosing.choose_destination(home, [])
    out = capsys.readouterr().out

    assert spec == "rclone:carryon:my-bucket"
    assert calls.created == [("carryon", "s3", [
        ("provider", "Cloudflare"), ("region", "auto"), ("acl", "private"),
        ("no_check_bucket", "true"),
        ("access_key_id", "AKID"), ("secret_access_key", "SEKRIT"),
        ("endpoint", "https://acct42.r2.cloudflarestorage.com"),
    ])]
    assert calls.made == [("carryon:my-bucket",
                           ("--s3-no-check-bucket=false",))]
    assert "SEKRIT" not in out, "a secret was echoed"
    assert "billable" in out.lower() or "your account" in out.lower(), \
        "creating a bucket did not say it costs money"


def test_declining_the_bucket_still_returns_the_spec(tmp_path, monkeypatch,
                                                     capsys):
    """Never create a billable resource silently - and never insist either:
    the bucket may exist already, and the probe is what finds out. (The
    probe CAN find out because the Remote is created with the upload-side
    bucket creation off - test_provider_setup pins that.)"""
    home = tmp_path / "home"
    home.mkdir()
    calls = RcloneCalls(monkeypatch)
    a_terminal(monkeypatch, "1", provider_menu_position("gcs"),
               "", "sa.json", "12345", "my-bucket", "n")

    spec = choosing.choose_destination(home, [])

    assert spec == "rclone:carryon:my-bucket"
    assert calls.created and calls.created[0][1] == "google cloud storage"
    assert calls.made == [], "declining still ran rclone mkdir"
    assert "probe" in capsys.readouterr().out.lower(), \
        "nothing said how an absent bucket will surface"


def test_a_bucket_that_cannot_be_made_stops_with_rclone_quoted(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    RcloneCalls(monkeypatch, make_place_why="AccessDenied: not yours")
    a_terminal(monkeypatch, "1", provider_menu_position("gcs"),
               "", "sa.json", "12345", "taken-name", "y")

    with pytest.raises(SystemExit) as exc:
        choosing.choose_destination(home, [])

    message = str(exc.value)
    assert "AccessDenied" in message
    assert "carryon" in message, \
        "the sentence does not say the created Remote survives for a re-run"


def test_sftp_asks_no_secret_and_calls_its_place_a_directory(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    home = tmp_path / "home"
    home.mkdir()
    calls = RcloneCalls(monkeypatch)
    a_terminal(monkeypatch, "1", provider_menu_position("sftp"),
               "", "nas.local", "me", "backups/carryon", "y")

    spec = choosing.choose_destination(home, [])

    assert spec == "rclone:carryon:backups/carryon"
    assert calls.created == [("carryon", "sftp", [
        ("host", "nas.local"), ("user", "me")])]
    assert "directory" in capsys.readouterr().out.lower()


# --- init --join through the same prompts --------------------------------------


def test_join_without_dest_runs_the_dialogue_then_spends_the_code(
        tmp_path, monkeypatch, capsys):
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=dest_spec, machine="machine-a"), home_a) == 0
    sync.pair(ns(), home_a)
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    a_terminal(monkeypatch, "2", dest_spec)  # somewhere else -> the spec

    assert sync.init(ns(join=code, machine="machine-b"), home_b) == 0

    assert keyring.fetch_master(home=home_b) == \
        keyring.fetch_master(home=home_a)
    assert config.load(home_b)["destination"] == dest_spec


def test_join_without_dest_and_without_a_terminal_still_refuses(tmp_path,
                                                                monkeypatch):
    """The scriptable spelling is unchanged: no terminal, no --dest, and the
    refusal names the flag."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(prompting, "available", lambda: False)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(join="AAAA-AAAA"), home)

    assert "--dest" in str(exc.value)
