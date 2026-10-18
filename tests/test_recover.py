"""Recovery: typing the recovery key back (ADR-0004's 2026-10-18 amendment).

`init --recover` is `--join`'s sibling. A key arrives on a machine that holds
none, and here it arrives from the user's password manager rather than from a
pairing code. The edges are where the decisions are. The key is asked at a
terminal and nowhere else. It is proved against the Archive's Index before
anything is kept, because a key that parses is not yet a key to this Archive.
A config the machine still has is kept rather than overwritten. A machine that
holds a key, or a broken one, is refused rather than written over.

"Nothing stored" is asserted the same way everywhere: no master key, and
config.json and state.json exactly as they were before the run.

Every home is a temp dir, and the keychain is forced to the fallback file.
"""

import argparse
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, cli, config, crypto, destinations  # noqa: E402
from carryon import keyring, prompting, sync  # noqa: E402

RECOVERY_KEY = re.compile(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}")


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw) -> argparse.Namespace:
    base = dict(dest=None, join=None, recover=False, machine=None,
                apply=False, agent=None, category=None, force=False)
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


def founded_archive(tmp_path, capsys, revision=1):
    """An Archive with an Index, founded by machine A. Returns the recovery
    key it printed, the spec, and the master key it derives."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=spec, machine="machine-a"), home_a) == 0
    key = RECOVERY_KEY.search(capsys.readouterr().out).group(0)
    master = keyring.fetch_master(home=home_a)
    dest = destinations.from_spec(spec, home_a)
    for _ in range(revision):
        archive.save_index(dest, master, archive.load_index(dest, master))
    return key, spec, master


def bare_home(tmp_path, name="home_b") -> pathlib.Path:
    home = tmp_path / name
    home.mkdir()
    return home


def snapshot(home):
    """Everything a recovery could store, as it stands."""
    def bytes_of(path):
        return path.read_bytes() if path.exists() else None
    return (bytes_of(config.config_path(home)),
            bytes_of(sync._state_path(home)),
            bytes_of(keyring._fallback_path(home)))


def assert_nothing_stored(home, before):
    assert snapshot(home) == before, "a refused recovery stored something"


# --- R1, R23: the shape ------------------------------------------------------


def test_recover_and_join_cannot_be_given_together(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["init", "--recover", "--join",
                           "ABCD-EFGH-JKMN-PQRS"])
    assert exc.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_recover_takes_no_value():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["init", "--recover=AAAA-BBBB"])
    assert parser.parse_args(["init", "--recover"]).recover is True


def test_init_help_names_recover_and_says_it_is_asked_for(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["init", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "--recover" in text
    assert "recovery key" in text and "asks for it" in text, \
        "the help has to say the key is asked for, not passed"


# --- R3: a terminal or nothing -----------------------------------------------


def test_without_a_terminal_recover_refuses_before_anything(
        tmp_path, monkeypatch, capsys):
    _, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    monkeypatch.setattr(prompting, "available", lambda: False)
    touched = []
    monkeypatch.setattr(destinations, "from_spec",
                        lambda *a, **k: touched.append(a))

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    message = str(exc.value)
    assert "terminal" in message and "recovery key" in message
    assert not touched, "a refusal for want of a terminal reached the Destination"
    assert_nothing_stored(home, before)


# --- R4-R7: the key, then the proof ------------------------------------------


def test_the_right_key_opens_the_archive_and_is_kept(
        tmp_path, monkeypatch, capsys):
    key, spec, master = founded_archive(tmp_path, capsys, revision=3)
    home = bare_home(tmp_path)
    a_terminal(monkeypatch, key.lower().replace("-", " "))

    assert sync.init(ns(recover=True, dest=spec, machine="machine-b"),
                     home) == 0
    out = capsys.readouterr().out

    assert keyring.fetch_master(home=home) == master
    cfg = config.load(home)
    assert cfg["destination"] == spec and cfg["machine"] == "machine-b"
    assert sync._seen_revision(home, spec) == 3, \
        "the revision of the Index that proved the key is this machine's mark"
    assert "recovered" in out and "machine-b" in out
    assert not RECOVERY_KEY.search(out), \
        "recovery must not print a recovery key, old or new"


def test_a_mistyped_key_is_asked_again_with_the_reason(
        tmp_path, monkeypatch, capsys):
    key, spec, master = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    prompts = a_terminal(monkeypatch, "AAAA-BBBB", key[:-1] + "0", key)

    assert sync.init(ns(recover=True, dest=spec, machine="machine-b"),
                     home) == 0
    out = capsys.readouterr().out

    assert len(prompts) == 3
    assert "32 characters" in out, "the length error is said, then re-asked"
    assert "0, 1, 8 and 9" in out, "the alphabet error is said, then re-asked"
    assert keyring.fetch_master(home=home) == master


def test_end_of_input_at_the_key_cancels(tmp_path, monkeypatch, capsys):
    _, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    a_terminal(monkeypatch)  # no answers: the first read is EOF

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    assert "cancelled" in str(exc.value)
    assert_nothing_stored(home, before)


def test_the_key_is_asked_before_the_destination(tmp_path, monkeypatch,
                                                 capsys):
    key, spec, master = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    monkeypatch.setattr(destinations, "detect_candidates",
                        lambda home=None: [(spec, "the archive")])
    prompts = a_terminal(monkeypatch, key, "1")

    assert sync.init(ns(recover=True, machine="machine-b"), home) == 0

    assert "recovery key" in prompts[0].lower(), prompts
    assert config.load(home)["destination"] == spec
    assert keyring.fetch_master(home=home) == master


def test_a_key_to_another_archive_is_refused(tmp_path, monkeypatch, capsys):
    """Asked again rather than refused outright (review finding 5), so a
    user who gives up stops at the next prompt - with nothing stored."""
    _, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    other, _ = crypto.new_recovery_key()
    a_terminal(monkeypatch, other)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    out = capsys.readouterr().out
    assert "not the recovery key" in out
    assert "nothing has been stored" in out.lower()
    assert "cancelled" in str(exc.value)
    assert_nothing_stored(home, before)


def test_an_empty_destination_has_nothing_to_recover(tmp_path, monkeypatch):
    home = bare_home(tmp_path)
    spec = str(tmp_path / "empty")
    (tmp_path / "empty").mkdir()
    before = snapshot(home)
    key, _ = crypto.new_recovery_key()
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    message = str(exc.value)
    assert "nothing to recover" in message
    assert "`carryon init`" in message, "plain init is the cure for a new Archive"
    assert_nothing_stored(home, before)


def test_sessions_without_an_index_are_the_removal_refusal(
        tmp_path, monkeypatch, capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    dest = destinations.from_spec(spec, home)
    dest.write(archive.SESSIONS_PREFIX + "abc.tar.enc", b"sealed")
    dest.delete(archive.INDEX_KEY)
    before = snapshot(home)
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    assert "no Index" in str(exc.value)
    assert_nothing_stored(home, before)


def test_objects_without_an_index_do_not_suggest_plain_init(
        tmp_path, monkeypatch, capsys):
    """A Setup object and no Index is somebody's Archive, and plain init
    would refuse it as occupied - so the sentence must not offer it."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    dest = destinations.from_spec(spec, home)
    dest.write(archive.PREFIX + "/setups/machine-a.tar.enc", b"sealed")
    dest.delete(archive.INDEX_KEY)
    before = snapshot(home)
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    message = str(exc.value)
    assert "no Index" in message
    assert "nothing to recover" not in message
    assert_nothing_stored(home, before)


def test_a_failed_probe_says_nothing_was_stored_not_a_pairing_code(
        tmp_path, monkeypatch, capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    monkeypatch.setattr(archive, "reachable", lambda dest: "it is read-only")
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    message = str(exc.value)
    assert "reachability probe" in message
    assert "pairing code" not in message
    assert "init --recover" in message
    assert_nothing_stored(home, before)


# --- R12-R18: a machine that still has its config ----------------------------


def kept_config(home, spec, machine="laptop-name"):
    """The config a machine keeps after its keychain entry is gone, with a
    handpick in it that a fresh config would not have."""
    cfg = config.default_config()
    cfg["destination"] = spec
    cfg["machine"] = machine
    cfg["excludes"] = ["skills/private-*"]
    config.save(cfg, home)
    return config.config_path(home).read_bytes()


def test_an_existing_config_is_used_and_left_byte_for_byte(
        tmp_path, monkeypatch, capsys):
    key, spec, master = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    original = kept_config(home, spec)
    # A hostname no machine name may be: the kept config's name wins.
    monkeypatch.setattr(config, "default_config",
                        lambda _real=config.default_config:
                            dict(_real(), machine="bad/name"))
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True), home) == 0
    out = capsys.readouterr().out

    assert config.config_path(home).read_bytes() == original
    assert keyring.fetch_master(home=home) == master
    assert "laptop-name" in out
    assert "kept" in out and str(config.config_path(home)) in out


def test_a_dest_that_disagrees_with_the_config_is_refused(
        tmp_path, monkeypatch, capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    before = snapshot(home)
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=str(tmp_path / "elsewhere")), home)

    message = str(exc.value)
    assert "--dest" in message and spec in message
    assert_nothing_stored(home, before)


def test_a_machine_that_disagrees_with_the_config_is_refused(
        tmp_path, monkeypatch, capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    before = snapshot(home)
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, machine="other-name"), home)

    message = str(exc.value)
    assert "--machine" in message and "laptop-name" in message
    assert_nothing_stored(home, before)


def test_agreeing_flags_are_fine(tmp_path, monkeypatch, capsys):
    key, spec, master = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    original = kept_config(home, spec)
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True, dest=spec, machine="laptop-name"),
                     home) == 0
    assert config.config_path(home).read_bytes() == original
    assert keyring.fetch_master(home=home) == master


def test_without_a_config_a_bad_machine_name_is_refused_before_the_key(
        tmp_path, monkeypatch, capsys):
    _, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    before = snapshot(home)
    prompts = a_terminal(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="a/b"), home)

    assert "machine name" in str(exc.value)
    assert not prompts, "a name that will be refused should not cost a key"
    assert_nothing_stored(home, before)


def test_a_removed_index_this_machine_had_seen_is_refused(
        tmp_path, monkeypatch, capsys):
    """An empty Destination is 'nothing to recover' to a stranger, and a
    removal to a machine whose mark says it read an Index there."""
    home = bare_home(tmp_path)
    spec = str(tmp_path / "emptied")
    (tmp_path / "emptied").mkdir()
    kept_config(home, spec)
    sync._record_revision(home, spec, 4)
    before = snapshot(home)
    key, _ = crypto.new_recovery_key()
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True), home)

    assert "refusing to recover" in str(exc.value)
    assert_nothing_stored(home, before)


def test_a_rolled_back_index_warns_and_recovers(tmp_path, monkeypatch,
                                                capsys):
    key, spec, master = founded_archive(tmp_path, capsys, revision=2)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    sync._record_revision(home, spec, 7)
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True), home) == 0
    out = capsys.readouterr().out

    assert "warning:" in out and "rolled back" in out
    assert keyring.fetch_master(home=home) == master
    assert sync._seen_revision(home, spec) == 7, "a mark is never lowered"


# --- R19, R20: only a machine that holds no key ------------------------------


def test_a_machine_that_holds_a_key_is_refused(tmp_path, monkeypatch, capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    keyring.store_master(b"\x01" * crypto.MASTER_BYTES, home=home)
    capsys.readouterr()
    prompts = a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    assert "already holds a master key" in str(exc.value)
    assert not prompts
    assert keyring.fetch_master(home=home) == b"\x01" * crypto.MASTER_BYTES


def test_a_corrupt_key_is_refused_not_written_over(tmp_path, monkeypatch,
                                                   capsys):
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    path = keyring._fallback_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not hex\n")
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    assert "is not the hex carryon wrote" in str(exc.value)
    assert path.read_text() == "not hex\n"


# --- R21, R22: the sentences a stuck user reads ------------------------------


def test_the_no_key_refusal_names_recover(tmp_path):
    home = bare_home(tmp_path)
    with pytest.raises(SystemExit) as exc:
        sync._require_master(home)
    assert "carryon init --recover" in str(exc.value)


def test_the_push_no_key_refusal_still_names_capture(tmp_path):
    home = bare_home(tmp_path)
    with pytest.raises(SystemExit) as exc:
        sync._require_master(home, for_push=True)
    message = str(exc.value)
    assert "carryon init --recover" in message
    assert "capture --out" in message


def test_the_corrupt_key_sentence_names_recover():
    message = keyring._corrupt(pathlib.Path("/x/master.key"))
    assert "carryon init --recover" in message
    assert "remove" in message.lower()


# --- the review round --------------------------------------------------------


def test_a_config_that_cannot_be_written_leaves_no_key(
        tmp_path, monkeypatch, capsys):
    """Finding 1. A key with no config is a machine every later `init
    --recover` refuses as already holding a key; a config with no key is one
    a re-run recovers on the kept-config path. So the config goes first."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    a_terminal(monkeypatch, key)

    def full_disk(cfg, home):
        raise SystemExit("could not write config.json: disk full")
    monkeypatch.setattr(config, "save", full_disk)

    with pytest.raises(SystemExit):
        sync.init(ns(recover=True, dest=spec, machine="machine-b"), home)

    assert keyring.fetch_master(home=home) is None


def test_a_dest_spelt_differently_but_naming_the_same_place_agrees(
        tmp_path, monkeypatch, capsys):
    """Finding 2. The chooser stores '~/...' verbatim and a shell expands
    '~' before carryon sees it, so the same Destination arrives in two
    spellings."""
    key, _, master = founded_archive(tmp_path, capsys)
    home = tmp_path  # so that '~/archive' is the founded Archive
    original = kept_config(home, "~/archive")
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True, dest=str(tmp_path / "archive")),
                     home) == 0
    assert config.config_path(home).read_bytes() == original
    assert keyring.fetch_master(home=home) == master


def test_a_config_that_will_not_load_says_to_fix_or_remove_it(
        tmp_path, monkeypatch, capsys):
    """Finding 3. load's own cure for a bad name is `init --machine NAME`,
    which under --recover reaches the same load and refuses again."""
    _, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    path = config.config_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"version": 1, "destination": "%s", "machine": "a/b", '
                    '"excludes": [], "carry": []}\n' % spec)
    before = snapshot(home)
    prompts = a_terminal(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True, machine="good"), home)

    message = str(exc.value)
    assert str(path) in message
    assert "init --recover" in message and "remove" in message.lower()
    assert not prompts
    assert_nothing_stored(home, before)


def test_the_index_is_read_once(tmp_path, monkeypatch, capsys):
    """Finding 4. One read: the bytes the key was proved against are the
    bytes the revision comes from, and a remote Destination pays once."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    reads = []
    real = destinations.directory.DirectoryDestination._read_blob

    def counting(self, key_):
        if key_ == archive.INDEX_KEY:
            reads.append(key_)
        return real(self, key_)
    monkeypatch.setattr(destinations.directory.DirectoryDestination,
                        "_read_blob", counting)
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True, dest=spec, machine="machine-b"),
                     home) == 0
    assert len(reads) == 1, reads


def test_a_key_that_parses_but_does_not_open_is_asked_again_in_place(
        tmp_path, monkeypatch, capsys):
    """Finding 5. One wrong letter is still base32, so it parses - and
    must not cost the Destination dialogue, which may have created an
    rclone remote."""
    key, spec, master = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    monkeypatch.setattr(destinations, "detect_candidates",
                        lambda home=None: [(spec, "the archive")])
    slip = ("B" if key[0] != "B" else "C") + key[1:]
    prompts = a_terminal(monkeypatch, slip, "1", key)

    assert sync.init(ns(recover=True, machine="machine-b"), home) == 0

    assert len(prompts) == 3, "key, Destination, key - the menu once"
    assert keyring.fetch_master(home=home) == master


def test_a_removed_index_refusal_does_not_say_push(tmp_path, monkeypatch,
                                                   capsys):
    """Finding 6. A machine recovering has no key, so 'push afresh' is a
    cure it cannot take."""
    home = bare_home(tmp_path)
    spec = str(tmp_path / "emptied")
    (tmp_path / "emptied").mkdir()
    kept_config(home, spec)
    sync._record_revision(home, spec, 4)
    key, _ = crypto.new_recovery_key()
    a_terminal(monkeypatch, key)

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(recover=True), home)

    message = str(exc.value)
    assert "refusing to recover" in message
    assert "push afresh" not in message
    assert "Nothing was stored" in message


def test_a_blank_key_is_not_called_a_remote_credential(
        tmp_path, monkeypatch, capsys):
    """Finding 7."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    a_terminal(monkeypatch, "  ", key)

    assert sync.init(ns(recover=True, dest=spec, machine="machine-b"),
                     home) == 0
    out = capsys.readouterr().out
    assert "nothing was entered" in out
    assert "remote" not in out.split("recovered as")[0]


def test_handpicks_in_a_config_with_no_destination_survive(
        tmp_path, monkeypatch, capsys):
    """Finding 8. A config with no Destination yet is still somebody's
    handpicking, and writing a fresh one over it dropped that silently."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    cfg = config.default_config()
    cfg["machine"] = "chosen-name"
    cfg["excludes"] = [".cursor/*"]
    config.save(cfg, home)
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True, dest=spec), home) == 0

    after = config.load(home)
    assert after["destination"] == spec
    assert after["excludes"] == [".cursor/*"]
    assert after["machine"] == "chosen-name"


def test_recover_says_once_per_command_that_state_is_unreadable(
        tmp_path, monkeypatch, capsys):
    """Finding 9. Recover reads the high-water mark, so it owns the
    once-per-command warning like push and pull do."""
    key, spec, _ = founded_archive(tmp_path, capsys)
    home = bare_home(tmp_path)
    kept_config(home, spec)
    sync._state_path(home).mkdir(parents=True)  # a directory: unreadable
    sync._load_state(home)  # an earlier command in this process said so
    capsys.readouterr()
    a_terminal(monkeypatch, key)

    assert sync.init(ns(recover=True), home) == 0
    assert "would not read" in capsys.readouterr().out
