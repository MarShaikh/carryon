"""The two questions `init` asks a Destination before it finishes (ADR-0011).

Occupancy - is an Archive already here - is a read of one known key and needs
no write. It is what catches the mistake that costs most: `init` without
`--join` against an Archive that already exists mints a second recovery key,
prints it as though it were the one that mattered, and fails only at the first
push, by which point the user holds two keys, cannot tell them apart, and
`init` refuses to run again.

Reachability - do write, read and delete work with these credentials - takes a
probe of random bytes under a random name. Random because it lands in the
plaintext half of untrusted storage before any master key exists, so it must
carry no machine name, no home path and no timestamp; random name so two
machines probing at once cannot collide.

Neither answers the question that matters most for a Setup, which is whether
the storage is private. No probe can, and what the tests below assert about the
wording is that it says what was checked rather than implying what was not.
"""

import argparse
import pathlib
import re
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, config, keyring, sync  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from tests.hostile_archive import build_home_a  # noqa: E402

RECOVERY_KEY = r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}"


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


def objects(root) -> list:
    root = pathlib.Path(root)
    if not root.is_dir():
        return []
    return sorted(p.relative_to(root).as_posix()
                  for p in root.rglob("*") if p.is_file())


# --- reachability ------------------------------------------------------------


def test_a_probe_writes_reads_and_deletes_and_leaves_nothing(tmp_path):
    """The positive answer, and the whole of what a green tick means."""
    root = tmp_path / "archive"
    dest = DirectoryDestination(root)

    assert archive.reachable(dest) is None

    assert objects(root) == [], "the probe was left in the Archive"


def test_a_probe_carries_no_machine_name_no_home_and_no_timestamp(tmp_path,
                                                                  monkeypatch):
    """It lands in the plaintext half of untrusted storage before any master
    key exists, so what it holds is somebody else's to read."""
    seen = {}
    root = tmp_path / "archive"
    dest = DirectoryDestination(root)
    real_write = DirectoryDestination.write

    def remember(self, key, data):
        seen[key] = data
        return real_write(self, key, data)

    monkeypatch.setattr(DirectoryDestination, "write", remember)
    assert archive.reachable(dest) is None

    assert len(seen) == 1, "a probe is one object"
    (key, data), = seen.items()
    assert key.startswith(archive.PREFIX + "/"), \
        "the probe landed outside the Archive's own prefix"
    for leaked in (str(tmp_path), str(pathlib.Path.home()), "2026"):
        assert leaked not in key and leaked.encode() not in data, \
            f"the probe carried {leaked!r}"
    assert len(set(data)) > 4, "the probe's bytes are not random"


def test_two_probes_do_not_collide(tmp_path, monkeypatch):
    """Random name, so two machines probing at once cannot take each other's
    object for their own."""
    names = set()
    dest = DirectoryDestination(tmp_path / "archive")
    real_write = DirectoryDestination.write

    def remember(self, key, data):
        names.add(key)
        return real_write(self, key, data)

    monkeypatch.setattr(DirectoryDestination, "write", remember)
    for _ in range(5):
        assert archive.reachable(dest) is None

    assert len(names) == 5


def test_a_destination_that_will_not_write_says_so(tmp_path):
    """A sentence naming what failed, not a traceback."""
    root = tmp_path / "archive"
    root.mkdir()
    root.chmod(0o500)
    try:
        why = archive.reachable(DirectoryDestination(root))
    finally:
        root.chmod(0o700)

    assert why is not None
    assert "write" in why


def test_a_destination_that_serves_back_other_bytes_says_so(tmp_path,
                                                            monkeypatch):
    """The rclone type's whole subject one layer up: a store that reports a
    successful write and serves the previous version reads as a working
    Destination to anything that only checks an exit code."""
    dest = DirectoryDestination(tmp_path / "archive")
    monkeypatch.setattr(DirectoryDestination, "read",
                        lambda self, key: b"somebody else's bytes")

    why = archive.reachable(dest)

    assert why is not None
    assert "read" in why


def test_a_probe_that_cannot_be_read_back_is_still_deleted(tmp_path,
                                                           monkeypatch):
    """Every way out after the write attempts the delete. The read failing
    is the case where carryon's own object is most likely to be left in
    somebody's storage - a token with write and no read is an ordinary
    scoped credential - and a stray probe under carryon/ is also what makes
    `init --join` misdiagnose a Destination that has never held an Archive."""
    root = tmp_path / "archive"
    dest = DirectoryDestination(root)
    monkeypatch.setattr(DirectoryDestination, "read",
                        lambda self, key: (_ for _ in ()).throw(
                            SystemExit("the remote would not serve it")))

    why = archive.reachable(dest)

    assert why is not None and "read" in why
    assert objects(root) == [], "the probe was left in the Archive"


def test_a_probe_that_can_be_neither_read_nor_deleted_names_the_key(
        tmp_path, monkeypatch):
    """And when the delete does not go through either, the sentence names
    the object, because that is the one carryon cannot take back."""
    dest = DirectoryDestination(tmp_path / "archive")
    monkeypatch.setattr(DirectoryDestination, "read",
                        lambda self, key: b"somebody else's bytes")
    monkeypatch.setattr(DirectoryDestination, "delete",
                        lambda self, key: False)

    why = archive.reachable(dest)

    assert why is not None
    assert archive.PROBE_PREFIX in why, "the stranded object is not named"


def test_a_destination_that_will_not_delete_says_so(tmp_path, monkeypatch):
    """Named, because what a probe leaves behind is an object in somebody's
    storage that carryon put there and cannot take back."""
    dest = DirectoryDestination(tmp_path / "archive")
    monkeypatch.setattr(DirectoryDestination, "delete",
                        lambda self, key: False)

    why = archive.reachable(dest)

    assert why is not None
    assert "delete" in why


# --- occupancy ---------------------------------------------------------------


def test_occupancy_is_a_read_and_a_listing_and_writes_nothing(tmp_path):
    root = tmp_path / "archive"
    dest = DirectoryDestination(root)

    assert archive.occupied(dest) is False
    assert objects(root) == [], "the occupancy question wrote to the Archive"

    dest.write(archive.INDEX_KEY, b"sealed")
    assert archive.occupied(dest) is True


def test_an_archive_whose_index_is_unservable_still_reads_as_occupied(
        tmp_path):
    """The Index is the one object that is there iff a push completed - and
    also one object, which anyone with write access to the Destination can
    make unservable (delete it, or on an object store shadow it with a
    prefix). Occupancy read as one key would then answer 'fresh' over a
    populated Archive, and a second machine would mint a second master key
    over it. So the listing _join already trusts is asked as well: objects
    under carryon/ with no readable Index is somebody's Archive in a state
    to investigate, never a place to found a new one."""
    root = tmp_path / "archive"
    dest = DirectoryDestination(root)
    dest.write(archive.SETUPS_PREFIX + "machine-a/settings.json", b"{}")

    assert archive.occupied(dest) is True


def test_init_refuses_an_archive_that_is_only_a_pairing_blob(tmp_path,
                                                             capsys):
    """init A, pair A, and no push yet. `pair` seals a fresh Index before it
    mints a code (sync.pair), so even this earliest Archive answers the
    one-key read - pinned here because occupancy leans on that ordering, and
    a pair that stopped sealing first would reopen the two-keys trap one
    push earlier than the tests above can see."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=dest_spec, machine="machine-a"), home_a) == 0
    assert sync.pair(ns(), home_a) == 0
    capsys.readouterr()

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, machine="machine-b"), home_b)

    assert "--join" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None
    assert not re.search(RECOVERY_KEY, capsys.readouterr().out)


def test_init_refuses_an_archive_that_already_exists(tmp_path, capsys):
    """The live trap: a second recovery key, printed as though it mattered,
    over an Archive the first machine's key already opens.

    A real push, because an Archive is what a push leaves rather than what an
    `init` promises - a machine that has run `init` and never pushed has put
    nothing anywhere, and there is nothing there for this to find."""
    home_a = build_home_a(tmp_path)
    dest_spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=dest_spec, machine="machine-a"), home_a) == 0
    assert sync.push(ns(apply=True), home_a) == 0
    capsys.readouterr()

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, machine="machine-b"), home_b)

    assert "--join" in str(exc.value), "the refusal does not name the cure"
    assert keyring.fetch_master(home=home_b) is None, \
        "a second master key was minted over an Archive that already existed"
    assert not re.search(RECOVERY_KEY, capsys.readouterr().out), \
        "a second recovery key was printed"
    assert config.load(home_b)["destination"] == "", \
        "a refused init wrote a config"


def test_init_join_refuses_a_destination_with_no_archive_in_it(tmp_path):
    """The other way round, and the same rule: a code cannot be spent against
    an Archive that is not there."""
    home = tmp_path / "home_b"
    home.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=str(tmp_path / "archive"), join="AAAAAA-AAAAAAAAAA",
                     machine="machine-b"), home)

    assert "no Archive" in str(exc.value)
    assert keyring.fetch_master(home=home) is None


def test_init_probes_before_it_mints_a_key(tmp_path, monkeypatch):
    """A machine whose Destination does not work is a machine that has not
    been set up: the refusal has to cost neither a key nor a config, because
    `init` refuses to run twice over one that holds a key."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(archive, "reachable",
                        lambda dest: "the store would not take the probe")

    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=str(tmp_path / "archive"), machine="a"), home)

    assert "probe" in str(exc.value)
    assert keyring.fetch_master(home=home) is None
    assert config.load(home)["destination"] == ""


def test_a_join_refused_by_the_probe_says_the_code_was_not_spent(
        tmp_path, monkeypatch, capsys):
    """The probe runs before the unwrap precisely so the code survives -
    and the user has to be TOLD it survived, because the fresh-init refusal
    beside this one talks about recovery keys and re-running `init`, both
    wrong for a join. A user who burns a fresh code after every refused
    join is following the sentence carryon gave them."""
    home_a = tmp_path / "home_a"
    home_a.mkdir()
    dest_spec = str(tmp_path / "archive")
    assert sync.init(ns(dest=dest_spec, machine="machine-a"), home_a) == 0
    assert sync.pair(ns(), home_a) == 0
    code = re.search(r"--join (\S+)", capsys.readouterr().out).group(1)

    monkeypatch.setattr(archive, "reachable",
                        lambda dest: "the store would not take the probe")
    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=dest_spec, join=code, machine="machine-b"), home_b)

    assert "NOT spent" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None
    dest = DirectoryDestination(tmp_path / "archive")
    assert len(dest.list(archive.PAIR_PREFIX)) == 1, \
        "the refusal spent the blob after all"


def test_init_says_what_it_checked_and_not_what_it_did_not(tmp_path, capsys):
    """No probe can say whether storage is private, and a green tick that
    implies one is worse than no tick at all."""
    home = tmp_path / "home"
    home.mkdir()
    assert sync.init(ns(dest=str(tmp_path / "archive"), machine="a"), home) == 0

    out = capsys.readouterr().out
    assert "write, read and delete" in out
    assert "private" in out, \
        "nothing in the report says what the probe cannot answer"


def test_a_recovery_key_is_still_shown_once(tmp_path, capsys):
    """The positive control for the whole file: the checks are two questions
    in front of what `init` already did, not a replacement for it."""
    home = tmp_path / "home"
    home.mkdir()
    assert sync.init(ns(dest=str(tmp_path / "archive"), machine="a"), home) == 0

    out = capsys.readouterr().out
    assert len(re.findall(RECOVERY_KEY, out)) == 1


# --- a git Destination is not probed -----------------------------------------


def bare_origin(tmp_path) -> pathlib.Path:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "--initial-branch=main",
                    str(origin)], capture_output=True, check=True)
    return origin


def commit_count(origin) -> int:
    result = subprocess.run(
        ["git", "-C", str(origin), "rev-list", "--all", "--count"],
        capture_output=True, text=True, check=True)
    return int(result.stdout.strip())


def test_a_git_destination_is_not_probed_and_the_report_says_why(
        tmp_path, capsys):
    """Every write to a git Destination is a commit, and a pushed commit
    stays in the remote's history for good - so a probe would leave two junk
    commits and an irremovable blob in a repository carryon does not own,
    on every init. The type says so and the report repeats it, instead of
    claiming a delete worked that git's own history contradicts."""
    home = tmp_path / "home"
    home.mkdir()
    origin = bare_origin(tmp_path)

    assert sync.init(ns(dest=str(origin), machine="laptop"), home) == 0
    out = capsys.readouterr().out

    assert commit_count(origin) == 0, \
        "init pushed commits to a repository it was only checking"
    assert keyring.fetch_master(home=home) is not None
    assert "not probed" in out
    assert "commit" in out, "the report does not say why there was no probe"
    assert "write, read and delete work" not in out, \
        "the report claims a probe that never ran"
    assert "private" in out, "the privacy line must survive the skip"


def test_occupancy_still_guards_a_git_destination(tmp_path, capsys):
    """Skipping the probe must not skip the other question: a pushed git
    Archive still refuses a second plain init, through the same clone the
    read side always makes."""
    home_a = build_home_a(tmp_path)
    origin = bare_origin(tmp_path)
    assert sync.init(ns(dest=str(origin), machine="machine-a"), home_a) == 0
    assert sync.push(ns(apply=True, category="config"), home_a) == 0
    capsys.readouterr()

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with pytest.raises(SystemExit) as exc:
        sync.init(ns(dest=str(origin), machine="machine-b"), home_b)

    assert "--join" in str(exc.value)
    assert keyring.fetch_master(home=home_b) is None
