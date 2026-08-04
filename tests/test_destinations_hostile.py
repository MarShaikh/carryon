"""What a Destination offers that is not a symlink, and what carryon says
about it.

The previous round closed the read-through: carryon follows no symlink it
finds on a Destination. What it put in place of the read is a line in the pull
report, and ADR-0009 makes that line the safety property - "refused by name"
is the whole promise. So the line itself is now attacker-reachable surface,
and this module attacks it from four directions.

The name is the attacker's string. A filename may hold newlines and control
characters, so an object called "x\\n  Setup: 6 file(s) written" writes its own
lines into the report it is supposed to appear in, and one holding a carriage
return or a CSI erase can blank the lines already printed above it.

Silence is the other way to lose the line. An object list() enumerated and
read() could not open reads back as absent, so a Setup arrives one file short
and the report says nothing at all - the exact partial-restore-reads-as-
complete failure the report line exists to prevent.

A crash is the third. A Destination is untrusted input and a pull has usually
written a History by the time the Setup half runs, so one planted object that
raises is a permanent abort on every pull from every machine: an object name
that is not valid UTF-8, a name past NAME_MAX, an ancestor directory carryon
cannot traverse, a NUL in a key.

And the guard is spelled is_symlink(), which a hard link is not. A hard link
needs no read permission on the file it points at, so another local user with
write access to a shared Destination can plant one at an Archive key and have
carryon read the victim's file and publish it on the next push.

The eighth round drove the same four directions at the two types nobody had
driven hostilely, git and rclone, and the sections at the foot of this file
are what that turned up. Both are the layer's rule reaching one place further
out than any round had put it: what a Destination returns is input, and for
these two types the Destination answers through another program, so the
program's OUTPUT is input too - the bytes on its stderr, the branch its HEAD
names, the tree its checkout did or did not lay down. A strict decode of
either program's output was a UnicodeDecodeError raised from inside
subprocess.run, which is the crash this module's third direction is about,
reached by a route neither type's own listing guard covers.

Every "secret" here is invented text, every home is synthetic, and no test
touches the network - rclone is a fake binary on a prepended PATH and git
talks to a bare repository on local disk.
"""

import argparse
import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import archive, keyring, rekey, sync  # noqa: E402
from carryon.destinations.base import require_key  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from carryon.destinations.git_repo import GitDestination  # noqa: E402
from carryon.destinations.rclone_remote import RcloneDestination  # noqa: E402
from tests.timeouts import time_limit  # noqa: E402

SECRET = b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n"
HONEST = b'{"model": "opus"}'
SETUP_PREFIX = "carryon/setups/mac"

# A forged report line, spelled the way pull spells the real one.
FORGERY = "  Setup: 6 file(s) written, 0 refused"


def unprivileged() -> bool:
    """False when root, which traverses a mode-000 directory regardless.

    A guard rather than a skip marker: run_tests.py stands in for pytest on a
    machine that has none, and its stub covers the three APIs the suite
    actually needs. Growing that stub for one platform caveat costs more than
    a sentence here.
    """
    return not (hasattr(os, "geteuid") and os.geteuid() == 0)


# --- helpers -----------------------------------------------------------------


def archive_with(tmp_path) -> tuple:
    """(dest, setup_dir): a Destination holding one honest stored object."""
    root = tmp_path / "archive"
    setup = root / "carryon" / "setups" / "mac"
    setup.mkdir(parents=True)
    (setup / "settings.json").write_bytes(HONEST)
    return DirectoryDestination(root), setup


def report_lines(out: str) -> list:
    return out.splitlines()


def secret_file(tmp_path) -> pathlib.Path:
    outside = tmp_path / "elsewhere"
    outside.mkdir(exist_ok=True)
    secret = outside / "id_ed25519"
    secret.write_bytes(SECRET)
    return secret


FAKE_RCLONE = """#!/bin/sh
LINES="__LINES__"
cmd="$1"; shift
case "$cmd" in
  lsf) cat "$LINES" ;;
  *) echo "unknown verb $cmd" >&2; exit 2 ;;
esac
"""


def install_rclone_listing(tmp_path, monkeypatch, raw: bytes):
    """A fake rclone whose lsf prints exactly these bytes, valid UTF-8 or not."""
    lines = tmp_path / "listing.bin"
    lines.write_bytes(raw)
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "rclone"
    script.write_text(FAKE_RCLONE.replace("__LINES__", str(lines)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


# --- the report line is the control, so the name cannot author one -----------


def test_a_planted_name_cannot_write_its_own_line_into_the_report(tmp_path,
                                                                  capsys):
    """A filename may hold newlines. The name goes into the line that reports
    it being skipped, so an unescaped one becomes as many report lines as it
    likes - and the forged line can say the restore was complete."""
    dest, setup = archive_with(tmp_path)
    os.symlink(secret_file(tmp_path), setup / f"x\n{FORGERY}\ny")

    dest.list("carryon/")
    out = capsys.readouterr().out

    assert FORGERY not in report_lines(out), \
        "an object name authored a line of the pull report"
    assert any("Setup" in line and "skipping" in line
               for line in report_lines(out)), \
        "the planted object must still be named, on one line of its own"


def test_a_planted_name_cannot_erase_the_lines_already_printed(tmp_path,
                                                               capsys):
    r"""\r, CSI 2K and CSI 1A move or blank a terminal's cursor. Passed
    through, a name can wipe the refusals printed above it - suppression by
    the same route as forgery."""
    dest, setup = archive_with(tmp_path)
    os.symlink(secret_file(tmp_path),
               setup / "safe\r\x1b[2K\x1b[1Ahidden.md")

    dest.list("carryon/")
    out = capsys.readouterr().out

    for control in ("\r", "\x1b"):
        assert control not in out, \
            "a control character in an object name reached the terminal"
    assert "hidden.md" in out, "the object is still named"


def test_a_read_refusal_carries_the_name_through_the_same_escaping(tmp_path,
                                                                   capsys):
    """list() and read() both print the attacker's string; one escaped name
    and one raw one is the same hole with a longer path to it."""
    dest, setup = archive_with(tmp_path)
    name = f"y\n{FORGERY}"
    os.symlink(secret_file(tmp_path), setup / name)

    assert dest.read(SETUP_PREFIX + "/" + name) is None
    assert FORGERY not in report_lines(capsys.readouterr().out)


# --- silence is the other way to lose the report line ------------------------


def test_an_unreadable_directory_is_reported_not_dropped(tmp_path, capsys):
    """A subtree carryon cannot list vanishes from the listing. Two stored
    files gone and an empty report reads as an Archive that never held
    them."""
    if not unprivileged():
        return
    dest, setup = archive_with(tmp_path)
    locked = setup / "skills"
    locked.mkdir()
    (locked / "SKILL.md").write_bytes(b"skill")
    os.chmod(locked, 0o000)
    try:
        keys = dest.list("carryon/")
        out = capsys.readouterr().out
    finally:
        os.chmod(locked, 0o700)

    assert SETUP_PREFIX + "/skills/SKILL.md" not in keys
    assert "skills" in out, \
        "a subtree that could not be listed left no line in the report"


def test_an_object_that_cannot_be_opened_is_reported_not_read_as_absent(
        tmp_path, capsys):
    """read() returning None means 'absent' everywhere upstream, and absent is
    the ordinary case that prints nothing. An object the listing just offered
    is not absent, so it needs a line."""
    if not unprivileged():
        return
    dest, setup = archive_with(tmp_path)
    locked = setup / "CLAUDE.md"
    locked.write_bytes(b"instructions")
    os.chmod(locked, 0o000)
    try:
        keys = dest.list("carryon/")
        capsys.readouterr()
        data = dest.read(SETUP_PREFIX + "/CLAUDE.md")
        out = capsys.readouterr().out
    finally:
        os.chmod(locked, 0o600)

    assert SETUP_PREFIX + "/CLAUDE.md" in keys, "the listing offered it"
    assert data is None
    assert "CLAUDE.md" in out, \
        "an object that was listed and could not be read said nothing"


def test_a_missing_object_stays_silent(tmp_path, capsys):
    """The other half of the rule: absent is the ordinary case - a fresh
    Archive has no Index - and must not print anything at all."""
    dest, _ = archive_with(tmp_path)
    assert dest.read("carryon/index.enc") is None
    assert capsys.readouterr().out == "", \
        "an absent object is not a refusal and must not be reported"


def test_read_and_list_answer_a_non_regular_file_the_same_way(tmp_path,
                                                              capsys):
    """_local_keys calls a fifo 'not an ordinary file' and reports it;
    _local_bytes handed back the same None it uses for absent. One fix, two
    answers for one object."""
    dest, setup = archive_with(tmp_path)
    os.mkfifo(setup / "pipe.md")

    # Under the shared limit: dropping O_NONBLOCK from _local_bytes wedged
    # this test for ever rather than failing it, which is no result at all
    # from the test written to catch that regression.
    with time_limit(what="the Destination never came back from the pipe"):
        dest.list("carryon/")
        listed = capsys.readouterr().out
        assert dest.read(SETUP_PREFIX + "/pipe.md") is None
        read = capsys.readouterr().out

    assert "pipe.md" in listed
    assert "pipe.md" in read, \
        "a fifo is reported by the listing and silently absent to the read"


def test_a_directory_standing_where_an_object_belongs_is_reported(tmp_path,
                                                                  capsys):
    """The cheapest denial of service on the list: mkdir at an object's key.

    A fifo reaches the S_ISREG check and is refused by it. A directory never
    gets there - os.fdopen() on a descriptor for one raises IsADirectoryError
    before the fstat below it runs - so the guard sat one line after the call
    that made it unreachable. Every read of that key raised, out of a layer
    whose whole posture is that a planted object is a report line.

    'carryon/index.enc' is the key that matters. load_index reads it first on
    every pull and every push, so one mkdir no key holder authorised aborted
    both, on every machine, with a traceback rather than a sentence.
    """
    dest, _ = archive_with(tmp_path)
    (pathlib.Path(dest.root) / "carryon" / "index.enc").mkdir(parents=True)

    assert dest.read("carryon/index.enc") is None
    out = capsys.readouterr().out

    assert "index.enc" in out, \
        "a directory planted at an object's key said nothing"
    assert "ordinary file" in out, \
        "it is refused for the same reason a fifo is, and should say so"


# --- one planted object must not abort every pull ----------------------------


def test_an_object_name_that_is_not_utf8_does_not_abort_a_listing(tmp_path,
                                                                  monkeypatch,
                                                                  capsys):
    """S3, B2 and sftp all allow arbitrary bytes in a key, and lsf prints
    them. Decoding the listing strictly means one planted object name ends
    every pull from every machine before any key is validated."""
    install_rclone_listing(tmp_path, monkeypatch,
                           b"carryon/index.enc\ncarryon/\xff\xfe.enc\n")
    dest = RcloneDestination("fakeremote:archive")

    keys = dest.list()
    out = capsys.readouterr().out

    assert keys == ["carryon/index.enc"], \
        "the usable key was lost with the unusable one"
    assert "skipping" in out, "the undecodable name is not reported"


def test_a_name_too_long_for_the_filesystem_does_not_raise_out_of_read(
        tmp_path, capsys):
    """ENAMETOOLONG is not in the errno set pathlib swallows, so a check
    written as is_symlink() raises it out of a read the caller wrote to treat
    filesystem trouble as absence."""
    dest, _ = archive_with(tmp_path)
    long_key = SETUP_PREFIX + "/" + ("a" * 5000)

    assert dest.read(long_key) is None
    assert "skipping" in capsys.readouterr().out


def test_a_path_longer_than_the_kernel_takes_does_not_raise_out_of_read(
        tmp_path, capsys):
    """Past PATH_MAX rather than NAME_MAX, so a per-component cap alone would
    not answer it.

    Absent rather than reported, and that is the right answer here: a walk
    that opens one component at a time never assembles the long path, so it
    reaches a directory that does not exist and says so the way every missing
    object does - silently. What matters is that it does not raise."""
    dest, _ = archive_with(tmp_path)
    long_key = SETUP_PREFIX + "/" + "/".join(["ab"] * 600)

    assert dest.read(long_key) is None


def test_a_name_too_long_for_the_filesystem_refuses_a_write_by_name(tmp_path):
    """The write side refuses loudly rather than skipping - but as a sentence,
    not as an OSError out of a check."""
    dest, _ = archive_with(tmp_path)
    with pytest.raises(SystemExit) as exc:
        dest.write(SETUP_PREFIX + "/" + ("a" * 5000), b"x")
    assert "too long" in str(exc.value) or "name" in str(exc.value)


def test_an_ancestor_carryon_cannot_traverse_does_not_raise(tmp_path, capsys):
    """EACCES on a directory above the object, which pathlib does not ignore
    either. One chmod on a shared Destination would otherwise end every
    pull."""
    if not unprivileged():
        return
    dest, setup = archive_with(tmp_path)
    locked = setup / "skills"
    locked.mkdir()
    (locked / "SKILL.md").write_bytes(b"skill")
    os.chmod(locked, 0o000)
    try:
        data = dest.read(SETUP_PREFIX + "/skills/SKILL.md")
        out = capsys.readouterr().out
    finally:
        os.chmod(locked, 0o700)

    assert data is None
    assert "skipping" in out


def test_a_key_holding_a_nul_is_refused_as_a_key(tmp_path, capsys):
    """require_key is the rule every later syscall is held to, so it has to
    refuse what those syscalls refuse. A NUL reaches os.lstat and comes back
    as ValueError from inside a read written to return None."""
    with pytest.raises(ValueError):
        require_key("carryon/setups/mac/a\x00b")

    dest, _ = archive_with(tmp_path)
    assert dest.list("carryon/") == [SETUP_PREFIX + "/settings.json"]


def test_a_listed_key_holding_a_nul_is_dropped_at_the_listing(tmp_path,
                                                              monkeypatch,
                                                              capsys):
    """A remote's listing is not split on NUL by splitlines(), so a key can
    carry one all the way to a read."""
    install_rclone_listing(tmp_path, monkeypatch,
                           b"carryon/index.enc\ncarryon/a\x00b.enc\n")
    dest = RcloneDestination("fakeremote:archive")

    assert dest.list() == ["carryon/index.enc"]
    assert "skipping" in capsys.readouterr().out


# --- a hard link is not a symlink --------------------------------------------


def test_a_hard_link_is_not_an_archive_object(tmp_path, capsys):
    """link() needs no read permission on the file it points at, so another
    local user with write access to a shared Destination can put the victim's
    key at an Archive key and let carryon read it. Same chain the symlink fix
    closed, one system call over."""
    dest, setup = archive_with(tmp_path)
    secret = secret_file(tmp_path)
    os.link(secret, setup / "CLAUDE.md")

    keys = dest.list("carryon/")
    listed = capsys.readouterr().out
    data = dest.read(SETUP_PREFIX + "/CLAUDE.md")
    read = capsys.readouterr().out

    assert data != SECRET, "a hard link was read as an Archive object"
    assert data is None
    assert SETUP_PREFIX + "/CLAUDE.md" not in keys
    assert "CLAUDE.md" in listed and "CLAUDE.md" in read


def test_a_hard_link_never_reaches_staging(tmp_path):
    dest, setup = archive_with(tmp_path)
    os.link(secret_file(tmp_path), setup / "CLAUDE.md")
    staging = tmp_path / "staging"

    dest.read_tree(SETUP_PREFIX, staging)

    staged = {p.name: p.read_bytes() for p in staging.rglob("*")
              if p.is_file()}
    assert staged == {"settings.json": HONEST}


def test_the_archive_objects_carryon_writes_are_still_readable(tmp_path):
    """The regression guard on the hard-link rule: nothing carryon writes has
    a second link, so no ordinary object may be caught by it."""
    dest = DirectoryDestination(tmp_path / "archive")
    dest.write("carryon/index.enc", b"sealed")
    dest.write("carryon/setups/mac/settings.json", HONEST)
    assert dest.read("carryon/index.enc") == b"sealed"
    assert dest.list() == ["carryon/index.enc",
                           "carryon/setups/mac/settings.json"]


# --- the check and the use have to be one syscall ----------------------------


def test_a_directory_swapped_mid_read_cannot_redirect_it(tmp_path):
    """The module comment says nothing can be swapped in between the check and
    the open. O_NOFOLLOW binds only the FINAL component, while the walk
    reasons about every component below the root, so a directory renamed to a
    symlink after its check and before the open is read straight through.

    A thread does the renaming; the assertion is over every read, so this
    fails the moment one of them comes back with the planted bytes.
    """
    root = tmp_path / "archive"
    setup = root / "carryon" / "setups" / "mac"
    setup.mkdir(parents=True)
    (setup / "settings.json").write_bytes(HONEST)

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "settings.json").write_bytes(SECRET)

    dest = DirectoryDestination(root)
    parent = setup.parent
    real, swapped = parent / "mac", parent / ".mac-real"
    stop = threading.Event()

    def flip():
        while not stop.is_set():
            try:
                os.rename(real, swapped)
                os.symlink(outside, real)
            except OSError:
                pass
            time.sleep(0)
            try:
                os.unlink(real)
                os.rename(swapped, real)
            except OSError:
                pass

    thread = threading.Thread(target=flip, daemon=True)
    thread.start()
    try:
        for _ in range(600):
            data = dest.read(SETUP_PREFIX + "/settings.json")
            assert data in (HONEST, None), \
                "a directory swapped after its check redirected the read"
    finally:
        stop.set()
        thread.join(timeout=5)
        # leave the tree in a state tmp_path cleanup can remove
        if real.is_symlink():
            os.unlink(real)
        if swapped.exists():
            os.rename(swapped, real)


# --- a staged symlink must not be published ----------------------------------


def test_write_tree_does_not_publish_the_target_of_a_staged_symlink(tmp_path):
    """The last is_file() in the layer that follows a link. A push reading
    through one would put the target's bytes in the Archive's one plaintext
    half, past the home-path neutralisation that deliberately skips
    symlinks."""
    dest = DirectoryDestination(tmp_path / "archive")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "settings.json").write_bytes(HONEST)
    os.symlink(secret_file(tmp_path), staging / "CLAUDE.md")

    dest.write_tree(SETUP_PREFIX, staging)

    assert dest.read(SETUP_PREFIX + "/CLAUDE.md") is None
    assert dest.list(SETUP_PREFIX + "/") == [SETUP_PREFIX + "/settings.json"]


def test_put_setup_does_not_publish_or_sweep_through_a_staged_symlink(tmp_path):
    """put_setup builds its stale-key set from the same is_file() walk, so a
    staged link both published its target and kept the published copy alive
    through the sweep."""
    dest = DirectoryDestination(tmp_path / "archive")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "settings.json").write_bytes(HONEST)
    os.symlink(secret_file(tmp_path), staging / "CLAUDE.md")

    archive.put_setup(dest, "mac", staging)

    assert dest.list(SETUP_PREFIX + "/") == [SETUP_PREFIX + "/settings.json"]


# --- git gets the same rules --------------------------------------------------


def make_git_dest(tmp_path) -> GitDestination:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)], check=True)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/setups/mac/settings.json", HONEST)
    return dest


def test_git_reports_an_object_it_cannot_read(tmp_path, capsys):
    """Every rule in this module lives in the base class precisely so the git
    clone cannot answer differently."""
    dest = make_git_dest(tmp_path)
    capsys.readouterr()
    os.mkfifo(dest.clone_dir / "carryon" / "setups" / "mac" / "pipe.md")

    with time_limit(what="the git Destination never came back from the pipe"):
        assert dest.read(SETUP_PREFIX + "/pipe.md") is None
    assert "pipe.md" in capsys.readouterr().out


def test_git_refuses_a_hard_link_planted_in_the_clone(tmp_path, capsys):
    """Planted inside a batch, which is the window a shared clone directory
    actually has: read_tree syncs once and then reads every key without
    re-syncing, so `git clean` is not what is refusing this one."""
    dest = make_git_dest(tmp_path)
    capsys.readouterr()

    with dest._batch():
        os.link(secret_file(tmp_path),
                dest.clone_dir / "carryon" / "setups" / "mac" / "CLAUDE.md")
        assert dest.read(SETUP_PREFIX + "/CLAUDE.md") is None
        assert "CLAUDE.md" in capsys.readouterr().out


def test_git_write_is_still_atomic_and_committed(tmp_path):
    """The regression guard for moving git's write onto the shared path."""
    dest = make_git_dest(tmp_path)
    dest.write("carryon/index.enc", b"sealed")
    assert dest.read("carryon/index.enc") == b"sealed"

    second = GitDestination(dest.url, home=tmp_path / "home-2")
    assert second.read("carryon/index.enc") == b"sealed", \
        "the write was not pushed to the origin"
    assert not [p for p in dest.clone_dir.rglob(".carryon-tmp-*")], \
        "a tmp file was left in the clone for git to commit"


def test_a_tree_of_refusals_still_stages_the_one_real_object(tmp_path):
    """Every refusal above is a report line or a SystemExit; none of them is
    an OSError escaping the layer, and none of them costs the honest object
    beside it."""
    dest, setup = archive_with(tmp_path)
    os.mkfifo(setup / "pipe.md")
    os.symlink(setup / "nowhere", setup / "gone.md")
    os.link(secret_file(tmp_path), setup / "linked.md")
    staging = tmp_path / "staging"

    with time_limit(what="read_tree never came back from the pipe in it"):
        dest.read_tree(SETUP_PREFIX, staging)  # must not raise, must return

    assert {p.name: p.read_bytes() for p in staging.rglob("*")
            if p.is_file()} == {"settings.json": HONEST}


# =============================================================================
# GIT, AGAINST A REAL BARE REPOSITORY ON LOCAL DISK
# =============================================================================
#
# The clone is the sharpest edge carryon has: a hostile remote ships whatever
# it likes on clone, and the clone sits at a FIXED depth under $HOME, so a
# committed link of a fixed number of parent steps is the same read on every
# machine that pulls. Everything below the clone's root - the walk, the read,
# the write, the delete - comes from LocalTreeDestination and was probed to
# death in the section above; what is left here is git itself, and git is
# another program, so its OUTPUT is input the same way a listing is.
#
# No network: origin is a bare repository beside the clone, and a hostile
# remote is one somebody with write access has committed to. A rejecting
# remote is a pre-receive hook, which is how a server rejects a push and how
# a server's sentence reaches carryon's stderr.

# Names a git tree holds happily and no decode can take at face value: raw
# bytes that are not UTF-8 at all, and the UTF-8 spelling of a lone surrogate,
# which is legal JSON, legal in a Python str, and not a valid encoding of one.
HOSTILE_NAMES = (b"bad\xff\xfe.enc", b"lone\xed\xa0\x80surrogate.enc")


def git(*args, **kwargs) -> subprocess.CompletedProcess:
    """git, captured as BYTES - a test that decodes git strictly has the
    defect it is here to measure."""
    return subprocess.run(["git"] + [str(a) for a in args],
                          capture_output=True, **kwargs)


def bare_origin(tmp_path, name="origin.git") -> pathlib.Path:
    origin = tmp_path / name
    assert git("init", "--quiet", "--bare", origin).returncode == 0
    return origin


def worktree(tmp_path, origin, name="hostile") -> pathlib.Path:
    """A clone somebody else drives, to commit hostile things through."""
    work = tmp_path / name
    assert git("clone", "--quiet", origin, work).returncode == 0
    git("-C", work, "config", "user.name", "someone")
    git("-C", work, "config", "user.email", "someone@example.invalid")
    return work


def commit_all(work, message="hostile") -> None:
    assert git("-C", work, "add", "-A").returncode == 0
    assert git("-C", work, "commit", "--quiet", "-m", message).returncode == 0
    assert git("-C", work, "push", "--quiet", "origin", "HEAD").returncode == 0


def push_raw_tree(work, entries: dict) -> None:
    """Commit `carryon/<name>` for each name -> content, names as raw BYTES.

    Through mktree rather than the index, because the names being tested are
    ones no filesystem on this machine will hold - a tree entry called '..',
    a name that is not valid UTF-8 - and git stores exactly the bytes it is
    given. That is what a remote gets to serve, whatever the local
    filesystem would have allowed.
    """
    lines = []
    for name, content in entries.items():
        blob = git("-C", work, "hash-object", "-w", "--stdin",
                   input=content).stdout.strip()
        lines.append(b"100644 blob " + blob + b"\t" + name)
    inner = git("-C", work, "mktree", input=b"\n".join(lines) + b"\n")
    assert inner.returncode == 0, inner.stderr
    outer = git("-C", work, "mktree",
                input=b"040000 tree " + inner.stdout.strip() + b"\tcarryon\n")
    assert outer.returncode == 0, outer.stderr
    env = dict(os.environ,
               GIT_AUTHOR_NAME="someone",
               GIT_AUTHOR_EMAIL="someone@example.invalid",
               GIT_COMMITTER_NAME="someone",
               GIT_COMMITTER_EMAIL="someone@example.invalid")
    commit = git("-C", work, "commit-tree", outer.stdout.strip().decode(),
                 "-m", "hostile", env=env)
    assert commit.returncode == 0, commit.stderr
    sha = commit.stdout.strip().decode()
    branch = git("-C", work, "symbolic-ref", "--short",
                 "HEAD").stdout.strip().decode() or "main"
    assert git("-C", work, "push", "--quiet", "-f", "origin",
               f"{sha}:refs/heads/{branch}").returncode == 0


def reject_pushes(origin, shell_body: bytes) -> None:
    """A remote that declines every push, saying whatever it likes about it.

    A pre-receive hook is how a server rejects, and git relays the hook's
    stderr verbatim - raw bytes, control characters and all - into the
    stderr carryon reads. It is the remote's string, so it is input.
    """
    hooks = origin / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "pre-receive"
    hook.write_bytes(b"#!/bin/sh\n" + shell_body)
    hook.chmod(0o755)


def dangle_remote_head(origin) -> None:
    """Point the remote's HEAD at a branch that is not there.

    Not an exotic state: a default branch deleted or renamed at the host
    leaves exactly this, and anyone with write access to the Destination can
    write the file. `git clone` then succeeds, warns, and checks nothing out.
    """
    (origin / "HEAD").write_bytes(b"ref: refs/heads/nope\n")


def seeded_origin(tmp_path) -> pathlib.Path:
    """A bare origin holding a small Archive, pushed by carryon itself."""
    origin = bare_origin(tmp_path)
    seed = GitDestination(str(origin), home=tmp_path / "seed-home")
    seed.write("carryon/index.enc", b"sealed")
    seed.write("carryon/sessions/a.tar.enc", b"one-session")
    return origin


# --- git's own output is input -----------------------------------------------


def test_a_remote_that_rejects_a_push_is_a_sentence_not_a_traceback(tmp_path):
    """git relays a server's message verbatim, and a server's message is the
    remote's string.

    `subprocess.run(text=True)` decodes it strictly, so one 0xff on the
    rejecting server's stderr is a UnicodeDecodeError raised INSIDE
    subprocess.run - before carryon has seen a return code, and out of the
    WRITE leg, where a push has usually put objects in the Archive already.
    The rclone type learned this for its listing and wrote it down; nothing
    carried it to the type beside it, whose every call decodes the same way.
    """
    origin = bare_origin(tmp_path)
    reject_pushes(origin,
                  b"printf 'declined: \\377\\376.enc\\n' >&2\n"
                  b"exit 1\n")
    dest = GitDestination(str(origin), home=tmp_path / "home")

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    assert "git" in str(exc.value).lower()


def test_a_rejecting_remote_cannot_erase_the_lines_printed_above_it(tmp_path):
    r"""The refusal carries the remote's sentence, so the remote gets a say in
    a line carryon prints - and \r plus CSI 2K blanks the lines already there,
    which is the suppression this module measures for an object name. Same
    string, one program further out."""
    origin = bare_origin(tmp_path)
    reject_pushes(origin,
                  b"printf 'no \\033[2K\\r  Setup: 6 file(s) written\\n' >&2\n"
                  b"exit 1\n")
    dest = GitDestination(str(origin), home=tmp_path / "home")

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    message = str(exc.value)
    for control in ("\r", "\x1b"):
        assert control not in message, \
            "a rejecting remote's control characters reached the terminal"
    assert "declined" in message or "git" in message.lower()


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_a_committed_name_that_is_not_utf8_does_not_traceback(name, tmp_path,
                                                              capsys):
    """A tree entry holds raw bytes, and the two platforms answer differently:
    a filesystem that will not hold the name makes git say so on stderr, WITH
    the name in it, and one that will hold it hands the name to the walk.

    Either way the answer is a sentence or a report line. What it may not be
    is a decode of git's stderr blowing up before carryon reads the exit
    code."""
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    push_raw_tree(work, {name: b"pwned\n", b"index.enc": b"sealed"})
    dest = GitDestination(str(origin), home=tmp_path / "home")

    try:
        keys = dest.list()
    except SystemExit as exc:
        # the checkout refused the name; carryon says so and keeps no clone
        assert "git" in str(exc).lower()
        assert not dest.clone_dir.exists(), \
            "a clone that failed to check out was left behind"
        return
    assert keys == ["carryon/index.enc"], keys
    assert "skipping" in capsys.readouterr().out, \
        "a key no machine can spell was dropped without a word"


def test_a_committed_dotdot_path_does_not_escape_the_clone(tmp_path):
    """A tree entry literally called '..' is a path outside the clone, and the
    clone sits at a fixed depth under $HOME. git's own checkout refuses it;
    what carryon owes is a sentence and no half-clone left at that name."""
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    push_raw_tree(work, {b"..": b"pwned\n"})
    dest = GitDestination(str(origin), home=tmp_path / "home")

    with pytest.raises(SystemExit) as exc:
        dest.list()
    assert "git" in str(exc.value).lower()
    assert not (tmp_path / "home" / ".carryon" / "pwned").exists()
    assert not dest.clone_dir.exists()


# --- what the clone holds is the remote's answer, not carryon's --------------


def test_a_fresh_clone_is_not_assumed_to_be_at_the_remote_head(tmp_path):
    """`_sync` returned early on a fresh clone - 'a fresh clone is already at
    the remote head' - which is an assumption about git, and the remote sets
    what git does.

    A remote whose HEAD names a branch that is not there makes `git clone`
    exit 0, warn, and check nothing out. Every object in the Archive then
    reads absent for the rest of that first operation, and the SECOND
    operation of the same run - which syncs properly - answers correctly.
    Two answers to one question in one run, and the wrong one comes first:
    an absent index.enc is how a fresh Archive looks, so a push reads a
    populated Archive as empty."""
    origin = seeded_origin(tmp_path)
    dangle_remote_head(origin)
    dest = GitDestination(str(origin), home=tmp_path / "home")

    assert dest.list() == ["carryon/index.enc",
                           "carryon/sessions/a.tar.enc"], \
        "the first operation of a run read a populated Archive as empty"
    assert dest.read("carryon/index.enc") == b"sealed"


def test_a_write_lands_on_the_branch_the_reads_come_from(tmp_path):
    """Reads come off whatever ref `_remote_head` picks; writes went to
    whatever branch the clone happened to be on, and nothing tied the two
    together.

    With the remote's HEAD naming a missing branch the clone sits on that
    name, so one `push --apply` committed the Archive's whole new state onto
    a branch nobody had ever read - and then, the branch now existing, every
    later reader reset to it and saw an Archive holding that one object and
    nothing else. Every stored Session gone from every machine's view, at
    exit 0."""
    origin = seeded_origin(tmp_path)
    before = GitDestination(str(origin), home=tmp_path / "before").list()
    dangle_remote_head(origin)

    writer = GitDestination(str(origin), home=tmp_path / "writer")
    writer.write("carryon/sessions/b.tar.enc", b"another-session")

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    keys = reader.list()
    for key in before:
        assert key in keys, \
            f"{key} left every reader's view when one object was pushed"
    assert "carryon/sessions/b.tar.enc" in keys, \
        "the pushed object landed where no reader looks"


def test_a_detached_head_in_the_clone_does_not_wedge_every_push(tmp_path):
    """`git push origin HEAD` names its destination after the local branch, so
    from a detached HEAD it fails - permanently, since nothing carryon does
    re-attaches one. The clone is a cache carryon resets hard on every sync;
    a state it can reset out of must not be a state it stops working in."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", b"v1")
    assert git("-C", dest.clone_dir, "checkout", "--quiet", "--detach",
               "HEAD").returncode == 0

    dest.write("carryon/index.enc", b"v2")

    other = GitDestination(str(origin), home=tmp_path / "home-2")
    assert other.read("carryon/index.enc") == b"v2", \
        "a write from a detached clone never reached the remote"


def test_a_dirty_clone_left_by_an_interrupted_push_does_not_reach_the_archive(
        tmp_path):
    """The clone is a cache, so `reset --hard` plus `clean` is the whole
    recovery from an interrupted push - a commit that never went out, and
    files left in the tree. Neither may survive into the Archive, and neither
    may cost the object another machine pushed meanwhile."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", b"v1")

    # a commit that was never pushed, plus an uncommitted file beside it
    (dest.clone_dir / "carryon" / "stray.enc").write_bytes(b"never-pushed")
    git("-C", dest.clone_dir, "add", "-A")
    git("-C", dest.clone_dir, "-c", "user.name=x", "-c", "user.email=x@y",
        "commit", "--quiet", "-m", "interrupted")
    (dest.clone_dir / "carryon" / "dirty.enc").write_bytes(b"uncommitted")

    elsewhere = GitDestination(str(origin), home=tmp_path / "home-2")
    elsewhere.write("carryon/other.enc", b"from-the-other-machine")

    assert dest.list() == ["carryon/index.enc", "carryon/other.enc"]
    dest.write("carryon/index.enc", b"v2")
    assert elsewhere.list() == ["carryon/index.enc", "carryon/other.enc"], \
        "an interrupted push's residue reached the Archive"


def test_a_tree_that_changes_between_two_fetches_answers_with_the_second(
        tmp_path):
    """Every unbatched operation fetches, so a remote is free to change under
    a run. What matters is that the change is a change and not a crash, and
    that a batch - which syncs once and then reads every key - is not
    re-synced underneath itself."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/setups/mac/settings.json", HONEST)
    assert dest.read("carryon/setups/mac/settings.json") == HONEST

    other = GitDestination(str(origin), home=tmp_path / "home-2")
    other.write("carryon/setups/mac/settings.json", b'{"model": "haiku"}')

    assert dest.read("carryon/setups/mac/settings.json") == \
        b'{"model": "haiku"}'

    with dest._batch():
        other.write("carryon/setups/mac/settings.json", b'{"model": "sonnet"}')
        assert dest.read("carryon/setups/mac/settings.json") == \
            b'{"model": "haiku"}', "a batch re-synced in the middle of itself"


def test_a_repository_that_is_not_a_repository_is_a_sentence(tmp_path):
    """Two spellings of it: a URL that was never a repository, and a clone
    whose own .git has been damaged since. Both are user-facing refusals, and
    neither may leave a directory behind that the next run mistakes for a
    working clone."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    (plain / "readme").write_text("just a directory")
    dest = GitDestination(str(plain), home=tmp_path / "home")
    with pytest.raises(SystemExit) as exc:
        dest.list()
    assert "git" in str(exc.value).lower()
    assert not dest.clone_dir.exists(), \
        "a failed clone left something at the clone's name"

    origin = bare_origin(tmp_path)
    live = GitDestination(str(origin), home=tmp_path / "home-2")
    live.write("carryon/index.enc", b"v1")
    (live.clone_dir / ".git" / "HEAD").unlink()
    with pytest.raises(SystemExit) as exc:
        live.list()
    assert "git" in str(exc.value).lower()


def test_core_symlinks_false_does_not_turn_a_committed_link_into_a_read(
        tmp_path, monkeypatch):
    """With core.symlinks=false git stores a committed symlink as an ordinary
    file holding the target's PATH, so the walk's symlink rule never fires -
    a second machine, same Archive, different answer.

    The property that has to hold either way is the one the rule is for: the
    target's BYTES do not come back. A path string does, which is the
    attacker's own string in a plaintext Setup and no worse than any other
    byte they can commit there."""
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    setup = work / "carryon" / "setups" / "mac"
    setup.mkdir(parents=True)
    (setup / "settings.json").write_bytes(HONEST)
    os.symlink(str(secret_file(tmp_path)), setup / "CLAUDE.md")
    commit_all(work)

    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[core]\n\tsymlinks = false\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    dest = GitDestination(str(origin), home=tmp_path / "home")

    staging = tmp_path / "staging"
    dest.read_tree(SETUP_PREFIX, staging)
    staged = {p.name: p.read_bytes()
              for p in staging.rglob("*") if p.is_file()}
    assert staged.get("settings.json") == HONEST
    assert SECRET not in staged.values(), \
        "core.symlinks=false read a committed link through to its target"
    for content in staged.values():
        assert SECRET not in content


def test_a_committed_symlink_at_a_directory_position_hides_what_is_under_it(
        tmp_path, capsys):
    """The file position is covered above; a link where a DIRECTORY belongs is
    the one that makes 'skills/SKILL.md' a read of somebody else's file with
    no '..' anywhere in the key. Both must be named, and neither read."""
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    setup = work / "carryon" / "setups" / "mac"
    setup.mkdir(parents=True)
    (setup / "settings.json").write_bytes(HONEST)
    outside = secret_file(tmp_path).parent
    os.symlink(str(outside), setup / "skills")
    os.symlink(str(outside / "id_ed25519"), setup / "CLAUDE.md")
    commit_all(work)

    dest = GitDestination(str(origin), home=tmp_path / "home")
    keys = dest.list()
    out = capsys.readouterr().out

    assert keys == [SETUP_PREFIX + "/settings.json"], keys
    assert "skills" in out and "CLAUDE.md" in out
    assert dest.read(SETUP_PREFIX + "/skills/id_ed25519") is None
    assert dest.read(SETUP_PREFIX + "/CLAUDE.md") is None


def test_a_deleted_pairing_object_stays_in_the_git_history(tmp_path):
    """ADR-0005 says the delete is a commit and the wrapped master key stays
    fetchable, which is why it says a key paired over git should be rotated.

    Asserted rather than assumed: it is the reason a whole ADR consequence
    exists, and a later change to how delete works could quietly make the
    document wrong in either direction."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/pairing/ABCDEF", b"WRAPPED-MASTER-KEY-NOT-A-REAL-ONE")
    dest.delete("carryon/pairing/ABCDEF")

    assert dest.list("carryon/pairing/") == []
    assert dest.read("carryon/pairing/ABCDEF") is None

    attacker = tmp_path / "attacker"
    assert git("clone", "--quiet", origin, attacker).returncode == 0
    objects = git("-C", attacker, "rev-list", "--objects",
                  "--all").stdout.decode()
    recovered = [git("-C", attacker, "cat-file", "-p",
                     line.split()[0]).stdout
                 for line in objects.splitlines() if "ABCDEF" in line]
    assert b"WRAPPED-MASTER-KEY-NOT-A-REAL-ONE" in recovered, \
        "ADR-0005 says the blob stays fetchable; it no longer does, so the " \
        "document needs changing rather than this test"

    adr = (pathlib.Path(__file__).resolve().parents[1] / "docs" / "adr"
           / "0005-pairing-goes-through-the-destination.md").read_text()
    assert "stays in the history" in adr and "rotated" in adr, \
        "the behaviour above is only tolerable because a document says so"


# =============================================================================
# RCLONE, AGAINST A FAKE BINARY THAT BACKS A WHOLE ARCHIVE
# =============================================================================
#
# The only type whose write is not a syscall that either moved the bytes or
# raised: rclone answers with an exit code, and an exit code is the remote's
# word about what it did. The module already says so of its LISTING - read as
# bytes, decoded leniently, because S3, B2 and sftp all allow arbitrary bytes
# in a key. The two verbs whose output is not a listing were left decoding
# strictly, which is the same sentence one verb over.
#
# The store below is a real one - copyto, cat, lsf -R, deletefile over a local
# root - with knobs for the ways a remote misbehaves that no local filesystem
# can: a verb that answers with bytes nothing can decode, a copyto that
# reports success and moves nothing, a listing of the remote's own choosing
# that is not the same twice, and a listing that is empty because the remote
# errored rather than because the Archive is.

FAKE_RCLONE_STORE = r'''#!__PY__
import base64, json, pathlib, shutil, sys

ROOT = pathlib.Path("__ROOT__")
CTL = pathlib.Path("__CTL__")
LOG = pathlib.Path("__LOG__")

argv = sys.argv[1:]
with LOG.open("a") as fh:
    fh.write(" ".join(argv) + "\n")
ctl = json.loads(CTL.read_text() or "{}") if CTL.is_file() else {}
verb = argv[0] if argv else ""
rest = [a for a in argv[1:] if not a.startswith("-")]


def resolve(spec):
    if spec.startswith("fakeremote:"):
        return ROOT / spec[len("fakeremote:"):]
    return pathlib.Path(spec)


def rel_of(spec):
    """The key `spec` names, or None for a path that is not on the remote."""
    if spec.startswith("fakeremote:"):
        return spec[len("fakeremote:"):].strip("/")
    return None


def under(here, key):
    """`key`'s own next component when it sits directly in `here`, else None."""
    if here is None:
        return None
    rest = key[len(here):].lstrip("/") if here and key.startswith(here) else (
        key if not here else None)
    if rest is None or not rest or "/" in rest:
        return None
    return rest


def deep_calls():
    """How many recursive listings have happened, this one included."""
    n = 0
    for line in LOG.read_text().splitlines():
        parts = line.split(" ")
        if parts[:1] == ["lsf"] and "-R" in parts:
            n += 1
    return n


garble = ctl.get("garble", {}).get(verb)
if garble is not None:
    sys.stderr.buffer.write(base64.b64decode(garble))
    raise SystemExit(ctl.get("garble_code", 1))

fail = ctl.get("fail", {}).get(verb)
if fail is not None:
    sys.stderr.write("fake rclone: %s refused\n" % verb)
    raise SystemExit(fail)

if verb == "lsf":
    deep = "-R" in argv
    canned = ctl.get("listing")
    if canned is not None and deep:
        raw = canned[min(deep_calls() - 1, len(canned) - 1)]
        sys.stdout.buffer.write(base64.b64decode(raw))
        raise SystemExit(0)
    spec = rest[0] if rest else "fakeremote:"
    target = resolve(spec)
    here = rel_of(spec)
    shadow = ctl.get("shadow", {})
    if not target.is_dir():
        sys.stderr.write("directory not found\n")
        raise SystemExit(3)
    if "--dirs-only" in argv:
        found = target.rglob("*") if deep else target.iterdir()
        names = set(p.relative_to(target).as_posix()
                    for p in found if p.is_dir())
        # a key that is an object AND a prefix answers as both, which is what
        # a flat key store does and a local filesystem cannot
        names |= set(under(here, key) for key in shadow
                     if under(here, key) is not None)
    else:
        found = target.rglob("*") if deep else target.iterdir()
        names = set(p.relative_to(target).as_posix()
                    for p in found if p.is_file())
    listing = sorted(names)
    out = ("\n".join(listing) + "\n").encode() if listing else b""
    sys.stdout.buffer.write(out)
elif verb == "copyto":
    src, dst = resolve(rest[0]), resolve(rest[1])
    if ctl.get("copyto_noop"):
        raise SystemExit(0)          # "uploaded", moved nothing: dry_run
    if not src.is_file():
        sys.stderr.write("source not found\n")
        raise SystemExit(1)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(src), str(dst))
elif verb == "cat":
    target = resolve(rest[0])
    extra = ctl.get("shadow", {}).get(rel_of(rest[0]))
    if not target.is_file():
        sys.stderr.write("object not found\n")
        raise SystemExit(1)
    # rclone cat on a prefix concatenates every object under it and exits 0,
    # so a key that is both serves its own bytes plus somebody else's
    sys.stdout.buffer.write(target.read_bytes()
                            + (base64.b64decode(extra) if extra else b""))
elif verb == "deletefile":
    target = resolve(rest[0])
    noop = ctl.get("deletefile_noop")
    if noop and (noop is True or noop in rest[0]):
        raise SystemExit(0)          # "deleted", removed nothing
    if not target.is_file():
        sys.stderr.write("object not found\n")
        raise SystemExit(1)
    target.unlink()
else:
    sys.stderr.write("unknown verb %s\n" % verb)
    raise SystemExit(2)
'''


class RcloneStore:
    """The store behind 'fakeremote:', and the knobs that make it misbehave."""

    def __init__(self, root, control, log):
        self.root, self.control, self.log = root, control, log

    def _control(self) -> dict:
        if not self.control.is_file():
            return {}
        return json.loads(self.control.read_text() or "{}")

    def _set(self, **kw):
        current = self._control()
        current.update(kw)
        self.control.write_text(json.dumps(current))

    def garble(self, verb, raw: bytes, code: int = 1):
        """Make `verb` fail, saying exactly these bytes on its stderr.

        Base64 through the control file, because the point of the knob is
        bytes no JSON string and no strict decode will hold."""
        current = dict(self._control().get("garble", {}))
        current[verb] = base64.b64encode(raw).decode()
        self._set(garble=current, garble_code=code)

    def fail(self, verb, code=1):
        self._set(fail={verb: code})

    def listing(self, *raws):
        """Answer lsf -R with these bytes - one per call, last repeats."""
        self._set(listing=[base64.b64encode(raw).decode() for raw in raws])

    def copyto_writes_nothing(self, on=True):
        self._set(copyto_noop=bool(on))

    def deletefile_removes_nothing(self, on=True, only=None):
        """A delete that exits 0 and removes nothing - RCLONE_DRY_RUN in this
        machine's environment, or a filter rule of the user's own. No local
        filesystem can spell it, which is why it is a knob.

        `only` limits the lie to targets containing that text, which is a
        SELECTIVE store - one no rclone.conf produces and any hostile remote
        can. The blanket spelling now meets ADR-0011's reachability probe
        before it meets anything else, so the selective one is what still
        reaches the legs downstream of `init`.
        """
        self._set(deletefile_noop=(only if on and only else bool(on)))

    def also_a_prefix(self, key: str, appended: bytes):
        """Make `key` an object AND a prefix, the way S3, B2 and GCS allow.

        The store behind 'fakeremote:' is a local directory, which cannot hold
        a name that is both - so the shape is modelled from the outside, where
        carryon stands: `lsf --dirs-only` on the parent answers with the leaf
        as a directory too, and `cat` on the key concatenates every object
        under the prefix onto the object's own bytes and exits 0, which is
        rclone's documented behaviour on a directory.
        """
        current = dict(self._control().get("shadow", {}))
        current[key.strip("/")] = base64.b64encode(appended).decode()
        self._set(shadow=current)

    def objects(self):
        return sorted(p.relative_to(self.root).as_posix()
                      for p in self.root.rglob("*") if p.is_file())


def install_rclone_store(tmp_path, monkeypatch, container="archive"
                         ) -> RcloneStore:
    """The store, with `container` already present.

    Present because on an object store the first component of a path IS a
    bucket, and ADR-0011's probe refuses to write into one that is not
    there rather than let rclone's upload conjure it. Every caller here
    drives a Destination that a user has already got, so the bucket
    existing is the state they are all in; `container=None` is the other
    one, and the probe's refusal is its own test.
    """
    root = tmp_path / "rclone-store"
    root.mkdir(exist_ok=True)
    if container:
        (root / container).mkdir(exist_ok=True)
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    control = tmp_path / "rclone-control.json"
    control.write_text("{}")
    log = tmp_path / "rclone-argv.log"
    log.write_text("")
    script = bin_dir / "rclone"
    script.write_text(FAKE_RCLONE_STORE
                      .replace("__PY__", sys.executable)
                      .replace("__ROOT__", str(root))
                      .replace("__CTL__", str(control))
                      .replace("__LOG__", str(log)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return RcloneStore(root, control, log)


# --- rclone's own output is input, on every verb and not just the listing ----


@pytest.mark.parametrize("verb", ["copyto", "deletefile"])
def test_an_rclone_verb_whose_message_is_not_utf8_does_not_traceback(
        verb, tmp_path, monkeypatch, capsys):
    """The listing is read as bytes and decoded leniently, and the module says
    why: S3, B2 and sftp all allow arbitrary bytes in a key, so a strict
    decode is a permanent abort for the price of one PUT. rclone puts the
    object's name in its error messages too, and copyto and deletefile were
    still asking subprocess to decode those strictly - so the same planted
    name comes back as a UnicodeDecodeError from inside subprocess.run, on
    the write leg and on the delete that ends a pairing."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/index.enc", b"sealed")   # so a delete has work to do
    capsys.readouterr()
    store.garble(verb, b"failed: object bad\xff\xfe.enc: no such object\n")

    if verb == "copyto":
        with pytest.raises(SystemExit) as exc:
            dest.write("carryon/index.enc", b"sealed")
        assert "rclone" in str(exc.value) or "index.enc" in str(exc.value)
    else:
        dest.delete("carryon/index.enc")     # a delete is reported, not raised
        out = capsys.readouterr().out
        assert "index.enc" in out and "skipping" in out
        assert "\x1b" not in out and "\r" not in out


def test_an_rclone_message_cannot_erase_the_lines_printed_above_it(
        tmp_path, monkeypatch):
    r"""The remote's sentence rides into carryon's refusal, so \r and CSI 2K
    in it blank the lines already printed - the same suppression an object
    name gets escaped for, arriving through the error message instead."""
    store = install_rclone_store(tmp_path, monkeypatch)
    store.garble("copyto",
                 b"no \x1b[2K\r  Setup: 6 file(s) written, 0 refused\n")
    dest = RcloneDestination("fakeremote:archive")

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    message = str(exc.value)
    for control in ("\r", "\x1b"):
        assert control not in message, \
            "a remote's error message reached the terminal unescaped"


# --- a write is not done because rclone said so ------------------------------


def test_the_write_confirmation_is_not_vacuous_on_the_second_write(
        tmp_path, monkeypatch):
    """The round-7 finding, checked rather than assumed fixed: a confirmation
    that asks whether a key of that name EXISTS is evidence for a create and
    nothing at all for an update, and every write after the first is an
    update.

    So the second write of the same key, against a store that reports success
    and moves nothing, has to stop - and the object still holding the first
    version is what makes it stop, since a stale object's seal verifies
    perfectly."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/index.enc", b"first")
    assert dest.read("carryon/index.enc") == b"first"

    store.copyto_writes_nothing()
    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"second")
    assert "carryon/index.enc" in str(exc.value)
    assert dest.read("carryon/index.enc") == b"first", \
        "the store was serving the old bytes and the write was called done"


def test_a_copyto_that_reports_success_and_stores_nothing_stops_the_write(
        tmp_path, monkeypatch):
    """The create case, which is the one the old check did answer."""
    store = install_rclone_store(tmp_path, monkeypatch)
    store.copyto_writes_nothing()
    dest = RcloneDestination("fakeremote:archive")

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    assert "carryon/index.enc" in str(exc.value)
    assert store.objects() == []


# --- a listing is the remote's answer ----------------------------------------


def test_a_hostile_listing_is_refused_key_by_key_not_wholesale(tmp_path,
                                                               monkeypatch,
                                                               capsys):
    """'..', an absolute key, an empty component, a lone surrogate and bytes
    that are not UTF-8 at all - the five shapes no local filesystem produces
    and a remote can print freely. Each costs its own key and none of them
    costs the honest one beside it."""
    store = install_rclone_store(tmp_path, monkeypatch)
    store.listing(("carryon/index.enc\n"
                   "carryon/../../../../etc/passwd\n"
                   "/etc/passwd\n"
                   "carryon//empty.enc\n"
                   "carryon/lone\udcffsurrogate.enc\n"
                   ).encode("utf-8", "surrogateescape")
                  + b"carryon/raw\xff\xfe.enc\n")
    dest = RcloneDestination("fakeremote:archive")

    keys = dest.list()
    out = capsys.readouterr().out

    assert keys == ["carryon/index.enc"], keys
    assert out.count("skipping") >= 5, out
    for control in ("\r", "\x1b"):
        assert control not in out


def test_a_listing_that_changes_between_two_calls_in_one_run(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    """A remote is free to answer differently twice, and read_tree lists and
    then reads. A key that has gone by the time it is read is absent, which
    is the ordinary silent case; what may not happen is the run ending on
    it."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/setups/mac/settings.json", HONEST)
    store.listing(b"carryon/setups/mac/settings.json\n",
                  (b"carryon/setups/mac/settings.json\n"
                   b"carryon/setups/mac/gone.json\n"))

    assert dest.list() == ["carryon/setups/mac/settings.json"]
    staging = tmp_path / "staging"
    dest.read_tree(SETUP_PREFIX, staging)   # the second listing offers a ghost

    staged = {p.name: p.read_bytes()
              for p in staging.rglob("*") if p.is_file()}
    assert staged == {"settings.json": HONEST}


def test_an_empty_listing_that_is_really_a_refusal_is_not_an_empty_archive(
        tmp_path, monkeypatch):
    """Exit 3 is rclone's 'directory not found', which is what an Archive
    nobody has pushed to answers with. Every other non-zero exit is the
    remote saying it could not tell carryon, and reading that as emptiness is
    how a push seals a fresh catalogue over a populated Archive."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/index.enc", b"sealed")

    store.fail("lsf", 3)
    assert dest.list() == [], "exit 3 is the fresh-Archive answer"

    store.fail("lsf", 1)
    with pytest.raises(SystemExit) as exc:
        dest.list()
    assert "rclone" in str(exc.value)


def test_a_verb_that_starts_failing_mid_run_names_the_object(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    """A cat that fails on an object the listing still holds is that object
    being refused, not absent: answering None there is the silence ADR-0009
    rules out, and a Setup that arrives short reads as a pull that worked."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/setups/mac/settings.json", HONEST)
    assert dest.list() == [SETUP_PREFIX + "/settings.json"]
    capsys.readouterr()

    store.fail("cat", 6)     # rclone's "less serious errors"
    assert dest.read(SETUP_PREFIX + "/settings.json") is None
    out = capsys.readouterr().out
    assert "settings.json" in out and "skipping" in out


# =============================================================================
# THE WHOLE JOURNEY, AND THEN THE SAME JOURNEY WITH THE REMOTE TURNED HOSTILE
# =============================================================================
#
# A type driven one verb at a time is a type driven in one state. Every
# defect above is about what happens when a verb answers something other than
# the one answer a unit test gave it, and the only way to ask that of a whole
# run is to have a whole run: init, push --apply, pair, join, pull --apply,
# over a bare repository on local disk with nothing else standing in.

RECOVERY_KEY = r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}"
_PAIR_CHAR = "[A-HJKMNP-TV-Z0-9]"
PAIR_CODE = r"--join ({c}{{4}}(?:-{c}{{4}}){{3}})(?!\S)".format(c=_PAIR_CHAR)
U1 = "11111111-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def file_keyring(monkeypatch):
    """Never let a test near the real OS keychain."""
    monkeypatch.setattr(keyring, "_backend", lambda platform=None: "file")


def ns(**kw):
    base = dict(dest=None, join=None, machine=None, apply=False, agent=None,
                category=None, force=False)
    base["map"] = []
    base.update(kw)
    return argparse.Namespace(**base)


def build_claude_home(tmp_path, name):
    """A minimal Claude Code machine: a Setup and one Session."""
    home = tmp_path / name
    cwd = str(home / "code" / "app")
    claude = home / ".claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"model": "opus"}')
    (claude / "CLAUDE.md").write_text("Answer briefly.\n")
    project = claude / "projects" / rekey.encode_project_dir(cwd)
    project.mkdir(parents=True)

    def jline(obj):
        return json.dumps(obj, separators=(",", ":")) + "\n"

    (project / (U1 + ".jsonl")).write_text(
        jline({"cwd": cwd, "type": "meta"})
        + jline({"type": "user", "text": f"see {cwd}/main.py"}))
    return home


def test_a_whole_journey_runs_against_a_git_remote(tmp_path, capsys):
    """init, push, pair, join, pull - the full trip, over git only, against a
    bare repository and no network."""
    origin = bare_origin(tmp_path)
    spec = "git:" + str(origin)

    home_a = build_claude_home(tmp_path, "home_a")
    assert sync.init(ns(dest=spec, machine="mac-a"), home_a) == 0
    assert re.search(RECOVERY_KEY, capsys.readouterr().out)
    assert sync.push(ns(apply=True), home_a) == 0
    capsys.readouterr()

    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    home_b = build_claude_home(tmp_path, "home_b")
    assert sync.init(ns(dest=spec, join=code, machine="box-b"), home_b) == 0
    capsys.readouterr()
    assert sync.pull(ns(apply=True), home_b) == 0
    out = capsys.readouterr().out

    landed = (home_b / ".claude" / "projects"
              / rekey.encode_project_dir(str(home_b / "code" / "app"))
              / (U1 + ".jsonl"))
    assert landed.is_file(), out
    text = landed.read_text()
    assert str(home_b) in text, "the incoming Transcript was not re-keyed to B"
    assert str(home_a) not in text, "A's home reached B's disk"
    assert (home_b / ".claude" / "CLAUDE.md").read_text() == \
        "Answer briefly.\n"


def test_the_same_journey_survives_a_remote_somebody_else_commits_to(tmp_path,
                                                                     capsys):
    """The re-drive. Between A's push and B's pull, somebody with write access
    to the repository commits the two things a git tree can hold that a
    Destination does not get to serve: a symlink standing at an object's key,
    and a directory standing where a blob belongs.

    Neither may abort the pull - one planted object that raises is a
    permanent abort on every pull from every machine - and neither may put
    the link's target anywhere near B's disk."""
    origin = bare_origin(tmp_path)
    spec = "git:" + str(origin)

    home_a = build_claude_home(tmp_path, "home_a")
    assert sync.init(ns(dest=spec, machine="mac-a"), home_a) == 0
    assert sync.push(ns(apply=True), home_a) == 0
    assert sync.pair(ns(), home_a) == 0
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    work = worktree(tmp_path, origin)
    planted = work / "carryon" / "sessions"
    planted.mkdir(parents=True, exist_ok=True)
    os.symlink(str(secret_file(tmp_path)), planted / "planted.tar.enc")
    (planted / "adir.tar.enc").mkdir()
    (planted / "adir.tar.enc" / "inside").write_bytes(b"not an object")
    commit_all(work, "planted by somebody else")

    home_b = build_claude_home(tmp_path, "home_b")
    assert sync.init(ns(dest=spec, join=code, machine="box-b"), home_b) == 0
    capsys.readouterr()
    code_out = sync.pull(ns(apply=True), home_b)
    out = capsys.readouterr().out

    assert code_out in (0, 1), out
    assert "Traceback" not in out
    landed = (home_b / ".claude" / "projects"
              / rekey.encode_project_dir(str(home_b / "code" / "app"))
              / (U1 + ".jsonl"))
    assert landed.is_file(), out
    for path in home_b.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert SECRET not in path.read_bytes(), \
                f"the planted link's target reached {path}"

    # and A can still push into the repository somebody else has been
    # committing to: a planted object is one object, not the Archive
    (home_a / ".claude" / "CLAUDE.md").write_text("Answer at length.\n")
    assert sync.push(ns(apply=True), home_a) == 0, capsys.readouterr().out


def test_the_clone_directory_is_answered_for_and_not_only_its_parent(tmp_path):
    """`_clone_room` asks whose `~/.carryon/git` is before a clone goes in it,
    and the clone does not go there: it goes one component down, at
    `~/.carryon/git/<slug>`, which nothing asked about.

    With a link at that name the whole clone lands in the linked tree -
    `.git`, index.enc and every plaintext Setup file in the Archive - and
    unlike the push's staging tree nothing sweeps a clone up afterwards. That
    is verbatim the harm `_clone_room`'s own docstring is about, at the
    component below the one it answers for, which is the shape ADR-0009 keeps
    naming: a rule closed at an item's root and open at its members.

    The slug is sha256 of the Destination URL, so it is not a secret - the
    URL is in ~/.carryon/config.json, and a name anyone can compute is a name
    anyone can plant."""
    origin = seeded_origin(tmp_path)
    home = tmp_path / "home"
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    dest = GitDestination(str(origin), home=home)
    (home / ".carryon" / "git").mkdir(parents=True)
    os.symlink(str(dotfiles), dest.clone_dir)

    with pytest.raises(SystemExit) as exc:
        dest.list()
    assert "carryon" in str(exc.value)
    assert sorted(p.name for p in dotfiles.iterdir()) == [], \
        "a whole clone was written through a link into somebody else's tree"


def test_the_remote_names_the_branch_and_a_write_goes_back_to_it(tmp_path):
    """The branch is the remote's choice too, and rebuilding 'refs/heads/<x>'
    out of the tracking ref has to survive what a remote may call it - a '/'
    in a branch name is ordinary and is the one that a naive split loses."""
    origin = bare_origin(tmp_path)
    seed = GitDestination(str(origin), home=tmp_path / "seed")
    seed.write("carryon/index.enc", b"v1")
    default = git("-C", origin, "symbolic-ref",
                  "HEAD").stdout.decode().strip()
    assert git("-C", origin, "branch", "-m",
               default.split("/")[-1], "carryon/archive").returncode == 0

    dest = GitDestination(str(origin), home=tmp_path / "home")
    assert dest.read("carryon/index.enc") == b"v1"
    dest.write("carryon/index.enc", b"v2")

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    assert reader.read("carryon/index.enc") == b"v2"
    assert git("-C", origin, "for-each-ref", "--format=%(refname)",
               "refs/heads").stdout.decode().split() == \
        ["refs/heads/carryon/archive"], \
        "the write invented a branch of its own beside the remote's"


def test_a_committed_symlink_standing_at_a_write_key_stops_the_push(tmp_path):
    """The write side's posture, in the one spelling `git clean` cannot sweep
    away: a link committed at an object's key comes back on every sync.

    Refused rather than skipped, and loudly - a push that quietly did not
    happen is worse than one that says why, and there is no attacker-chosen
    object here to abandon, only the blob carryon itself is pushing. The cost
    is that a remote can stop every push with one commit, which is the trade
    ADR-0009 makes on purpose and the reason the sentence has to name the key
    and say nothing carryon wrote put it there."""
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    (work / "carryon").mkdir()
    os.symlink(str(secret_file(tmp_path)), work / "carryon" / "index.enc")
    commit_all(work)

    dest = GitDestination(str(origin), home=tmp_path / "home")
    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    message = str(exc.value)
    assert "carryon/index.enc" in message and "symlink" in message
    assert dest.read("carryon/index.enc") is None, \
        "the refused write left the link readable as an object"


# =============================================================================
# GIT'S WRITE IS ANOTHER PROGRAM'S EXIT CODE, AND ITS CLONE IS A NAME
# =============================================================================
#
# Two rules this layer already states, applied to the one type that had
# neither. The clone directory is answered for on the run that CLONES and on
# no other, and `.is_dir()` follows a symlink - so the guard is unreachable
# exactly when the link points at something that already holds a `.git`, which
# is what a dotfiles repository is and what `_clone_room`'s own docstring
# describes. And `base._confirm_write`'s default is "the write already
# answered", which is true of a syscall and false of git: the syscall writes
# into a CACHE, and the Archive-facing half is add/commit/push, every step of
# which has a documented way to succeed and move nothing.


def dotfiles_repo(tmp_path, name="dotfiles"):
    """A repository somebody else manages, with its own remote and history.

    Not an empty directory: the guard under test is only reachable when the
    planted link points at a tree that does NOT already hold a `.git`, so a
    test that plants it on an empty directory is testing the one target that
    keeps the check alive.
    """
    their_origin = bare_origin(tmp_path, name + "-origin.git")
    repo = worktree(tmp_path, their_origin, name)
    (repo / "README").write_text("theirs\n")
    commit_all(repo, "their own work")
    assert git("-C", repo, "push", "--quiet", "origin", "HEAD").returncode == 0
    (repo / "work-in-progress").write_text("not committed yet\n")
    return repo, their_origin


def keys_in(origin):
    """Every path at the head of a bare repository, as a set."""
    listing = git("-C", origin, "ls-tree", "-r", "--name-only", "HEAD")
    return set(listing.stdout.decode("utf-8", "surrogateescape").split())


def test_a_clone_directory_linked_at_a_real_repository_is_still_refused(
        tmp_path):
    """The guard is asked on the run that clones, and only then.

    `_sync` calls `_clone_room()` inside `if not (clone_dir / '.git')
    .is_dir()`, and `is_dir()` follows a symlink - so a link pointing at any
    directory that already holds a `.git` walks straight past it. A dotfiles
    repository is that directory by definition, and it is the example
    `_clone_room`'s own docstring gives.

    What it cost, measured: `push --apply` at exit 0 printing 'Setup: pushed
    (clean)', with index.enc, the session tar and every plaintext Setup file
    committed and PUSHED to the user's dotfiles remote, `clean -fdq` deleting
    an untracked file in that tree, and carryon's own Destination left empty.
    """
    origin = seeded_origin(tmp_path)
    home = tmp_path / "home"
    repo, their_origin = dotfiles_repo(tmp_path)
    dest = GitDestination(str(origin), home=home)
    (home / ".carryon" / "git").mkdir(parents=True)
    os.symlink(str(repo), dest.clone_dir)

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    assert "carryon" in str(exc.value)
    assert keys_in(their_origin) == {"README"}, \
        "carryon pushed its Archive to somebody else's remote"
    assert (repo / "work-in-progress").is_file(), \
        "`git clean` swept a file out of a repository carryon does not own"


def test_a_git_directory_that_is_a_link_is_refused_too(tmp_path):
    """The same root cause, one component further in.

    A REAL directory at ~/.carryon/git/<slug> with a symlink at its `.git`:
    `state_write_path` answers for the two components it makes and says
    nothing about what is inside them, and git reads `.git` as the repository
    to work in. The write returned normally, the victim repository's remote
    gained carryon/index.enc, and carryon's Destination stayed empty.
    """
    origin = seeded_origin(tmp_path)
    home = tmp_path / "home"
    repo, their_origin = dotfiles_repo(tmp_path)
    dest = GitDestination(str(origin), home=home)
    dest.clone_dir.mkdir(parents=True)
    os.symlink(str(repo / ".git"), dest.clone_dir / ".git")

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    assert ".git" in str(exc.value) or "carryon" in str(exc.value)
    assert keys_in(their_origin) == {"README"}, \
        "carryon pushed its Archive to somebody else's remote"


def test_a_committed_ignore_rule_cannot_make_a_push_a_silent_no_op(tmp_path):
    """One committed '.gitignore' line, from anyone with write access.

    `git add -A` is a successful no-op for anything an ignore rule matches,
    `status --porcelain` does not list ignored files so `_commit_push`
    returned 'nothing changed, nothing to push', and `clean -fdq` does not
    remove them either - so the local clone kept serving the bytes to the
    machine that wrote them and a read-back on this machine would have passed
    too. The push said 'Sessions: 1 pushed' and 'Setup: pushed (clean)' at
    exit 0 while the Archive received the plaintext Setup and no index.enc:
    the shape ADR-0009 says a pull must refuse. Then the local high-water mark
    advanced past an Index that was never stored, and every later push refused
    for ever as a rollback - carryon manufacturing the removal signal and
    wedging itself on it.
    """
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    (work / ".gitignore").write_text("*.enc\n")
    commit_all(work, "planted by somebody else")
    assert git("-C", work, "push", "--quiet", "origin", "HEAD").returncode == 0

    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", b"sealed")

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    assert reader.read("carryon/index.enc") == b"sealed", \
        "the Archive never received the object the write reported storing"


def test_the_users_own_global_excludes_cannot_make_a_push_a_no_op(
        tmp_path, monkeypatch):
    """The same defect with no hostile party at all.

    This module's rclone sibling already makes the argument one type over:
    'rclone reads the user's own rclone.conf ... dry_run = true there ...
    makes every copyto a successful no-op'. git reads the user's own gitconfig
    exactly that way, and a `core.excludesFile` naming a file with '*.enc' in
    it is an ordinary thing to have.
    """
    excludes = tmp_path / "global-ignore"
    excludes.write_text("*.enc\n")
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(f"[core]\n\texcludesFile = {excludes}\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))

    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", b"sealed")

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    assert reader.read("carryon/index.enc") == b"sealed", \
        "the user's own global excludes silently emptied the Archive"


def test_a_committed_gitattributes_cannot_rewrite_what_every_reader_sees(
        tmp_path):
    """A committed .gitattributes is the remote choosing what each checkout
    lays down.

    With '* text eol=crlf' committed, a write of b'\\x00sealed\\nbytes\\x01'
    came back byte-identical on the machine that wrote it and with every \\n
    doubled on every OTHER machine. The asymmetry is the sharp part: the
    pushing machine's report is clean, so nothing carryon prints where the key
    holder is looking ever shows it. The seal turns it into refusals rather
    than into wrong plaintext, so this is availability - one committed file
    and no reader can open the Archive.
    """
    sealed = b"\x00sealed\nciphertext\nbytes\x01"
    origin = bare_origin(tmp_path)
    work = worktree(tmp_path, origin)
    (work / ".gitattributes").write_text("* text eol=crlf\n")
    commit_all(work, "planted by somebody else")
    assert git("-C", work, "push", "--quiet", "origin", "HEAD").returncode == 0

    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", sealed)
    assert dest.read("carryon/index.enc") == sealed, \
        "the writing machine could not even read back its own bytes"

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    assert reader.read("carryon/index.enc") == sealed, \
        "the remote decided what a second machine's checkout laid down"


def test_an_honest_git_destination_still_carries_an_archive(tmp_path):
    """The control every refusal above is worth nothing without: a repository
    nobody has planted anything in still takes a write, serves it back, and
    serves it to a second machine."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/index.enc", b"sealed")
    dest.write("carryon/sessions/a.tar.enc", b"one-session")
    dest.delete("carryon/sessions/a.tar.enc")

    reader = GitDestination(str(origin), home=tmp_path / "reader")
    assert reader.read("carryon/index.enc") == b"sealed"
    assert reader.list("carryon/") == ["carryon/index.enc"]


# =============================================================================
# THE OBJECT STORE NEITHER FAKE COULD SPELL, AND THE DELETE NOBODY CONFIRMED
# =============================================================================
#
# Both fake rclone binaries resolve 'fakeremote:' onto a local directory, so
# the whole type had only ever been probed against a store that cannot hold a
# key which is both an object and a prefix, and has no way to spell a delete
# that exits 0 and removes nothing. S3, B2 and GCS all allow the first; the
# second is `RCLONE_DRY_RUN` in the environment or a filter rule of the user's
# own, which the module docstring already names one verb over. Both are knobs
# on the store now, modelled from the outside - what carryon can observe -
# rather than by pretending the local filesystem is flat.


def test_a_key_that_is_also_a_prefix_is_refused_by_name_and_never_silently(
        tmp_path, monkeypatch, capsys):
    """`rclone cat` on a prefix concatenates every object under it, exits 0,
    and says nothing about it.

    One PUT of 'carryon/index.enc/pwn' on any bucket the attacker can write to
    and every read of 'carryon/index.enc' came back as the real sealed object
    with somebody else's bytes appended - at exit 0, with no report line at
    all, which is the one outcome this layer's posture rules out. Silence is
    the finding: the seal turns the wrong bytes into a refusal somewhere else
    entirely, and nothing tells the user a planted object is why.
    """
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/index.enc", b"REAL-SEALED-INDEX")
    capsys.readouterr()

    store.also_a_prefix("archive/carryon/index.enc", b"APPENDED-BY-SOMEBODY")

    got = dest.read("carryon/index.enc")
    out = capsys.readouterr().out
    assert got != b"REAL-SEALED-INDEXAPPENDED-BY-SOMEBODY", \
        "carryon handed its caller an object concatenated with another one"
    assert got is None
    assert "carryon/index.enc" in out and "skipping" in out, \
        f"the planted prefix was not named in the report: {out!r}"


def test_a_key_that_is_also_a_prefix_does_not_blame_the_users_own_config(
        tmp_path, monkeypatch, capsys):
    """The second half, which is a wrong diagnosis rather than a wrong answer.

    Every write of that key refused for ever with a sentence saying the cause
    is "usually `dry_run` in the rclone config, or a filter rule that matches
    the temp file carryon uploads from" - a permanent push denial pointing the
    user at their own settings, when what is there is somebody else's object.
    """
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/index.enc", b"v1")
    store.also_a_prefix("archive/carryon/index.enc", b"APPENDED")
    capsys.readouterr()

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"v2")
    message = str(exc.value)
    assert "carryon/index.enc" in message
    assert "prefix" in message, \
        f"the refusal does not name what is actually there: {message}"
    assert "dry_run" not in message, \
        "the refusal blames the user's own config for somebody else's object"


def test_a_delete_that_exits_zero_and_removes_nothing_is_not_a_delete(
        tmp_path, monkeypatch, capsys):
    """The one-time half of ADR-0005 is a delete, and nothing confirmed it.

    `_confirm_write` exists because an exit code is the remote's word about
    what it did; the delete beside it took that word. With a `deletefile` that
    exits 0 and removes nothing - RCLONE_DRY_RUN in the joining machine's own
    environment - the pairing blob stayed in the Archive while carryon
    reported the pairing consumed, and a third machine joined with the same
    one-time code and derived the identical master key.
    """
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/pair/ABCDEF.enc", b"wrapped-master-key")
    capsys.readouterr()
    store.deletefile_removes_nothing()

    gone = dest.delete("carryon/pair/ABCDEF.enc")
    out = capsys.readouterr().out

    assert gone is False, \
        "the store reported a delete it did not make and carryon agreed"
    assert "ABCDEF" in out and "skipping" in out, \
        f"a delete that removed nothing said nothing: {out!r}"


def test_an_honest_delete_answers_that_it_happened(tmp_path, monkeypatch,
                                                   capsys):
    """The control: a store that really removes the object says so with no
    report line, so the confirmation cannot be passing by refusing
    everything."""
    store = install_rclone_store(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")
    dest.write("carryon/pair/ABCDEF.enc", b"wrapped-master-key")
    capsys.readouterr()

    assert dest.delete("carryon/pair/ABCDEF.enc") is True
    assert capsys.readouterr().out == ""
    assert store.objects() == []


def test_a_join_over_an_undeletable_pairing_blob_says_the_code_is_still_live(
        tmp_path, monkeypatch, capsys):
    """Driven end to end, because the harm is what the user is told.

    `join` printed "paired as 'box-b'" at rc 0 with the wrapped master key
    still sitting in the Archive, and carryon's own `pair` output says the
    code "works once". The ordinary spellings of an undeletable store -
    RCLONE_DRY_RUN in the joining machine's environment, a filter rule - are
    now met by ADR-0011's reachability probe, which refuses the join before
    the code is spent. What still reaches this leg is a store that lies
    SELECTIVELY: probes deleted honestly, the pairing blob kept. That is
    nobody's rclone.conf and any hostile remote, and the warning is the one
    thing standing between it and a code that quietly works twice.
    """
    store = install_rclone_store(tmp_path, monkeypatch)
    spec = "rclone:fakeremote:archive"
    home_a = build_claude_home(tmp_path, "home_a")
    assert sync.init(ns(dest=spec, machine="box-a"), home_a) == 0
    assert sync.push(ns(apply=True), home_a) == 0
    sync.pair(ns(), home_a)
    code = re.search(PAIR_CODE, capsys.readouterr().out).group(1)

    store.deletefile_removes_nothing(only="/pair/")
    home_b = build_claude_home(tmp_path, "home_b")
    assert sync.init(ns(dest=spec, join=code, machine="box-b"), home_b) == 0
    out = capsys.readouterr().out

    assert "still" in out.lower() or "live" in out.lower(), (
        "the pairing blob outlived the code that was said to work once, and "
        f"the run said nothing about it:\n{out}")
    assert any(key.endswith(".enc") and "/pair" in key
               for key in ("/" + o for o in store.objects())), \
        "the test did not actually leave a pairing blob behind"


def test_a_commit_that_never_happened_stops_the_write_by_name(tmp_path,
                                                              monkeypatch):
    """The confirmation itself, driven directly.

    The two ignore mechanisms above are turned off rather than detected, so
    neither of them reaches `_confirm_write` any more - and a guard nothing
    exercises is a guard nobody knows is wrong. What is simulated here is the
    class rather than an instance: add, commit and push all exit 0 and the
    Archive gains nothing, which is what the NEXT mechanism nobody has heard
    of looks like from carryon's side. The clone still holds the bytes, so a
    read-back on this machine would pass - which is why the question is asked
    of the commit.
    """
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    monkeypatch.setattr(GitDestination, "_commit_push",
                        lambda self, message: None)

    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"sealed")
    message = str(exc.value)
    assert "carryon/index.enc" in message and "commit" in message
    assert (dest.clone_dir / "carryon" / "index.enc").read_bytes() == b"sealed", \
        "the clone was serving the bytes, so a local read-back proves nothing"


def test_a_tree_write_is_confirmed_after_the_batch_commits(tmp_path,
                                                           monkeypatch):
    """Inside a batch there is nothing to compare against yet, so the
    confirmation defers to the end of it - and still has to fire. A Setup is
    pushed as a tree, so a check that only worked per blob would cover the
    Index and none of the Setup."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    staging = tmp_path / "staging"
    (staging / "claude").mkdir(parents=True)
    (staging / "claude" / "settings.json").write_bytes(HONEST)
    monkeypatch.setattr(GitDestination, "_commit_push",
                        lambda self, message: None)

    with pytest.raises(SystemExit) as exc:
        dest.write_tree("carryon/setups/mac", staging)
    assert "carryon/setups/mac/claude/settings.json" in str(exc.value)


def test_a_delete_the_commit_did_not_take_is_named_and_answered(tmp_path,
                                                                monkeypatch,
                                                                capsys):
    """The delete half of the same question. Reported rather than raised (a
    delete leaves something stale, not something wrong) and answered, because
    the pairing leg needs to know."""
    origin = bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home")
    dest.write("carryon/pair/ABCDEF.enc", b"wrapped-master-key")
    capsys.readouterr()
    monkeypatch.setattr(GitDestination, "_commit_push",
                        lambda self, message: None)

    gone = dest.delete("carryon/pair/ABCDEF.enc")
    out = capsys.readouterr().out

    assert gone is False
    assert "ABCDEF" in out and "skipping" in out
