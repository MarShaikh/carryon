"""A Destination is untrusted storage, and a symlink planted there is an
instruction to read somewhere else.

ADR-0009 confined a restore to paths some Adapter on this machine declares,
which killed '..' in a stored MANIFEST as an exfiltration route. The same
primitive survived one layer down with no '..' anywhere, because the
Destination layer read *through* symlinks: `path.is_file()` follows one, so
a link planted on the Destination pointing at ~/.ssh/id_ed25519 was
enumerated as an ordinary Archive object and its bytes copied into staging
under a legitimate-looking key - from where a restore writes them to a
declared Setup path and the victim's next push publishes them back to
whoever planted the link. A link to a *directory* was not listed (pathlib's
rglob has never descended into one) but was read straight through by name,
which is the same exfiltration with one more step.

These tests plant the link and check the bytes never move. The git clone
lives at a fixed depth under $HOME, so a committed symlink of a fixed number
of parent steps reaches any victim's home: that one runs against a real bare
repo. No network anywhere - rclone is a fake binary on a prepended PATH that
records its argv, and its listing is canned so a remote can answer with
object names no filesystem would let a test create.
"""

import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon.destinations.base import Destination  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from carryon.destinations.git_repo import GitDestination  # noqa: E402
from carryon.destinations.rclone_remote import RcloneDestination  # noqa: E402

SECRET = b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n"
SETUP_PREFIX = "carryon/setups/mac"


# --- helpers -----------------------------------------------------------------


def files_under(root) -> dict:
    """{relative posix path: bytes} for the real files below root.

    Walks with lstat semantics of its own so that a symlink staging picked
    up is visible to the assertions rather than silently read through.
    """
    root = pathlib.Path(root)
    found = {}
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            found[rel] = b"<symlink to " + os.readlink(path).encode() + b">"
        elif path.is_file():
            found[rel] = path.read_bytes()
    return found


def victim_home(tmp_path) -> tuple:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    secret = home / ".ssh" / "id_ed25519"
    secret.write_bytes(SECRET)
    return home, secret


def hostile_directory(tmp_path) -> tuple:
    """A directory Destination an attacker has planted symlinks in."""
    _home, secret = victim_home(tmp_path)

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.md").write_bytes(SECRET)

    root = tmp_path / "archive"
    setup = root / "carryon" / "setups" / "mac"
    setup.mkdir(parents=True)
    (setup / "settings.json").write_bytes(b'{"model": "opus"}')
    os.symlink(secret, setup / "CLAUDE.md")          # a file outside the root
    os.symlink(outside, setup / "skills")            # a directory outside it
    os.symlink(tmp_path / "nowhere", setup / "gone.md")  # dangling
    return DirectoryDestination(root)


def git(repo, *args, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo)] + list(args),
                          capture_output=True, text=True, check=True, **kwargs)


def hostile_git(tmp_path, extra_files=()) -> tuple:
    """A bare origin whose committed tree holds a symlink out of the clone.

    The link is written as the number of parent steps that reaches the
    victim's home from where carryon puts its clone - $HOME/.carryon/git/
    <slug> is a fixed depth on every machine, so one committed link works
    against every machine that pulls.
    """
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)], check=True)
    home, secret = victim_home(tmp_path)

    dest = GitDestination(str(origin), home=home)
    setup_dir = dest.clone_dir / "carryon" / "setups" / "mac"
    hops = os.path.relpath(secret, setup_dir)

    work = tmp_path / "hostile-work"
    subprocess.run(["git", "clone", "--quiet", str(origin), str(work)], check=True)
    planted = work / "carryon" / "setups" / "mac"
    planted.mkdir(parents=True)
    (planted / "settings.json").write_bytes(b'{"model": "opus"}')
    os.symlink(hops, planted / "CLAUDE.md")
    for rel in extra_files:
        path = planted / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ordinary")
    git(work, "add", "-A")
    git(work, "-c", "user.name=a", "-c", "user.email=a@b", "commit",
        "--quiet", "-m", "plant")
    git(work, "push", "--quiet", "origin", "HEAD")
    return dest, hops


FAKE_RCLONE = """#!/bin/sh
# A stand-in rclone whose listing is canned: a remote answers with whatever
# object names it likes, including ones no local filesystem would accept.
LOG="__LOG__"
ROOT="__ROOT__"
LINES="__LINES__"
printf '%s\\n' "$*" >> "$LOG"

resolve() {
  case "$1" in
    fakeremote:*) printf '%s/%s' "$ROOT" "${1#fakeremote:}" ;;
    *) printf '%s' "$1" ;;
  esac
}

cmd="$1"; shift
case "$cmd" in
  lsf) cat "$LINES" ;;
  cat)
    f="$(resolve "$1")"
    if [ ! -f "$f" ]; then echo "object not found" >&2; exit 1; fi
    cat "$f"
    ;;
  copyto)
    src="$(resolve "$1")"; dst="$(resolve "$2")"
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    ;;
  *) echo "unknown verb $cmd" >&2; exit 2 ;;
esac
"""


def install_recording_rclone(tmp_path, monkeypatch, listing):
    """Fake rclone first on PATH, answering lsf with the given lines."""
    root = tmp_path / "rclone-store"
    root.mkdir(exist_ok=True)
    lines = tmp_path / "rclone-listing.txt"
    lines.write_text("".join(line + "\n" for line in listing))
    log = tmp_path / "rclone.log"
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "rclone"
    script.write_text(FAKE_RCLONE.replace("__LOG__", str(log))
                                 .replace("__ROOT__", str(root))
                                 .replace("__LINES__", str(lines)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return root, log


class ListingDestination(Destination):
    """Answers a listing with keys of the caller's choosing.

    Stands in for storage that is not a filesystem at all, which is where a
    key shaped to escape staging comes from: read() hands back planted bytes
    for anything, so anything that reaches disk did so through read_tree.
    """

    def __init__(self, keys):
        self.keys = list(keys)

    def list(self, prefix: str = "") -> list:
        return [k for k in self.keys if k.startswith(prefix)]

    def read(self, key: str):
        return SECRET

    def describe(self) -> str:
        return "listing double"


# --- the planted link is armed -----------------------------------------------


def test_the_planted_directory_symlink_really_does_reach_the_secret(tmp_path):
    """Without this, every assertion below could pass for the wrong reason."""
    dest = hostile_directory(tmp_path)
    planted = dest.root / "carryon" / "setups" / "mac" / "CLAUDE.md"
    assert planted.is_symlink()
    assert pathlib.Path(os.path.realpath(planted)).read_bytes() == SECRET


def test_the_committed_git_symlink_reaches_the_home_of_whoever_clones(tmp_path):
    dest, hops = hostile_git(tmp_path)
    assert hops.startswith("../"), "the link must climb out of the clone"
    dest.list("carryon/")  # forces the clone
    planted = dest.clone_dir / "carryon" / "setups" / "mac" / "CLAUDE.md"
    assert planted.is_symlink(), "git carries a symlink through a clone"
    assert pathlib.Path(os.path.realpath(planted)).read_bytes() == SECRET, \
        "a fixed number of parent steps reaches $HOME on any machine"


# --- directory ---------------------------------------------------------------


def test_directory_read_does_not_follow_a_symlink_out_of_the_destination(tmp_path):
    dest = hostile_directory(tmp_path)
    got = dest.read(SETUP_PREFIX + "/CLAUDE.md")
    assert got != SECRET
    assert got is None, "a symlink is not an Archive object; it is absent"


def test_directory_read_does_not_reach_through_a_symlinked_directory(tmp_path):
    dest = hostile_directory(tmp_path)
    assert dest.read(SETUP_PREFIX + "/skills/loot.md") is None


def test_directory_list_does_not_enumerate_a_symlink_as_a_key(tmp_path, capsys):
    dest = hostile_directory(tmp_path)
    keys = dest.list("carryon/")
    assert keys == [SETUP_PREFIX + "/settings.json"], \
        "only the real file is an Archive object"
    assert "CLAUDE.md" in capsys.readouterr().out, \
        "a skipped object is named in the report, not silently dropped"


def test_directory_list_does_not_descend_into_a_symlinked_directory(tmp_path):
    """pathlib's rglob happens not to descend into a linked directory, while
    os.walk and glob(recursive=True) both do. The invariant is asserted here
    rather than inherited from whichever walk the module is written with -
    and the read side, which did follow one, is what makes the pair worth
    having: a linked directory whose contents cannot be listed but can be
    fetched by name is no better than one that can."""
    dest = hostile_directory(tmp_path)
    assert not [k for k in dest.list() if "loot" in k or k.endswith("skills")]
    assert dest.read(SETUP_PREFIX + "/skills/loot.md") is None


def test_directory_read_tree_never_stages_the_secret(tmp_path):
    dest = hostile_directory(tmp_path)
    staging = tmp_path / "staging"

    dest.read_tree(SETUP_PREFIX, staging)

    staged = files_under(staging)
    assert staged == {"settings.json": b'{"model": "opus"}'}
    assert not any(SECRET in data for data in staged.values())


def test_directory_a_dangling_symlink_does_not_abort_a_pull(tmp_path):
    """A hostile object is reported and skipped. If one could raise, an
    attacker with write access could stop every pull instead."""
    dest = hostile_directory(tmp_path)
    dest.list("carryon/")
    assert dest.read(SETUP_PREFIX + "/gone.md") is None
    dest.read_tree(SETUP_PREFIX, tmp_path / "staging")
    assert (tmp_path / "staging" / "settings.json").is_file()


def test_directory_write_refuses_to_write_through_a_planted_directory(tmp_path):
    """The read side is the exfiltration; writing through a planted link
    would put Archive bytes wherever the attacker aimed it."""
    dest = hostile_directory(tmp_path)
    with pytest.raises(SystemExit) as exc:
        dest.write(SETUP_PREFIX + "/skills/new.md", b"pushed")
    assert "symlink" in str(exc.value)
    assert not (tmp_path / "outside" / "new.md").exists()


# --- git ---------------------------------------------------------------------


def test_git_list_does_not_enumerate_a_committed_symlink(tmp_path):
    dest, _ = hostile_git(tmp_path)
    assert dest.list("carryon/") == [SETUP_PREFIX + "/settings.json"]


def test_git_read_does_not_follow_a_committed_symlink(tmp_path):
    dest, _ = hostile_git(tmp_path)
    assert dest.read(SETUP_PREFIX + "/CLAUDE.md") is None


def test_git_read_tree_never_stages_the_secret(tmp_path):
    dest, _ = hostile_git(tmp_path)
    staging = tmp_path / "staging"

    dest.read_tree(SETUP_PREFIX, staging)

    staged = files_under(staging)
    assert staged == {"settings.json": b'{"model": "opus"}'}
    assert not any(SECRET in data for data in staged.values())


# --- containment: relative_to is not a containment check ---------------------


def test_read_tree_refuses_a_key_that_resolves_out_of_staging(tmp_path):
    """dst/'sub/evil.md' is lexically inside dst and lands outside it when
    'sub' is a symlink. relative_to and a startswith on the key are both
    lexical and say the path is contained; only resolving says otherwise."""
    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, staging / "skills")
    dest = ListingDestination([SETUP_PREFIX + "/skills/evil.md"])

    with pytest.raises(ValueError):
        dest.read_tree(SETUP_PREFIX, staging)
    assert not (outside / "evil.md").exists(), \
        "read_tree wrote through a symlink and left staging"


def test_git_read_tree_holds_the_same_containment_as_the_base(tmp_path):
    """Two implementations of one rule is how the guards drifted apart: the
    git override had neither the key check nor the containment check."""
    dest, _ = hostile_git(tmp_path, extra_files=("skills/evil.md",))
    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, staging / "skills")

    with pytest.raises(ValueError):
        dest.read_tree(SETUP_PREFIX, staging)
    assert not (outside / "evil.md").exists()


# --- rclone: a listing is the remote's answer, not carryon's layout ----------


def test_rclone_listing_keys_are_validated_at_the_point_of_listing(tmp_path,
                                                                   monkeypatch):
    install_recording_rclone(tmp_path, monkeypatch, [
        "carryon/index.enc",
        "../../../../home/.ssh/id_ed25519",
        "/etc/passwd",
        "carryon//empty-component.enc",
        "carryon\\windows.enc",
        "carryon/sessions/../../../escape.enc",
    ])
    dest = RcloneDestination("fakeremote:archive")

    assert dest.list() == ["carryon/index.enc"], \
        "every key from a listing is checked where it is listed"


def test_rclone_read_tree_writes_nothing_outside_staging(tmp_path, monkeypatch):
    store, _ = install_recording_rclone(tmp_path, monkeypatch, [
        SETUP_PREFIX + "/settings.json",
        SETUP_PREFIX + "/../../../../../outside/evil.md",
    ])
    real = store / "archive" / SETUP_PREFIX
    real.mkdir(parents=True)
    (real / "settings.json").write_bytes(b'{"model": "opus"}')
    dest = RcloneDestination("fakeremote:archive")
    staging = tmp_path / "staging"

    dest.read_tree(SETUP_PREFIX, staging)

    assert files_under(staging) == {"settings.json": b'{"model": "opus"}'}
    assert not (tmp_path / "outside").exists()


def test_rclone_still_uses_the_fake_binary_and_no_network(tmp_path, monkeypatch):
    _, log = install_recording_rclone(tmp_path, monkeypatch, ["carryon/x.enc"])
    RcloneDestination("fakeremote:archive").list()
    assert "lsf" in log.read_text()
