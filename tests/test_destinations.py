"""Destination behaviour, exercised against local stand-ins.

Every Destination type gets a local double: directory gets a tmp root, git gets
a bare repo on disk as origin, rclone gets a fake executable on a prepended
PATH that records its argv. No network, no credentials, no real ~ anywhere.
"""

import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon.destinations import detect_candidates, from_spec  # noqa: E402
from carryon.destinations.base import Destination  # noqa: E402
from carryon.destinations.directory import DirectoryDestination  # noqa: E402
from carryon.destinations.git_repo import GitDestination  # noqa: E402
from carryon.destinations.rclone_remote import RcloneDestination  # noqa: E402


# --- doubles -----------------------------------------------------------------

FAKE_RCLONE = """#!/bin/sh
# A stand-in rclone: maps 'fakeremote:' onto a local directory and records
# every invocation, so tests can assert on the verbs carryon actually used.
LOG="__LOG__"
ROOT="__ROOT__"
printf '%s\\n' "$*" >> "$LOG"

resolve() {
  case "$1" in
    fakeremote:*) printf '%s/%s' "$ROOT" "${1#fakeremote:}" ;;
    *) printf '%s' "$1" ;;
  esac
}

cmd="$1"; shift
case "$cmd" in
  lsf)
    target=""; kind="-type f"
    for a in "$@"; do
      case "$a" in
        --dirs-only) kind="-type d" ;;
        -*) ;;
        *) target="$a" ;;
      esac
    done
    dir="$(resolve "$target")"
    if [ ! -d "$dir" ]; then echo "directory not found" >&2; exit 3; fi
    # a prefix comes back with a trailing '/', which is how rclone says it is
    # one; carryon asks --dirs-only to find a key that is an object AND a
    # prefix, which a local store like this one can never be
    if [ "$kind" = "-type d" ]; then
      (cd "$dir" && find . -mindepth 1 -type d | sed 's|^\\./||;s|$|/|')
    else
      (cd "$dir" && find . -type f | sed 's|^\\./||')
    fi
    ;;
  copyto)
    src="$(resolve "$1")"; dst="$(resolve "$2")"
    if [ ! -f "$src" ]; then echo "source not found" >&2; exit 1; fi
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    ;;
  deletefile)
    f="$(resolve "$1")"
    if [ ! -f "$f" ]; then echo "object not found" >&2; exit 1; fi
    rm "$f"
    ;;
  cat)
    f="$(resolve "$1")"
    if [ ! -f "$f" ]; then echo "object not found" >&2; exit 1; fi
    cat "$f"
    ;;
  listremotes)
    echo "fakeremote:"
    ;;
  *)
    echo "unknown verb $cmd" >&2; exit 2
    ;;
esac
"""


def install_fake_rclone(tmp_path, monkeypatch):
    """Put a fake rclone first on PATH. Returns (backing store, argv log)."""
    root = tmp_path / "rclone-store"
    root.mkdir(exist_ok=True)
    log = tmp_path / "rclone.log"
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "rclone"
    script.write_text(FAKE_RCLONE.replace("__LOG__", str(log))
                                 .replace("__ROOT__", str(root)))
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return root, log


def make_bare_origin(tmp_path) -> pathlib.Path:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(origin)], check=True)
    return origin


def make_destination(kind, tmp_path, monkeypatch):
    if kind == "directory":
        return DirectoryDestination(tmp_path / "archive")
    if kind == "git":
        origin = make_bare_origin(tmp_path)
        return GitDestination(str(origin), home=tmp_path / "home-a")
    if kind == "rclone":
        install_fake_rclone(tmp_path, monkeypatch)
        return RcloneDestination("fakeremote:archive")
    raise AssertionError(kind)


KINDS = ("directory", "git", "rclone")


def build_tree(tmp_path) -> pathlib.Path:
    src = tmp_path / "setup-src"
    (src / "claude" / "skills" / "mine").mkdir(parents=True)
    (src / "claude" / "settings.json").write_bytes(b'{"model": "opus"}')
    (src / "claude" / "skills" / "mine" / "SKILL.md").write_bytes(b"authored here")
    (src / "MANIFEST.json").write_bytes(b"\x00\x01\xffnot-utf8")
    return src


# --- round trips through all three types -------------------------------------

@pytest.mark.parametrize("kind", KINDS)
def test_blob_round_trip(kind, tmp_path, monkeypatch):
    dest = make_destination(kind, tmp_path, monkeypatch)

    assert dest.read("carryon/index.enc") is None
    assert dest.list() == []

    dest.write("carryon/index.enc", b"\x00\x01binary v1")
    assert dest.read("carryon/index.enc") == b"\x00\x01binary v1"

    dest.write("carryon/index.enc", b"v2")  # overwrite wins
    assert dest.read("carryon/index.enc") == b"v2"

    dest.write("carryon/sessions/bb.tar.enc", b"session-b")
    dest.write("carryon/sessions/aa.tar.enc", b"session-a")
    assert dest.list("carryon/sessions/") == [
        "carryon/sessions/aa.tar.enc",
        "carryon/sessions/bb.tar.enc",
    ]
    assert dest.list() == [
        "carryon/index.enc",
        "carryon/sessions/aa.tar.enc",
        "carryon/sessions/bb.tar.enc",
    ]

    dest.delete("carryon/sessions/aa.tar.enc")
    assert dest.read("carryon/sessions/aa.tar.enc") is None
    assert dest.list("carryon/sessions/") == ["carryon/sessions/bb.tar.enc"]
    dest.delete("carryon/sessions/aa.tar.enc")  # deleting a missing key is fine


@pytest.mark.parametrize("kind", KINDS)
def test_tree_round_trip(kind, tmp_path, monkeypatch):
    dest = make_destination(kind, tmp_path, monkeypatch)
    src = build_tree(tmp_path)

    dest.write_tree("carryon/setups/mac", src)
    assert dest.list("carryon/setups/mac/") == [
        "carryon/setups/mac/MANIFEST.json",
        "carryon/setups/mac/claude/settings.json",
        "carryon/setups/mac/claude/skills/mine/SKILL.md",
    ]

    dst = tmp_path / "restored"
    dest.read_tree("carryon/setups/mac", dst)
    got = {p.relative_to(dst).as_posix(): p.read_bytes()
           for p in dst.rglob("*") if p.is_file()}
    want = {p.relative_to(src).as_posix(): p.read_bytes()
            for p in src.rglob("*") if p.is_file()}
    assert got == want


@pytest.mark.parametrize("kind", KINDS)
def test_describe_says_something_identifying(kind, tmp_path, monkeypatch):
    dest = make_destination(kind, tmp_path, monkeypatch)
    text = dest.describe()
    assert text.strip()
    assert ("archive" in text) or ("origin.git" in text) or ("fakeremote" in text)


@pytest.mark.parametrize("kind", KINDS)
def test_traversal_keys_are_refused(kind, tmp_path, monkeypatch):
    dest = make_destination(kind, tmp_path, monkeypatch)
    for bad in ("../escape", "/absolute", "a/../b", ""):
        with pytest.raises(ValueError):
            dest.write(bad, b"x")


def test_every_write_goes_past_the_question_of_whether_it_happened(tmp_path):
    """"Did the store actually do it" is asked ON THE BASE, like the four
    verbs above it.

    The base made read/write/delete/list concrete so no type could forget
    their guards, and left this one question to each type to remember - which
    rclone answered with a listing, right for a create and vacuous for an
    update, and nobody else answered at all because a syscall that either
    moved the bytes or raised had already answered it. A question each type
    remembers is the shape every defect in this package has had. So `write`
    calls `_confirm_write`, whose default says in as many words why nothing
    more is needed, and a type whose write can lie overrides it.
    """
    asked = []

    class Forgetful(Destination):
        def _write_blob(self, key, data):
            pass

        def describe(self):
            return "a type that answers nothing"

    class Careful(Forgetful):
        def _confirm_write(self, key, data):
            asked.append((key, data))

    Careful().write("carryon/index.enc", b"sealed")
    assert asked == [("carryon/index.enc", b"sealed")], \
        "Destination.write does not put the question to the type"
    # And the default is an answer rather than an omission: a type that says
    # nothing is one whose write already raised or moved the bytes.
    Forgetful().write("carryon/index.enc", b"sealed")


# --- directory ---------------------------------------------------------------

def test_directory_write_is_atomic(tmp_path, monkeypatch):
    """A failed write leaves neither a partial file under the final key name
    nor tmp residue that a sync client would upload.

    Both rename spellings are broken, because the two are not one call here:
    os.rename takes the directory descriptors the write is made inside on
    POSIX, and os.replace is what the fallback path uses where there are
    none. And the failure surfaces as a sentence - a refused push is
    user-facing, and the house rule for those is SystemExit, not an errno."""
    dest = DirectoryDestination(tmp_path / "archive")
    dest.write("carryon/index.enc", b"old")

    def boom(src, dst, **kwargs):
        raise OSError("simulated failure at the replace step")

    monkeypatch.setattr(os, "replace", boom)
    monkeypatch.setattr(os, "rename", boom)
    with pytest.raises(SystemExit) as exc:
        dest.write("carryon/index.enc", b"new-would-be-partial")
    monkeypatch.undo()
    assert "carryon/index.enc" in str(exc.value)

    assert dest.read("carryon/index.enc") == b"old"
    assert dest.list() == ["carryon/index.enc"]
    leftovers = [p for p in (tmp_path / "archive").rglob("*")
                 if p.is_file() and p.name != "index.enc"]
    assert leftovers == [], "a failed write must clean up its tmp file"


def test_directory_in_flight_tmp_files_are_not_listed(tmp_path):
    """A concurrent writer's tmp file must never surface as a key."""
    dest = DirectoryDestination(tmp_path / "archive")
    dest.write("carryon/index.enc", b"x")
    sessions = tmp_path / "archive" / "carryon"
    (sessions / ".carryon-tmp-inflight").write_bytes(b"partial")
    assert dest.list() == ["carryon/index.enc"]


# --- git ---------------------------------------------------------------------

def test_git_second_clone_sees_pushed_content(tmp_path):
    origin = make_bare_origin(tmp_path)
    a = GitDestination(str(origin), home=tmp_path / "home-a")
    b = GitDestination(str(origin), home=tmp_path / "home-b")

    # b clones while the origin is still empty - the awkward path.
    assert b.read("carryon/index.enc") is None

    a.write("carryon/index.enc", b"v1")
    assert b.read("carryon/index.enc") == b"v1", \
        "a second clone must see content pushed by the first"

    b.write("carryon/index.enc", b"v2")
    assert a.read("carryon/index.enc") == b"v2"

    a.delete("carryon/index.enc")
    assert b.read("carryon/index.enc") is None


def test_git_commit_author_is_carryon(tmp_path):
    origin = make_bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home-a")
    dest.write("carryon/index.enc", b"x")

    check = tmp_path / "check"
    subprocess.run(["git", "clone", "--quiet", str(origin), str(check)], check=True)
    out = subprocess.run(
        ["git", "-C", str(check), "log", "-1", "--format=%an <%ae>|%cn <%ce>"],
        capture_output=True, text=True, check=True).stdout.strip()
    assert out == "carryon <carryon@localhost>|carryon <carryon@localhost>"


def test_git_write_tree_is_one_commit(tmp_path):
    origin = make_bare_origin(tmp_path)
    dest = GitDestination(str(origin), home=tmp_path / "home-a")
    dest.write_tree("carryon/setups/mac", build_tree(tmp_path))

    check = tmp_path / "check"
    subprocess.run(["git", "clone", "--quiet", str(origin), str(check)], check=True)
    count = subprocess.run(["git", "-C", str(check), "rev-list", "--count", "HEAD"],
                           capture_output=True, text=True, check=True).stdout.strip()
    assert count == "1", "a write batch is one commit, not one per file"


def test_git_fetch_failure_is_a_systemexit_with_git_stderr(tmp_path):
    dest = GitDestination(str(tmp_path / "no-such-origin.git"),
                          home=tmp_path / "home-a")
    with pytest.raises(SystemExit) as exc:
        dest.read("carryon/index.enc")
    assert "git" in str(exc.value).lower()


def test_git_never_prompts_for_credentials():
    from carryon.destinations import git_repo
    assert git_repo.git_env()["GIT_TERMINAL_PROMPT"] == "0"


def test_git_clone_lives_under_dot_carryon(tmp_path):
    home = tmp_path / "home-a"
    dest = GitDestination("git@example.invalid:me/archive.git", home=home)
    assert str(dest.clone_dir).startswith(str(home / ".carryon" / "git"))


# --- rclone ------------------------------------------------------------------

def test_rclone_missing_is_a_systemexit(tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(SystemExit) as exc:
        RcloneDestination("fakeremote:archive")
    assert "rclone" in str(exc.value)


def test_rclone_uses_the_expected_verbs(tmp_path, monkeypatch):
    _, log = install_fake_rclone(tmp_path, monkeypatch)
    dest = RcloneDestination("fakeremote:archive")

    dest.write("carryon/index.enc", b"x")
    dest.read("carryon/index.enc")
    dest.list("carryon/")
    dest.delete("carryon/index.enc")

    lines = log.read_text().splitlines()
    assert any(l.startswith("copyto ") and
               l.endswith("fakeremote:archive/carryon/index.enc") for l in lines)
    assert any(l.startswith("cat ") and
               "fakeremote:archive/carryon/index.enc" in l for l in lines)
    assert any(l.startswith("lsf ") and "fakeremote:archive" in l for l in lines)
    assert any(l.startswith("deletefile ") and
               "fakeremote:archive/carryon/index.enc" in l for l in lines)


# --- from_spec ---------------------------------------------------------------

def test_from_spec_table(tmp_path, monkeypatch):
    install_fake_rclone(tmp_path, monkeypatch)  # rclone specs need it on PATH
    home = tmp_path / "home"
    home.mkdir()

    dest = from_spec("/abs/archive", home)
    assert isinstance(dest, DirectoryDestination)
    assert dest.root == pathlib.Path("/abs/archive")

    assert from_spec("~", home).root == home
    assert from_spec("~/archive", home).root == home / "archive"
    assert from_spec("dir:/abs/archive", home).root == pathlib.Path("/abs/archive")
    assert from_spec("dir:~/archive", home).root == home / "archive"

    for spec, url in (
        ("git:https://example.invalid/r", "https://example.invalid/r"),
        ("git@example.invalid:me/r.git", "git@example.invalid:me/r.git"),
        ("ssh://example.invalid/r", "ssh://example.invalid/r"),
        ("/data/archive.git", "/data/archive.git"),  # a local bare repo is git
    ):
        dest = from_spec(spec, home)
        assert isinstance(dest, GitDestination), spec
        assert dest.url == url
        assert str(dest.clone_dir).startswith(str(home / ".carryon" / "git"))

    dest = from_spec("rclone:gdrive:backup", home)
    assert isinstance(dest, RcloneDestination)
    assert dest.target == "gdrive:backup"

    for bad in ("ftp://nope", "", "relative/path", "rclone:no-colon"):
        with pytest.raises(SystemExit):
            from_spec(bad, home)


# --- detect_candidates -------------------------------------------------------

def install_fake_git(tmp_path, monkeypatch, credential_helper=""):
    bin_dir = tmp_path / "git-bin"
    bin_dir.mkdir(exist_ok=True)
    if credential_helper:
        body = ('#!/bin/sh\nif [ "$1" = "config" ]; then echo "%s"; exit 0; fi\n'
                'exit 0\n') % credential_helper
    else:
        body = '#!/bin/sh\nif [ "$1" = "config" ]; then exit 1; fi\nexit 0\n'
    script = bin_dir / "git"
    script.write_text(body)
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    return bin_dir


def test_detect_candidates_empty_home_finds_nothing(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert detect_candidates(home) == []


def test_detect_candidates_finds_synced_folders(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Library" / "Mobile Documents" / "com~apple~CloudDocs").mkdir(parents=True)
    (home / "Dropbox").mkdir()
    (home / "Google Drive").mkdir()
    (home / "OneDrive").mkdir()
    (home / "Sync").mkdir()
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    found = dict(detect_candidates(home))
    assert "~/Library/Mobile Documents/com~apple~CloudDocs" in found
    assert "iCloud" in found["~/Library/Mobile Documents/com~apple~CloudDocs"]
    assert found["~/Dropbox"] == "Dropbox"
    assert found["~/Google Drive"] == "Google Drive"
    assert found["~/OneDrive"] == "OneDrive"
    assert "Syncthing" in found["~/Sync"]
    # every synced-folder spec must parse as a directory Destination
    for spec in found:
        assert isinstance(from_spec(spec, home), DirectoryDestination)


def test_detect_candidates_offers_git_only_with_a_way_to_authenticate(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    install_fake_git(tmp_path, monkeypatch)

    assert detect_candidates(home) == [], \
        "git on PATH alone is not enough - no ssh key, no credential helper"

    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("not a real key")
    specs = [spec for spec, _ in detect_candidates(home)]
    assert any(spec.startswith("git:") for spec in specs)


def test_detect_candidates_accepts_a_credential_helper_instead_of_a_key(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()  # no .ssh at all
    install_fake_git(tmp_path, monkeypatch, credential_helper="osxkeychain")
    specs = [spec for spec, _ in detect_candidates(home)]
    assert any(spec.startswith("git:") for spec in specs)


def test_detect_candidates_lists_rclone_remotes_only_with_a_config(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    install_fake_rclone(tmp_path, monkeypatch)

    assert detect_candidates(home) == [], \
        "rclone on PATH with no config means no remotes to offer"

    conf = home / ".config" / "rclone" / "rclone.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("")  # exists but empty: still nothing to offer
    assert detect_candidates(home) == []

    conf.write_text("[fakeremote]\ntype = local\n")
    found = dict(detect_candidates(home))
    assert "rclone:fakeremote:" in found
    assert "fakeremote" in found["rclone:fakeremote:"]


# --- a Destination root has to be somewhere, and the same somewhere twice ----
#
# `--dest` takes the string half at the CLI door and its MEANING here, which
# makes this the one function that says what a spec names. Two spellings got
# past it, and both put an Archive somewhere the user did not name.


@pytest.mark.parametrize("spec", [
    "dir:",          # three characters of prefix defeat the empty-argument door
    "dir:.",         # '.' alone IS refused as a bare spec, and was not here
    "dir: ",         # the whole spec is stripped, so this is 'dir:' again
    "dir:carryon",   # relative: the Archive follows the working directory
    "dir:./here",
    "dir:..",
    "dir:~nosuchuser/archive",   # Path('~x') is relative, not somebody's home
])
def test_a_directory_spec_that_names_no_absolute_root_is_refused(spec, tmp_path):
    """A relative Destination root is an Archive that follows the user around.

    `dir:` expands to Path(''), whose meaning is the PROCESS WORKING
    DIRECTORY, so `push --apply` wrote carryon/index.enc and a plaintext
    carryon/setups/<machine>/ tree into whatever directory the command
    happened to run in - complete in neither of two, at exit 0. `--dest '.'`
    was refused all along, which is what shows the check existed and was
    spelled one level too high.
    """
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(SystemExit) as exc:
        from_spec(spec, home)
    assert "dir:" in str(exc.value) or "absolute" in str(exc.value)


def test_a_tilde_spec_with_a_doubled_slash_stays_inside_the_home(tmp_path):
    """`Path('/home/me') / '/etc'` is '/etc', so '~//etc' left the home.

    cli._expanded lstrips for exactly this reason, two modules over and in the
    same command: `init --dest '~//etc'` stored the spec and every later push
    targeted /etc. Two doors in one package normalising '~' differently is the
    shape every one of these rounds has been about.
    """
    home = tmp_path / "home"
    home.mkdir()
    assert from_spec("~//etc", home).root == home / "etc"
    assert from_spec("dir:~//etc", home).root == home / "etc"
    assert from_spec("~///a/b", home).root == home / "a" / "b"


def test_an_absolute_directory_spec_still_parses(tmp_path):
    """The control beside the refusals above: what a spec is FOR still works."""
    home = tmp_path / "home"
    home.mkdir()
    assert from_spec("dir:/abs/archive", home).root == pathlib.Path("/abs/archive")
    assert from_spec("dir:~", home).root == home
    assert from_spec("dir:~/archive", home).root == home / "archive"
    assert from_spec("~", home).root == home
