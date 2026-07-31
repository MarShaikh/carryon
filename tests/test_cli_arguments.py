"""One door for every path a user names on the command line.

Argument normalisation runs upstream of every guard in this package, so a
path mangled here defeats guards that are themselves correct. That is not a
hypothesis: `cmd_capture` called `.expanduser().resolve()` on `--out` and
`--archive`, and `resolve()` follows a symlink - so `external.write_owned`,
the one writer, was handed a path that was no longer the one the user named
and answered its ownership question about the target. The guard was present,
correct, and asked about the wrong path, which is round seven's lesson said
in a place round seven did not look.

Three shapes of finding live here, and they are the same finding:

  the named path   `--out <a link into a dotfiles repo>` filled that repo at
                   exit 0. `--archive <a link>` overwrote the file at the
                   other end. Nothing named either one.
  the sentence     `--out ''` captured a plaintext Setup into whatever
                   directory the shell happened to be in (it did that to this
                   project's own working tree while this suite was being
                   written). A path with a NUL was a ValueError - and not even
                   the same ValueError on the two interpreters carryon must
                   pass. A wrong path deserves a sentence.
  the enumeration  every one of the above was one argument of one subcommand.
                   The next one is a different argument of a different
                   subcommand, so the tables below name every argument of
                   every subcommand and say which door settles it. An argument
                   that is in neither table fails a test, which is the whole
                   of what stops the eighth round of this bug.

What the door does NOT do is replace the write chokepoint. It answers whether
an argument can be used at all, once, before a line of report has been
printed; `external.write_owned` still answers at the syscall, from the
descriptor, because the answer about a name is only true until the next one
(ADR-0009, ADR-0010). The door's own ownership question earns its place on
exactly one path: `--out` names the ROOT every later question is asked from,
and a root is the one thing that walk cannot see - so if the door does not ask
about it, nothing does.
"""

import argparse
import ast
import contextlib
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import cli, crypto, external  # noqa: E402
from tests.hostile_archive import (  # noqa: E402,F401
    build_home_a, file_keyring)
from tests.timeouts import time_limit  # noqa: E402

# --- the enumeration, which is the deliverable -------------------------------
#
# Every argument of every subcommand, and the door that settles it. Three
# tables rather than one because they are three different questions, and a
# rule with an unstated exception is what produced this round.

# Path-valued: a string that becomes a path carryon opens, makes or writes.
# Every one of these goes through cli._named_path and nothing else.
ARGUMENTS_THAT_NAME_A_PATH = {
    ("capture", "out"): "the directory a Setup is captured into",
    ("capture", "archive"): "the .tar.gz a Setup is also packed into",
    ("encrypt", "file"): "the file to encrypt",
    ("encrypt", "out"): "where the ciphertext goes",
    ("decrypt", "file"): "the file to decrypt",
    ("decrypt", "out"): "where the plaintext goes",
}

# User text that becomes a filesystem name somewhere ELSE, so the string half
# is asked here - empty, blank, a NUL - and what the value MEANS is settled by
# the one function that owns that meaning. Expanding any of these here would
# be the defect in the other direction: a Destination spec is stored verbatim
# in config.json and expanded against each machine's own home at use time, so
# a '~' resolved on this machine would stop the Archive being machine-neutral.
ARGUMENTS_WHOSE_MEANING_IS_SETTLED_ELSEWHERE = {
    ("init", "dest"): "a Destination SPEC - destinations.from_spec, which "
                      "sync.init calls before it mints anything",
    ("init", "machine"): "this machine's name in the Archive - "
                         "config.machine_name_refusal, asked by sync.init "
                         "before the key is minted or a pairing blob burnt, "
                         "and by config.validate on every load and save",
    ("pull", "map"): "a rewrite rule over text inside restored Transcripts, "
                     "never opened - sync._parse_maps, rekey.map_refusal",
}

# The entry above used to name sync._machine_name_refusal, which has exactly
# one caller - on the PULL leg, over names that came back off a Destination,
# so it never saw the argument at all. An enumeration whose entries are prose
# is an enumeration nobody can be wrong about out loud, so each of these is
# driven: a value that names something other than one place or one name has to
# be refused BY THE SUBCOMMAND, and the refusal has to arrive before the run
# has cost anything.
MEANS_SOMETHING_ELSE = [
    # (argv, what it would have meant)
    (["init", "--dest", "dir:"], "the working directory"),
    (["init", "--dest", "dir:."], "the working directory"),
    (["init", "--dest", "dir:relative/path"], "the working directory"),
    (["init", "--dest", "/tmp/x", "--machine", "."], "the shared setups root"),
    (["init", "--dest", "/tmp/x", "--machine", "/"], "the shared setups root"),
    (["init", "--dest", "/tmp/x", "--machine", "a/b"], "a nested directory"),
]

# Neither: settled entirely by a door of its own, which is already a sentence.
ARGUMENTS_THAT_ARE_NOT_TEXT_AT_ALL = {
    ("capture", "apply"): "a flag",
    ("capture", "agent"): "a subset of a known set - cli._parse_subset",
    ("capture", "category"): "a subset of a known set - cli._parse_subset",
    ("push", "apply"): "a flag",
    ("push", "agent"): "a subset of a known set - cli._parse_subset",
    ("push", "category"): "a subset of a known set - cli._parse_subset",
    ("pull", "apply"): "a flag",
    ("pull", "force"): "a flag",
    ("init", "join"): "a pairing code - sync.parse_pairing_code, which admits "
                      "16 characters from one alphabet and is a stricter door "
                      "than this one",
}

ALL_ARGUMENTS = dict(ARGUMENTS_THAT_NAME_A_PATH)
ALL_ARGUMENTS.update(ARGUMENTS_WHOSE_MEANING_IS_SETTLED_ELSEWHERE)
ALL_ARGUMENTS.update(ARGUMENTS_THAT_ARE_NOT_TEXT_AT_ALL)

# The functions the door is made of. Named here rather than derived, so that
# adding a helper to it is a review rather than a widening nobody sees.
THE_DOOR = {"_named_path", "_spelling", "_expanded", "_absolute", "_shape",
            "_size_of", "_refuse"}

# What a subcommand may not do for itself. `resolve()` is the defect this
# round is about; the rest are the bare probes layout.py was rewritten to stop
# using - Path.exists() swallows exactly four errnos and raises every other
# one, EACCES included.
NORMALISING = {"expanduser", "resolve", "exists", "is_file", "is_dir",
               "is_symlink", "stat", "lstat", "cwd", "mkdir", "iterdir"}


# --- helpers -----------------------------------------------------------------


@contextlib.contextmanager
def in_directory(path):
    """Run with the working directory pinned.

    Not tidiness: `--out ''` is `Path('')`, which resolves to the working
    directory, and the run that proves it captured a plaintext Setup into this
    project's own tree before this was here.
    """
    was = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(was)


def as_home(monkeypatch, home):
    """What every command will call this machine's home directory."""
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))


def no_passphrase(monkeypatch):
    """Make a passphrase prompt a failure rather than a wait.

    Every refusal below has to happen BEFORE the prompt: a user who typed a
    path wrong should be told so, not asked for a passphrase twice first. The
    prompt reads stdin, so leaving it in place would hang run_tests.py on a
    terminal; raising names the defect instead.
    """
    def asked(*_args, **_kw):
        raise AssertionError(
            "the passphrase was asked for before the path arguments were "
            "settled")

    monkeypatch.setattr(cli.getpass, "getpass", asked)


def answer(argv):
    """What `carryon <argv>` did: its exit code, or the exception it chose.

    Returned rather than raised, because the type IS the finding here and an
    assertion that names the argument beats a bare traceback.
    """
    try:
        return cli.main(argv)
    except BaseException as exc:      # noqa: B036 - the type is the finding
        return exc


def refusal_of(argv):
    """The SystemExit `carryon <argv>` ends with, having proved it is one."""
    got = answer(argv)
    assert isinstance(got, SystemExit), (
        f"`carryon {' '.join(argv)}` answered with "
        f"{type(got).__name__}: {got!r}")
    assert not isinstance(got, OSError)
    text = str(got)
    assert text and not text.isdigit(), \
        "SystemExit with no sentence in it - a user gets an exit code " \
        "and no idea which argument was wrong"
    return text


def parser_arguments():
    """[(subcommand, dest)] for every argument argparse accepts.

    Read off the parser rather than listed, so an argument added to any
    subcommand shows up here without anybody remembering to write it down.
    """
    parser = cli.build_parser()
    subs = [action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
    assert len(subs) == 1, "the parser grew a second set of subcommands"
    found = []
    for name, sub in subs[0].choices.items():
        for action in sub._actions:
            if action.dest in ("help", "==SUPPRESS=="):
                continue
            found.append((name, action.dest))
    return found


def cli_tree():
    return ast.parse(pathlib.Path(cli.__file__).read_text(), filename="cli.py")


def functions_of(tree):
    return {node.name: node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)}


def is_args_attribute(node, dests):
    return (isinstance(node, ast.Attribute) and node.attr in dests
            and isinstance(node.value, ast.Name) and node.value.id == "args")


# --- the confirmed defect: the guard was asked about the wrong path ----------


def test_capture_out_is_the_path_the_user_named(tmp_path, monkeypatch, capsys):
    """`--out` pointing at a symlink.

    cmd_capture called `.expanduser().resolve()`, so the directory every later
    ownership question is asked FROM was the link's target. carryon filled a
    tree it does not own, at exit 0, with nothing in the report about a link -
    which is ADR-0007's harm arriving through the one path ADR-0007's guard
    could not see, because `external._owning_link` walks DOWN from the root it
    is given and a root cannot be its own ancestor.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    repo = tmp_path / "dotfiles"          # somebody else's tree
    repo.mkdir()
    named = tmp_path / "setup"
    named.symlink_to(repo, target_is_directory=True)

    got = answer(["capture", "--out", str(named), "--apply"])
    capsys.readouterr()

    assert sorted(p.name for p in repo.iterdir()) == [], (
        "`capture --out <a symlink>` wrote through the link into a tree "
        "carryon does not own (ADR-0007)")
    assert isinstance(got, SystemExit), \
        f"the link was not named: {type(got).__name__} {got!r}"
    assert str(named) in str(got), \
        f"the refusal names something other than what was typed: {got}"


def test_capture_archive_is_the_path_the_user_named(tmp_path, monkeypatch,
                                                    capsys):
    """The same defect on the other argument, where the harm is a file that
    was already there.

    `write_owned` asks `owner_of(archive, archive.parent)`, which answers
    'externally owned' for a symlink at the leaf - and never saw one, because
    `resolve()` had already turned the argument into the link's target.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    repo = tmp_path / "dotfiles"
    repo.mkdir()
    theirs = repo / "setup.tar.gz"
    theirs.write_bytes(b"not carryon's bytes\n")
    named = tmp_path / "mine.tar.gz"
    named.symlink_to(theirs)

    got = answer(["capture", "--out", str(tmp_path / "out"), "--apply",
                  "--archive", str(named)])
    capsys.readouterr()

    assert theirs.read_bytes() == b"not carryon's bytes\n", \
        "`capture --archive <a symlink>` overwrote the file at the other end"
    assert isinstance(got, SystemExit), \
        f"the link was not named: {type(got).__name__} {got!r}"


def test_capture_out_does_not_materialise_a_dangling_link(
        tmp_path, monkeypatch, capsys):
    """A broken link is still externally owned (external.py's one non-obvious
    decision): whatever made it still claims the name. `resolve()` answers a
    dangling link with the path it points at, so `--out` created the target -
    a directory somewhere carryon was never pointed at, made from a name
    something else put there.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    target = tmp_path / "never-existed"
    named = tmp_path / "setup"
    named.symlink_to(target, target_is_directory=True)

    got = answer(["capture", "--out", str(named), "--apply"])
    capsys.readouterr()

    assert not os.path.lexists(str(target)), \
        "a dangling --out link was followed and its target created"
    assert isinstance(got, SystemExit), \
        f"the link was not named: {type(got).__name__} {got!r}"


def test_an_empty_out_does_not_capture_into_the_working_directory(
        tmp_path, monkeypatch, capsys):
    """`--out ''` is `Path('')`, which `resolve()` answers with the working
    directory - so `carryon capture --out '' --apply` wrote a plaintext Setup
    into whatever directory the shell was in. It did exactly that to this
    project's own tree while this suite was being written: `claude/`,
    `MANIFEST.json` and `RESTORE.md` beside `pyproject.toml`.

    An empty argument is not a path, and the shortest correct answer to one is
    a sentence.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    working = tmp_path / "working"
    working.mkdir()

    with in_directory(working):
        got = answer(["capture", "--out", "", "--apply"])
    capsys.readouterr()

    assert sorted(p.name for p in working.iterdir()) == [], \
        "`capture --out ''` captured a Setup into the working directory"
    assert isinstance(got, SystemExit), \
        f"an empty --out was not refused: {type(got).__name__} {got!r}"


# --- a wrong path gets a sentence, on both interpreters ----------------------


HOSTILE = {
    "empty": lambda tmp: "",
    "blank": lambda tmp: "   ",
    "a NUL": lambda tmp: str(tmp / "a\x00b"),
    "a nonexistent parent": lambda tmp: str(tmp / "no" / "such" / "name"),
    # The two spellings with no last component of their own. `resolve()`
    # collapsed both, which is the one thing it did that was worth having, so
    # they are the shapes most likely to have been carried by it silently:
    # `--out ..` names a directory whose name is '..', and capture packs a
    # .tar.gz whose members are all named after it.
    "the filesystem root": lambda tmp: "/",
    "a trailing dot-dot": lambda tmp: str(tmp / ".."),
}


def command_for(subcommand, dest, value, tmp):
    """The shortest `carryon <subcommand>` that puts `value` at `dest`.

    Every other argument is something ordinary, so a refusal is about the one
    under test and not about its neighbours.
    """
    readable = tmp / "readable.txt"
    if not readable.exists():
        readable.write_text("plaintext\n")
    if subcommand == "capture":
        base = ["capture", "--out", str(tmp / "out"), "--apply"]
        if dest == "out":
            return ["capture", "--out", value, "--apply"]
        return base + ["--archive", value]
    if dest == "file":
        return [subcommand, value]
    return [subcommand, str(readable), "--out", value]


@pytest.mark.parametrize("shape", sorted(HOSTILE))
@pytest.mark.parametrize("argument", sorted(ARGUMENTS_THAT_NAME_A_PATH))
def test_every_path_argument_answers_a_bad_spelling_with_a_sentence(
        argument, shape, tmp_path, monkeypatch, capsys):
    """A user typing a path wrong gets a sentence, on both interpreters.

    The round-7 verifier reported five shapes of `capture` argument that
    answered with a raw OS exception. Every shape below is one nobody had
    asked about: a NUL is a ValueError whose text is not even the same on the
    two interpreters carryon must pass ('embedded null byte' on 3.9, 'lstat:
    embedded null character in path' on 3.13), an empty argument was the
    working directory, and a path ending at '..' or the root was whatever
    `resolve()` made of it.

    Parametrised over the whole table rather than over the arguments that were
    reported, because the next one will be a different argument of a different
    subcommand: that is what every round of this project has found.
    """
    subcommand, dest = argument
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    no_passphrase(monkeypatch)
    working = tmp_path / "working"
    working.mkdir(exist_ok=True)
    argv = command_for(subcommand, dest, HOSTILE[shape](tmp_path), tmp_path)

    with in_directory(working), time_limit():
        text = refusal_of(argv)
    capsys.readouterr()

    flag = "FILE" if dest == "file" else "--" + dest
    assert flag in text, \
        f"the refusal does not say which argument was wrong: {text}"
    assert sorted(p.name for p in working.iterdir()) == [], \
        "a refused argument still wrote into the working directory"


@pytest.mark.parametrize("shape", ["out-is-a-file", "out-is-a-device",
                                   "archive-is-a-directory",
                                   "archive-under-a-file",
                                   "archive-is-a-fifo"])
def test_capture_answers_a_path_of_the_wrong_kind_with_a_sentence(
        shape, tmp_path, monkeypatch, capsys):
    """Naming a file where a directory belongs is the most ordinary
    user-facing error there is. `--out <an existing file> --apply` and
    `--out /dev/null --apply` were both NotADirectoryError, and `--archive <a
    directory>` had its own.

    All five were green before this round's fix: `capture.run` grew a mkdir
    guard and `external.write_owned` refuses the fifo with O_NONBLOCK and
    S_ISREG, so these are regression guards for work already done rather than
    evidence for work done here. They stay because the door now answers them
    one call earlier, before a line of report has been printed, and a refusal
    that moves is a refusal that can be lost.

    The fifo is the shape where asking costs more than a wrong answer: open()
    on a named pipe waits for a writer that never arrives, so a door that
    opened rather than stat-ed would hang rather than refuse (CONTEXT.md, 'a
    path this machine will not answer about').
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    standing = tmp_path / "a-file"
    standing.write_text("not a directory\n")
    directory = tmp_path / "a-directory"
    directory.mkdir()
    pipe = tmp_path / "a-pipe.tar.gz"
    os.mkfifo(str(pipe))
    argv = {
        "out-is-a-file": ["capture", "--out", str(standing), "--apply"],
        "out-is-a-device": ["capture", "--out", "/dev/null", "--apply"],
        "archive-is-a-directory": ["capture", "--out", str(tmp_path / "o"),
                                   "--apply", "--archive", str(directory)],
        "archive-under-a-file": ["capture", "--out", str(tmp_path / "o"),
                                 "--apply", "--archive",
                                 str(standing / "x.tar.gz")],
        "archive-is-a-fifo": ["capture", "--out", str(tmp_path / "o"),
                              "--apply", "--archive", str(pipe)],
    }[shape]

    with time_limit():
        refusal_of(argv)
    capsys.readouterr()


@pytest.mark.parametrize("argv,flag", [
    (["init", "--dest", "/tmp/a\x00b"], "--dest"),
    (["init", "--dest", "/tmp/x", "--machine", "a\x00b"], "--machine"),
    (["pull", "--map", "/a\x00b=/c"], "--map"),
])
def test_an_argument_that_becomes_a_name_elsewhere_is_still_spelled_here(
        argv, flag, tmp_path, monkeypatch, capsys):
    """The other two tables' string half.

    None of these is a path carryon opens, and none may be expanded here - a
    Destination spec is stored verbatim and expanded per machine, a map is a
    rewrite over text. But each becomes a filesystem name somewhere: `--dest`
    a directory to write an Archive into, `--machine` a directory name inside
    it. A NUL in one is admitted at exit 0 today and surfaces as a ValueError
    from a syscall several commands later, with nothing to connect it to the
    argument that caused it.

    The refusal has to NAME the argument. `pull --map <a NUL>` already ends in
    a SystemExit today - "this machine holds no master key" - which is a
    sentence about something else entirely, and a test that accepted it would
    be green over an unasked question.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)

    with time_limit():
        text = refusal_of(argv)
    capsys.readouterr()

    assert flag in text, \
        f"the refusal does not say which argument was wrong: {text}"


@pytest.mark.parametrize("argv,meant", MEANS_SOMETHING_ELSE,
                         ids=[" ".join(a) for a, _m in MEANS_SOMETHING_ELSE])
def test_an_argument_settled_elsewhere_is_really_settled_somewhere(
        argv, meant, tmp_path, monkeypatch, capsys):
    """The enumeration, driven rather than read.

    Both of these got past the door by being classified as somebody else's
    question and then not being anybody's. `--dest 'dir:'` was stored verbatim
    and expanded to a RELATIVE root, so every later `push --apply` wrote
    carryon/index.enc and a plaintext carryon/setups/<machine>/ tree into
    whatever directory the command ran in - it followed the user between
    projects and was complete in neither. `--machine .` and `--machine /` put
    this machine's Setup in the SHARED carryon/setups/ root and `--machine
    a/b` nested it, all at exit 0, after which every other machine's pull
    restored nothing and reported phantom machines called 'MANIFEST.json' and
    'RESTORE.md' for ever.

    `--dest '.'` and `--machine ..` were refused all along, which is what made
    both gaps look closed: the rule existed and was spelled one level above
    where the value arrives.

    Refused before anything is minted, which is the second half: `init` prints
    a recovery key it will never print again, and a refusal after that has
    cost the user the one secret carryon cannot reissue.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)

    with time_limit():
        text = refusal_of(argv)
    capsys.readouterr()

    assert not (home / ".carryon" / "config.json").exists(), \
        f"a Destination that means {meant} was stored"
    assert not (home / ".carryon" / "master.key").exists(), \
        "a refused argument still cost a recovery key"
    # The value the user typed, quoted back. Not the flag: `--dest` and the
    # `destination` key of a hand-edited config.json both arrive at the same
    # function, so a sentence naming the flag would be wrong for one of them -
    # and what the user has to find is which of the things they typed was
    # rejected (cli._refuse gives the same reason for quoting a value).
    assert repr(argv[-1]) in text, \
        f"the refusal does not quote what was typed: {text}"
    assert ("Destination" in text) if "--machine" not in argv \
        else ("machine" in text), \
        f"the refusal does not say which argument was wrong: {text}"


def test_list_answers_a_directory_it_cannot_look_at(tmp_path, monkeypatch,
                                                    capsys):
    """`list` walks $HOME with the answers `adapters.present` gives, which is
    the guarded form of Path.exists().

    A regression guard rather than a fix: this was closed while this round was
    being prepared, and a green test proves nothing about work already done.
    It is here because `list` is one of the two commands in this file that
    touch a path nobody named on the command line, and because the failure it
    guards - a PermissionError out of a command whose whole job is to describe
    this machine - needs no attacker at all.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    (home / ".claude").chmod(0o000)
    try:
        with time_limit():
            got = answer(["list"])
    finally:
        (home / ".claude").chmod(0o755)
    capsys.readouterr()

    assert not isinstance(got, OSError), \
        f"`carryon list` answered an unreadable directory with {got!r}"


# --- the enumeration is enforced, not maintained by reading -----------------


def test_every_argument_of_every_subcommand_is_classified():
    """The tables above cover the parser exactly.

    This is the test that makes the enumeration a deliverable rather than a
    paragraph. An argument added to any subcommand - a `--to` on pull, a
    second output on capture - fails here until somebody has said which door
    settles it, which is the review that would have caught `--archive` when it
    was added beside an `--out` that already had its own normalisation.
    """
    found = parser_arguments()
    assert len(found) == len(set(found)), "an argument is listed twice"

    unclassified = sorted(set(found) - set(ALL_ARGUMENTS))
    assert not unclassified, (
        "an argument no table names. Say which door settles it - "
        "cli._named_path for a path, the string half for a name that becomes "
        "one elsewhere, or its own parser: "
        + ", ".join(map(str, unclassified)))

    stale = sorted(set(ALL_ARGUMENTS) - set(found))
    assert not stale, ("the tables name arguments the parser no longer has: "
                       + ", ".join(map(str, stale)))

    overlap = (set(ARGUMENTS_THAT_NAME_A_PATH)
               & set(ARGUMENTS_WHOSE_MEANING_IS_SETTLED_ELSEWHERE))
    assert not overlap, "an argument in two tables has two doors"


def test_no_subcommand_normalises_a_path_of_its_own():
    """The structural half, and the honest answer to "what stops the seventh
    subcommand".

    Nothing in Python takes `.resolve()` away from a command, so cli.py's own
    syntax tree is what enforces the door: a subcommand that expands, resolves
    or probes a path for itself fails here with the function and the line
    named. Every previous round of this project ended with a rule written down
    in one function and a caller that did not call it, and this is the shape
    ADR-0010 settled on instead - a failing test rather than a reviewer's
    attention.
    """
    stray = []
    for name, node in sorted(functions_of(cli_tree()).items()):
        if name in THE_DOOR:
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr in NORMALISING):
                stray.append(f"{name}() line {inner.lineno}: "
                             f".{inner.func.attr}()")

    assert not stray, (
        "a subcommand normalises or probes a path for itself. Route it "
        "through cli._named_path, which expands the user's spelling without "
        "resolving it away and answers with a sentence:\n  "
        + "\n  ".join(stray))


def test_every_path_valued_argument_reaches_its_command_through_the_door():
    """The other half: the door exists AND every path argument goes through it.

    A subcommand can satisfy the test above by doing nothing at all - reading
    `args.out` and handing the raw string to an engine normalises nothing and
    resolves nothing. So every `args.<dest>` in cli.py whose dest names a path
    has to appear inside a `_named_path(...)` call, and nowhere else.
    """
    dests = {dest for _sub, dest in ARGUMENTS_THAT_NAME_A_PATH}
    tree = cli_tree()

    guarded = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_named_path"):
            continue
        for supplied in list(node.args) + [kw.value for kw in node.keywords]:
            for inner in ast.walk(supplied):
                if is_args_attribute(inner, dests):
                    guarded.add(inner.lineno)

    stray = sorted({f"line {node.lineno}: args.{node.attr}"
                    for node in ast.walk(tree)
                    if is_args_attribute(node, dests)
                    and node.lineno not in guarded})
    assert not stray, (
        "a path-valued argument reaches its subcommand without passing "
        "cli._named_path:\n  " + "\n  ".join(stray))

    used = {node.attr for node in ast.walk(tree)
            if is_args_attribute(node, dests)}
    assert used == dests, (
        "the table names a path argument cli.py never reads: "
        + ", ".join(sorted(dests - used)))


def test_the_door_is_one_function_that_answers_with_a_sentence():
    """The door's own contract, asked of the door.

    Everything else here drives `cli.main`, which cannot tell a refusal from
    one door from a refusal from another. This pins the piece the other tests
    assume: one callable, one SystemExit, one sentence naming the flag.
    """
    home = pathlib.Path("/nowhere-that-exists")
    for value in ("", "   ", "/tmp/a\x00b", "~someone-else/x"):
        with pytest.raises(SystemExit) as exc:
            cli._named_path(value, "--out", cli.DIR_TO_MAKE, home)
        assert "--out" in str(exc.value), \
            f"{value!r} was refused without naming the argument: {exc.value}"

    nothing = cli._named_path(None, "--archive", cli.FILE_TO_MAKE, home)
    assert nothing is None, \
        "an argument nobody passed is not a path, and not a refusal either"


# --- positive controls: the fix is not "refuse everything" -------------------


def test_an_ordinary_capture_still_writes_both_of_its_paths(tmp_path,
                                                            monkeypatch,
                                                            capsys):
    """The command as the README spells it, with both path arguments naming
    ordinary things that are not there yet."""
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    out = tmp_path / "setup"
    archive = tmp_path / "setup.tar.gz"

    code = cli.main(["capture", "--out", str(out), "--apply",
                     "--archive", str(archive)])
    report = capsys.readouterr().out

    assert code == 0, report
    landed = (out / "claude" / "settings.json").read_text()
    assert landed == '{"model": "opus"}', report
    assert archive.stat().st_size > 0


def test_a_relative_out_lands_where_the_user_is_standing(tmp_path, monkeypatch,
                                                         capsys):
    """`--out setup` is an ordinary way to name a directory, and the door
    makes it absolute against the working directory rather than refusing it.
    Absolute, not resolved: the two are the whole subject of this file.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    working = tmp_path / "working"
    working.mkdir()

    with in_directory(working):
        code = cli.main(["capture", "--out", "setup", "--apply"])
    capsys.readouterr()

    assert code == 0
    assert (working / "setup" / "claude" / "settings.json").is_file()


def test_a_tilde_expands_against_the_home_the_command_is_running_under(
        tmp_path, monkeypatch, capsys):
    """'~' is the user's spelling of their own home and has to keep working.

    Against the home the command is running under, never `$HOME` from the
    environment: every other expansion in this package takes the home it is
    given (destinations._expand says so in as many words), and a door that
    read the environment instead would be untestable and would disagree with
    the rest of the package on any machine where the two differ.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    monkeypatch.setenv("HOME", str(tmp_path / "somewhere-else"))

    code = cli.main(["capture", "--out", "~/setup", "--apply"])
    capsys.readouterr()

    assert code == 0
    assert (home / "setup" / "claude" / "settings.json").is_file(), \
        "'~' was expanded against something other than this command's home"


def test_encrypt_hands_the_engine_the_paths_the_user_named(tmp_path,
                                                           monkeypatch,
                                                           capsys):
    """The crypt leg's positive control, and the one place the claim can be
    made exactly: the engine is handed the named path, expanded and made
    absolute, with no link resolved away.

    crypto.encrypt is stood in for rather than run, because what is under test
    is which paths reach it - openssl's own behaviour has its own suite.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_a, **_kw: "hunter2")
    plain = home / "notes.txt"
    plain.write_text("plaintext\n")
    seen = {}

    def fake(src, dst, passphrase):
        seen["src"], seen["dst"] = src, dst
        dst.write_bytes(b"ciphertext\n")

    monkeypatch.setattr(crypto, "encrypt", fake)

    code = cli.main(["encrypt", "~/notes.txt"])
    capsys.readouterr()

    assert code == 0
    assert seen["src"] == home / "notes.txt"
    assert seen["dst"] == home / "notes.txt.enc"


def test_encrypt_will_not_write_through_a_link_it_was_handed(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    """The crypt leg's half of the confirmed defect.

    `--out` here is handed to openssl, which follows a link like everything
    else does, and the only question carryon had in front of it was
    `dst.exists()` - which answers False for a DANGLING link and re-raises
    EACCES rather than answering at all. So `carryon encrypt notes.txt --out
    <a dangling link into a dotfiles repo>` created the file at the other end.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    no_passphrase(monkeypatch)
    plain = home / "notes.txt"
    plain.write_text("plaintext\n")
    repo = tmp_path / "dotfiles"
    repo.mkdir()
    named = tmp_path / "out.enc"
    named.symlink_to(repo / "theirs.enc")

    with time_limit():
        refusal_of(["encrypt", str(plain), "--out", str(named)])
    capsys.readouterr()

    assert not (repo / "theirs.enc").exists(), \
        "encrypt --out wrote through a link into a tree carryon does not own"


def test_a_crypt_round_trip_through_the_cli_still_works(tmp_path, monkeypatch,
                                                        capsys):
    """The whole leg end to end, with real openssl, because the door now
    answers about `file` before the engine ever sees it - and an argument
    check that refuses the ordinary case is worse than the defect."""
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_a, **_kw: "hunter2")
    plain = home / "notes.txt"
    plain.write_text("plaintext\n")

    assert cli.main(["encrypt", str(plain)]) == 0
    plain.unlink()
    assert cli.main(["decrypt", str(home / "notes.txt.enc")]) == 0
    capsys.readouterr()

    assert (home / "notes.txt").read_text() == "plaintext\n"


def test_the_refusal_sentence_is_one_sentence(tmp_path):
    """`external.refusal` is what says who holds a path, and both askers get
    it from there.

    The door has to name an externally owned path in the same words the
    writer does. Two spellings of one rule is what ADR-0010 is about, and a
    sentence is easier to copy than a check.
    """
    assert "ADR-0007" in external.refusal(tmp_path / "somewhere")
    assert str(tmp_path) in external.refusal(tmp_path / "somewhere")


# --- where the door draws the ownership boundary, and why there ---------------
#
# The door asked `external.owner_of(path, path.parent)`, so it answered about
# the LEAF and about nothing above it. `--out ~/backups` with ~/backups a link
# into a dotfiles repo was refused with the link named; `--out ~/backups/today`
# filled that repo, at exit 0, with nothing in the report about a link - which
# is word for word the harm the leaf check exists to prevent, one keystroke
# away from the refusal. The rule was drawn in two places at once: the leaf
# refused as if the user had not chosen it, the parent accepted as if they had.
#
# It is drawn once now, at $HOME, and the boundary is worth stating because
# neither obvious answer is right. Walking the whole chain from the filesystem
# root refuses `--out /tmp/x` on every mac, since /tmp and /var are both
# symlinks there - `cli._shape`'s own docstring says a parent reached through a
# link is ordinary. Accepting the whole chain gives up ADR-0007 on the one
# argument that writes a plaintext Setup to a path with no Destination and no
# key in front of it. $HOME is where the tools ADR-0007 is about put their
# links - stow, chezmoi, yadm, a bare checkout - and it is the root
# `external.plan` already asks the restore leg's copy of this question from.
# Outside $HOME `owner_of` judges the named path alone, which is what it did
# here before and what keeps a tmp directory usable.


@pytest.fixture
def linked_repo(tmp_path, monkeypatch):
    """A home whose ~/backups is a link into a tree carryon does not own."""
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    repo = home / "dotfiles" / "agents"
    repo.mkdir(parents=True)
    (repo / "already-here").write_text("somebody else's file\n")
    (home / "backups").symlink_to(repo, target_is_directory=True)
    return home, repo


def contents(repo):
    return sorted(p.name for p in repo.iterdir())


@pytest.mark.parametrize("argv", [
    ["capture", "--out", "~/backups/today", "--apply"],
    ["capture", "--out", "~/out", "--apply", "--archive",
     "~/backups/setup.tar.gz"],
    ["encrypt", "~/.claude/settings.json", "--out", "~/backups/settings.enc"],
])
def test_a_write_one_component_under_a_link_is_refused_like_the_link_itself(
        argv, linked_repo, tmp_path, monkeypatch, capsys):
    """One component past the refusal was the whole Setup in somebody's repo.

    Measured on the leg it costs most: `capture --out ~/backups/today --apply`
    wrote MANIFEST.json, RESTORE.md and the entire claude/ tree into a git
    repository, and the report said nothing about a link. `--archive` and
    `encrypt --out` are the same shape on the other two arguments - and the
    encrypt case has to refuse BEFORE the passphrase prompt, which
    `no_passphrase` asserts by raising if it is reached.
    """
    home, repo = linked_repo
    no_passphrase(monkeypatch)

    text = refusal_of(argv)
    capsys.readouterr()

    assert contents(repo) == ["already-here"], (
        "carryon wrote through a link one component above the path it was "
        "given, into a tree it does not own (ADR-0007)")
    assert "backups" in text, \
        f"the refusal does not say which link stopped it: {text}"


def test_the_derived_encrypt_output_is_answered_for_too(
        linked_repo, monkeypatch, capsys):
    """`encrypt FILE` with no --out writes beside the input, and 'beside a
    file reached through a link' is inside the same repo. The door already
    settles that derived path; what it did not do was look above it."""
    home, repo = linked_repo
    no_passphrase(monkeypatch)
    (repo / "notes.txt").write_text("plaintext\n")

    text = refusal_of(["encrypt", "~/backups/notes.txt"])
    capsys.readouterr()

    assert contents(repo) == ["already-here", "notes.txt"], \
        "the derived --out landed inside the linked tree"
    assert "backups" in text


def test_an_ordinary_directory_under_the_home_is_untouched_by_the_rule(
        tmp_path, monkeypatch, capsys):
    """The control the refusals above are worth nothing without: a real
    directory under $HOME is nobody else's, and a path below it is written."""
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    (home / "backups").mkdir()

    code = cli.main(["capture", "--out", "~/backups/today", "--apply"])
    capsys.readouterr()

    assert code == 0
    assert (home / "backups" / "today" / "claude" / "settings.json").is_file()


def test_a_path_outside_the_home_is_judged_alone_and_not_by_its_ancestors(
        tmp_path, monkeypatch, capsys):
    """The boundary, stated as a test rather than only as a comment.

    Every macOS puts /tmp and /var behind symlinks, and pytest's own tmp
    directory sits under one of them, so a rule that walked the chain from the
    filesystem root would refuse the most ordinary `--out` there is. Outside
    $HOME the question is about the path the user named and nothing above it,
    which is what `external._owning_link` already does with a target it cannot
    make relative to the root it was given.
    """
    home = build_home_a(tmp_path)
    as_home(monkeypatch, home)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    through = tmp_path / "via-a-link"
    through.symlink_to(elsewhere, target_is_directory=True)

    code = cli.main(["capture", "--out", str(through / "today"), "--apply"])
    capsys.readouterr()

    assert code == 0
    assert (elsewhere / "today" / "claude" / "settings.json").is_file()
