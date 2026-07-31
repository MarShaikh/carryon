"""Command line entry point.

Argument normalisation runs upstream of every guard in this package, which is
why it is a chokepoint rather than a convenience. A path mangled here defeats
guards that are themselves correct: `cmd_capture` called
`.expanduser().resolve()` on `--out` and `--archive`, and `resolve()` follows
a symlink - so `external.write_owned`, the one function in carryon that puts
content at a path carryon does not own, was handed a path that was no longer
the one the user typed. It asked its ownership question about the link's
TARGET and answered correctly about the wrong path, which is round seven's
lesson arriving in the one place round seven did not look.

So every path-valued argument goes through `_named_path` and no subcommand
normalises anything for itself. What that function does, in order, is the
whole of the design:

  the spelling   an argument that is empty, blank or holds a NUL is not a
                 path, and neither is one this machine will not answer about.
                 `--out ''` is `Path('')`, whose `resolve()` is the working
                 directory - it captured a plaintext Setup into this project's
                 own tree while the fix was being written. A NUL was a
                 ValueError, and not even the same ValueError on the two
                 interpreters carryon must pass.
  the expansion  '~' against the home this command is running under, never
                 `$HOME` from the environment and never `resolve()`. Expanding
                 is what the user asked for; resolving is answering about a
                 different path than the one they named.
  the use        whether it can be used for what the subcommand needs - a
                 directory to capture into, a file to write, one to read - and
                 whether something else already holds the name. `external`
                 answers that half, in `external`'s own words.

The ownership question here does NOT replace the one at the write. Two things
are true at once: the answer about a name is only true until the next syscall
(ADR-0009), so `write_owned` still asks on the descriptor; and `--out` names
the ROOT every later question is asked FROM, which no walk downward from that
root can ever see. If the door does not ask about the root, nothing does.

The other half is the enumeration. Every argument of every subcommand is
either path-valued and goes through `_named_path`, or becomes a filesystem
name somewhere else and takes the string half here while the one function that
owns its meaning settles the rest (a Destination spec is stored verbatim and
expanded per machine, so expanding it here would stop the Archive being
machine-neutral), or has a door of its own. tests/test_cli_arguments.py holds
that table and reads it off the parser, so an argument added to a subcommand
fails a test until somebody has said which door settles it.
"""

from __future__ import annotations

import argparse
import errno
import getpass
import os
import pathlib
import stat
import sys

from . import __version__, capture, config, crypto, external, layout, sync
# No HOME here on purpose: it is bound at import in adapters/__init__, and
# every command below asks pathlib.Path.home() for itself instead.
from .adapters import ADAPTERS, CATEGORIES, is_installed
from .adapters import present as adapters_present
from .destinations import SPEC_FORMS
from .destinations.base import printable


def _parse_subset(value: str, known, label: str) -> set:
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    unknown = chosen - set(known)
    if unknown:
        raise SystemExit(
            f"unknown {label}: {', '.join(sorted(unknown))}\n"
            f"known {label}s: {', '.join(known)}")
    return chosen


# --- the door every path-valued argument goes through ------------------------

# What a subcommand needs the path FOR. The question is not "is this a valid
# path" - every one of these is a legal name - but "can this be used for what
# the command is about to do", which has a different answer per argument and
# is the reason one flag's refusal cannot be another's.
DIR_TO_MAKE = "a directory carryon captures into"
FILE_TO_MAKE = "a file carryon writes"
NEW_FILE = "a file carryon creates without replacing one"
FILE_TO_READ = "a file carryon reads"

_ABSENT, _DIR, _FILE, _OTHER, _UNANSWERED = (
    "absent", "dir", "file", "other", "unanswered")


def _why(exc) -> str:
    return getattr(exc, "strerror", None) or str(exc)


def _refuse(flag, value, why):
    """A refusal naming the argument and the spelling the user gave it.

    `repr` of the value, the way `sync._parse_maps` already names a bad
    `--map`: the difference between an empty argument and a missing one, or
    between a path and a path with a trailing space, is invisible otherwise -
    and these refusals exist to tell somebody which of the things they typed
    was wrong. Through `printable` because a name may hold a newline or the
    ESC that starts a CSI sequence, and the sentence is the whole output.
    """
    raise SystemExit(f"{flag} {printable(repr(str(value)))}: {why}")


def _spelling(value, flag: str) -> str:
    """The argument as text carryon can put in a name, or SystemExit.

    The half of the door that touches no filesystem, and the WHOLE of it for
    an argument that becomes a name somewhere else - a Destination spec, a
    machine name, a `--map` rule. Those must not be expanded here (a spec is
    stored verbatim and expanded against each machine's own home, which is
    what keeps an Archive machine-neutral), but a NUL in one is admitted at
    exit 0 today and surfaces as a ValueError from a syscall several commands
    later, with nothing left to connect it to the argument that caused it.
    """
    if not isinstance(value, str):
        _refuse(flag, value, "that is not text")
    if not value.strip():
        _refuse(flag, value, "an empty argument names nothing. Leave the flag "
                             "out, or give it a value")
    if "\x00" in value:
        _refuse(flag, value, "a NUL cannot be part of a name, and no "
                             "filesystem will take one. Python answers it "
                             "with a ValueError whose text is not even the "
                             "same on two interpreters, so carryon says it "
                             "here instead")
    return value


def _expanded(text: str, flag: str, home) -> pathlib.Path:
    """'~' against the home this command is running under.

    Never `os.path.expanduser`, which reads `$HOME` from the environment: the
    rest of this package expands against the home it was handed
    (`destinations._expand` says so in as many words), a command running over
    a different home would disagree with itself, and a test could not point
    the two anywhere.

    A leading '~' that is not this machine's home is refused rather than left
    alone. `Path('~alice/x')` is a RELATIVE path - it lands under the working
    directory, which is nobody's home at all.
    """
    if text == "~":
        return pathlib.Path(home)
    if text.startswith("~/"):
        # lstrip, because `Path('/home/me') / '/etc'` is `/etc`: a '~//etc'
        # would otherwise expand to somewhere outside the home it names.
        return pathlib.Path(home) / text[2:].lstrip("/")
    if text.startswith("~"):
        _refuse(flag, text, "carryon expands '~' against this machine's home "
                            "and knows no other one; spell the path out")
    return pathlib.Path(text)


def _absolute(path: pathlib.Path, flag: str) -> pathlib.Path:
    """The same path, against the working directory if it is relative.

    Absolute, not resolved - which is the whole subject of this module.
    `resolve()` also made a path absolute, and every report line and every
    ownership question downstream took its answer, so the two got confused
    for each other. This does the half the user asked for.
    """
    if path.is_absolute():
        return path
    try:
        return pathlib.Path.cwd() / path
    except OSError as exc:
        _refuse(flag, path, "that is a relative path and this machine will "
                            f"not say where it is standing ({_why(exc)})")


def _shape(path, follow: bool) -> tuple:
    """(kind, why) for one name - never an exception.

    `os.stat` rather than `Path.exists()`, for the reason layout.py's own
    walk gives: exists() swallows exactly four errnos and raises every other
    one, EACCES included, so "this machine will not answer about that path"
    arrives as a traceback rather than as an answer.

    `follow` is the difference between a parent and a leaf. A parent
    directory reached through a link is ordinary - `/tmp` is one on macOS -
    so the parent question follows. A leaf is asked about as itself, because
    what stands AT the name is the question.
    """
    try:
        info = os.stat(str(path)) if follow else os.lstat(str(path))
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return _ABSENT, ""
        return _UNANSWERED, f"this machine would not look at it ({_why(exc)})"
    except ValueError as exc:
        return _UNANSWERED, f"this machine would not look at it ({exc})"
    if stat.S_ISDIR(info.st_mode):
        return _DIR, ""
    if stat.S_ISREG(info.st_mode):
        return _FILE, ""
    return _OTHER, ""


def _size_of(path) -> int:
    """A file's size for a report line, or 0.

    The line says how big what was just written is. A file that vanished
    between the write and the report is worth one wrong number, not a
    traceback out of a command that had already done its job.
    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _named_path(value, flag: str, want: str, home) -> pathlib.Path:
    """The path `flag` names, having answered whether it can be used for
    `want`. SystemExit with a sentence when it cannot, None when the argument
    was not given.

    The one place in carryon where a command-line argument becomes a path.
    Every subcommand takes its paths from here, and none of them expands,
    resolves or probes one of its own - which tests/test_cli_arguments.py
    enforces over this module's syntax tree, because a rule written down in
    one function and trusted to every caller is exactly what the last seven
    rounds each found one caller short of.

    The ownership question is `external.owner_of` asked from the HOME this
    command is running under, which is the one thing this function knows that
    the writer cannot: `owner_of` walks down from the root it is given, a root
    is not its own ancestor, and `--out` is the root every later question is
    asked from. A link at or above `--out` is invisible to every guard
    downstream of it.

    It used to be asked from the path's own parent, which answered about the
    leaf and about nothing above it - so `--out ~/backups` was refused with
    the link named and `--out ~/backups/today` wrote a whole plaintext Setup
    into the repository behind it, at exit 0, with nothing in the report about
    a link. That is one rule drawn in two places at once: the leaf refused as
    if the user had not chosen the path, the parent accepted as if they had.

    $HOME is where it is drawn now, and neither of the obvious alternatives
    works. Walking the chain from the filesystem root refuses `--out /tmp/x`
    on every mac, where /tmp and /var are both symlinks - `_shape` says a
    parent reached through a link is ordinary for exactly that reason.
    Accepting the whole chain gives ADR-0007 up on the one argument that
    writes a plaintext Setup with no Destination and no key in front of it.
    $HOME is where the tools ADR-0007 is about put their links - stow,
    chezmoi, yadm, a bare checkout - and it is the root `external.plan`
    already asks the restore leg's copy of this question from, so the two legs
    now answer it the same way. Outside $HOME `owner_of` judges the named path
    alone, which is what this call did before and what keeps a tmp directory
    usable.

    The cost is real and it is the same cost the leaf check already charged: a
    user whose ~/Dropbox is itself a symlink has to spell out where it points,
    or point `--out` somewhere else. A Destination is exempt from this and
    stays exempt (ADR-0009, "a Destination is often ~/Dropbox, which is quite
    reasonably a link") - it is not a path argument, carryon never writes
    through it with an ownership question of its own, and its spec is stored
    verbatim rather than expanded here.

    None rather than a refusal for an argument nobody passed, so the caller
    needs no `if` around the call - an `if args.archive` before the door is
    the shape that lets the next argument past it.
    """
    if value is None:
        return None
    path = _absolute(_expanded(_spelling(value, flag), flag, home), flag)

    if want == FILE_TO_READ:
        # Follows a link: ADR-0007 says carryon reads through an externally
        # owned path happily. It is the writing that defers.
        kind, why = _shape(path, follow=True)
        if kind == _ABSENT:
            _refuse(flag, path, "no such file")
        if kind == _UNANSWERED:
            _refuse(flag, path, why)
        if kind != _FILE:
            _refuse(flag, path, "that is not an ordinary file, and carryon "
                                "reads one of those")
        return path

    if path.name in ("", ".."):
        # `resolve()` used to collapse these into a real name, which is the
        # one thing it did that was worth having. A write argument has to name
        # its own last component: what `--out` makes is named after it, and so
        # is every member of the .tar.gz `--archive` packs - `--out ..` put
        # '../claude/settings.json' inside a tar carryon produced, which is a
        # tar that writes outside wherever it is unpacked.
        _refuse(flag, path, "that has no last component of its own - a path "
                            "ending at the filesystem root or at '..' leaves "
                            "carryon nothing to name, and what it writes is "
                            "named after one")

    kind, why = _shape(path.parent, follow=True)
    if kind == _ABSENT:
        _refuse(flag, path,
                f"the directory {printable(str(path.parent))} does not exist. "
                "carryon makes the last component of a path it is given, "
                "never the ones above it - a mistyped directory should be a "
                "sentence rather than a tree of new directories")
    if kind == _UNANSWERED:
        _refuse(flag, path, why)
    if kind != _DIR:
        _refuse(flag, path, "something that is not a directory stands at "
                            f"{printable(str(path.parent))}")

    status, owner = external.owner_of(path, pathlib.Path(home))
    if status == external.EXTERNALLY_OWNED:
        _refuse(flag, path, external.refusal(owner))

    kind, _why_leaf = _shape(path, follow=False)
    if want == DIR_TO_MAKE and kind not in (_ABSENT, _DIR):
        _refuse(flag, path, "something that is not a directory stands there, "
                            "and this argument names a directory carryon "
                            "writes a Setup into")
    if want == FILE_TO_MAKE and kind == _DIR:
        _refuse(flag, path, "a directory stands there, and this argument "
                            "names a file")
    if want == NEW_FILE and kind != _ABSENT:
        _refuse(flag, path, "that exists already, and carryon will not write "
                            "over it - remove it, or name another with --out")
    return path


def cmd_list(args) -> int:
    """Show which agents are here and what would be carried from each.

    Both halves of cmd_capture's docstring, because this command's help text
    is "show detected agents and what would be captured" and it had only the
    first. It passes the home explicitly, and it reads the EFFECTIVE registry
    - excludes applied, handpicked paths added (ADR-0008) - so what it lists
    is what `capture` and `push` would actually write. Reading the raw
    registry instead described a different Setup from the one carryon
    produces: a file the user had excluded was listed as carried, and a path
    they carry by hand was missing from the listing entirely.

    `present` rather than a bare exists(): a mode-000 agent directory is a
    PermissionError out of the second of those two calls, and this command
    should answer the same way `doctor` does (adapters.present).
    """
    home = pathlib.Path.home()
    effective = sync._effective_adapters(config.load(home), home)
    print("Agents detected on this machine:\n")
    for key, adapter in effective.items():
        installed = key not in ADAPTERS or is_installed(key, home)
        print(f"  [{'x' if installed else ' '}] {key:<20} {adapter.name}")
        if not installed:
            continue
        for category in CATEGORIES:
            names = [item.src.split("/")[-1] for item in adapter.items
                     if item.category == category
                     and adapters_present(home / item.src)]
            if names:
                print(f"        {category:<11} {', '.join(names)}")
    print("\nEverything above is Setup - carried plaintext, refused if a "
          "credential is found.\nThe History (Transcripts, per-project "
          "memory) moves with `carryon push`, always encrypted.")
    return 0


def cmd_crypt(args) -> int:
    """Encrypt or decrypt any file with a passphrase.

    Both paths come from the door, the derived one included: a default output
    beside the input is a path nobody typed, and it is every bit as likely to
    be a link into a repository somebody else manages. It used to be a bare
    `dst.exists()`, which answers False for a DANGLING link - so `--out` at
    one created the file at the other end, through openssl, which follows a
    link like everything else does.

    Both are settled BEFORE the passphrase prompt. A user who typed the path
    wrong should be told which argument was wrong, not asked to type a secret
    twice and then told the file was never there.
    """
    home = pathlib.Path.home()
    src = _named_path(args.file, "FILE", FILE_TO_READ, home)
    encrypting = args.command == "encrypt"
    named = _named_path(args.out, "--out", NEW_FILE, home)
    dst = named if named is not None else _named_path(
        str(_alongside(src, encrypting)), "--out", NEW_FILE, home)

    passphrase = getpass.getpass("passphrase: ")
    if encrypting:
        if passphrase != getpass.getpass("confirm: "):
            raise SystemExit("passphrases do not match")
        if not passphrase:
            raise SystemExit("empty passphrase")

    try:
        (crypto.encrypt if encrypting else crypto.decrypt)(src, dst, passphrase)
    except crypto.CryptoError as exc:
        raise SystemExit(f"{args.command} failed: {exc}")

    print(f"{dst}  ({_size_of(dst)/1024:.0f}K)")
    if encrypting:
        print("The plaintext is still on disk. Delete it when you no longer need it.")
    return 0


def _alongside(src: pathlib.Path, encrypting: bool) -> pathlib.Path:
    """Where the output goes when the user named no `--out`."""
    if encrypting:
        return src.with_suffix(src.suffix + ".enc")
    return _strip_enc(src)


def _strip_enc(path: pathlib.Path) -> pathlib.Path:
    return path.with_suffix("") if path.suffix == ".enc" else path.with_name(
        path.name + ".decrypted")


def cmd_doctor(args) -> int:
    """Report anything on disk this tool does not recognise.

    Passes the home directory explicitly, the way cmd_push, cmd_pull and
    cmd_capture do. It was left to layout.inspect's default before, which is
    bound at import in adapters/__init__ and so cannot be pointed anywhere
    else - which meant the one command whose whole job is to describe this
    machine's agent directories was the one command no test could point at a
    directory. cmd_capture's docstring names this exact shape, one command
    over, after it had been fixed there.

    And over the effective registry, which is the other half of that same
    docstring. `doctor` calls an entry no adapter declares "unrecognised" and
    then prints "Nothing unrecognised is ever captured" - which is false of a
    handpicked path (ADR-0008), the one kind of entry the user has explicitly
    told carryon to carry. This is the command someone runs to find out
    whether something is wrong; it has to describe the Setup this machine
    actually produces.
    """
    home = pathlib.Path.home()
    effective = sync._effective_adapters(config.load(home), home)
    with sync._swapped_registry(effective):
        print(layout.format_report(layout.inspect(home)))
    return 0


def cmd_init(args) -> int:
    """Set this machine up, having spelled its two text arguments.

    Neither is a path carryon opens, and neither may be expanded here: the
    Destination spec is written to config.json verbatim and expanded against
    each machine's own home at use time (destinations._expand), which is what
    lets one Archive be shared by machines whose homes are `/Users/you` and
    `/home/you`. What the string half catches is a name no filesystem will
    take - a NUL in `--dest` or `--machine` was stored happily and surfaced
    as a ValueError out of a `push` two commands later.
    """
    args.dest = _spelling(args.dest, "--dest") if args.dest else args.dest
    args.machine = (_spelling(args.machine, "--machine") if args.machine
                    else args.machine)
    return sync.init(args, pathlib.Path.home())


def cmd_push(args) -> int:
    return sync.push(args, pathlib.Path.home())


def cmd_pull(args) -> int:
    """Lay the Archive down here.

    What a `--map` MEANS is settled in sync._parse_maps rather than here,
    which is the one function every pull takes its maps from - before the
    Destination is opened and before a byte of History is read, because the
    rewrite it drives runs inside the loop that writes and a refusal from
    there would land on a $HOME that is already half re-keyed. It was asked
    here instead, so `sync.pull` called any other way - by this project's own
    suites, or by whatever command pulls next - never asked it at all.

    The string half is asked here and is not a second door: `_parse_maps`
    settles what a usable map SET is, and this settles what a usable
    ARGUMENT is, which is the same question every other argument of every
    other subcommand takes. A `--map` holding a NUL passes rekey.map_refusal
    (both sides are absolute, neither is prose) and is then substituted into
    the text of every restored Transcript.
    """
    args.map = [_spelling(raw, "--map") for raw in args.map]
    return sync.pull(args, pathlib.Path.home())


def cmd_pair(args) -> int:
    return sync.pair(args, pathlib.Path.home())


def cmd_capture(args) -> int:
    """Capture into a directory, with no Destination and no key involved.

    Both paths are settled at the door before anything else happens - before
    the config is read and before the registry is swapped - because a wrong
    path should be a sentence rather than three printed lines and then a
    NotADirectoryError. They used to be `.expanduser().resolve()` here, which
    is this round's whole subject: `resolve()` follows a symlink, so `--out <a
    link into a dotfiles repo>` filled that repo at exit 0 and `--archive <a
    link>` overwrote the file at the other end, with the guard for both
    present, correct and asked about the target instead of the name.

    Passes the home directory explicitly, the way cmd_push and cmd_pull do.
    It was left to capture.run's default before, which is bound at import and
    so cannot be pointed anywhere else - which meant the one command that
    writes a plaintext Setup straight to a path the user names was the one
    command no test could drive over a synthetic home.

    And it captures from the same registry `push` captures from: excludes
    applied, handpicked paths added (ADR-0008). This command read no config at
    all, so the two described different Setups - a file the user had excluded
    was left out of the Archive and written in the clear here, under a scan
    verdict that cannot see an opaque token, while a path the user carries by
    hand was in the Archive and missing from this directory. The registry is
    swapped in place because the engine reads it as a module global and knows
    about no caller (sync's docstring says why).
    """
    home = pathlib.Path.home()
    out = _named_path(args.out, "--out", DIR_TO_MAKE, home)
    archive = _named_path(args.archive, "--archive", FILE_TO_MAKE, home)
    cfg = config.load(home)
    with sync._swapped_registry(sync._effective_adapters(cfg, home)):
        agents = (_parse_subset(args.agent, ADAPTERS, "agent")
                  if args.agent else None)
        categories = (_parse_subset(args.category, CATEGORIES, "category")
                      if args.category else None)
        code, _ = capture.run(
            out=out,
            dry=not args.apply,
            want_agents=agents,
            want_categories=categories,
            home=home,
            archive=archive,
        )
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="carryon",
        # What a Setup carries is scanned against the credential shapes carryon
        # knows and bounded in what it may read (ADR-0001, ADR-0008); neither
        # proves it holds no secret, since a random token matches no rule. So
        # this says what was checked, and that a Setup travels in the clear -
        # which is what decides whether the storage needs to be private.
        description="Carry an AI coding agent's working life between "
                    "machines: the Setup that makes an agent yours, and the "
                    "History of what you did with it - the Setup in the clear "
                    "and checked for credentials, the History always "
                    "encrypted.")
    parser.add_argument("--version", action="version",
                        version=f"carryon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show detected agents and what would be captured")
    listing.set_defaults(func=cmd_list)

    doctor = sub.add_parser(
        "doctor",
        help="check for layout changes: entries no adapter recognises")
    doctor.set_defaults(func=cmd_doctor)

    ini = sub.add_parser(
        "init", help="set up this machine: Destination, recovery key, config")
    ini.add_argument("--dest", metavar="SPEC",
                     help=f"the Destination: {SPEC_FORMS}")
    ini.add_argument("--join", metavar="CODE",
                     help="pairing code from `carryon pair` on an "
                          "already-paired machine (needs --dest too)")
    ini.add_argument("--machine", metavar="NAME",
                     help="this machine's name in the Archive (default: hostname)")
    ini.set_defaults(func=cmd_init)

    pus = sub.add_parser(
        "push", help="push this machine's Snapshot: the Setup plaintext, "
                     "the History encrypted, changed Sessions only")
    pus.add_argument("--apply", action="store_true",
                     help="actually push (default: dry run)")
    pus.add_argument("--agent", metavar="A,B",
                     help=f"subset of: {', '.join(ADAPTERS)}")
    pus.add_argument("--category", metavar="A,B",
                     help=f"subset of: {', '.join(CATEGORIES)}")
    pus.set_defaults(func=cmd_push)

    pul = sub.add_parser(
        "pull", help="lay the Archive down here: union the History, "
                     "replace the Setup after a backup")
    pul.add_argument("--apply", action="store_true",
                     help="actually write (default: dry run, shows the plan)")
    pul.add_argument("--map", action="append", default=[], metavar="OLD=NEW",
                     help="rewrite a path outside $HOME on the way in - both "
                          "sides absolute, no '~'. Repeatable; longest OLD "
                          "wins. It is a plain substring replace over every "
                          "value in every restored Transcript and over the "
                          "restored Setup, so it is refused unless it names "
                          "paths")
    pul.add_argument("--force", action="store_true",
                     help="write through externally owned paths "
                          "(dotfiles symlinks) instead of skipping them")
    pul.set_defaults(func=cmd_pull)

    par = sub.add_parser(
        "pair", help="mint a one-time code that hands another machine the "
                     "master key, via the Destination")
    par.set_defaults(func=cmd_pair)

    cap = sub.add_parser("capture", help="capture portable state into a directory")
    cap.add_argument("--out", required=True, help="destination directory")
    cap.add_argument("--apply", action="store_true",
                     help="actually write (default: dry run)")
    cap.add_argument("--agent", metavar="A,B",
                     help=f"subset of: {', '.join(ADAPTERS)}")
    cap.add_argument("--category", metavar="A,B",
                     help=f"subset of: {', '.join(CATEGORIES)}")
    cap.add_argument("--archive", metavar="FILE.tar.gz",
                     help="also pack the Setup into a single file")
    cap.set_defaults(func=cmd_capture)

    for name, helptext in (
        ("encrypt", "encrypt any file before it crosses a network"),
        ("decrypt", "decrypt a file encrypted by `carryon encrypt`"),
    ):
        crypt = sub.add_parser(name, help=helptext)
        crypt.add_argument("file")
        crypt.add_argument("--out", help="output path (default: alongside the input)")
        crypt.set_defaults(func=cmd_crypt)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
