"""When a question may be asked, and how one is asked (ADR-0011).

`init` asks - which Destination, which Provider, create the bucket or not -
and one rule decides whether it may: a terminal on both ends. Over SSH with
no tty, in CI, in a container, under a pipe on either side, nothing here is
called at all; the command prints what it found and exits the way it always
did, so nothing that used to be scriptable stops being scriptable. That rule
is `available`, it is the only policy in this module, and every caller asks
it rather than re-spelling `isatty` for itself.

The rest is the mechanics of one question: ask, choose from a numbered list,
confirm yes-or-no, take a secret without echo. Two seams - `_read_line` and
`_read_secret` - are all of the terminal this module touches, so the suite
can hold a whole dialogue's answers without one, and no other module in the
package ever calls input() or getpass for itself.

End of input is a cancelled command, not a traceback: the dialogue runs
before anything is minted or written, so Ctrl-D costs nothing and says so.
"""

from __future__ import annotations

import getpass
import sys

_CANCELLED = ("cancelled - the input ended mid-question, and nothing was "
              "set up or written")


def available() -> bool:
    """Whether a question may be asked at all: a terminal on BOTH ends.

    stdin because an answer must come from a person rather than from a pipe
    that never planned to give one; stdout because a question nobody sees is
    a command that hangs - a redirected `init` is being parsed, not read.
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def _read_line(prompt: str) -> str:
    return input(prompt)


def _read_secret(prompt: str) -> str:
    return getpass.getpass(prompt)


def _next(reader, prompt: str) -> str:
    try:
        return reader(prompt)
    except EOFError:
        raise SystemExit(_CANCELLED)


def ask(question: str, default=None) -> str:
    """One free-text answer, stripped. An empty answer takes the default when
    there is one and re-asks when there is not - a blank is not a name, and
    the door in cli.py says the same of an argument."""
    prompt = (f"{question} [{default}]: " if default is not None
              else f"{question}: ")
    while True:
        answer = _next(_read_line, prompt).strip()
        if "\x00" in answer:
            # The same rule cli._spelling applies to an argument: a NUL is
            # not part of any name, a terminal can produce one (Ctrl-@),
            # and stored now it is a ValueError out of a later command with
            # nothing connecting it to the answer that caused it.
            print("a NUL cannot be part of a name, and no filesystem will "
                  "take one - try again")
            continue
        if answer:
            return answer
        if default is not None:
            return default


def choose(intro: str, labels) -> int:
    """One pick off a numbered list, as the index into `labels`.

    Numbered because the labels are paths and provider names - things nobody
    should have to retype to select, which is the friction ADR-0011 exists
    to remove.
    """
    print(intro)
    for n, label in enumerate(labels, start=1):
        print(f"  {n}) {label}")
    while True:
        answer = _next(_read_line, f"[1-{len(labels)}]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(labels):
            return int(answer) - 1


def confirm(question: str, default: bool = False) -> bool:
    """Yes or no, with the default shown in the prompt's case."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = _next(_read_line, f"{question} {hint}: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def secret(question: str) -> str:
    """One secret, unechoed and untouched - no strip, because a credential is
    whatever the service issued and its whitespace is the service's business.
    It passes through carryon on its way to rclone's config and is never
    kept (ADR-0011)."""
    return _next(_read_secret, f"{question}: ")
