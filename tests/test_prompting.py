"""When a question may be asked, and what an answer is (ADR-0011).

One rule decides whether carryon may prompt at all: a terminal on BOTH ends.
Over SSH with no tty, in CI, in a container, under a pipe on either side,
`init` prints the candidates and exits exactly as it always did - nothing that
used to be scriptable stops being scriptable, and no script ever blocks on a
question it cannot see.

Everything here reads through two seams (`_read_line`, `_read_secret`) so the
suite can hold a whole dialogue's answers without a terminal, and so no other
module in the package ever calls input() or getpass for itself.
"""

import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from carryon import prompting  # noqa: E402


def wire(monkeypatch, *answers):
    """Feed the dialogue these answers, in order; running out is EOF."""
    queue = list(answers)

    def next_answer(prompt):
        assert isinstance(prompt, str) and prompt, "a question with no text"
        if not queue:
            raise EOFError
        return queue.pop(0)

    monkeypatch.setattr(prompting, "_read_line", next_answer)
    monkeypatch.setattr(prompting, "_read_secret", next_answer)
    return queue


def a_tty(monkeypatch, stdin=True, stdout=True):
    monkeypatch.setattr(sys, "stdin",
                        types.SimpleNamespace(isatty=lambda: stdin))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(
        isatty=lambda: stdout, write=sys.stdout.write,
        flush=sys.stdout.flush))


# --- available: the one rule -------------------------------------------------


def test_available_needs_a_terminal_on_both_ends(monkeypatch):
    a_tty(monkeypatch, stdin=True, stdout=True)
    assert prompting.available() is True

    a_tty(monkeypatch, stdin=False, stdout=True)
    assert prompting.available() is False, "stdin is a pipe - CI, a heredoc"

    a_tty(monkeypatch, stdin=True, stdout=False)
    assert prompting.available() is False, \
        "stdout is a pipe - the listing is being parsed, not read"


def test_the_suite_itself_is_not_a_terminal():
    """The property every existing test leans on without saying so: under
    either runner, nothing prompts unless a test wires the seams."""
    assert prompting.available() is False


# --- ask ----------------------------------------------------------------------


def test_ask_strips_and_returns_what_was_typed(monkeypatch):
    wire(monkeypatch, "  my-bucket  ")
    assert prompting.ask("Bucket name") == "my-bucket"


def test_ask_returns_the_default_for_an_empty_answer(monkeypatch):
    wire(monkeypatch, "")
    assert prompting.ask("Remote name", default="carryon") == "carryon"


def test_ask_re_asks_when_empty_and_no_default(monkeypatch):
    wire(monkeypatch, "", "   ", "real")
    assert prompting.ask("Bucket name") == "real"


def test_ask_shows_the_default_in_the_prompt(monkeypatch):
    prompts = []

    def remember(prompt):
        prompts.append(prompt)
        return ""

    monkeypatch.setattr(prompting, "_read_line", remember)
    prompting.ask("Remote name", default="carryon")
    assert "carryon" in prompts[0], \
        "a default the user cannot see is a decision made for them"


# --- choose --------------------------------------------------------------------


def test_choose_returns_the_index_of_the_numbered_answer(monkeypatch, capsys):
    wire(monkeypatch, "2")
    picked = prompting.choose("Where should the Archive live?",
                              ["iCloud Drive", "Dropbox", "somewhere else"])
    out = capsys.readouterr().out
    assert picked == 1
    assert "1)" in out and "3)" in out, "the options are numbered for typing"
    assert "Dropbox" in out


def test_choose_re_asks_on_garbage_and_out_of_range(monkeypatch):
    wire(monkeypatch, "nope", "0", "9", "3")
    assert prompting.choose("Pick", ["a", "b", "c"]) == 2


# --- confirm -------------------------------------------------------------------


def test_confirm_takes_yes_and_no_in_their_spellings(monkeypatch):
    wire(monkeypatch, "y")
    assert prompting.confirm("Create the bucket?") is True
    wire(monkeypatch, "NO")
    assert prompting.confirm("Create the bucket?") is False


def test_confirm_empty_takes_the_stated_default(monkeypatch):
    wire(monkeypatch, "")
    assert prompting.confirm("Proceed?", default=True) is True
    wire(monkeypatch, "")
    assert prompting.confirm("Proceed?", default=False) is False


def test_confirm_re_asks_on_anything_else(monkeypatch):
    wire(monkeypatch, "maybe", "yes")
    assert prompting.confirm("Proceed?") is True


def test_ask_re_asks_on_a_nul(monkeypatch, capsys):
    """The dialogue is a door for the same values cli._spelling guards on
    the command line, and a terminal can produce a NUL (Ctrl-@). Stored now,
    it is a ValueError out of a push two commands later."""
    wire(monkeypatch, "my\x00bucket", "my-bucket")
    assert prompting.ask("Bucket name") == "my-bucket"
    assert "NUL" in capsys.readouterr().out


# --- secret --------------------------------------------------------------------


def test_secret_passes_through_untouched(monkeypatch):
    """No strip: a credential is whatever the service issued, and trailing
    whitespace in one is the service's business, not carryon's."""
    wire(monkeypatch, " s3cr3t ")
    assert prompting.secret("Secret access key") == " s3cr3t "


# --- the way out ----------------------------------------------------------------


def test_end_of_input_is_a_cancelled_init_not_a_traceback(monkeypatch):
    """Ctrl-D half way through: a sentence saying nothing was set up. The
    dialogue runs before anything is minted, so cancelling costs nothing."""
    wire(monkeypatch)  # no answers at all
    for asking in (lambda: prompting.ask("Name"),
                   lambda: prompting.choose("Pick", ["a"]),
                   lambda: prompting.confirm("Sure?"),
                   lambda: prompting.secret("Key")):
        with pytest.raises(SystemExit) as exc:
            asking()
        assert "cancelled" in str(exc.value)
        assert "nothing" in str(exc.value)
