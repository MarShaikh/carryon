"""The two ways of running this suite must run the same suite, and finish.

`.venv/bin/pytest tests/ -q` collects whatever sits in this directory.
run_tests.py works from a hand-written list instead, because it exists for a
machine that has no pytest and therefore no collection either. A hand-written
list drifts silently and in the safe-looking direction: two security modules
once sat here for a session while run_tests.py reported green over 54 fewer
tests than pytest was running. Nothing about that output looked wrong.

The second rule here is the same failure in the other dimension. A test that
does not finish reports nothing at all, and neither runner has a timeout of
its own: run_tests.py calls the function, and pytest without a plugin waits
as long as the function does. The suite plants named pipes on purpose - it is
the cheapest denial of service anyone with an account on the machine has, and
several guards exist for it - so a regression in one `O_NONBLOCK` turns the
test that was written to catch it into a run that never comes back. Measured,
not supposed: dropping O_NONBLOCK from the Destination layer's read wedged
two of these for ever, and dropping it from `config.read_carryable` wedged a
third.

That guard was in five modules in five hand-written copies and absent from
the four that needed it, which is ADR-0010's shape one layer out from the
package. It is `tests/timeouts.py` now, and this file is where the rule that
every fifo test uses it stops being something somebody has to remember.
"""

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_tests  # noqa: E402

# Importing run_tests is safe from inside either runner: everything at its
# top level is idempotent, main() is behind __name__ == "__main__", and its
# pytest stub installs only when `import pytest` fails - which it cannot
# here, since whichever runner is executing this has already provided one.


def test_run_tests_lists_every_test_module():
    on_disk = {"tests." + path.stem
               for path in (ROOT / "tests").glob("test_*.py")}
    listed = list(run_tests.MODULES)

    assert len(listed) == len(set(listed)), "a module is listed twice"
    missing = sorted(on_disk - set(listed))
    assert not missing, (
        "run_tests.py would skip these silently, and pytest would not: "
        + ", ".join(missing))
    assert not sorted(set(listed) - on_disk), \
        "run_tests.py lists a module that no longer exists"


def _calls(node) -> set:
    """Every function name called anywhere under `node`, dotted call included.

    `os.mkfifo(...)` is an Attribute call and `time_limit(...)` is a Name
    call, so both spellings are reduced to the last component - which is the
    part that says what is being done either way.
    """
    names = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if isinstance(func, ast.Attribute):
            names.add(func.attr)
        elif isinstance(func, ast.Name):
            names.add(func.id)
    return names


def test_a_test_that_plants_a_named_pipe_runs_under_a_time_limit():
    """A fifo blocks open() until a writer comes, and no writer is coming.

    Checked at two granularities because a fifo is planted at two: the test
    itself, which is the usual shape and is checked by name, and a helper the
    test calls, which the module-level half covers. Neither alone is the rule
    - a module that imports the limit and never uses it passes the first, and
    a test that plants a pipe through a helper passes nothing at all - so both
    are asserted and the failure names the function or the file.

    The limit is the shared one on purpose. Five modules had five copies of it
    when this was written and four modules that needed it had none, which is
    the arrangement every round of this project has found something in.
    """
    offenders, unguarded = [], []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        source = path.read_text()
        if "mkfifo" not in source:
            continue
        if "time_limit" not in source:
            unguarded.append(path.name)
        tree = ast.parse(source, filename=path.name)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            calls = _calls(node)
            if "mkfifo" in calls and "time_limit" not in calls:
                offenders.append(f"{path.name}::{node.name}")

    assert not unguarded, (
        "these modules plant a named pipe and never import a time limit, so a "
        "regression in the guard they test wedges both runners with no "
        "output: " + ", ".join(unguarded))
    assert not offenders, (
        "these tests plant a named pipe and call their subject outside a time "
        "limit: " + ", ".join(offenders))
