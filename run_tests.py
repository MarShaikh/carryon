#!/usr/bin/env python3
"""Run the test suite without requiring pytest to be installed.

`.venv/bin/pytest tests/ -q` is the normal way. This exists because a fresh
macOS has no pytest, and a migration tool that cannot be verified on a bare
machine is not much use. The test modules themselves are written for pytest,
so when pytest is absent a small stub of the three APIs they actually use
(fixture, mark.parametrize, raises) is installed before they import - the
alternative, keeping the tests free of pytest, would forfeit real fixtures
for everyone who does have it.
"""

import contextlib
import importlib
import io
import os
import pathlib
import shutil
import sys
import tempfile
import traceback
import types

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

MODULES = (
    # first, because it is the one that notices this list going stale
    "tests.test_harness",
    "tests.test_secrets",
    "tests.test_capture",
    "tests.test_layout",
    "tests.test_transport",
    "tests.test_crypto",
    "tests.test_cli_arguments",
    "tests.test_config",
    "tests.test_config_security",
    "tests.test_capture_security",
    "tests.test_capture_gate",
    "tests.test_state_chokepoint",
    "tests.test_state_files",
    "tests.test_highwater_once",
    "tests.test_init_checks",
    "tests.test_write_chokepoint",
    "tests.test_keyring",
    "tests.test_prompting",
    "tests.test_provider_setup",
    "tests.test_init_dialogue",
    "tests.test_destinations",
    "tests.test_destinations_security",
    "tests.test_destinations_hostile",
    "tests.test_archive",
    "tests.test_rekey",
    "tests.test_external",
    "tests.test_history",
    "tests.test_history_security",
    "tests.test_restore_writes",
    "tests.test_pair",
    "tests.test_pair_security",
    "tests.test_sync",
    "tests.test_sync_command",
    "tests.test_sync_security",
    "tests.test_sync_hostile",
    "tests.test_push_union",
    "tests.test_pull_never_deletes",
    "tests.test_pull_member_union",
    "tests.test_setup_auth",
    "tests.test_setup_authorship",
    "tests.test_index_trust",
    "tests.test_index_replay",
    "tests.test_input_robustness",
    "tests.test_archive_robustness",
    "tests.test_unprobed_surfaces",
    "tests.test_e2e",
)


# --- a pytest stub for machines without pytest -------------------------------


class _ExcInfo:
    """What `pytest.raises` hands back: the caught exception as .value."""

    def __init__(self):
        self.value = None
        self.type = None

    def __str__(self):
        return str(self.value)


class _Raises:
    def __init__(self, expected, match=None):
        self.expected = expected
        self.match = match
        self.info = _ExcInfo()

    def __enter__(self):
        return self.info

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError(f"DID NOT RAISE {self.expected}")
        if not issubclass(exc_type, self.expected):
            return False  # a different exception propagates unchanged
        if self.match is not None:
            import re
            if not re.search(self.match, str(exc)):
                raise AssertionError(
                    f"pattern {self.match!r} not found in {exc}")
        self.info.value = exc
        self.info.type = exc_type
        return True


def _stub_fixture(fn=None, **kwargs):
    def deco(func):
        func._stub_fixture = True
        func._stub_autouse = bool(kwargs.get("autouse", False))
        return func
    return deco(fn) if fn is not None else deco


class _StubMark:
    @staticmethod
    def parametrize(argnames, argvalues, **_kwargs):
        def deco(fn):
            marks = list(getattr(fn, "pytestmark", []))
            marks.append(types.SimpleNamespace(
                name="parametrize", args=(argnames, argvalues), kwargs={}))
            fn.pytestmark = marks
            return fn
        return deco


def _install_pytest_stub():
    stub = types.ModuleType("pytest")
    stub.fixture = _stub_fixture
    stub.raises = _Raises
    stub.mark = _StubMark()
    stub.__version__ = "0 (carryon stub)"
    sys.modules["pytest"] = stub


try:
    import pytest as _real_pytest  # noqa: F401
except ImportError:
    _install_pytest_stub()


# --- built-in fixtures -------------------------------------------------------


class _Capsys:
    def __init__(self, out, err):
        self._out, self._err = out, err

    def readouterr(self):
        out, err = self._out.getvalue(), self._err.getvalue()
        self._out.seek(0)
        self._out.truncate(0)
        self._err.seek(0)
        self._err.truncate(0)
        return types.SimpleNamespace(out=out, err=err)


class _Monkeypatch:
    def __init__(self):
        self._undo = []

    def setattr(self, target, name, value):
        had = hasattr(target, name)
        old = getattr(target, name, None)
        self._undo.append(lambda: (setattr(target, name, old) if had
                                   else delattr(target, name)))
        setattr(target, name, value)

    def setenv(self, name, value):
        old = os.environ.get(name)
        self._undo.append(lambda: (os.environ.__setitem__(name, old)
                                   if old is not None
                                   else os.environ.pop(name, None)))
        os.environ[name] = value

    def delenv(self, name, raising=True):
        if name not in os.environ:
            if raising:
                raise KeyError(name)
            return
        old = os.environ[name]
        self._undo.append(lambda: os.environ.__setitem__(name, old))
        del os.environ[name]

    def undo(self):
        while self._undo:
            self._undo.pop()()


# --- fixture resolution ------------------------------------------------------


def _fixture_info(obj):
    """(function, autouse) when obj is a fixture definition, else None.

    Handles the stub, pytest < 8.4 (marker attribute on the function) and
    pytest >= 8.4 (a FixtureFunctionDefinition wrapping it).

    Modules are ruled out first. A test module importing another module is
    ordinary, and this file carries a module-level `_stub_fixture` of its
    own, so a test that imported it read as a fixture and took the whole run
    down with an AttributeError - a traceback instead of a result, from an
    import that was none of the runner's business.
    """
    if isinstance(obj, types.ModuleType):
        return None
    if getattr(obj, "_stub_fixture", False):
        return obj, getattr(obj, "_stub_autouse", False)
    marker = getattr(obj, "_pytestfixturefunction", None)
    if marker is not None:
        return getattr(obj, "__wrapped__", obj), marker.autouse
    marker = getattr(obj, "_fixture_function_marker", None)
    if marker is not None:
        return obj.__wrapped__, marker.autouse
    return None


def _module_fixtures(module):
    fixtures = {}
    for name, obj in vars(module).items():
        info = _fixture_info(obj)
        if info is not None:
            fixtures[name] = info
    return fixtures


def _params_of(fn):
    return fn.__code__.co_varnames[:fn.__code__.co_argcount]


def _expand_parametrize(fn):
    """[(case_label, {param: value})] - one entry per parametrize case."""
    marks = [m for m in getattr(fn, "pytestmark", [])
             if getattr(m, "name", "") == "parametrize"]
    cases = [("", {})]
    for mark in reversed(marks):  # innermost decorator varies fastest
        argnames, argvalues = mark.args[0], mark.args[1]
        names = [n.strip() for n in argnames.split(",")]
        grown = []
        for label, bound in cases:
            for value in argvalues:
                values = tuple(value) if len(names) > 1 else (value,)
                new = dict(bound)
                new.update(zip(names, values))
                tag = "-".join(repr(v)[:24] for v in values)
                grown.append((f"{label}[{tag}]" if label else f"[{tag}]", new))
        cases = grown
    return cases


class _FixtureRequest:
    """Builds fixture values for one test run and tears them down after."""

    def __init__(self, fixtures, capsys):
        self.fixtures = fixtures
        self.capsys = capsys
        self.cache = {}
        self.cleanup = []

    def get(self, name):
        if name in self.cache:
            return self.cache[name]
        if name == "tmp_path":
            tmp = tempfile.mkdtemp(prefix="carryon-test-")
            self.cleanup.append(lambda: shutil.rmtree(tmp, ignore_errors=True))
            value = pathlib.Path(tmp)
        elif name == "capsys":
            value = self.capsys
        elif name == "monkeypatch":
            value = _Monkeypatch()
            self.cleanup.append(value.undo)
        elif name in self.fixtures:
            fn, _ = self.fixtures[name]
            result = fn(*[self.get(p) for p in _params_of(fn)])
            if hasattr(result, "__next__"):  # a yield fixture
                gen = result
                value = next(gen)
                self.cleanup.append(
                    lambda: next(gen, None) and None)
            else:
                value = result
        else:
            raise RuntimeError(f"run_tests.py knows no fixture {name!r}")
        self.cache[name] = value
        return value

    def teardown(self):
        while self.cleanup:
            self.cleanup.pop()()


def _run_test(fn, fixtures, params):
    out, err = io.StringIO(), io.StringIO()
    request = _FixtureRequest(fixtures, _Capsys(out, err))
    # Teardown runs INSIDE the redirect, matching pytest. The other order
    # swallowed the rest of the run: redirect exit restored the real stdout,
    # then a monkeypatch.undo of a test that had patched sys.stdout put the
    # redirect's own dead StringIO back - and every later PASS line and the
    # final summary went into it, at exit 0. The runner looked finished two
    # lines into a module, which is this file's docstring's own failure mode
    # (a run that reports nothing looks like nothing to report).
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            for name, (_fx, autouse) in fixtures.items():
                if autouse:
                    request.get(name)
            args = [params[p] if p in params else request.get(p)
                    for p in _params_of(fn)]
            fn(*args)
        finally:
            request.teardown()


def main() -> int:
    passed = failed = 0
    failures = []

    for module_name in MODULES:
        module = importlib.import_module(module_name)
        fixtures = _module_fixtures(module)
        tests = [(n, f) for n, f in vars(module).items()
                 if n.startswith("test_") and callable(f)
                 and _fixture_info(f) is None]
        print(f"\n{module_name}  ({len(tests)} tests)")

        for name, fn in tests:
            for label, params in _expand_parametrize(fn):
                shown = name + label
                try:
                    _run_test(fn, fixtures, params)
                    passed += 1
                    print(f"  PASS  {shown}")
                except (Exception, SystemExit) as exc:
                    failed += 1
                    failures.append((f"{module_name}.{shown}", exc))
                    print(f"  FAIL  {shown}: {type(exc).__name__}: {exc}")

    print(f"\n{'-' * 60}\n{passed} passed, {failed} failed")
    if failures:
        print()
        for name, exc in failures:
            print(f"=== {name} ===")
            traceback.print_exception(type(exc), exc, exc.__traceback__,
                                      limit=5)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
