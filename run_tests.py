#!/usr/bin/env python3
"""Run the test suite without requiring pytest to be installed.

`python3 -m pytest tests/ -q` is the normal way. This exists because a fresh
macOS has no pytest, and a migration tool that cannot be verified on a bare
machine is not much use.
"""

import contextlib
import importlib
import io
import pathlib
import sys
import tempfile
import traceback

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

MODULES = ("tests.test_secrets", "tests.test_capture", "tests.test_layout",
           "tests.test_transport")


def main() -> int:
    passed = failed = 0
    failures = []

    for module_name in MODULES:
        module = importlib.import_module(module_name)
        tests = [(n, f) for n, f in vars(module).items()
                 if n.startswith("test_") and callable(f)]
        print(f"\n{module_name}  ({len(tests)} tests)")

        for name, fn in tests:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    if fn.__code__.co_argcount:
                        with tempfile.TemporaryDirectory() as tmp:
                            fn(pathlib.Path(tmp))
                    else:
                        fn()
                passed += 1
                print(f"  PASS  {name}")
            except Exception as exc:
                failed += 1
                failures.append((f"{module_name}.{name}", exc))
                print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")

    print(f"\n{'-' * 60}\n{passed} passed, {failed} failed")
    if failures:
        print()
        for name, exc in failures:
            print(f"=== {name} ===")
            traceback.print_exception(type(exc), exc, exc.__traceback__, limit=3)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
