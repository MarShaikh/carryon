#!/usr/bin/env python3
"""Fail when pytest and run_tests.py did not run the same suite.

    compare_runners.py <pytest junit xml> <run_tests.py output>

tests/test_harness.py already checks that run_tests.py lists every module on
disk. That is the list; this is the run. A module can be listed and still
yield a different number of tests under the two runners - a test class
pytest collects and the runner does not, a parametrize case the stub expands
differently - and each runner on its own reports green over whatever it did
run. So the counts are compared per module, where a mismatch names its
cause, and not only in total, where two mismatches could cancel.
"""

import collections
import re
import sys
import xml.etree.ElementTree as ET


def pytest_counts(junit_path):
    counts = collections.Counter()
    for case in ET.parse(junit_path).iter("testcase"):
        if case.find("skipped") is not None:
            continue  # run_tests.py has no skip, so a skip ran nothing
        # classname is "tests.test_x", or "tests.test_x.TestClass"
        counts[".".join(case.get("classname").split(".")[:2])] += 1
    return counts


def run_tests_counts(log_path):
    counts = collections.Counter()
    module = None
    with open(log_path, encoding="utf-8") as log:
        for line in log:
            header = re.match(r"^(tests\.\w+)  \(\d+ tests\)$", line)
            if header:
                module = header.group(1)
                counts[module] += 0  # a module that ran nothing still shows
            elif module and re.match(r"^  (PASS|FAIL)  ", line):
                counts[module] += 1
    return counts


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    by_pytest = pytest_counts(argv[1])
    by_runner = run_tests_counts(argv[2])
    if not by_pytest or not by_runner:
        # nothing parsed is a broken comparison, not an agreement
        print("compare_runners: a runner reported no tests at all")
        return 1

    disagree = [(m, by_pytest[m], by_runner[m])
                for m in sorted(set(by_pytest) | set(by_runner))
                if by_pytest[m] != by_runner[m]]
    total_p, total_r = sum(by_pytest.values()), sum(by_runner.values())
    if disagree:
        print("pytest and run_tests.py ran different suites:")
        for module, p, r in disagree:
            print(f"  {module}: pytest {p}, run_tests.py {r}")
        print(f"  total: pytest {total_p}, run_tests.py {total_r}")
        return 1
    print(f"pytest and run_tests.py agree: {total_p} tests "
          f"in {len(by_pytest)} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
