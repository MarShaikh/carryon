"""One time limit, for every test that opens a path it did not make.

Not a test module - it holds the guard nine suites need and five of them had
written out for themselves. That duplication is the shape ADR-0010 is about,
and it had already cost what the ADR says it costs: the four suites that
planted a named pipe without a copy of it were the four whose tests do not
fail when the guard they cover regresses. They hang, which under either
runner is no output at all and no exit code, for ever.

Measured rather than supposed. Dropping `O_NONBLOCK` from the Destination
layer's read wedged `test_destinations_hostile` twice; dropping it from
`config.read_carryable` wedged `test_state_chokepoint`. Each of those tests
was written for exactly that regression and each of them reported nothing
about it.

SIGALRM rather than a thread or a subprocess: the failure being guarded is a
blocked syscall inside this process, and a signal is the only thing that
reaches one. PEP 475 propagates an exception raised from a handler instead of
retrying the interrupted call, so it arrives at the test even from inside
open(). The previous handler and any running itimer are restored, because a
suite is many tests in one interpreter and a leaked handler is a failure
attributed to whichever test runs next.
"""

import contextlib
import signal

# Long enough that a loaded machine running a whole journey is not mistaken
# for a hang, short enough that a suite of them is not a coffee break. What is
# guarded is unbounded rather than slow: open() on a fifo waits for a writer
# that never comes.
HANG_LIMIT = 10

# A whole end-to-end journey - init, push, pair, join, pull, push back - is
# seconds rather than milliseconds, and over a git Destination every step is
# subprocesses. Same guard, a limit sized for what is being run.
JOURNEY_LIMIT = 60


class Hung(Exception):
    """Something under test did not come back inside its time limit."""


@contextlib.contextmanager
def time_limit(seconds=HANG_LIMIT, what="nothing came back"):
    """Turn a hang into a failure.

    `what` names the thing that did not return, because the whole content of
    this failure is which call never came back - by the time it fires there is
    no output, no report and no exit code to read.
    """
    def fire(signum, frame):
        raise Hung(f"{what} within {seconds}s")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
