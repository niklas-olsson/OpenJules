"""Watchdog event-loop bounds; native Docker tests establish actual adoption."""

import builtins
import io
from types import SimpleNamespace

import pytest

from src.worker.child_runtime import CHILD_WATCHDOG
from src.worker.docker_runtime import _WATCHDOG


class TickComplete(BaseException):
    pass


class WatchdogExit(BaseException):
    def __init__(self, code):
        self.code = code


def run_tick(script, wait, *, root_deadline=100, child_deadline=None):
    calls = []
    clock = SimpleNamespace(now=0.0)

    def waitpid(pid, flags):
        calls.append((pid, flags))
        return wait(clock, len(calls))

    def stop(code):
        raise WatchdogExit(code)

    def sleep(seconds):
        assert seconds == 0.05
        raise TickComplete()

    def control(path, **_kwargs):
        if path == "/control/deadline":
            return io.StringIO(str(root_deadline))
        assert path == "/control/children/original" and child_deadline is not None
        return io.StringIO(str(child_deadline))

    # The fake OS exposes no signal, kill or blocking-wait convenience API.
    # Its waitpid flag is deliberately nonstandard to detect literal misuse.
    modules = {
        "os": SimpleNamespace(
            WNOHANG=0x40, waitpid=waitpid, _exit=stop,
            listdir=lambda _path: [] if child_deadline is None else ["original"],
        ),
        "time": SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep),
    }
    original_import = builtins.__import__

    def importing(name, *args, **kwargs):
        return modules[name] if name in modules else original_import(name, *args, **kwargs)

    try:
        exec(script, {"__builtins__": vars(builtins) | {"__import__": importing}, "open": control})
    except (TickComplete, WatchdogExit) as outcome:
        return outcome, calls, clock
    raise AssertionError("watchdog left its event loop without a tick or exit")


@pytest.mark.parametrize("script", [_WATCHDOG, CHILD_WATCHDOG], ids=["root", "children"])
def test_continuous_exited_children_do_not_starve_the_next_tick(script):
    outcome, calls, _clock = run_tick(script, lambda _clock, index: (index, 0))
    assert isinstance(outcome, TickComplete)
    assert len(calls) == 128
    assert set(calls) == {(-1, 0x40)}


@pytest.mark.parametrize("script", [_WATCHDOG, CHILD_WATCHDOG], ids=["root", "children"])
@pytest.mark.parametrize("no_children", [False, True], ids=["live-child", "no-child"])
def test_reaping_returns_to_tick_when_no_exited_child_is_available(script, no_children):
    def wait(_clock, _index):
        if no_children:
            raise ChildProcessError()
        return 0, 0

    outcome, calls, _clock = run_tick(script, wait)
    assert isinstance(outcome, TickComplete)
    assert calls == [(-1, 0x40)]


@pytest.mark.parametrize("script", [_WATCHDOG, CHILD_WATCHDOG], ids=["root", "children"])
def test_interrupted_wait_is_nonblocking_and_remains_bounded(script):
    def wait(_clock, _index):
        raise InterruptedError()

    outcome, calls, _clock = run_tick(script, wait)
    assert isinstance(outcome, TickComplete)
    assert len(calls) == 128 and set(calls) == {(-1, 0x40)}


@pytest.mark.parametrize("script", [_WATCHDOG, CHILD_WATCHDOG], ids=["root", "children"])
def test_original_deadline_expires_during_continuous_reaping(script):
    def wait(clock, index):
        clock.now += 0.1
        return index, 0

    outcome, calls, clock = run_tick(script, wait, root_deadline=0.25)
    assert isinstance(outcome, WatchdogExit) and outcome.code == 0
    assert len(calls) == 3 and clock.now < 0.4


def test_earliest_child_deadline_still_expires_during_reaping():
    def wait(clock, index):
        clock.now += 0.1
        return index, 0

    outcome, calls, clock = run_tick(CHILD_WATCHDOG, wait, root_deadline=100, child_deadline=0.25)
    assert isinstance(outcome, WatchdogExit) and outcome.code == 0
    assert len(calls) == 3 and clock.now < 0.4
