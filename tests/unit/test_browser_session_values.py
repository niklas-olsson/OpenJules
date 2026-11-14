"""Independent input and retained-origin regressions for the source component."""

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from src.browser_session.control import SessionControl
from src.browser_session.types import Limits, SessionDenied, SessionSpec, SessionUnavailable, integer, origin
from tests.unit.test_browser_session_control import Clock, FakeAdapter


class SessionValueTests(unittest.TestCase):
    def spec(self, now=1000):
        return SessionSpec("session", "context", "target", "document", "driver", "human",
            ("https://one.example", "https://two.example"), ("price",), now + 1000, now + 2000)

    def test_safe_integer_limit_cannot_be_expanded_by_relative_deadline_bounds(self):
        for now in (2**53 - 1, 2**53, True, -1):
            with self.subTest(now=now), self.assertRaises(SessionDenied):
                self.spec(now).validate(now)
        with self.assertRaises(SessionDenied):
            integer(2**53, 0, 2**53 + 100)
        with self.assertRaises(SessionDenied):
            integer(-(2**53), -(2**53 + 100), 0)
        self.assertEqual(integer(2**53 - 1, 0, 2**53 + 100), 2**53 - 1)

    def test_operation_cap_reserves_both_owner_and_host_stop_slots(self):
        with self.assertRaises(SessionDenied):
            Limits(operations=1).validate()
        self.assertEqual(Limits(operations=2).validate().operations, 2)

    def test_fixture_origins_have_one_browser_origin_spelling_and_no_ambiguous_hosts(self):
        for value in ("https://example.test:", "https://example.test:0", "https://example.test.",
                      "https://2130706433", "https://127.1", "https://a\\b", "https://x%2ey", "https://u:p@host"):
            with self.subTest(value=value), self.assertRaises(SessionDenied):
                origin(value)
        self.assertEqual(origin("https://ONE.example:443/path"), "https://one.example")
        self.assertEqual(origin("https://[::1]:8443/path"), "https://[::1]:8443")
        for declared in ("https://one.example:443", "https://ONE.example"):
            with self.assertRaises(SessionDenied):
                replace(self.spec(), fixture_origins=(declared, "https://two.example")).validate(1000)

    def test_boolean_original_schema_is_not_an_integer_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            clock = Clock()
            adapter = FakeAdapter(clock)
            directory = parent / "session"
            core = SessionControl.create(directory, self.spec(clock.wall), adapter, clock)
            core.close()
            anchor = directory / "origin.json"
            value = json.loads(anchor.read_bytes())
            value["schema_version"] = True
            anchor.write_text(json.dumps(value))
            with self.assertRaises(SessionUnavailable):
                SessionControl.reopen(directory, clock)


if __name__ == "__main__":
    unittest.main()
