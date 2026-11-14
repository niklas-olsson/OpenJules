"""Real core plus pure request-auth components, with a deterministic fake owner.

No listener, TLS connection, native browser, model or website is exercised.
"""

import json
from pathlib import Path
import tempfile
import unittest

from src.browser_session.control import SessionControl
from src.browser_session.pairing import COOKIE_NAME, PairingBroker, PairingDenied, RequestContext
from src.browser_session.types import SessionDenied, SessionSpec
from tests.unit.test_browser_session_control import Clock, FakeAdapter


class SessionPairingTests(unittest.IsolatedAsyncioTestCase):
    async def test_original_grants_cookie_csrf_core_recheck_stop_and_retained_only_reopen(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            clock, directory = Clock(), parent / "session"
            adapter = FakeAdapter(clock)
            spec = SessionSpec("session", "context", "target", "document", "driver", "human",
                ("https://one.example", "https://two.example"), ("price",), clock.wall + 300_000,
                clock.wall + 600_000)
            core = SessionControl.create(directory, spec, adapter, clock)
            adapter.core = core
            try:
                broker = PairingBroker(core, "https://control.example:8443", clock=clock)

                def request(method, path, alias=None, csrf=None):
                    headers = [("Host", "control.example:8443"), ("Origin", "https://control.example:8443")]
                    if alias:
                        headers.append(("Cookie", COOKIE_NAME + "=" + alias))
                    if csrf:
                        headers.append(("X-CSRF-Token", csrf))
                    return RequestContext(method, path, True, tuple(headers))

                def pair(token, right):
                    code = broker.issue_code(token, clock.wall + 500, binding_right=right)
                    reply = broker.redeem(request("POST", "/pair"), json.dumps({"code": code}).encode())
                    self.assertNotIn(token, reply.set_cookie)
                    return reply, reply.set_cookie.split(";", 1)[0].split("=", 1)[1]

                driver = core.issue_grant("driver", {"observe": clock.wall + 1500, "control": clock.wall + 1500})
                owner = core.issue_grant("human", {"observe": clock.wall + 1000,
                    "control": clock.wall + 1500, "stop": clock.wall + 10_000})
                driver_reply, driver_alias = pair(driver, "control")
                owner_reply, owner_alias = pair(owner, "stop")
                core.publish_observation(adapter.observation())
                authorized = broker.authorize_request(request("GET", "/observe", driver_alias),
                    right="observe", method="GET", path="/observe")
                view = core.observe(authorized.grant_token)
                action = {name: view[name] for name in ("session_id", "context_id", "target_id",
                    "control_generation", "document_id", "document_generation")}
                action.update(operation_id="original-action", observation_id=view["frame"]["observation_id"],
                              action="click", parameters={"x": 1, "y": 2, "button": "left"})
                with self.assertRaises(PairingDenied):
                    broker.authorize_request(request("POST", "/action", driver_alias),
                        right="control", method="POST", path="/action")
                authorized = broker.authorize_request(request("POST", "/action", driver_alias, driver_reply.csrf_token),
                    right="control", method="POST", path="/action")
                core.submit(authorized.grant_token, **action)
                self.assertEqual((await core.execute_next())["state"], "applied")
                self.assertEqual(len(adapter.executions), 1)

                # The auth result is only a server-private snapshot. Core must
                # refuse a delayed use even after the request-auth step passed.
                clock.advance(1501)
                with self.assertRaises(SessionDenied):
                    core.submit(authorized.grant_token, **(action | {"operation_id": "late-action"}))
                self.assertEqual(len(adapter.executions), 1)
                with self.assertRaises(PairingDenied):
                    broker.authorize_request(request("GET", "/observe", owner_alias),
                        right="observe", method="GET", path="/observe")
                session = broker.session(request("GET", "/session", owner_alias))
                self.assertEqual(session.authorization.right, "stop")
                self.assertEqual(session.csrf_token, owner_reply.csrf_token)
                self.assertEqual(session.expires_at_ms, owner_reply.expires_at_ms)

                content = b'{"fixture_result":"retained"}\n'
                core.retain_result("result.json", content)
                stopping = broker.authorize_request(request("POST", "/stop", owner_alias, owner_reply.csrf_token),
                    right="stop", method="POST", path="/stop")
                self.assertEqual((await core.stop(stopping.grant_token, "original-stop"))["state"], "confirmed")
                self.assertEqual(len(adapter.stops), 1)
                broker.revoke(owner_alias)
                with self.assertRaises(PairingDenied):
                    broker.session(request("GET", "/session", owner_alias))
                with self.assertRaises(SessionDenied):
                    core.authorize(owner, "stop")

                still_valid = core.issue_grant("still-valid-observer", {"observe": clock.wall + 10_000})
                self.assertEqual(core.authorize(still_valid, "observe").actor_id, "still-valid-observer")
                core.close()
                core = SessionControl.reopen(directory, clock)
                restarted = PairingBroker(core, "https://control.example:8443", clock=clock)
                with self.assertRaises(PairingDenied):
                    restarted.session(request("GET", "/session", owner_alias))
                with self.assertRaises(SessionDenied):
                    core.authorize(driver, "observe")
                with self.assertRaises(SessionDenied):
                    core.authorize(still_valid, "observe")
                with self.assertRaises(SessionDenied):
                    core.issue_grant("human", {"control": clock.wall + 1000})
                observer = core.issue_grant("returning-observer", {"observe": clock.wall + 1000})
                broker = restarted
                observer_reply, observer_alias = pair(observer, "observe")
                retained = broker.authorize_request(request("GET", "/result", observer_alias),
                    right="observe", method="GET", path="/result")
                self.assertEqual(core.read_result(retained.grant_token, "result.json"), content)
                self.assertEqual(core.observe(retained.grant_token)["mode"], "lost")
                with self.assertRaises(PairingDenied):
                    broker.authorize_request(request("POST", "/action", observer_alias, observer_reply.csrf_token),
                        right="control", method="POST", path="/action")
                self.assertEqual(len(adapter.executions), 1)
                self.assertEqual(len(adapter.stops), 1)
            finally:
                core.close()


if __name__ == "__main__":
    unittest.main()
