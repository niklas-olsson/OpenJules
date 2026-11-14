"""Pure authentication-boundary tests. No listener, browser or TLS session."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import traceback
import unittest
from unittest.mock import patch

from src.browser_session.pairing import (
    COOKIE_NAME, PairingBroker, PairingDenied, PairingLimits, RequestContext,
)


@dataclass(frozen=True)
class Authorization:
    actor_id: str
    session_id: str
    context_id: str
    target_id: str
    right: str
    expires_at_ms: int


class Clock:
    def __init__(self):
        self.wall, self.mono = 1_000_000, 1000.0

    def wall_ms(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, milliseconds):
        self.wall += milliseconds
        self.mono += milliseconds / 1000


class Authority:
    def __init__(self, clock, token, rights):
        self.clock, self.token, self.rights = clock, token, rights
        self.cutoffs = {right: clock.mono + (expiry - clock.wall) / 1000 for right, expiry in rights.items()}
        self.calls, self.revocations = [], []
        self.revoked = False
        self.target = "original-target"

    def authorize(self, token, right):
        self.calls.append((token, right))
        if (token != self.token or self.revoked or right not in self.rights
                or self.clock.wall >= self.rights[right] or self.clock.mono >= self.cutoffs[right]):
            raise RuntimeError("private authority denial " + self.token)
        return Authorization("human", "original-session", "original-context", self.target,
                             right, self.rights[right])

    def revoke(self, token):
        self.revocations.append(token)
        self.revoked = True


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.token = "private_core_grant_" + "x" * 32
        self.authority = Authority(self.clock, self.token,
                                   {right: self.clock.wall + 300_000 for right in ("observe", "control", "stop")})
        self.broker = PairingBroker(self.authority, "https://control.example:8443", clock=self.clock)

    def request(self, method="POST", path="/pair", *, alias=None, csrf=None, origin=True, extra=()):
        headers = [("Host", "control.example:8443")]
        if origin:
            headers.append(("Origin", "https://control.example:8443"))
        else:
            headers.append(("Sec-Fetch-Site", "same-origin"))
        if alias:
            headers.append(("Cookie", COOKIE_NAME + "=" + alias))
        if csrf:
            headers.append(("X-CSRF-Token", csrf))
        return RequestContext(method, path, True, tuple(headers) + tuple(extra))

    def pair(self, *, binding_right="observe"):
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000, binding_right=binding_right)
        reply = self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        alias = reply.set_cookie.split(";", 1)[0].split("=", 1)[1]
        return code, reply, alias

    def authorize(self, alias, csrf, right="control"):
        return self.broker.authorize_request(self.request(path="/action", alias=alias, csrf=csrf),
                                             right=right, method="POST", path="/action")

    def test_cookie_is_an_alias_with_fixed_host_only_attributes_and_no_core_token(self):
        code, reply, alias = self.pair()
        self.assertNotEqual(alias, code)
        self.assertNotEqual(alias, self.token)
        self.assertNotIn(self.token, reply.set_cookie)
        self.assertEqual(reply.set_cookie.split(";")[1:],
                         [" Path=/", " Max-Age=300", " Secure", " HttpOnly", " SameSite=Strict"])
        self.assertNotIn("Domain", reply.set_cookie)
        authenticated = self.authorize(alias, reply.csrf_token)
        self.assertEqual(authenticated.grant_token, self.token)
        self.assertEqual(authenticated.authorization.target_id, "original-target")

    def test_concurrent_redemption_has_one_success_and_does_not_issue_or_renew_a_grant(self):
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        body = json.dumps({"code": code}).encode()
        def redeem():
            try:
                return self.broker.redeem(self.request(), body)
            except PairingDenied:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = [future.result(timeout=5) for future in [pool.submit(redeem) for _ in range(16)]]
        self.assertEqual(sum(value is not None for value in results), 1)
        self.assertEqual(self.authority.revocations, [])

    def test_lost_reply_and_broker_restart_never_reissue_original_code_or_cookie(self):
        code, reply, alias = self.pair()
        with self.assertRaises(PairingDenied):
            self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        restarted = PairingBroker(self.authority, "https://control.example:8443", clock=self.clock)
        with self.assertRaises(PairingDenied):
            restarted.redeem(self.request(), json.dumps({"code": code}).encode())
        with self.assertRaises(PairingDenied):
            restarted.session(self.request("GET", "/session", alias=alias, origin=False))

    def test_pairing_body_cannot_choose_scope_rights_target_or_expiry(self):
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        for extra in ({"role": "owner"}, {"session_id": "foreign"}, {"target_id": "foreign"},
                      {"rights": ["stop"]}, {"expires_at_ms": 2**53 - 1}):
            with self.subTest(extra=extra), self.assertRaises(PairingDenied):
                self.broker.redeem(self.request(), json.dumps({"code": code, **extra}).encode())
        for body in ((f'{{"code":"{code}","code":"{code}"}}').encode(), b'{"code":NaN}', b"[1]", b"x" * 513):
            with self.subTest(body=body[:20]), self.assertRaises(PairingDenied):
                self.broker.redeem(self.request(), body)
        self.broker.redeem(self.request(), json.dumps({"code": code}).encode())

    def test_security_header_duplicates_are_not_combined_or_selected(self):
        _, reply, alias = self.pair()
        cases = (("hOsT", "control.example:8443"), ("ORIGIN", "https://control.example:8443"),
                 ("COOKIE", COOKIE_NAME + "=" + alias), ("X-Csrf-Token", reply.csrf_token))
        for extra in cases:
            request = self.request(path="/action", alias=alias, csrf=reply.csrf_token, extra=(extra,))
            with self.subTest(header=extra[0]), self.assertRaises(PairingDenied):
                self.broker.authorize_request(request, right="control", method="POST", path="/action")

    def test_origin_host_tls_and_csrf_denials_do_not_consume_the_code_or_authorize_input(self):
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        good = self.request()
        variants = [RequestContext("POST", "/pair", False, good.headers),
                    RequestContext("POST", "/pair", 1, good.headers),
                    self.request(origin=False),
                    RequestContext("POST", "/pair", True, (("Host", "other.example"), ("Origin", "https://control.example:8443"))),
                    RequestContext("POST", "/pair", True, (("Host", "control.example:8443"), ("Origin", "null"))),
                    RequestContext("POST", "/pair?code=" + code, True, good.headers)]
        for request in variants:
            with self.assertRaises(PairingDenied):
                self.broker.redeem(request, json.dumps({"code": code}).encode())
        reply = self.broker.redeem(good, json.dumps({"code": code}).encode())
        alias = reply.set_cookie.split(";", 1)[0].split("=", 1)[1]
        before = len(self.authority.calls)
        for csrf in (None, "z" * 43):
            with self.assertRaises(PairingDenied):
                self.authorize(alias, csrf)
        self.assertEqual(len(self.authority.calls), before)

    def test_browser_get_uses_same_origin_metadata_and_reload_keeps_original_csrf_and_expiry(self):
        _, reply, alias = self.pair()
        self.clock.advance(1000)
        view = self.broker.session(self.request("GET", "/session", alias=alias, origin=False))
        self.assertEqual((view.csrf_token, view.expires_at_ms), (reply.csrf_token, reply.expires_at_ms))
        wrong = RequestContext("GET", "/session", True,
            (("Host", "control.example:8443"), ("Cookie", COOKIE_NAME + "=" + alias), ("Sec-Fetch-Site", "same-site")))
        with self.assertRaises(PairingDenied):
            self.broker.session(wrong)
        with self.assertRaises(PairingDenied):
            self.broker.session(self.request("GET", "/session", alias=alias, origin=False,
                                            extra=(("sec-fetch-site", "same-origin"),)))

    def test_original_longer_stop_right_survives_observe_and_control_expiry_without_renewal(self):
        self.authority = Authority(self.clock, self.token,
            {"observe": self.clock.wall + 500, "control": self.clock.wall + 700, "stop": self.clock.wall + 30_000})
        self.broker = PairingBroker(self.authority, "https://control.example:8443", clock=self.clock)
        _, reply, alias = self.pair(binding_right="stop")
        self.clock.advance(1000)
        for right in ("observe", "control"):
            with self.assertRaises(PairingDenied):
                self.authorize(alias, reply.csrf_token, right)
        view = self.broker.session(self.request("GET", "/session", alias=alias, origin=False))
        self.assertEqual(view.authorization.right, "stop")
        self.assertEqual(self.authorize(alias, view.csrf_token, "stop").authorization.expires_at_ms, 1_030_000)
        self.assertEqual(view.expires_at_ms, reply.expires_at_ms)

    def test_view_only_cookie_never_acquires_control_or_stop(self):
        self.authority.rights = {"observe": self.clock.wall + 300_000}
        _, reply, alias = self.pair()
        for right in ("control", "stop"):
            with self.assertRaises(PairingDenied):
                self.authorize(alias, reply.csrf_token, right)

    def test_monotonic_expiry_denies_pairing_and_cookies_after_wall_clock_rollback(self):
        code = self.broker.issue_code(self.token, self.clock.wall + 500)
        self.clock.wall -= 10_000
        self.clock.mono += 1
        with self.assertRaises(PairingDenied):
            self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        self.clock.wall = 1_000_000
        _, reply, alias = self.pair()
        self.clock.wall -= 50_000
        self.clock.mono += 301
        with self.assertRaises(PairingDenied):
            self.authorize(alias, reply.csrf_token)

    def test_expired_forward_wall_observation_cannot_be_undone_by_rollback(self):
        _, reply, alias = self.pair()
        self.clock.wall += 300_000
        with self.assertRaises(PairingDenied):
            self.broker.session(self.request("GET", "/session", alias=alias))
        self.clock.wall = 1_000_000
        with self.assertRaises(PairingDenied):
            self.authorize(alias, reply.csrf_token)

    def test_invalid_deadlines_clocks_and_configuration_refuse_before_prebinding(self):
        for value in (True, 1.5, float("nan"), float("inf"), -1, 2**53, self.clock.wall, self.clock.wall + 60_001):
            with self.subTest(value=value), self.assertRaises(PairingDenied):
                self.broker.issue_code(self.token, value)
        for value in (float("nan"), float("inf"), True, -1):
            self.clock.mono = value
            with self.assertRaises(PairingDenied):
                self.broker.issue_code(self.token, self.clock.wall + 10_000)
        for origin in ("http://control.example", "https://control.example/", "https://user@control.example",
                       "https://CONTROL.example", "https://control.example:443", "https://control.example:",
                       "https://[::1]:", "https://control\\.example", "https://control.example\\foreign"):
            with self.subTest(origin=origin), self.assertRaises(PairingDenied):
                PairingBroker(self.authority, origin, clock=Clock())
        for limits in ({"cookie_ttl_ms": float("inf")}, {"pending_codes": True}, {"issued_codes": 129}):
            with self.assertRaises(PairingDenied):
                PairingLimits(**limits)

    def test_alias_rechecks_time_after_authority_returns_and_refuses_changed_identity(self):
        _, reply, alias = self.pair()
        self.authority.target = "replacement-target"
        with self.assertRaises(PairingDenied):
            self.authorize(alias, reply.csrf_token)
        self.authority.target = "original-target"
        original = self.authority.authorize
        def late(token, right):
            result = original(token, right)
            self.clock.advance(300_001)
            return result
        with patch.object(self.authority, "authorize", side_effect=late), self.assertRaises(PairingDenied):
            self.authorize(alias, reply.csrf_token)

    def test_host_revocation_delegates_to_core_and_fences_original_grant(self):
        _, reply, alias = self.pair()
        self.broker.revoke(alias)
        self.assertEqual(self.authority.revocations, [self.token])
        with self.assertRaises(PairingDenied):
            self.authorize(alias, reply.csrf_token)
        self.authority.revoked = False
        with self.assertRaisesRegex(PairingDenied, "grant_revocation_pending"):
            self.pair()

    def test_unknown_revocation_fences_all_original_aliases_pending_codes_and_repairing(self):
        _, first, first_alias = self.pair()
        _, second, second_alias = self.pair(binding_right="stop")
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        with patch.object(self.authority, "revoke", side_effect=RuntimeError(self.token)), self.assertRaisesRegex(PairingDenied, "revocation_unconfirmed"):
            self.broker.revoke(first_alias)
        for reply, alias in ((first, first_alias), (second, second_alias)):
            with self.assertRaises(PairingDenied):
                self.authorize(alias, reply.csrf_token)
            with self.assertRaises(PairingDenied):
                self.broker.session(self.request("GET", "/session", alias=alias))
        with self.assertRaises(PairingDenied):
            self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        before = len(self.authority.calls)
        with self.assertRaisesRegex(PairingDenied, "grant_revocation_pending"):
            self.broker.issue_code(self.token, self.clock.wall + 10_000, binding_right="stop")
        self.assertEqual(len(self.authority.calls), before)
        self.assertFalse(self.authority.revoked)
        # An explicit different host-issued grant is independent of the intent.
        self.token = "different_private_core_grant_" + "y" * 32
        self.authority.token = self.token
        _, reply, alias = self.pair()
        self.assertEqual(self.authorize(alias, reply.csrf_token).grant_token, self.token)

    def test_redemption_rechecks_a_shortened_authorization_after_a_slow_authority(self):
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        original = self.authority.authorize
        def late(token, right):
            authorization = original(token, right)
            shortened = Authorization(authorization.actor_id, authorization.session_id,
                authorization.context_id, authorization.target_id, right, self.clock.wall + 10)
            self.clock.advance(11)
            return shortened
        with patch.object(self.authority, "authorize", side_effect=late), self.assertRaisesRegex(PairingDenied, "session_unavailable"):
            self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        self.assertEqual(self.broker._sessions, {})

    def test_finite_pending_session_issuance_and_redemption_limits_are_enforced(self):
        self.broker = PairingBroker(self.authority, "https://control.example:8443", clock=self.clock,
                                   limits=PairingLimits(pending_codes=1, browser_sessions=1, issued_codes=2, redemption_attempts=2))
        code = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        with self.assertRaises(PairingDenied):
            self.broker.issue_code(self.token, self.clock.wall + 10_000)
        self.broker.redeem(self.request(), json.dumps({"code": code}).encode())
        second = self.broker.issue_code(self.token, self.clock.wall + 10_000)
        with self.assertRaises(PairingDenied):
            self.broker.redeem(self.request(), json.dumps({"code": second}).encode())
        with self.assertRaises(PairingDenied):
            self.broker.redeem(self.request(), json.dumps({"code": second}).encode())
        with self.assertRaises(PairingDenied):
            self.broker.issue_code(self.token, self.clock.wall + 10_000)

    def test_secret_material_is_absent_from_repr_and_public_exception_trace(self):
        code, reply, alias = self.pair()
        request = self.request(path="/action", alias=alias, csrf=reply.csrf_token)
        authorized = self.authorize(alias, reply.csrf_token)
        visible = repr(reply) + repr(authorized) + repr(request) + repr(self.broker)
        self.authority.revoked = True
        try:
            self.authorize(alias, reply.csrf_token)
        except PairingDenied as error:
            visible += "".join(traceback.format_exception(error))
        for secret in (self.token, code, alias, reply.csrf_token):
            self.assertNotIn(secret, visible)


if __name__ == "__main__":
    unittest.main()
