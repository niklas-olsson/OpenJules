"""Authenticated v2 HTTP identity contract with deterministic runtime effects."""

from dataclasses import asdict
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

import httpx

from src.api.worker_lifecycle import create_worker_app
from src.worker.destination import DestinationState
from src.worker.lifecycle import WorkerLifecycle, WorkerScope
from tests.unit.test_execution_destination import initialized, prepare_application, SCOPE, SPEC
from tests.unit.test_worker_lifecycle import ContractRuntime


class DestinationAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = TemporaryDirectory()
        self.config, self.state = initialized(Path(self.temporary.name))
        prepare_application(self.config, self.state)
        self.binding = self.state.binding(SCOPE, SPEC.profile)
        self.runtime = ContractRuntime()
        self.runtime.capabilities = Mock(wraps=self.runtime.capabilities)
        self.runtime.observe = Mock(wraps=self.runtime.observe)
        self.lifecycle = WorkerLifecycle(self.config["lifecycle_database"], self.runtime, destination=self.state)
        self.token = "destination-credential-" * 2
        self.app = create_worker_app(self.lifecycle, {self.token: {SCOPE}})
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://fixture",
            headers={"Authorization": "Bearer " + self.token},
        )
        self.query = asdict(SCOPE) | self.binding | {"schema_version": "2"}
        self.body = asdict(SPEC) | {"schema_version": 2, "destination_binding": self.binding}
        self.control = asdict(SCOPE) | {
            "schema_version": 2, "destination_binding": self.binding, "request_key": "control",
        }

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temporary.cleanup()

    async def test_all_v2_routes_echo_original_binding_and_empty_discovery(self):
        empty = await self.client.get("/api/v2/workers", params=self.query | {"profile": "fixture"})
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json(), {"schema_version": 2, "destination_binding": self.binding, "workers": []})
        capability = await self.client.get("/api/v2/workers/capabilities", params=self.query | {"profile": "fixture"})
        self.assertEqual(capability.status_code, 200)
        self.assertEqual(capability.json()["destination_binding"], self.binding)
        self.assertEqual(capability.json()["identity_binding"], 1)
        self.assertFalse(capability.json()["portable_manifest"])
        self.assertFalse(capability.json()["local_admission"])
        ensured = await self.client.post("/api/v2/workers/ensure", json=self.body)
        self.assertEqual(ensured.status_code, 200, ensured.text)
        worker = ensured.json()
        self.assertEqual(worker["schema_version"], 2)
        self.assertEqual(worker["destination_binding"], self.binding)
        route = "/api/v2/workers/" + worker["worker_id"]
        observed = await self.client.get(route, params=self.query)
        self.assertEqual(observed.json(), worker)
        discovered = await self.client.get("/api/v2/workers", params=self.query | {
            "profile": "fixture", "launch_key": SPEC.launch_key,
        })
        self.assertEqual(discovered.json()["workers"], [worker])
        for action in ("drain", "stop"):
            result = await self.client.post(route + "/" + action, json=self.control | {"request_key": action})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()["destination_binding"], self.binding)
        self.assertEqual(result.json()["state"], "stopped")
        self.assertEqual(self.runtime.launches, 1)

    async def test_wrong_expected_identity_is_refused_before_any_runtime_call(self):
        created = (await self.client.post("/api/v2/workers/ensure", json=self.body)).json()
        route = "/api/v2/workers/" + created["worker_id"]
        self.runtime.capabilities.reset_mock()
        self.runtime.observe.reset_mock()
        for field, changed in (
            ("destination_id", "other-host"), ("journal_incarnation", "a" * 32),
            ("policy_binding_id", "b" * 32),
        ):
            binding = self.binding | {field: changed}
            query = self.query | {field: changed}
            responses = [
                await self.client.get("/api/v2/workers/capabilities", params=query | {"profile": "fixture"}),
                await self.client.get("/api/v2/workers", params=query | {"profile": "fixture", "launch_key": SPEC.launch_key}),
                await self.client.get(route, params=query),
                await self.client.get("/api/v2/workers/unknown", params=query),
                await self.client.post("/api/v2/workers/ensure", json=self.body | {"destination_binding": binding}),
                await self.client.post(route + "/drain", json=self.control | {"destination_binding": binding}),
                await self.client.post(route + "/stop", json=self.control | {"destination_binding": binding}),
            ]
            self.assertEqual([result.status_code for result in responses], [409] * len(responses))
        self.runtime.capabilities.assert_not_called()
        self.runtime.observe.assert_not_called()
        self.assertEqual(self.runtime.launches, 1)
        self.assertEqual(self.runtime.stops, 0)

    async def test_auth_scope_precedes_binding_lookup_and_worker_existence(self):
        for token, status in (("", 401), ("Bearer wrong", 401)):
            result = await self.client.get("/api/v2/workers/unknown", params=self.query, headers={"Authorization": token})
            self.assertEqual(result.status_code, status)
        for changed in ({"deployment_id": "other"}, {"repository": "github:github.com/example/other"}):
            result = await self.client.get("/api/v2/workers/unknown", params=self.query | changed)
            self.assertEqual(result.status_code, 403)
        result = await self.client.get("/api/v2/workers/unknown", params=self.query)
        self.assertEqual(result.status_code, 404)
        self.runtime.capabilities.assert_not_called()
        self.runtime.observe.assert_not_called()

    async def test_missing_or_changed_state_is_503_and_is_never_recreated(self):
        path = Path(self.state.value["members"]["runtime"])
        path.unlink()
        for method, route, values in (
            ("get", "/api/v2/workers/capabilities", {"params": self.query | {"profile": "fixture"}}),
            ("get", "/api/v2/workers", {"params": self.query | {"profile": "fixture"}}),
            ("post", "/api/v2/workers/ensure", {"json": self.body}),
            ("get", "/api/v2/workers/unknown", {"params": self.query}),
            ("post", "/api/v2/workers/unknown/stop", {"json": self.control}),
        ):
            response = await getattr(self.client, method)(route, **values)
            self.assertEqual(response.status_code, 503, response.text)
            self.assertFalse(path.exists())
        self.runtime.capabilities.assert_not_called()
        self.runtime.observe.assert_not_called()

    async def test_corrupt_private_metadata_is_unavailable_not_client_validation(self):
        original = self.state.path.read_bytes()
        for raw in (b"\xff", b"{", b'{"schema_version":NaN}'):
            self.state.path.write_bytes(raw)
            response = await self.client.get("/api/v2/workers", params=self.query | {"profile": "fixture"})
            self.assertEqual(response.status_code, 503, response.text)
        self.state.path.write_bytes(original)
        self.runtime.capabilities.assert_not_called()
        self.runtime.observe.assert_not_called()

    async def test_v1_cannot_create_discover_or_control_in_bound_service(self):
        worker = (await self.client.post("/api/v2/workers/ensure", json=self.body)).json()
        query = asdict(SCOPE)
        route = "/api/workers/" + worker["worker_id"]
        responses = [
            await self.client.get("/api/workers/capabilities", params=query | {"profile": "fixture"}),
            await self.client.get("/api/workers", params=query),
            await self.client.post("/api/workers/ensure", json=asdict(SPEC)),
            await self.client.get(route, params=query),
            await self.client.post(route + "/drain", json=query | {"schema_version": 1, "request_key": "v1-drain"}),
            await self.client.post(route + "/stop", json=query | {"schema_version": 1, "request_key": "v1-stop"}),
        ]
        self.assertEqual([result.status_code for result in responses], [409] * len(responses))
        self.assertEqual(self.runtime.launches, 1)
        self.assertEqual(self.runtime.stops, 0)

    async def test_v2_expected_identity_does_not_enroll_a_legacy_service(self):
        runtime = ContractRuntime()
        lifecycle = WorkerLifecycle(Path(self.temporary.name) / "legacy.sqlite3", runtime)
        app = create_worker_app(lifecycle, {self.token: {SCOPE}})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://legacy-fixture",
            headers={"Authorization": "Bearer " + self.token},
        ) as client:
            capability = await client.get("/api/v2/workers/capabilities", params=self.query | {"profile": "fixture"})
            ensured = await client.post("/api/v2/workers/ensure", json=self.body)
            self.assertEqual(capability.status_code, 409)
            self.assertEqual(ensured.status_code, 409)
            self.assertEqual(runtime.launches, 0)
            legacy = await client.post("/api/workers/ensure", json=asdict(SPEC))
            self.assertEqual(legacy.status_code, 200)
            self.assertEqual(legacy.json()["schema_version"], 1)
            self.assertNotIn("destination_binding", legacy.json())

    async def test_v2_request_shapes_versions_and_duplicate_json_are_closed(self):
        bodies = [
            self.body | {"schema_version": True}, self.body | {"schema_version": "2"},
            self.body | {"extra": "ignored"}, self.body | {"destination_binding": self.binding | {"policy_binding_version": True}},
            self.body | {"destination_binding": self.binding | {"policy_binding_version": "1"}},
            self.body | {"destination_binding": self.binding | {"extra": 1}},
            {key: value for key, value in self.body.items() if key != "destination_binding"},
        ]
        for body in bodies:
            response = await self.client.post("/api/v2/workers/ensure", json=body)
            self.assertEqual(response.status_code, 422, response.text)
        duplicate = json.dumps(self.body)[:-1] + ',"schema_version":2}'
        response = await self.client.post("/api/v2/workers/ensure", content=duplicate)
        self.assertEqual(response.status_code, 422)
        response = await self.client.post("/api/v2/workers/ensure", content=b" " * 65537)
        self.assertEqual(response.status_code, 422)
        good = self.query | {"profile": "fixture"}
        for changed in ({"schema_version": "02"}, {"schema_version": "2.0"}, {"policy_binding_version": "01"}, {"extra": "ignored"}):
            response = await self.client.get("/api/v2/workers/capabilities", params=good | changed)
            self.assertEqual(response.status_code, 422)
        response = await self.client.get("/api/v2/workers/capabilities", params=[*good.items(), ("profile", "fixture")])
        self.assertEqual(response.status_code, 422)
        response = await self.client.get("/api/v2/workers", params=self.query)
        self.assertEqual(response.status_code, 422)
        self.runtime.capabilities.assert_not_called()
        self.runtime.observe.assert_not_called()
        self.assertEqual(self.runtime.launches, 0)

    async def test_recovery_uses_original_profile_binding_after_configuration_change(self):
        created = (await self.client.post("/api/v2/workers/ensure", json=self.body)).json()
        self.config["profiles"][0]["memory_bytes"] = 268435456
        changed = DestinationState.load(self.config)
        self.lifecycle.destination = changed
        response = await self.client.get("/api/v2/workers", params=self.query | {"profile": "fixture", "launch_key": SPEC.launch_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["workers"][0]["worker_id"], created["worker_id"])
        response = await self.client.post("/api/v2/workers/" + created["worker_id"] + "/stop", json=self.control)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "stopped")
