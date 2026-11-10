"""API authorization and exact ZPM v1 wire contract."""

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import httpx

from src.api.worker_lifecycle import create_worker_app
from src.worker.lifecycle import WorkerLifecycle, WorkerScope, WorkerSpec
from tests.unit.test_worker_lifecycle import ContractRuntime


class LifecycleAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = TemporaryDirectory()
        self.scope = WorkerScope("deployment-a", "github:github.com/example/repo")
        self.spec = WorkerSpec(
            self.scope.deployment_id, self.scope.repository, "slot-0", 1, "launch", "fixture"
        )
        self.runtime = ContractRuntime()
        self.lifecycle = WorkerLifecycle(Path(self.directory.name) / "runtime.sqlite", self.runtime)
        self.token = "a" * 40
        self.app = create_worker_app(self.lifecycle, {self.token: {self.scope}})
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://testserver",
            headers={"Authorization": "Bearer " + self.token},
        )
        self.query = asdict(self.scope)

    async def asyncTearDown(self):
        await self.client.aclose()
        self.directory.cleanup()

    async def test_exact_v1_routes_and_envelopes(self):
        capability = await self.client.get(
            "/api/workers/capabilities", params=self.query | {"profile": "fixture"}
        )
        self.assertEqual(capability.status_code, 200)
        self.assertEqual(capability.json(), {
            "schema_version": 1,
            "deployment_id": self.scope.deployment_id,
            "repository": self.scope.repository,
            "profile": "fixture",
            "operations": ["ensure", "discover", "observe", "drain", "stop"],
            "managed_dispatch": True, "profile_supported": True,
            "repository_access": True, "reason": "Contract fixture",
        })
        ensured = await self.client.post("/api/workers/ensure", json=asdict(self.spec))
        self.assertEqual(ensured.status_code, 200)
        worker = ensured.json()
        self.assertEqual(worker["schema_version"], 1)
        self.assertEqual(worker["deployment_id"], self.scope.deployment_id)
        self.assertNotIn("runtime_id", worker)
        observed = await self.client.get("/api/workers/" + worker["worker_id"], params=self.query)
        self.assertEqual(observed.json()["worker_id"], worker["worker_id"])
        listing = await self.client.get("/api/workers", params=self.query | {"launch_key": "launch"})
        self.assertEqual(listing.json(), {"schema_version": 1, "workers": [worker]})
        for operation in ("drain", "stop"):
            response = await self.client.post(
                f"/api/workers/{worker['worker_id']}/{operation}",
                json=self.query | {"schema_version": 1, "request_key": operation},
            )
            self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "stopped")

    async def test_authentication_and_both_scope_dimensions_are_required(self):
        query = self.query | {"profile": "fixture"}
        for header in ("", "Bearer wrong-token"):
            response = await self.client.get(
                "/api/workers/capabilities", params=query, headers={"Authorization": header}
            )
            self.assertEqual(response.status_code, 401)
        for changed in ({"deployment_id": "other"}, {"repository": "github:github.com/example/other"}):
            response = await self.client.post("/api/workers/ensure", json=asdict(self.spec) | changed)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.runtime.launches, 0)

    async def test_missing_capability_and_changed_retry_are_not_success(self):
        result = await self.client.post("/api/workers/ensure", json=asdict(self.spec))
        self.assertEqual(result.status_code, 200)
        changed = await self.client.post(
            "/api/workers/ensure", json=asdict(self.spec) | {"profile": "new-profile"}
        )
        self.assertEqual(changed.status_code, 409)
        self.runtime.available = False
        blocked = await self.client.post(
            "/api/workers/ensure", json=asdict(self.spec) | {"slot_id": "slot-1", "launch_key": "next"}
        )
        self.assertEqual(blocked.status_code, 503)
        self.assertEqual(self.runtime.launches, 1)

    async def test_unknown_fields_versions_and_missing_scope_fail_validation(self):
        for changed in (
            asdict(self.spec) | {"schema_version": 2},
            asdict(self.spec) | {"schema_version": True},
            asdict(self.spec) | {"generation": 1 << 63},
            asdict(self.spec) | {"command": "not-authorized"},
            {key: value for key, value in asdict(self.spec).items() if key != "deployment_id"},
        ):
            result = await self.client.post("/api/workers/ensure", json=changed)
            self.assertEqual(result.status_code, 422)
        self.assertEqual(self.runtime.launches, 0)


if __name__ == "__main__":
    unittest.main()
