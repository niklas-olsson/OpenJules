"""Lifecycle-owned full destination admission and immutable approval records.

Every mutation uses the lifecycle's short write transaction. No transaction is
held across Docker, canonical authority, model, or other external I/O.
"""

import json

from .destination import DestinationConflict, DestinationUnavailable, IDENTITY_TABLE, canonical
from .execution_contract import integer, parse_approval, qualification, project, MAX_INTEGER


def candidate_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def initialize_tables(connection, destination):
    existing = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='destination_admission'"
    ).fetchone() is not None
    sealed = connection.execute("SELECT application_schema FROM " + IDENTITY_TABLE).fetchone()[0] is not None
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS destination_admission (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            revision INTEGER NOT NULL, closure_epoch INTEGER NOT NULL,
            new_effects_open INTEGER NOT NULL CHECK(new_effects_open IN (0,1)),
            worker_ceiling INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS execution_approvals (
            policy_binding_id TEXT PRIMARY KEY, candidate TEXT NOT NULL,
            approved INTEGER NOT NULL CHECK(approved IN (0,1))
        );
        CREATE TABLE IF NOT EXISTS full_workers (
            worker_id TEXT PRIMARY KEY, qualification TEXT NOT NULL,
            disposition TEXT,
            FOREIGN KEY(worker_id) REFERENCES managed_workers(worker_id)
        );
        CREATE TABLE IF NOT EXISTS execution_intents (
            worker_id TEXT NOT NULL, intent_key TEXT NOT NULL,
            closure_epoch INTEGER NOT NULL, initially_open INTEGER NOT NULL,
            execution_id TEXT,
            PRIMARY KEY(worker_id,intent_key), UNIQUE(worker_id,execution_id),
            FOREIGN KEY(worker_id) REFERENCES managed_workers(worker_id)
        );
    """)
    if not existing and not sealed:
        connection.execute("INSERT INTO destination_admission VALUES (1,1,1,0,?)",
                           (destination.value["execution_contract"]["initial_worker_ceiling"],))
    read_admission(connection)


def read_admission(connection):
    rows = connection.execute("SELECT * FROM destination_admission").fetchall()
    try:
        if len(rows) != 1 or rows[0]["singleton"] != 1:
            raise ValueError()
        row = dict(rows[0])
        integer(row["revision"], 1)
        integer(row["closure_epoch"], 1)
        integer(row["new_effects_open"], 0, 1)
        integer(row["worker_ceiling"])
    except (ValueError, TypeError, KeyError):
        raise DestinationUnavailable("original destination admission is unavailable") from None
    return row


def unreleased(connection):
    return connection.execute("""
        SELECT COUNT(*) FROM managed_workers w
        WHERE NOT (state IN ('stopped','failed') AND termination_confirmed=1 AND artifacts_captured=1)
        OR EXISTS (SELECT 1 FROM worker_executions e WHERE e.worker_id=w.worker_id
                   AND NOT(e.termination_confirmed=1 AND e.artifacts_captured=1))
    """).fetchone()[0]


def observation(connection, row=None):
    row = read_admission(connection) if row is None else row
    return {"version": 1, "revision": row["revision"],
            "new_effects_open": bool(row["new_effects_open"]),
            "worker_ceiling": row["worker_ceiling"], "unreleased_workers": unreleased(connection)}


class FullExecutionAdmission:
    """Private mixin used only by WorkerLifecycle, the transaction owner."""

    def _require_full(self):
        if not self.full_mode:
            raise DestinationUnavailable("full execution contract is unsupported")

    def admission_status(self, action="inspect", ceiling=None):
        self._require_full()
        if action not in {"inspect", "open", "close", "ceiling"}:
            raise ValueError("unsupported admission operation")
        if action == "ceiling":
            integer(ceiling)
        elif ceiling is not None:
            raise ValueError("unexpected worker ceiling")
        # These host-local actions intentionally work before first ready and
        # against a running service. They never construct or call its runtime.
        with self._transaction(initializing=True) as db:
            row = read_admission(db)
            desired_open = {"open": 1, "close": 0}.get(action, row["new_effects_open"])
            desired_ceiling = ceiling if action == "ceiling" else row["worker_ceiling"]
            changed_open = desired_open != row["new_effects_open"]
            if changed_open or desired_ceiling != row["worker_ceiling"]:
                if row["revision"] == MAX_INTEGER or (changed_open and row["closure_epoch"] == MAX_INTEGER):
                    raise DestinationConflict("destination admission counter is exhausted")
                db.execute("UPDATE destination_admission SET revision=?,closure_epoch=?,new_effects_open=?,worker_ceiling=? WHERE singleton=1",
                           (row["revision"] + 1, row["closure_epoch"] + int(changed_open), desired_open, desired_ceiling))
            return observation(db)

    def retain_candidate(self, candidate):
        self._require_full()
        from .lifecycle import WorkerScope
        scope = WorkerScope(candidate["deployment_id"], candidate["repository"])
        binding = self.destination.binding(scope, candidate["profile"])
        if candidate["destination_binding"] != binding:
            raise DestinationConflict("execution candidate belongs to another destination")
        encoded = candidate_json(candidate)
        with self._transaction(initializing=True) as db:
            row = db.execute("SELECT * FROM execution_approvals WHERE policy_binding_id=?", (binding["policy_binding_id"],)).fetchone()
            if row is not None:
                if row["candidate"] != encoded:
                    raise DestinationConflict("original execution candidate cannot be replaced")
                return
            if self.destination.value["phase"] == "ready":
                raise DestinationUnavailable("ready destination is missing its original execution approval")
            db.execute("INSERT INTO execution_approvals VALUES (?,?,0)", (binding["policy_binding_id"], encoded))

    def approve_candidate(self, candidate):
        self._require_full()
        from .lifecycle import WorkerScope
        scope = WorkerScope(candidate["deployment_id"], candidate["repository"])
        binding = self.destination.binding(scope, candidate["profile"])
        if candidate["destination_binding"] != binding:
            raise DestinationConflict("execution approval belongs to another destination")
        with self._transaction(initializing=True) as db:
            row = db.execute("SELECT * FROM execution_approvals WHERE policy_binding_id=?", (binding["policy_binding_id"],)).fetchone()
            if row is None or row["candidate"] != candidate_json(candidate):
                raise DestinationConflict("approval does not match the original inspected candidate")
            if row["approved"] == 1:
                return  # Exact reapproval cannot reset anything.
            if self.destination.value["phase"] == "ready":
                raise DestinationUnavailable("execution approval requires original pre-ready state")
            db.execute("UPDATE execution_approvals SET approved=1 WHERE policy_binding_id=? AND approved=0", (binding["policy_binding_id"],))

    def execution_approval(self, scope, profile, *, initializing=False):
        self._require_full()
        binding = self.destination.binding(scope, profile)
        with self._transaction(initializing=initializing) as db:
            row = db.execute("SELECT * FROM execution_approvals WHERE policy_binding_id=?", (binding["policy_binding_id"],)).fetchone()
        if row is None or row["approved"] != 1:
            raise DestinationUnavailable("original execution approval is unavailable")
        try:
            value = parse_approval(row["candidate"].encode("utf-8"))
            if (value["destination_binding"] != binding or value["deployment_id"] != scope.deployment_id
                    or value["repository"] != scope.repository or value["profile"] != profile):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise DestinationUnavailable("original execution approval is invalid") from None
        return value

    def verify_new_execution_contract(self, scope, profile, expected=None):
        """Installed reinspection for new effects, never original-row recovery."""
        self._require_full()
        self.destination.validate(scope, profile, self.destination.binding(scope, profile), admission=True)
        original = self.execution_approval(scope, profile)
        if expected is not None and original["execution_manifest_sha256"] != expected:
            raise DestinationConflict("execution manifest differs from the original approval")
        from .managed_configuration import prepare_configuration
        try:
            image = self.runtime.execution_image(scope, profile)
            actual = project(self.destination.config, prepare_configuration(self.destination.config),
                             (scope.deployment_id, scope.repository, profile), image)
        except Exception:
            raise DestinationUnavailable("installed execution contract is unavailable") from None
        if actual != original["manifest"]:
            raise DestinationUnavailable("installed execution contract differs from its approval")
        return original

    def execution_contract(self, scope, profile, binding):
        self.validate_binding(scope, binding, profile)
        original = self.verify_new_execution_contract(scope, profile)
        return {"schema_version": 2, "contract_version": 1,
                "deployment_id": scope.deployment_id, "repository": scope.repository,
                "profile": profile, "destination_binding": dict(binding),
                "manifest": original["manifest"],
                "execution_manifest_sha256": original["execution_manifest_sha256"],
                "admission": self.admission_status()}

    def discover_bound_workers(self, scope, profile, binding, *, launch_key=None,
                               full_inventory=False, execution_qualification=None):
        self.validate_binding(scope, binding, profile)
        if execution_qualification is not None:
            execution_qualification = qualification(execution_qualification)
            self._require_full()
            if launch_key is None or full_inventory:
                raise ValueError("full keyed discovery requires its original launch key")
        if full_inventory and launch_key is not None:
            raise ValueError("mixed inventory cannot filter an original launch key")
        if full_inventory:
            self._require_full()
        # Resolve the original mode/tuple before current qualification or any
        # runtime observation. Empty full discovery validates immutable approval,
        # not today's admission revision or runtime readiness.
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM managed_workers WHERE deployment_id=? AND repository=? ORDER BY slot_id,generation",
                              (scope.deployment_id, scope.repository)).fetchall()
            selected = []
            for row in rows:
                spec = json.loads(row["spec"])
                if spec["profile"] != profile or (launch_key is not None and spec["launch_key"] != launch_key):
                    continue
                full = self._full_record(db, row)
                if not full_inventory:
                    original = None if full is None else {k: v for k, v in full.items() if k != "disposition"}
                    if original != execution_qualification:
                        raise DestinationConflict("discovery mode or original execution qualification differs")
                selected.append(row["worker_id"])
        if execution_qualification is not None and not selected:
            approved = self.execution_approval(scope, profile)
            if execution_qualification["execution_manifest_sha256"] != approved["execution_manifest_sha256"]:
                raise DestinationConflict("empty discovery qualification differs from its approval")
        return [self.observe_worker(scope, worker_id) for worker_id in selected]

    def _full_record(self, db, row):
        if not self.full_mode:
            return None
        result = db.execute("SELECT * FROM full_workers WHERE worker_id=?", (row["worker_id"],)).fetchone()
        original = db.execute("SELECT payload FROM worker_operations WHERE worker_id=? AND action='ensure'", (row["worker_id"],)).fetchall()
        if len(original) != 1:
            raise DestinationUnavailable("original worker launch intent is unavailable")
        payload = json.loads(original[0]["payload"])
        retained = payload.get("execution_qualification")
        if result is None:
            if retained is not None:
                raise DestinationUnavailable("original full worker qualification is unavailable")
            return None
        try:
            bound = qualification(json.loads(result["qualification"]))
            if bound != retained:
                raise ValueError()
            disposition = json.loads(result["disposition"]) if result["disposition"] is not None else None
            if disposition is not None:
                if (set(disposition) != {"version", "kind", "reason", "observed_admission_revision"}
                        or disposition["kind"] != "never_admitted"
                        or disposition["reason"] not in {"closed", "ceiling", "stale_admission_revision"}
                        or row["runtime_id"] is not None
                        or db.execute("SELECT 1 FROM worker_executions WHERE worker_id=? LIMIT 1", (row["worker_id"],)).fetchone() is not None
                        or row["state"] != "stopped" or row["reason"] != "never_admitted"
                        or row["draining"] != 1 or row["termination_confirmed"] != 1 or row["artifacts_captured"] != 1):
                    raise ValueError()
                integer(disposition["version"], 1, 1)
                integer(disposition["observed_admission_revision"], 1)
        except (ValueError, TypeError, KeyError):
            raise DestinationUnavailable("original full worker qualification is invalid") from None
        return bound | {"disposition": disposition}

    def reserve_execution_intent(self, scope, worker_id, intent_key):
        if not self.full_mode:
            return
        from .lifecycle import LifecycleConflict, _text
        _text(intent_key, "execution intent")
        with self._transaction() as db:
            worker = self._get(db, scope, worker_id)
            if self._terminal(worker):
                raise LifecycleConflict("terminal worker cannot reserve an execution intent")
            row = db.execute("SELECT * FROM execution_intents WHERE worker_id=? AND intent_key=?", (worker_id, intent_key)).fetchone()
            current = read_admission(db)
            if row is None:
                db.execute("INSERT INTO execution_intents VALUES (?,?,?,?,NULL)",
                           (worker_id, intent_key, current["closure_epoch"], current["new_effects_open"]))
                row = db.execute("SELECT * FROM execution_intents WHERE worker_id=? AND intent_key=?", (worker_id, intent_key)).fetchone()
            allowed = row["execution_id"] is not None or (
                row["initially_open"] == 1 and current["new_effects_open"] == 1 and row["closure_epoch"] == current["closure_epoch"])
        if not allowed:
            # Persist a refused original intent before reporting refusal. A
            # close/reopen never refreshes the same intent's closure epoch.
            raise LifecycleConflict("original execution intent is closed or stale")

    def execution_intent_allowed(self, scope, worker_id, intent_key):
        if not self.full_mode:
            return True
        with self._transaction() as db:
            self._get(db, scope, worker_id)
            row = db.execute("SELECT * FROM execution_intents WHERE worker_id=? AND intent_key=?", (worker_id, intent_key)).fetchone()
            state = read_admission(db)
            return row is not None and (row["execution_id"] is not None or (
                row["initially_open"] == 1 and state["new_effects_open"] == 1
                and row["closure_epoch"] == state["closure_epoch"]))

    def require_execution_intent(self, scope, worker_id, intent_key):
        if not self.full_mode:
            return
        with self._transaction() as db:
            self._get(db, scope, worker_id)
            row = db.execute("SELECT * FROM execution_intents WHERE worker_id=? AND intent_key=?", (worker_id, intent_key)).fetchone()
            if row is None:
                raise DestinationUnavailable("original execution intent is unavailable")
            integer(row["closure_epoch"], 1)
            integer(row["initially_open"], 0, 1)

    def _admit_execution_intent(self, db, worker_id, intent_key, execution_id):
        from .lifecycle import LifecycleConflict
        row = db.execute("SELECT * FROM execution_intents WHERE worker_id=? AND intent_key=?", (worker_id, intent_key)).fetchone()
        state = read_admission(db)
        if (row is None or row["execution_id"] is not None or row["initially_open"] != 1
                or not state["new_effects_open"] or row["closure_epoch"] != state["closure_epoch"]):
            raise LifecycleConflict("original execution intent is absent, closed or already admitted")
        db.execute("UPDATE execution_intents SET execution_id=? WHERE worker_id=? AND intent_key=? AND execution_id IS NULL",
                   (execution_id, worker_id, intent_key))
