import json
import time
import uuid
from datetime import UTC, datetime

from birbverify.closure import (
    BeginClosure,
    Binding,
    ClosureReceipt,
    LifecycleIntent,
    Progress,
    Registration,
    ReservationProvenance,
    Snapshot,
)
from birbverify.contract import Manifest, Request, digest
from birbverify.lifecycle import ADAPTER, CHECKER, CLEANUP, classify, load_evidence
from birbverify.policy import authorize

MUTATORS = {
    "apply",
    "assert_active",
    "revoke",
    "uncertain",
    "cancel",
    "recover",
    "stop",
    "cleanup",
    "release",
    "finish",
}
OPERATIONS = {
    "begin_closure",
    "read_closure",
    "confirm_closure_stop",
    "cleanup_closure",
    "release_closure",
    "observe_closure_state",
    "register_worker",
    "lifecycle_intent",
    "lifecycle_completion",
    "lifecycle_records",
    "capabilities",
    "validate_closure_receipt",
}


OWNER_FIELDS = {"attempt_id", "token", "execution_epoch"}
RPC_FIELDS = {
    "admit": {"request", "admission_target_incarnation"},
    "reserve": {"request_id", "attempt_id", "execution_epoch", "worker_execution_id"},
    "apply": OWNER_FIELDS
    | {"operation_id", "request_id", "candidate", "payload_sha256", "lose_reply"},
    "receipt": OWNER_FIELDS | {"operation_id", "request_id", "candidate", "payload_sha256"},
    "finish": OWNER_FIELDS | {"manifest", "lose_reply"},
    "result": {"request_id"},
    "current_attempt": {"request_id"},
    "snapshot": {"attempt_id"},
    "inspect": set(),
    "capabilities": set(),
    "validate_closure_receipt": {"closure_id"},
    "begin_closure": {"command", "recovery_key"},
    "read_closure": {"closure_id", "request_id", "recovery_key"},
    "confirm_closure_stop": {"closure_id", "evidence_ref", "expected_revision", "recovery_key"},
    "cleanup_closure": {
        "closure_id",
        "cleanup_payload_sha256",
        "expected_revision",
        "recovery_key",
    },
    "release_closure": {"closure_id", "expected_revision", "recovery_key"},
    "observe_closure_state": {"request_ids"},
    "register_worker": {"registration", "recovery_key"},
    "lifecycle_intent": OWNER_FIELDS | {"intent", "recovery_key"},
    "lifecycle_completion": {"operation_id", "evidence_ref", "checker_key"},
    "lifecycle_records": {"request_id", "recovery_key"},
}
for _method in MUTATORS - {"apply", "finish"}:
    RPC_FIELDS[_method] = OWNER_FIELDS | {"recovery_key"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def stamp():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ClosureStore:
    def __init__(self, target, error):
        self.target = target
        self.error = error
        self.config = target.installation
        self.root = target.path.parent
        self.binding = Binding.model_validate(self.config["closure_binding"])
        with target.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS closure_meta (
                    id INTEGER PRIMARY KEY CHECK(id=1), incarnation TEXT, revision INTEGER,
                    epoch INTEGER, restore_blocked INTEGER);
                CREATE TABLE IF NOT EXISTS request_epochs (
                    request TEXT PRIMARY KEY, incarnation TEXT, epoch INTEGER UNIQUE,
                    sealed_by TEXT UNIQUE);
                CREATE TABLE IF NOT EXISTS worker_registrations (
                    id TEXT PRIMARY KEY, digest TEXT, payload TEXT);
                CREATE TABLE IF NOT EXISTS reservation_provenance (
                    attempt TEXT PRIMARY KEY, request TEXT UNIQUE, digest TEXT, payload TEXT);
                CREATE TABLE IF NOT EXISTS closure_records (
                    id TEXT PRIMARY KEY, request TEXT UNIQUE, command_hash TEXT, command TEXT,
                    progress TEXT, history TEXT, observations TEXT);
                CREATE TABLE IF NOT EXISTS lifecycle_intents (
                    id TEXT PRIMARY KEY, request TEXT, digest TEXT, payload TEXT,
                    intent_revision INTEGER, completion TEXT, completion_revision INTEGER,
                    settlement TEXT NOT NULL DEFAULT 'unknown');
                CREATE TABLE IF NOT EXISTS release_transitions (
                    request TEXT PRIMARY KEY, attempt TEXT, revision INTEGER, payload TEXT);
                CREATE TABLE IF NOT EXISTS closure_owner (
                    id INTEGER PRIMARY KEY CHECK(id=1), closure TEXT);
                INSERT OR IGNORE INTO closure_owner VALUES (1,NULL);
            """)
            row = db.execute("SELECT incarnation FROM closure_meta WHERE id=1").fetchone()
            incarnation = str(self.binding.target_incarnation)
            if row is None:
                db.execute(
                    "INSERT INTO closure_meta VALUES (1,?,0,0,?)",
                    (
                        incarnation,
                        int(bool(self.config.get("restored_from_incarnation"))),
                    ),
                )
            elif row[0] != incarnation:
                db.execute(
                    "UPDATE closure_meta SET incarnation=?,restore_blocked=1 WHERE id=1",
                    (incarnation,),
                )

    def fail(self, message):
        raise self.error(message)

    def validate_fields(self, method, data):
        if method not in RPC_FIELDS:
            self.fail("unknown_method")
        if data.keys() - RPC_FIELDS[method]:
            self.fail("unexpected_rpc_fields")
        for key in ("execution_epoch", "expected_revision"):
            if key in data and (
                type(data[key]) is not int or data[key] < (0 if key == "expected_revision" else 1)
            ):
                self.fail("invalid_numeric_authority")

    def check_binding(self, binding):
        if binding is None or Binding.model_validate(binding) != self.binding:
            self.fail("target_binding_mismatch")

    def revision(self, db):
        return db.execute("SELECT revision FROM closure_meta WHERE id=1").fetchone()[0]

    def bump(self, db):
        db.execute("UPDATE closure_meta SET revision=revision+1 WHERE id=1")
        return self.revision(db)

    def supervisor(self, data):
        self.target.supervisor(data)

    def checker(self, data):
        if digest(data.get("checker_key", "").encode()) != self.config["checker_key_sha256"]:
            self.fail("checker_required")

    def epoch_row(self, db, request_id):
        row = db.execute("SELECT * FROM request_epochs WHERE request=?", (request_id,)).fetchone()
        if row is not None and row["incarnation"] != str(self.binding.target_incarnation):
            self.fail("legacy_provenance_unavailable")
        return row

    def insert_request(self, db, request, admission_incarnation):
        if admission_incarnation != str(self.binding.target_incarnation):
            self.fail("legacy_provenance_unavailable")
        if db.execute("SELECT restore_blocked FROM closure_meta").fetchone()[0]:
            self.fail("restore_reconciliation_required")
        authorize(request, self.config)
        if request.resources.max_attempts != 1:
            self.fail("one_attempt_profile_required")
        row = db.execute(
            "SELECT * FROM requests WHERE id=? OR key=?",
            (
                request.request_id,
                request.idempotency_key,
            ),
        ).fetchone()
        if row:
            if row["hash"] != digest(request):
                self.fail("identity_conflict")
            epoch = self.epoch_row(db, request.request_id)
            if epoch is None:
                self.fail("legacy_provenance_unavailable")
            return epoch
        db.execute(
            "INSERT INTO requests VALUES (?,?,?,?)",
            (
                request.request_id,
                request.idempotency_key,
                digest(request),
                request.model_dump_json(),
            ),
        )
        db.execute("UPDATE closure_meta SET epoch=epoch+1 WHERE id=1")
        epoch = db.execute("SELECT epoch FROM closure_meta").fetchone()[0]
        db.execute(
            "INSERT INTO request_epochs VALUES (?,?,?,NULL)",
            (
                request.request_id,
                str(self.binding.target_incarnation),
                epoch,
            ),
        )
        self.bump(db)
        return self.epoch_row(db, request.request_id)

    def admission(self, db, data):
        request = Request.model_validate(data["request"])
        row = self.insert_request(db, request, data["admission_target_incarnation"])
        return {
            "request": request.model_dump(mode="json"),
            "execution_epoch": row["epoch"],
            "sealed": row["sealed_by"] is not None,
        }

    def registration(self, db, identity):
        row = db.execute(
            "SELECT payload FROM worker_registrations WHERE id=?", (identity,)
        ).fetchone()
        if row is None:
            self.fail("worker_registration_missing")
        return json.loads(row[0])

    def register(self, db, data):
        self.supervisor(data)
        registration = Registration.model_validate(data["registration"])
        if registration.target_id != self.binding.target_id or (
            registration.target_incarnation != self.binding.target_incarnation
        ):
            self.fail("target_binding_mismatch")
        evidence = load_evidence(self.root, registration.evidence_ref.model_dump(mode="json"))
        inspection = evidence["inspection"]
        group = registration.group
        config = inspection["HostConfig"]
        if (
            inspection["Id"] != group.container_id
            or evidence["daemon_id"] != group.daemon_id
            or evidence["host_boot_id"] != str(group.host_boot_id)
            or inspection["State"]["Pid"] != group.worker_pid
            or evidence["worker_start_ticks"] != group.worker_start_ticks
            or digest(inspection) != group.config_sha256
            or not inspection["State"]["Running"]
            or config.get("Privileged")
            or config.get("PidMode")
            or config.get("RestartPolicy", {}).get("Name") not in {"no", ""}
            or "ALL" not in config.get("CapDrop", [])
            or config.get("CapAdd")
            or "no-new-privileges" not in config.get("SecurityOpt", [])
            or inspection["Config"]["Labels"].get("birbverify.worker_execution")
            != registration.worker_execution_id
        ):
            self.fail("invalid_worker_execution_group")
        row = db.execute(
            "SELECT digest FROM worker_registrations WHERE id=?",
            (registration.worker_execution_id,),
        ).fetchone()
        if row:
            if row[0] != digest(registration):
                self.fail("registration_identity_conflict")
        else:
            db.execute(
                "INSERT INTO worker_registrations VALUES (?,?,?)",
                (
                    registration.worker_execution_id,
                    digest(registration),
                    registration.model_dump_json(),
                ),
            )
            self.bump(db)
        return {"registered": registration.worker_execution_id}

    def reserve(self, db, env, data, peer):
        request_id, attempt_id = data["request_id"], data["attempt_id"]
        row = self.epoch_row(db, request_id)
        if row is None:
            self.fail("request_not_admitted")
        terminal = db.execute(
            "SELECT manifest FROM attempts WHERE request=? AND manifest IS NOT NULL", (request_id,)
        ).fetchone()
        if terminal:
            return {"result": json.loads(terminal[0])}
        if row["sealed_by"]:
            self.fail("request_closed")
        if row["epoch"] != data.get("execution_epoch"):
            self.fail("execution_epoch_mismatch")
        if env["state"] != "free":
            return {"busy": True, "state": env["state"]}
        request = Request.model_validate_json(
            db.execute(
                "SELECT payload FROM requests WHERE id=?",
                (request_id,),
            ).fetchone()[0]
        )
        if time.time() >= request.resources.deadline.timestamp():
            self.fail("deadline_expired")
        if db.execute(
            "SELECT 1 FROM attempts WHERE request=? OR id=?",
            (
                request_id,
                attempt_id,
            ),
        ).fetchone():
            self.fail("attempt_budget_exhausted")
        registration = self.registration(db, data["worker_execution_id"])
        group = registration["group"]
        if not peer or any(
            peer.get(key) != group[key]
            for key in (
                "container_id",
                "worker_pid",
                "worker_start_ticks",
                "host_boot_id",
            )
        ):
            self.fail("worker_peer_mismatch")
        token = uuid.uuid4().hex
        provenance = ReservationProvenance(
            request_id=request_id,
            request_sha256=digest(request),
            execution_epoch=row["epoch"],
            admission_target_incarnation=row["incarnation"],
            attempt_id=attempt_id,
            acquired_at=datetime.now(UTC),
            registration=registration,
            candidate_container=f"birbverify-{attempt_id}",
            policy_sha256=digest(request.authority),
        )
        db.execute("INSERT INTO attempts VALUES (?,?,?,NULL)", (attempt_id, request_id, "running"))
        db.execute(
            "INSERT INTO reservation_provenance VALUES (?,?,?,?)",
            (
                attempt_id,
                request_id,
                digest(provenance),
                provenance.model_dump_json(),
            ),
        )
        db.execute(
            "UPDATE environment SET owner=?,token=?,state='active',expires=?,stopped=0,"
            "cleanup=0 WHERE id=1",
            (attempt_id, token, request.resources.deadline.timestamp()),
        )
        self.bump(db)
        return {
            "token": token,
            "attempt_number": 1,
            "prior_attempt_id": None,
            "execution_epoch": row["epoch"],
        }

    def worker_guard(self, db, env, data):
        if not data.get("attempt_id") or not data.get("token"):
            self.fail("stale_owner")
        attempt = db.execute(
            "SELECT request FROM attempts WHERE id=?", (data["attempt_id"],)
        ).fetchone()
        if not attempt:
            self.fail("stale_owner")
        row = self.epoch_row(db, attempt[0])
        if row is None:
            self.fail("legacy_provenance_unavailable")
        if row["sealed_by"]:
            self.fail("request_closed")
        if row["epoch"] != data.get("execution_epoch"):
            self.fail("execution_epoch_mismatch")
        if db.execute("SELECT closure FROM closure_owner").fetchone()[0] is not None:
            self.fail("stale_owner")
        self.target.owner(env, data)
        return row

    def before(self, db, env, method, data):
        if method not in MUTATORS:
            return
        if method == "finish":
            old = db.execute(
                "SELECT manifest FROM attempts WHERE id=?", (data.get("attempt_id"),)
            ).fetchone()
            if old and old[0] is not None:
                return
        self.worker_guard(db, env, data)
        if method in {"stop", "recover"}:
            self.normal_stop_ready(db, data["attempt_id"])
        if method == "finish" and data.get("manifest", {}).get("termination") == "confirmed":
            self.normal_stop_ready(db, data["attempt_id"])

    def after(self, db, old_env, method, data, result):
        if method in MUTATORS:
            current = db.execute("SELECT state FROM environment").fetchone()[0]
            revision = self.bump(db)
            if method in {"release", "finish"} and current == "free" and old_env["owner"]:
                attempt = db.execute(
                    "SELECT request FROM attempts WHERE id=?", (old_env["owner"],)
                ).fetchone()
                db.execute(
                    "INSERT OR IGNORE INTO release_transitions VALUES (?,?,?,?)",
                    (
                        attempt[0],
                        old_env["owner"],
                        revision,
                        encode({"method": method, "result_sha256": digest(result), "at": stamp()}),
                    ),
                )

    def records(self, db, request_id):
        return [
            {
                "intent": json.loads(row["payload"]),
                "intent_revision": row["intent_revision"],
                "completion": json.loads(row["completion"]) if row["completion"] else None,
                "completion_revision": row["completion_revision"],
                "settlement": row["settlement"],
            }
            for row in db.execute(
                "SELECT * FROM lifecycle_intents WHERE request=? ORDER BY rowid", (request_id,)
            )
        ]

    def normal_stop_ready(self, db, attempt_id):
        row = db.execute(
            "SELECT payload FROM reservation_provenance WHERE attempt=?", (attempt_id,)
        ).fetchone()
        if not row:
            self.fail("legacy_provenance_unavailable")
        provenance = json.loads(row[0])
        records = self.records(db, provenance["request_id"])
        for item in records:
            self.validate_completion(item)
        creates = [item for item in records if item["intent"]["verb"] == "create"]
        if creates:
            candidate = provenance["candidate_container"]
            mutations = [
                item for item in records if item["intent"]["verb"] in {"create", "start", "remove"}
            ]
            latest = max((item["completion_revision"] for item in mutations), default=0)
            if not any(
                self.absence(item, candidate) and item["intent_revision"] > latest
                for item in records
            ):
                self.fail("container_absence_unconfirmed")

    def validate_completion(self, item):
        if item["completion"] is None or item["settlement"] == "unknown":
            self.fail("intent_unsettled")
        evidence = load_evidence(self.root, item["completion"])
        intent = LifecycleIntent.model_validate(item["intent"])
        response = evidence["response"]
        if evidence["intent_sha256"] != digest(intent) or (
            response.get("command_sha256") != intent.arguments_sha256
            or response.get("command") != intent.command.model_dump(mode="json")
            or classify(intent.verb, response) != item["settlement"]
        ):
            self.fail("intent_evidence_mismatch")
        return evidence

    def absence(self, item, container):
        return (
            item["intent"]["verb"] == "inspect"
            and item["intent"]["container"] == container
            and self.validate_completion(item)["response"]["status"] == 404
        )

    def authorize_command(self, command):
        auth, original = command.authorization, command.request.authority
        if (
            command.target_id != self.binding.target_id
            or command.target_incarnation != self.binding.target_incarnation
            or auth.admission_target_incarnation != self.binding.target_incarnation
        ):
            self.fail("legacy_provenance_unavailable")
        if (
            auth.principal != original.principal
            or auth.workflow != original.workflow
            or auth.policy_revision != original.policy_revision
            or auth.closure_actor != self.config["closure_actor"]
            or auth.grant_reference != self.config["closure_grant"]
        ):
            self.fail("closure_authorization_denied")
        authorize(command.request, self.config)

    def operation(self, closure_id, step):
        return {
            "target_incarnation": str(self.binding.target_incarnation),
            "closure_id": closure_id,
            "step": step,
        }

    def closure(self, db, identity):
        row = db.execute(
            "SELECT * FROM closure_records WHERE id=? OR request=?",
            (
                identity,
                identity,
            ),
        ).fetchone()
        if not row:
            self.fail("closure_unknown")
        return row

    def view(self, db, row):
        return {
            "command": json.loads(row["command"]),
            "progress": json.loads(row["progress"]),
            "record_revision": self.revision(db),
            "observations": json.loads(row["observations"]),
        }

    def write_progress(self, db, row, progress):
        Progress.model_validate(progress)
        db.execute(
            "UPDATE closure_records SET progress=? WHERE id=?", (encode(progress), row["id"])
        )
        self.bump(db)
        return self.view(db, self.closure(db, row["id"]))

    def begin(self, db, env, data):
        self.supervisor(data)
        command = BeginClosure.model_validate(data["command"])
        self.authorize_command(command)
        identity = str(command.closure_id)
        existing = db.execute("SELECT * FROM closure_records WHERE id=?", (identity,)).fetchone()
        if existing:
            if existing["command_hash"] != digest(command):
                self.fail("closure_identity_conflict")
            return self.view(db, existing)
        old = db.execute(
            "SELECT id FROM closure_records WHERE request=?", (command.request.request_id,)
        ).fetchone()
        if old:
            self.fail("request_already_closing")
        epoch = self.insert_request(
            db, command.request, str(command.authorization.admission_target_incarnation)
        )
        if (
            command.expected_execution_epoch is not None
            and command.expected_execution_epoch != epoch["epoch"]
        ):
            self.fail("expected_epoch_mismatch")
        attempt = db.execute(
            "SELECT * FROM attempts WHERE request=? ORDER BY rowid LIMIT 1",
            (command.request.request_id,),
        ).fetchone()
        attempt_id = attempt["id"] if attempt else None
        if command.expected_attempt_id is not None and command.expected_attempt_id != attempt_id:
            self.fail("expected_attempt_mismatch")
        prior_release = db.execute(
            "SELECT * FROM release_transitions WHERE request=?", (command.request.request_id,)
        ).fetchone()
        if prior_release:
            return {"status": "already_released", "release": dict(prior_release)}
        closure_owner = db.execute("SELECT closure FROM closure_owner").fetchone()[0]
        if (
            closure_owner
            or (attempt and env["owner"] != attempt_id)
            or (not attempt and env["state"] != "free")
        ):
            self.fail(
                "environment_owner_conflict"
                if not attempt or env["owner"]
                else "release_history_unavailable"
            )
        if not attempt and (env["value"] != 0 or env["candidate"] is not None):
            self.fail("dirty_target_conflict")
        reservation = (
            db.execute(
                "SELECT digest FROM reservation_provenance WHERE attempt=?", (attempt_id,)
            ).fetchone()
            if attempt
            else None
        )
        acquired = (
            {
                "kind": "acquired",
                "attempt_id": attempt_id,
                "reservation_sha256": reservation[0]
                if reservation
                else digest({"legacy": attempt_id}),
            }
            if attempt
            else {"kind": "never_acquired", "attempt_id": None, "reservation_sha256": None}
        )
        db.execute(
            "UPDATE request_epochs SET sealed_by=? WHERE request=?",
            (
                identity,
                command.request.request_id,
            ),
        )
        db.execute("UPDATE closure_owner SET closure=? WHERE id=1", (identity,))
        db.execute("UPDATE environment SET state='quarantined',token=NULL WHERE id=1")
        revision = self.bump(db)
        effects = [
            dict(row)
            for row in db.execute(
                "SELECT * FROM operations WHERE request=?", (command.request.request_id,)
            )
        ]
        sealed = {
            "request_sha256": command.request_sha256,
            "epoch": epoch["epoch"],
            "closure_id": identity,
            "target_incarnation": str(command.target_incarnation),
        }
        fence_ref = {
            "id": digest(sealed),
            "sha256": digest(sealed),
            "kind": "fence",
            "checker_id": self.binding.target_id,
        }
        fence = {
            "operation_id": self.operation(identity, "fence"),
            "commit_revision": revision,
            "sealed_request_sha256": digest(sealed),
            "effect_history_sha256": digest({"effects": effects}),
            "evidence_ref": fence_ref,
        }
        progress = {
            "closure_id": identity,
            "execution_epoch": epoch["epoch"],
            "acquisition": acquired,
            "phase": "fenced_stop_unknown" if attempt else "fenced_cleanup_unknown",
            "blocking_reason": "legacy_provenance_unavailable"
            if attempt and not reservation
            else None,
            "fence": fence,
            "stop": None
            if attempt
            else {"kind": "not_started_target_confirmed", "evidence_refs": [fence_ref]},
            "cleanup": None,
            "receipt": None,
        }
        history = (
            {
                "manifest_status": "present",
                "manifest_sha256": digest(Manifest.model_validate_json(attempt["manifest"])),
            }
            if attempt and attempt["manifest"]
            else {"manifest_status": "unavailable", "manifest_sha256": None}
        )
        Progress.model_validate(progress)
        db.execute(
            "INSERT INTO closure_records VALUES (?,?,?,?,?,?,?)",
            (
                identity,
                command.request.request_id,
                digest(command),
                command.model_dump_json(),
                encode(progress),
                encode(history),
                "[]",
            ),
        )
        return self.view(db, self.closure(db, identity))

    def claimed(self, db, row):
        if db.execute("SELECT closure FROM closure_owner").fetchone()[0] != row["id"]:
            self.fail("closure_owner_mismatch")
        epoch = self.epoch_row(db, row["request"])
        if not epoch or epoch["sealed_by"] != row["id"]:
            self.fail("request_seal_missing")

    def current_revision(self, db, row, data):
        return data.get("expected_revision") == self.revision(db)

    def lifecycle_intent(self, db, env, data):
        intent = LifecycleIntent.model_validate(data["intent"])
        provenance_row = db.execute(
            "SELECT payload FROM reservation_provenance WHERE attempt=?", (intent.attempt_id,)
        ).fetchone()
        if not provenance_row:
            self.fail("legacy_provenance_unavailable")
        provenance = json.loads(provenance_row[0])
        if (
            intent.request_id != provenance["request_id"]
            or intent.execution_epoch != provenance["execution_epoch"]
            or intent.worker_execution_id != provenance["registration"]["worker_execution_id"]
        ):
            self.fail("intent_binding_mismatch")
        if intent.authority == "worker":
            self.worker_guard(db, env, data)
            if intent.verb in {"create", "start"}:
                self.target.fence(env, data)
        else:
            self.supervisor(data)
            row = self.closure(db, str(intent.closure_id))
            self.claimed(db, row)
            if row["request"] != intent.request_id or intent.verb not in {
                "remove",
                "inspect",
                "list",
            }:
                self.fail("closure_intent_denied")
            if json.loads(row["progress"])["stop"] is not None:
                self.fail("closure_stop_already_confirmed")
        self.validate_intent_endpoint(intent, provenance)
        existing = db.execute(
            "SELECT digest FROM lifecycle_intents WHERE id=?", (intent.operation_id,)
        ).fetchone()
        if existing:
            if existing[0] != digest(intent):
                self.fail("operation_identity_conflict")
            return {"send_authorized": False, "reason": "intent_already_committed"}
        revision = self.bump(db)
        db.execute(
            "INSERT INTO lifecycle_intents(id,request,digest,payload,intent_revision) "
            "VALUES (?,?,?,?,?)",
            (
                intent.operation_id,
                intent.request_id,
                digest(intent),
                intent.model_dump_json(),
                revision,
            ),
        )
        return {
            "send_authorized": True,
            "intent_sha256": digest(intent),
            "record_revision": revision,
        }

    def validate_intent_endpoint(self, intent, provenance):
        candidate = provenance["candidate_container"]
        worker = provenance["registration"]["group"]["container_id"]
        if intent.container != candidate and not (
            intent.authority == "closure" and intent.container == worker
        ):
            self.fail("container_identity_mismatch")
        prefix = "/containers/" + intent.container
        endpoints = {
            "create": ("POST", "/containers/create?name=" + candidate),
            "start": ("POST", prefix + "/start"),
            "remove": ("DELETE", prefix + "?force=true"),
            "inspect": ("GET", prefix + "/json"),
            "wait": ("POST", prefix + "/wait?condition=not-running"),
            "logs": ("GET", prefix + "/logs?stdout=true&stderr=true"),
        }
        if endpoints.get(intent.verb) != (intent.command.method, intent.command.path):
            self.fail("unsupported_lifecycle_command")
        if intent.verb == "create":
            body = intent.command.body
            host = body.get("HostConfig", {}) if body else {}
            if (
                not body
                or body.keys()
                - {"Image", "Cmd", "User", "AttachStdout", "AttachStderr", "Labels", "HostConfig"}
                or host.keys()
                - {
                    "Binds",
                    "NetworkMode",
                    "ReadonlyRootfs",
                    "CapDrop",
                    "SecurityOpt",
                    "PidsLimit",
                    "Memory",
                    "NanoCpus",
                    "LogConfig",
                }
                or body.get("Image") != self.config["candidate_image"]
                or body.get("Cmd") != ["python", "-I", "-S", "/candidate/check.py"]
                or body.get("Labels", {}).get("birbverify.attempt") != intent.attempt_id
                or body.get("Labels", {}).get("birbverify.incarnation")
                != str(self.binding.target_incarnation)
                or host.get("NetworkMode") != "none"
                or not host.get("ReadonlyRootfs")
                or host.get("Privileged")
                or host.get("PidMode")
                or host.get("CapDrop") != ["ALL"]
                or host.get("CapAdd")
                or host.get("RestartPolicy", {}).get("Name") not in {None, "no"}
                or host.get("Binds") != [f"{self.root}/checkouts/{intent.attempt_id}:/candidate:ro"]
            ):
                self.fail("candidate_configuration_denied")
        elif intent.command.body is not None:
            self.fail("unexpected_command_body")

    def completion(self, db, data):
        self.checker(data)
        row = db.execute(
            "SELECT * FROM lifecycle_intents WHERE id=?", (data["operation_id"],)
        ).fetchone()
        if not row:
            self.fail("intent_unknown")
        reference = data["evidence_ref"]
        evidence = load_evidence(self.root, reference)
        intent = LifecycleIntent.model_validate_json(row["payload"])
        provenance = json.loads(
            db.execute(
                "SELECT payload FROM reservation_provenance WHERE attempt=?", (intent.attempt_id,)
            ).fetchone()[0]
        )
        response = evidence["response"]
        if (
            evidence["intent_sha256"] != row["digest"]
            or evidence["daemon_id"] != provenance["registration"]["group"]["daemon_id"]
            or evidence.get("host_boot_id") != provenance["registration"]["group"]["host_boot_id"]
            or response.get("command_sha256") != intent.arguments_sha256
            or response.get("command") != intent.command.model_dump(mode="json")
        ):
            self.fail("intent_evidence_mismatch")
        if row["completion"]:
            if json.loads(row["completion"]) != reference:
                self.fail("completion_immutable")
            return {"settlement": row["settlement"]}
        settlement = classify(intent.verb, response)
        db.execute(
            "UPDATE lifecycle_intents SET completion=?,completion_revision=?,settlement=? "
            "WHERE id=?",
            (
                encode(reference),
                self.bump(db),
                settlement,
                intent.operation_id,
            ),
        )
        return {"settlement": settlement}

    def confirm_stop(self, db, row, data):
        progress = json.loads(row["progress"])
        if progress["stop"]:
            return self.view(db, row)
        self.claimed(db, row)
        if not self.current_revision(db, row, data):
            return self.view(db, row)
        observations = json.loads(row["observations"])
        try:
            if progress["blocking_reason"] == "legacy_provenance_unavailable":
                self.fail("legacy_provenance_unavailable")
            evidence = load_evidence(self.root, data["evidence_ref"])
            reservation = json.loads(
                db.execute(
                    "SELECT payload FROM reservation_provenance WHERE request=?", (row["request"],)
                ).fetchone()[0]
            )
            if evidence.get("closure_id") != row["id"] or evidence.get(
                "reservation_sha256"
            ) != digest(reservation):
                self.fail("stop_evidence_binding_mismatch")
            records = self.records(db, row["request"])
            references = [item["completion"] for item in records if item["completion"]]
            if evidence.get("command_evidence") != references:
                self.fail("stop_evidence_incomplete")
            for item in records:
                self.validate_completion(item)
            group = reservation["registration"]["group"]
            worker_remove = [
                item
                for item in records
                if item["intent"]["authority"] == "closure"
                and item["intent"]["container"] == group["container_id"]
                and item["intent"]["verb"] == "remove"
            ]
            worker_absent = [item for item in records if self.absence(item, group["container_id"])]
            candidate_absent = [
                item for item in records if self.absence(item, reservation["candidate_container"])
            ]
            if not worker_remove or not worker_absent or not candidate_absent:
                self.fail("worker_or_container_stop_unconfirmed")
            removal_revision = worker_remove[-1]["completion_revision"]
            if worker_absent[-1]["intent_revision"] <= removal_revision:
                self.fail("worker_inspection_precedes_removal")
            last_worker_completion = max(
                (
                    item["completion_revision"]
                    for item in records
                    if item["intent"]["authority"] == "worker"
                ),
                default=0,
            )
            if candidate_absent[-1]["intent_revision"] <= max(
                last_worker_completion, removal_revision
            ):
                self.fail("candidate_inspection_precedes_settlement")
            progress.update(
                phase="fenced_cleanup_unknown",
                blocking_reason=None,
                stop={
                    "kind": "confirmed",
                    "checker_id": CHECKER,
                    "evidence_refs": [data["evidence_ref"], *references],
                },
            )
            observations.append({"evidence_ref": data["evidence_ref"], "accepted": True})
        except (ValueError, OSError, KeyError, TypeError, self.error) as error:
            reason = (
                str(error) if str(error).replace("_", "").isalnum() else "stop_evidence_unavailable"
            )
            progress["blocking_reason"] = reason[:96]
            observations.append(
                {
                    "evidence_ref": data.get("evidence_ref"),
                    "accepted": False,
                    "reason": progress["blocking_reason"],
                }
            )
        db.execute(
            "UPDATE closure_records SET observations=? WHERE id=?",
            (encode(observations), row["id"]),
        )
        return self.write_progress(db, row, progress)

    def cleanup_payload(self, row):
        progress = json.loads(row["progress"])
        return digest(
            {
                "operation_id": self.operation(row["id"], "cleanup"),
                "execution_epoch": progress["execution_epoch"],
                "procedure_sha256": CLEANUP,
            }
        )

    def cleanup(self, db, row, data):
        progress = json.loads(row["progress"])
        expected = self.cleanup_payload(row)
        if data["cleanup_payload_sha256"] != expected:
            self.fail("cleanup_payload_conflict")
        if progress["cleanup"]:
            return self.view(db, row)
        self.claimed(db, row)
        if not self.current_revision(db, row, data):
            return self.view(db, row)
        if not progress["stop"]:
            self.fail("stop_confirmation_required")
        self.validate_stop_refs(progress)
        env = dict(db.execute("SELECT * FROM environment").fetchone())
        never = progress["acquisition"]["kind"] == "never_acquired"
        if never and (env["value"] != 0 or env["candidate"] is not None):
            self.fail("dirty_target_conflict")
        if not never:
            db.execute(
                "UPDATE environment SET value=0,candidate=NULL,stopped=1,cleanup=1 WHERE id=1"
            )
        progress["cleanup"] = {
            "status": "complete",
            "procedure_sha256": CLEANUP,
            "operation_id": self.operation(row["id"], "cleanup"),
            "payload_sha256": expected,
            "result_sha256": digest({"value": 0, "candidate": None}),
            "no_op_reason": "never_acquired" if never else None,
        }
        return self.write_progress(db, row, progress)

    def validate_stop_refs(self, progress):
        if progress["stop"]["kind"] == "confirmed":
            for reference in progress["stop"]["evidence_refs"]:
                load_evidence(self.root, reference)

    def release(self, db, row, data):
        progress = json.loads(row["progress"])
        if progress["receipt"]:
            return progress["receipt"]
        self.claimed(db, row)
        if not self.current_revision(db, row, data):
            return self.view(db, row)
        if not progress["cleanup"] or not progress["stop"]:
            self.fail("stop_and_cleanup_required")
        self.validate_stop_refs(progress)
        command = json.loads(row["command"])
        revision = self.bump(db)
        receipt = {
            "contract_version": "birbverify.closure.v1",
            "producer_revision": self.config["producer_revision"],
            "adapter_revision": ADAPTER,
            "closure_actor": command["authorization"]["closure_actor"],
            "grant_reference": command["authorization"]["grant_reference"],
            "policy_revision": command["authorization"]["policy_revision"],
            "committed_at": stamp(),
            "closure_id": row["id"],
            "command_sha256": row["command_hash"],
            "request_id": row["request"],
            "idempotency_key": command["request"]["idempotency_key"],
            "request_sha256": command["request_sha256"],
            "target_id": self.binding.target_id,
            "target_incarnation": str(self.binding.target_incarnation),
            "execution_epoch": progress["execution_epoch"],
            "acquisition": progress["acquisition"],
            "fence": progress["fence"],
            "stop": progress["stop"],
            "cleanup": progress["cleanup"],
            "history": json.loads(row["history"]),
            "release": {
                "status": "release_confirmed",
                "operation_id": self.operation(row["id"], "release"),
                "environment_revision": revision,
            },
        }
        receipt["receipt_sha256"] = digest(receipt)
        ClosureReceipt.model_validate(receipt)
        progress.update(phase="release_confirmed", blocking_reason=None, receipt=receipt)
        db.execute(
            "UPDATE closure_records SET progress=? WHERE id=?", (encode(progress), row["id"])
        )
        db.execute("UPDATE closure_owner SET closure=NULL WHERE id=1")
        db.execute(
            "UPDATE environment SET owner=NULL,token=NULL,state='free',stopped=1,"
            "cleanup=1 WHERE id=1"
        )
        return receipt

    def observe(self, db, data):
        observations = []
        for identity in data["request_ids"]:
            request = db.execute("SELECT hash FROM requests WHERE id=?", (identity,)).fetchone()
            epoch = self.epoch_row(db, identity)
            terminal = db.execute(
                "SELECT manifest FROM attempts WHERE request=? AND manifest IS NOT NULL",
                (identity,),
            ).fetchone()
            closure = db.execute(
                "SELECT progress FROM closure_records WHERE request=?", (identity,)
            ).fetchone()
            progress = json.loads(closure[0]) if closure else None
            observations.append(
                {
                    "request_id": identity,
                    "request_sha256": request[0] if request else None,
                    "execution_epoch": epoch["epoch"] if epoch else None,
                    "manifest": json.loads(terminal[0]) if terminal else None,
                    "closure": progress,
                    "terminal": "verification"
                    if terminal
                    else "closed_without_verification"
                    if progress and progress["receipt"]
                    else None,
                }
            )
        env = dict(db.execute("SELECT * FROM environment").fetchone())
        claim = db.execute("SELECT closure FROM closure_owner").fetchone()[0]
        owner = {"kind": "none"}
        if claim:
            row = self.closure(db, claim)
            owner = {
                "kind": "closure",
                "request_id": row["request"],
                "closure_id": claim,
                "execution_epoch": self.epoch_row(db, row["request"])["epoch"],
            }
        elif env["owner"]:
            attempt = db.execute(
                "SELECT request FROM attempts WHERE id=?", (env["owner"],)
            ).fetchone()
            owner = {
                "kind": "attempt",
                "request_id": attempt[0],
                "attempt_id": env["owner"],
                "execution_epoch": self.epoch_row(db, attempt[0])["epoch"],
            }
        result = {
            "contract_version": "birbverify.closure.v1",
            "target_id": self.binding.target_id,
            "target_incarnation": str(self.binding.target_incarnation),
            "record_revision": self.revision(db),
            "requests": observations,
            "environment": {
                "state": env["state"],
                "owner": owner,
                "candidate": env["candidate"],
                "value": env["value"],
            },
        }
        return Snapshot.model_validate(result).model_dump(mode="json")

    def call(self, db, env, method, data):
        if method == "validate_closure_receipt":
            row = self.closure(db, data["closure_id"])
            progress = json.loads(row["progress"])
            receipt = progress["receipt"]
            if receipt is None:
                return {"valid": False, "reason": "release_unconfirmed"}
            try:
                ClosureReceipt.model_validate(receipt)
                self.validate_stop_refs(progress)
                if self.epoch_row(db, row["request"])["sealed_by"] != row["id"]:
                    self.fail("request_seal_missing")
                return {"valid": True, "receipt_sha256": receipt["receipt_sha256"]}
            except (OSError, ValueError, KeyError, self.error):
                return {"valid": False, "reason": "closure_evidence_unavailable"}
        if method == "capabilities":
            return {
                "extensions": ["birbverify.closure.v1"],
                "adapter_revision": ADAPTER,
                **self.binding.model_dump(mode="json"),
            }
        if method == "register_worker":
            return self.register(db, data)
        if method == "lifecycle_intent":
            return self.lifecycle_intent(db, env, data)
        if method == "lifecycle_completion":
            return self.completion(db, data)
        if method == "lifecycle_records":
            self.supervisor(data)
            return self.records(db, data["request_id"])
        if method == "observe_closure_state":
            return self.observe(db, data)
        if method == "begin_closure":
            return self.begin(db, env, data)
        self.supervisor(data)
        row = self.closure(db, data.get("closure_id", data.get("request_id")))
        if method == "read_closure":
            view = self.view(db, row)
            reservation = db.execute(
                "SELECT payload FROM reservation_provenance WHERE request=?", (row["request"],)
            ).fetchone()
            view["reservation"] = json.loads(reservation[0]) if reservation else None
            view["cleanup_payload_sha256"] = self.cleanup_payload(row)
            return view
        if method == "confirm_closure_stop":
            return self.confirm_stop(db, row, data)
        if method == "cleanup_closure":
            return self.cleanup(db, row, data)
        if method == "release_closure":
            return self.release(db, row, data)
        self.fail("unknown_method")
