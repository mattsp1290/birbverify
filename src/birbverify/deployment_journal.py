"""Private, installation-bound admission intents and API audit settlement.

The caller authorizes the writer and final object before admit(). The audit
receiver binds authenticated delivery before a production admission.
Settlement proves an API effect, not controller quiescence or object termination.
"""

import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from birbverify.contract import digest
from birbverify.deployment_helm import secret_view

_SERVER_METADATA = {"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"}
MAX_INTENTS = 2048
MAX_AUDIT_EVENTS = 4096
_VERBS = {"create": "CREATE", "update": "UPDATE", "patch": "UPDATE", "delete": "DELETE"}


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}", value)


class Journal:
    def __init__(self, path, installation_sha256, webhook_name, namespace, *, expected_epoch=None):
        if not re.fullmatch(r"[0-9a-f]{64}", installation_sha256):
            raise ValueError("invalid installation digest")
        if not _identifier(namespace) or not _identifier(webhook_name):
            raise ValueError("invalid installation identity")
        self.path = Path(path).absolute()
        self.expected_epoch = expected_epoch
        if expected_epoch is None:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif not _identifier(expected_epoch):
            raise ValueError("invalid installed epoch")
        if self.path.is_symlink():
            raise ValueError("journal must not be a symbolic link")
        flags = os.O_RDWR | os.O_NOFOLLOW
        fd = os.open(self.path, flags | (os.O_CREAT if expected_epoch is None else 0), 0o600)
        os.fchmod(fd, 0o600)
        os.close(fd)
        self.webhook_name = webhook_name
        self.namespace = namespace
        identity = _encode([installation_sha256, webhook_name, namespace])
        with self._transaction() as db:
            if expected_epoch is not None:
                tables = {
                    item[0]
                    for item in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")
                }
                required = {
                    "epoch",
                    "installation",
                    "intents",
                    "audit_events",
                    "audit_source",
                    "ownership_slots",
                    "terminal_status",
                    "deployment_account_operation",
                }
                if not required <= tables:
                    raise ValueError("installed journal is incomplete")
                if db.execute("SELECT identity FROM installation").fetchall() != [(identity,)]:
                    raise ValueError("journal belongs to another installation")
                return
            db.execute("CREATE TABLE IF NOT EXISTS installation (identity TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS epoch (data TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS intents (uid TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit_events ("
                "audit_id TEXT NOT NULL, stage TEXT NOT NULL, digest TEXT NOT NULL, "
                "correlated TEXT NOT NULL, PRIMARY KEY (audit_id, stage))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS audit_source (identity TEXT NOT NULL)")
            saved = db.execute("SELECT identity FROM installation").fetchone()
            if saved and saved[0] != identity:
                raise ValueError("journal belongs to another installation")
            if not saved:
                db.execute("INSERT INTO installation VALUES (?)", (identity,))

    def bind_audit_source(self, cluster_uid, client_cert_sha256):
        if not _identifier(cluster_uid) or not re.fullmatch("[a-f0-9]{64}", client_cert_sha256):
            raise ValueError("invalid audit source")
        identity = _encode([cluster_uid, client_cert_sha256])
        with self._transaction() as db:
            saved = db.execute("SELECT identity FROM audit_source").fetchone()
            if saved is None:
                occupied = db.execute("SELECT 1 FROM intents UNION ALL SELECT 1 FROM audit_events")
                if occupied.fetchone():
                    raise ValueError("cannot adopt existing proof journal")
                db.execute(
                    "CREATE TABLE ownership_slots("
                    "slot TEXT PRIMARY KEY, review_uid TEXT UNIQUE NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE terminal_status("
                    "slot TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                    "observation TEXT NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE deployment_account_operation ("
                    "slot INTEGER PRIMARY KEY CHECK(slot=1), epoch TEXT NOT NULL, "
                    "operation_id TEXT NOT NULL, result TEXT)"
                )
                db.execute("INSERT INTO audit_source VALUES (?)", (identity,))
            elif saved[0] != identity:
                raise ValueError("audit source already pinned")

    def require_audit_source(self, cluster_uid, client_cert_sha256):
        with self._transaction() as db:
            self._require_audit_source(db, cluster_uid, client_cert_sha256)

    def _require_audit_source(self, db, cluster_uid, client_cert_sha256):
        saved = db.execute("SELECT identity FROM audit_source").fetchone()
        if saved != (_encode([cluster_uid, client_cert_sha256]),):
            raise ValueError("audit source mismatch")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=30)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            if self.expected_epoch is not None:
                self._epoch(db, self.expected_epoch)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _epoch(self, db, epoch=None):
        saved = db.execute("SELECT data FROM epoch").fetchone()
        if not saved:
            raise ValueError("no epoch has begun")
        row = json.loads(saved[0])
        if epoch is not None and row["epoch"] != epoch:
            raise ValueError("epoch mismatch")
        return row

    def begin(self, request_id, request_sha256):
        if not _identifier(request_id) or not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
            raise ValueError("invalid request identity")
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM epoch").fetchone():
                row = self._epoch(db)
                if (row["request_id"], row["request_sha256"]) != (request_id, request_sha256):
                    raise ValueError("journal already belongs to another request")
                return row
            row = dict(
                epoch=str(uuid.uuid4()),
                request_id=request_id,
                request_sha256=request_sha256,
                state="active",
            )
            db.execute("INSERT INTO epoch VALUES (?)", (_encode(row),))
            return row

    def _validate_admission(self, request):
        if not isinstance(request, dict) or not _identifier(request.get("uid")):
            raise ValueError("invalid admission UID")
        if request.get("dryRun") is not False:
            raise ValueError("only explicit non-dry-run admission is supported")
        if request.get("operation") not in {"CREATE", "UPDATE", "DELETE"}:
            raise ValueError("unsupported operation")
        if request.get("namespace") != self.namespace or not request.get("name"):
            raise ValueError("wrong namespace or unnamed object")
        if request.get("subResource", ""):
            raise ValueError("subresources are outside this proof")
        if not isinstance(request.get("userInfo"), dict) or not request["userInfo"].get("username"):
            raise ValueError("missing authenticated writer")
        resource = request.get("resource", {})
        kind = request.get("kind", {})
        if (
            resource.get("group", "") != ""
            or resource.get("version") != "v1"
            or (resource.get("resource"), kind.get("kind"))
            not in {("configmaps", "ConfigMap"), ("pods", "Pod")}
            or kind.get("group", "") != ""
            or kind.get("version") != "v1"
        ):
            raise ValueError("only core v1 ConfigMap and Pod proof objects are supported")
        obj = request.get("oldObject" if request["operation"] == "DELETE" else "object")
        if not isinstance(obj, dict):
            raise ValueError("missing final object")
        metadata = obj.get("metadata", {})
        if (
            metadata.get("name") != request["name"]
            or metadata.get("namespace") != self.namespace
            or obj.get("apiVersion") != "v1"
            or obj.get("kind") != kind["kind"]
        ):
            raise ValueError("object identity mismatch")
        if request["operation"] in {"UPDATE", "DELETE"} and not metadata.get("uid"):
            raise ValueError("existing object requires UID")
        if request["operation"] == "DELETE":
            preconditions = (request.get("options") or {}).get("preconditions", {})
            if preconditions.get("uid") != metadata["uid"]:
                raise ValueError("delete requires exact UID precondition")

    def _prepare_admission(self, request):
        self._validate_admission(request)
        return request

    def _reserve_intent(self, db, request):
        """The proof journal relies on its caller for authorization."""

    def admit(self, epoch, admission_request):
        encoded = _encode(admission_request)
        if len(encoded.encode()) > 2 * 1024 * 1024:
            raise ValueError("admission request exceeds journal limit")
        request = json.loads(encoded)
        if not isinstance(request, dict):
            return {"uid": "", "allowed": False, "status": {"message": "invalid request"}}
        response = {"uid": request.get("uid", ""), "allowed": False}
        try:
            request = self._prepare_admission(request)
        except (ValueError, TypeError, AttributeError) as error:
            return response | {"status": {"message": str(error)}}
        with self._transaction() as db:
            row = self._epoch(db, epoch)
            if row["state"] != "active":
                return response | {"status": {"message": "epoch sealed"}}
            previous = db.execute(
                "SELECT data FROM intents WHERE uid=?", (request["uid"],)
            ).fetchone()
            if previous:
                intent = json.loads(previous[0])
                if intent["request"] != request or intent["state"] == "quarantined":
                    intent.update(state="quarantined", reason="admission UID reused")
                    self._save_intent(db, intent)
                    return response | {"status": {"message": "admission UID reused"}}
            else:
                if db.execute("SELECT 1 FROM audit_source").fetchone():
                    if db.execute("SELECT COUNT(*) FROM intents").fetchone()[0] >= MAX_INTENTS:
                        return response | {"status": {"message": "intent capacity exhausted"}}
                try:
                    self._reserve_intent(db, request)
                except ValueError as error:
                    return response | {"status": {"message": str(error)}}
                intent = dict(uid=request["uid"], epoch=epoch, request=request, state="pending")
                self._save_intent(db, intent)
            return response | {
                "allowed": True,
                "auditAnnotations": {"intent-" + request["uid"]: epoch},
            }

    def _save_intent(self, db, intent):
        if intent["state"] == "quarantined":
            row = self._epoch(db)
            row["state"] = "quarantined"
            db.execute("UPDATE epoch SET data=?", (_encode(row),))
        db.execute("INSERT OR REPLACE INTO intents VALUES (?, ?)", (intent["uid"], _encode(intent)))

    def _snapshot(self, db, epoch):
        row = self._epoch(db, epoch)
        intents = [
            json.loads(item[0]) for item in db.execute("SELECT data FROM intents ORDER BY uid")
        ]
        return row | {
            "intents": intents,
            **{
                state: [intent["uid"] for intent in intents if intent["state"] == state]
                for state in ("pending", "settled", "quarantined")
            },
        }

    def snapshot(self, epoch):
        with self._transaction() as db:
            return self._snapshot(db, epoch)

    def seal(self, epoch):
        with self._transaction() as db:
            row = self._epoch(db, epoch)
            if row["state"] == "active":
                row["state"] = "sealed"
            db.execute("UPDATE epoch SET data=?", (_encode(row),))
            return self._snapshot(db, epoch)

    def _completion(self, intent, event):
        request = intent["request"]
        if (
            event.get("apiVersion") != "audit.k8s.io/v1"
            or event.get("kind") != "Event"
            or event.get("stage") != "ResponseComplete"
            or event.get("level") != "RequestResponse"
            or not event.get("auditID")
        ):
            raise ValueError("audit completion envelope mismatch")
        if _VERBS.get(event.get("verb")) != request["operation"]:
            raise ValueError("audit verb mismatch")
        user = event.get("impersonatedUser", event.get("user"))
        helm_storage = request["kind"]["kind"] == "Secret"
        if helm_storage:
            if "impersonatedUser" in event or event["verb"] != request["operation"].lower():
                raise ValueError("Helm audit identity or operation mismatch")
            writer_matches = digest(user) == request["principal_sha256"]
        else:
            writer_matches = user == request["userInfo"]
        if not writer_matches or not event.get("user", {}).get("username"):
            raise ValueError("audit writer mismatch")
        ref = event.get("objectRef", {})
        expected = {
            "apiGroup": request["resource"].get("group", ""),
            "apiVersion": request["resource"]["version"],
            "resource": request["resource"]["resource"],
            "subresource": "",
            "namespace": self.namespace,
            "name": request["name"],
        }
        if "name" not in ref and request["operation"] == "CREATE":
            submitted = event.get("requestObject") or {}
            submitted_metadata = submitted.get("metadata", {})
            admitted = request["object"]
            generated_prefix = admitted["metadata"].get("generateName")
            if (
                isinstance(generated_prefix, str)
                and generated_prefix
                and request["name"].startswith(generated_prefix)
                and len(request["name"]) > len(generated_prefix)
                and submitted_metadata.get("generateName") == generated_prefix
                and not submitted_metadata.get("name")
                and submitted_metadata.get("namespace", self.namespace) == self.namespace
                and submitted.get("kind") == admitted["kind"]
                and submitted.get("apiVersion") == admitted["apiVersion"]
            ):
                # Collection POST audit references precede generated-name assignment.
                expected.pop("name")
        if any(ref.get(key, "") != value for key, value in expected.items()):
            raise ValueError("audit resource identity mismatch")
        code = event.get("responseStatus", {}).get("code")
        if type(code) is not int or not 200 <= code < 300:
            raise ValueError("unsuccessful or unknown API outcome")
        response = event.get("responseObject")
        if not isinstance(response, dict):
            raise ValueError("missing API response object")
        if helm_storage:
            response = secret_view(response)
            if (
                request["operation"] == "UPDATE"
                and response["metadata"].get("resourceVersion")
                == request["oldObject"]["metadata"]["resourceVersion"]
            ):
                raise ValueError("Helm storage resource version did not advance")
        obj = request["oldObject" if request["operation"] == "DELETE" else "object"]
        if request["operation"] == "DELETE":
            uid = obj["metadata"]["uid"]
            if ref.get("uid") and ref["uid"] != uid:
                raise ValueError("audit object UID mismatch")
            if response.get("kind") == "Status":
                details = response.get("details", {})
                if (
                    response.get("apiVersion") != "v1"
                    or response.get("status") != "Success"
                    or details.get("uid") != uid
                    or details.get("name") != request["name"]
                    or details.get("kind") != request["resource"]["resource"]
                ):
                    raise ValueError("delete Status identity mismatch")
                return {
                    "object_uid": uid,
                    "audit_id": event["auditID"],
                    "termination_proven": False,
                }
        metadata = response.get("metadata", {})
        if (
            not metadata.get("uid")
            or not metadata.get("resourceVersion")
            or metadata.get("name") != request["name"]
            or metadata.get("namespace") != self.namespace
            or response.get("apiVersion") != obj["apiVersion"]
            or response.get("kind") != obj["kind"]
            or (obj["metadata"].get("uid") and metadata["uid"] != obj["metadata"]["uid"])
        ):
            raise ValueError("response object identity mismatch")
        if ref.get("uid") and ref["uid"] != metadata["uid"]:
            raise ValueError("audit object UID mismatch")
        if request["operation"] != "DELETE":
            # Admission sees API defaults. Only server metadata and status may change afterward.
            for key in set(obj) | set(response):
                if key not in {"metadata", "status"} and obj.get(key) != response.get(key):
                    raise ValueError("persisted object differs from admitted object")
            admitted_metadata = {
                k: v for k, v in obj["metadata"].items() if k not in _SERVER_METADATA
            }
            returned_metadata = {k: v for k, v in metadata.items() if k not in _SERVER_METADATA}
            if admitted_metadata != returned_metadata:
                raise ValueError("persisted metadata differs from admitted object")
        return {
            "object_uid": metadata["uid"],
            "resource_version": metadata["resourceVersion"],
            "audit_id": event["auditID"],
            "termination_proven": False,
        }

    def ingest(self, event):
        """Consume an event from the installation-owned local audit log only."""
        event = json.loads(_encode(event))
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM audit_source").fetchone():
                raise ValueError("bound journals require authenticated delivery")
            epoch = self._ingest(db, event, authenticated=False)
            return self._snapshot(db, epoch) if epoch else None

    def ingest_audit_batch(self, cluster_uid, client_cert_sha256, events):
        """Internal receiver entry point. The receiver authenticates the TLS peer first."""
        with self._transaction() as db:
            self._require_audit_source(db, cluster_uid, client_cert_sha256)
            for event in events:
                self._ingest(db, event, authenticated=True)

    def _ingest(self, db, event, *, authenticated):
        prefix = self.webhook_name + "/intent-"
        annotations = event.get("annotations", {})
        if not isinstance(annotations, dict):
            return None
        correlated = [
            (key[len(prefix) :], value)
            for key, value in annotations.items()
            if key.startswith(prefix)
        ]
        if not correlated:
            return None
        if authenticated and (
            not _identifier(event.get("auditID"))
            or event.get("stage") != "ResponseComplete"
            or len(correlated) != 1
            or any(not _identifier(uid) or not _identifier(epoch) for uid, epoch in correlated)
            or "impersonatedUser" in event
        ):
            row = self._epoch(db)
            row.update(state="quarantined", reason="malformed or ambiguous audit completion")
            db.execute("UPDATE epoch SET data=?", (_encode(row),))
            return row["epoch"]
        row = self._epoch(db)
        event_hash = digest(event)
        audit_id, stage = event.get("auditID"), event.get("stage")
        conflicting_event = False
        if isinstance(audit_id, str) and audit_id and isinstance(stage, str) and stage:
            previous = db.execute(
                "SELECT digest, correlated FROM audit_events WHERE audit_id=? AND stage=?",
                (audit_id, stage),
            ).fetchone()
            if previous:
                if previous[0] == event_hash:
                    return row["epoch"]
                conflicting_event = True
                correlated = list(dict(json.loads(previous[1]) + correlated).items())
            else:
                if authenticated and (
                    db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                    >= MAX_AUDIT_EVENTS
                ):
                    row.update(state="quarantined", reason="audit identity capacity exhausted")
                    db.execute("UPDATE epoch SET data=?", (_encode(row),))
                    return row["epoch"]
                db.execute(
                    "INSERT INTO audit_events VALUES (?, ?, ?, ?)",
                    (audit_id, stage, event_hash, _encode(correlated)),
                )
        for uid, epoch in correlated:
            saved = db.execute("SELECT data FROM intents WHERE uid=?", (uid,)).fetchone()
            if not saved:
                row.update(state="quarantined", reason="audit intent absent from journal")
                db.execute("UPDATE epoch SET data=?", (_encode(row),))
                continue
            intent = json.loads(saved[0])
            if intent["state"] == "quarantined":
                continue
            if intent.get("event_sha256") == event_hash and not conflicting_event:
                continue
            try:
                if conflicting_event:
                    raise ValueError("audit identity reused for a different event")
                if len(correlated) != 1 or epoch != intent["epoch"]:
                    raise ValueError("ambiguous audit intent correlation")
                if intent.get("event_sha256"):
                    raise ValueError("conflicting audit completion replay")
                evidence = self._completion(intent, event)
                intent.update(state="settled", evidence=evidence, event_sha256=event_hash)
            except (ValueError, TypeError, AttributeError, KeyError) as error:
                intent.update(state="quarantined", reason=str(error), event_sha256=event_hash)
            self._save_intent(db, intent)
        return row["epoch"]
