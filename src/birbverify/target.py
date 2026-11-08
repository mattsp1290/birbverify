"""Transactional fixture effects and reservation lifecycle."""

import json
import os
import socket
import socketserver
import sqlite3
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from birbverify.contract import Manifest, Request, digest
from birbverify.policy import authorize


class TargetError(RuntimeError):
    pass


class Target:
    def __init__(self, path: Path, installation: dict):
        self.path = path
        self.installation = installation
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, key TEXT UNIQUE, hash TEXT, payload TEXT);
                CREATE TABLE IF NOT EXISTS environment (
                    id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT, token TEXT,
                    state TEXT, expires REAL, stopped INTEGER, cleanup INTEGER,
                    candidate TEXT, value INTEGER);
                INSERT OR IGNORE INTO environment VALUES (1,NULL,NULL,'free',0,1,1,NULL,0);
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, request TEXT, payload TEXT, receipt TEXT);
                CREATE TABLE IF NOT EXISTS attempts (
                    id TEXT PRIMARY KEY, request TEXT, state TEXT, manifest TEXT);
                CREATE TABLE IF NOT EXISTS diagnostics (
                    seq INTEGER PRIMARY KEY, at REAL, event TEXT, request TEXT, attempt TEXT);
            """)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level="IMMEDIATE")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def supervisor(self, data):
        if (
            digest(data.get("recovery_key", "").encode())
            != self.installation["recovery_key_sha256"]
        ):
            raise TargetError("supervisor_required")

    def call(self, method: str, data: dict):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN IMMEDIATE")
            env = dict(db.execute("SELECT * FROM environment").fetchone())
            if method in {"reserve", "inspect", "snapshot"} and (
                env["state"] == "active" and time.time() >= env["expires"]
            ):
                env["state"] = "quarantined"
                db.execute("UPDATE environment SET state='quarantined' WHERE id=1")
                db.execute(
                    "UPDATE attempts SET state='infrastructure_uncertain' "
                    "WHERE id=? AND manifest IS NULL",
                    (env["owner"],),
                )
            match method:
                case "admit":
                    request = Request.model_validate(data["request"])
                    authorize(request, self.installation)
                    row = db.execute(
                        "SELECT * FROM requests WHERE key=? OR id=?",
                        (request.idempotency_key, request.request_id),
                    ).fetchone()
                    if row:
                        if row["hash"] != digest(request):
                            raise TargetError("identity_conflict")
                        return json.loads(row["payload"])
                    db.execute(
                        "INSERT INTO requests VALUES (?,?,?,?)",
                        (
                            request.request_id,
                            request.idempotency_key,
                            digest(request),
                            request.model_dump_json(),
                        ),
                    )
                    return request.model_dump(mode="json")
                case "reserve":
                    request_id, attempt_id = data["request_id"], data["attempt_id"]
                    terminal = db.execute(
                        "SELECT manifest FROM attempts WHERE request=? AND manifest IS NOT NULL "
                        "ORDER BY rowid LIMIT 1",
                        (request_id,),
                    ).fetchone()
                    if terminal:
                        return {"result": json.loads(terminal[0])}
                    if env["state"] != "free":
                        db.execute(
                            "INSERT INTO diagnostics(at,event,request,attempt) VALUES (?,?,?,?)",
                            (time.time(), "environment_wait", request_id, attempt_id),
                        )
                        return {"busy": True, "state": env["state"]}
                    row = db.execute(
                        "SELECT payload FROM requests WHERE id=?", (request_id,)
                    ).fetchone()
                    if not row:
                        raise TargetError("request_not_admitted")
                    request = Request.model_validate_json(row[0])
                    if time.time() >= request.resources.deadline.timestamp():
                        raise TargetError("deadline_expired")
                    prior = db.execute(
                        "SELECT * FROM attempts WHERE id=?", (attempt_id,)
                    ).fetchone()
                    if prior:
                        raise TargetError("attempt_already_stopped")
                    count = db.execute(
                        "SELECT count(*) FROM attempts WHERE request=?", (request_id,)
                    ).fetchone()[0]
                    if count >= request.resources.max_attempts:
                        raise TargetError("attempt_budget_exhausted")
                    token = uuid.uuid4().hex
                    db.execute(
                        "UPDATE environment SET owner=?,token=?,state='active', "
                        "expires=?,stopped=0,cleanup=0 WHERE id=1",
                        (attempt_id, token, request.resources.deadline.timestamp()),
                    )
                    db.execute(
                        "INSERT INTO attempts VALUES (?,?,?,NULL)",
                        (attempt_id, request_id, "running"),
                    )
                    predecessor = db.execute(
                        "SELECT id FROM attempts WHERE request=? AND id!=? "
                        "ORDER BY rowid DESC LIMIT 1",
                        (request_id, attempt_id),
                    ).fetchone()
                    return {
                        "token": token,
                        "attempt_number": count + 1,
                        "prior_attempt_id": predecessor[0] if predecessor else None,
                    }
                case "receipt":
                    row = db.execute(
                        "SELECT * FROM operations WHERE id=?", (data["operation_id"],)
                    ).fetchone()
                    if row and (
                        row["request"] != data["request_id"]
                        or row["payload"] != data["payload_sha256"]
                    ):
                        raise TargetError("operation_identity_conflict")
                    return json.loads(row["receipt"]) if row else None
                case "assert_active":
                    self.fence(env, data)
                    return {"active": True}
                case "apply":
                    self.fence(env, data)
                    attempt = db.execute(
                        "SELECT request FROM attempts WHERE id=?", (data["attempt_id"],)
                    ).fetchone()
                    request = Request.model_validate_json(
                        db.execute(
                            "SELECT payload FROM requests WHERE id=?", (attempt[0],)
                        ).fetchone()[0]
                    )
                    expected = digest(
                        {"request": digest(request), "candidate": request.candidate.commit}
                    )
                    if (
                        data["request_id"] != request.request_id
                        or data["payload_sha256"] != expected
                        or data["candidate"] != request.candidate.commit
                        or data["operation_id"] != f"{request.request_id}.apply"
                    ):
                        raise TargetError("operation_identity_conflict")
                    if "fixture.apply" not in request.authority.permitted_operations:
                        raise TargetError("operation_not_permitted")
                    existing = db.execute(
                        "SELECT receipt FROM operations WHERE id=?", (data["operation_id"],)
                    ).fetchone()
                    if existing:
                        return json.loads(existing[0])
                    receipt = {
                        "operation_id": data["operation_id"],
                        "candidate": data["candidate"],
                        "value": env["value"] + 1,
                    }
                    db.execute(
                        "UPDATE environment SET candidate=?,value=? WHERE id=1",
                        (data["candidate"], receipt["value"]),
                    )
                    db.execute(
                        "INSERT INTO operations VALUES (?,?,?,?)",
                        (
                            data["operation_id"],
                            data["request_id"],
                            data["payload_sha256"],
                            json.dumps(receipt),
                        ),
                    )
                    return receipt
                case "revoke" | "uncertain" | "cancel":
                    self.owner(env, data)
                    state = (
                        "quarantined"
                        if method == "uncertain" or env["state"] == "quarantined"
                        else "revoked"
                    )
                    db.execute("UPDATE environment SET state=? WHERE id=1", (state,))
                    if method == "uncertain":
                        db.execute("UPDATE environment SET stopped=0,cleanup=0 WHERE id=1")
                    phase = "cancel_requested" if method == "cancel" else "infrastructure_uncertain"
                    db.execute(
                        "UPDATE attempts SET state=? WHERE id=? AND manifest IS NULL",
                        (phase, env["owner"]),
                    )
                    return {"state": state}
                case "recover":
                    self.owner(env, data)
                    self.supervisor(data)
                    if env["state"] != "quarantined":
                        raise TargetError("not_quarantined")
                    db.execute("UPDATE environment SET stopped=1,state='revoked' WHERE id=1")
                    return {"termination": "supervisor_confirmed"}
                case "stop":
                    self.owner(env, data)
                    if env["state"] == "quarantined" or time.time() >= env["expires"]:
                        raise TargetError("supervisor_required")
                    db.execute("UPDATE environment SET stopped=1,state='revoked' WHERE id=1")
                    return {"termination": "confirmed"}
                case "cleanup":
                    self.owner(env, data)
                    if not env["stopped"]:
                        raise TargetError("termination_unknown")
                    db.execute("UPDATE environment SET cleanup=1,value=0,candidate=NULL WHERE id=1")
                    return {"cleanup": "complete"}
                case "release":
                    self.owner(env, data)
                    if not env["stopped"] or not env["cleanup"]:
                        raise TargetError("stop_and_cleanup_required")
                    self.supervisor(data)
                    terminal = db.execute(
                        "SELECT manifest FROM attempts WHERE id=?", (env["owner"],)
                    ).fetchone()
                    if not terminal or terminal[0] is None:
                        raise TargetError("terminal_manifest_required")
                    db.execute(
                        "UPDATE environment SET owner=NULL,token=NULL,state='free' WHERE id=1"
                    )
                    return {"released": True}
                case "finish":
                    row = db.execute(
                        "SELECT manifest FROM attempts WHERE id=?", (data["attempt_id"],)
                    ).fetchone()
                    if not row:
                        raise TargetError("attempt_unknown")
                    manifest = Manifest.model_validate(data["manifest"])
                    attempt = db.execute(
                        "SELECT request FROM attempts WHERE id=?", (data["attempt_id"],)
                    ).fetchone()
                    request = Request.model_validate_json(
                        db.execute(
                            "SELECT payload FROM requests WHERE id=?", (attempt[0],)
                        ).fetchone()[0]
                    )
                    if (
                        manifest.attempt_id != data["attempt_id"]
                        or manifest.request_id != request.request_id
                        or manifest.request_sha256 != digest(request)
                        or manifest.candidate != request.candidate
                        or manifest.plan_sha256 != request.plan_sha256
                        or manifest.policy_revision != request.authority.policy_revision
                        or manifest.environment != request.authority.environment
                        or manifest.correlation_id != request.correlation_id
                        or manifest.telemetry_correlation != request.evidence.telemetry_correlation
                    ):
                        raise TargetError("manifest_identity_conflict")
                    encoded = manifest.model_dump_json()
                    if row[0] is not None:
                        if Manifest.model_validate_json(row[0]) != manifest:
                            raise TargetError("immutable_manifest")
                        return json.loads(row[0])
                    self.owner(env, data)
                    released = env["state"] != "quarantined" and env["stopped"] and env["cleanup"]
                    expected = (
                        ("complete", "confirmed", "released")
                        if released
                        else ("unknown", "unknown", "quarantined")
                    )
                    if (
                        manifest.cleanup,
                        manifest.termination,
                        manifest.environment_release,
                    ) != expected:
                        raise TargetError("manifest_state_conflict")
                    if not released and manifest.outcome not in {"inconclusive", "failed"}:
                        raise TargetError("manifest_state_conflict")
                    if released:
                        db.execute(
                            "UPDATE environment SET owner=NULL,token=NULL,state='free' WHERE id=1"
                        )
                    else:
                        db.execute("UPDATE environment SET state='quarantined' WHERE id=1")
                    db.execute(
                        "UPDATE attempts SET state='terminal',manifest=? WHERE id=?",
                        (encoded, data["attempt_id"]),
                    )
                    return data["manifest"]
                case "result":
                    row = db.execute(
                        "SELECT manifest FROM attempts WHERE request=? AND manifest IS NOT NULL "
                        "ORDER BY rowid LIMIT 1",
                        (data["request_id"],),
                    ).fetchone()
                    return json.loads(row[0]) if row else None
                case "current_attempt":
                    row = db.execute(
                        "SELECT id FROM attempts WHERE request=? ORDER BY rowid DESC LIMIT 1",
                        (data["request_id"],),
                    ).fetchone()
                    return row[0] if row else None
                case "snapshot":
                    row = db.execute(
                        "SELECT * FROM attempts WHERE id=?", (data["attempt_id"],)
                    ).fetchone()
                    return dict(row) if row else None
                case "inspect":
                    return {
                        "environment": {key: value for key, value in env.items() if key != "token"},
                        "operations": [dict(row) for row in db.execute("SELECT * FROM operations")],
                        "events": [dict(row) for row in db.execute("SELECT * FROM diagnostics")],
                    }
                case _:
                    raise TargetError("unknown_method")

    @staticmethod
    def owner(env, data):
        if env["owner"] != data["attempt_id"] or env["token"] != data["token"]:
            raise TargetError("stale_owner")

    @classmethod
    def fence(cls, env, data):
        cls.owner(env, data)
        if env["state"] != "active" or time.time() >= env["expires"]:
            raise TargetError("fenced")


def rpc(root: Path, method: str, **data):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(root / "target.sock"))
        sock.sendall(json.dumps({"method": method, "data": data}).encode() + b"\n")
        with sock.makefile("rb") as stream:
            response = json.loads(stream.readline(131072))
    if "error" in response:
        raise TargetError(response["error"])
    return response["result"]


def serve(root: Path):
    os.umask(0o077)
    target = Target(root / "target.sqlite", json.loads((root / "installation.json").read_text()))

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                message = json.loads(self.rfile.readline(131072))
                result = target.call(message["method"], message["data"])
                if (
                    target.installation.get("fixture_mode")
                    and message["method"] in {"apply", "finish"}
                    and message["data"].get("lose_reply")
                ):
                    (
                        root
                        / (
                            "lost-operation-reply"
                            if message["method"] == "apply"
                            else "lost-finish-reply"
                        )
                    ).touch()
                    return
                response = {"result": result}
            except (TargetError, ValueError, KeyError, sqlite3.Error, TypeError) as error:
                response = {"error": str(error)[:256]}
            self.wfile.write(json.dumps(response).encode() + b"\n")

    with socketserver.UnixStreamServer(str(root / "target.sock"), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    serve(Path(sys.argv[1]))
