"""Run one producer-owned account/auth operation against an admitted deployment."""

import argparse
import asyncio
import base64
import json
import os
import re
import secrets
import sqlite3
import ssl
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from temporalio import activity
from temporalio.client import Client, TLSConfig
from temporalio.exceptions import ApplicationError
from temporalio.worker import Worker

from birbverify.contract import digest
from birbverify.deployment_activity_contract import (
    ActivityInstallation,
    ActivityResult,
    Assertions,
    Invocation,
)
from birbverify.deployment_activity_runtime import PodTarget
from birbverify.deployment_journal import Journal
from birbverify.kubernetes_api import KubernetesAPI

ACTIVITY = "birbverify_deployment_account_auth_v1"


def suite_sha256():
    here = Path(__file__).parent
    return digest(
        {
            name: digest((here / name).read_bytes())
            for name in (
                "deployment_activity.py",
                "deployment_activity_contract.py",
                "deployment_activity_runtime.py",
                "deployment_http.py",
            )
        }
    )


def _account_row(db: sqlite3.Connection):
    if not db.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='deployment_account_operation'"
    ).fetchone():
        return None
    return db.execute(
        "SELECT epoch, operation_id, result FROM deployment_account_operation WHERE slot=1"
    ).fetchone()


def account_activity_state(db: sqlite3.Connection, epoch: str) -> str:
    """Read under the same journal transaction that decides closure."""
    row = _account_row(db)
    if row is None:
        return "absent"
    if row[0] != epoch or row[2] is None:
        return "running"
    return ActivityResult.model_validate_json(row[2]).outcome


def lookup_account_result(db: sqlite3.Connection, invocation: Invocation) -> dict:
    """Look up the exact epoch's operation without reserving or executing it."""
    record = db.execute("SELECT data FROM epoch").fetchone()
    epoch = json.loads(record[0]) if record else {}
    if any(epoch.get(key) != value for key, value in invocation.model_dump().items()):
        raise ValueError("account_result_identity_mismatch")
    row = _account_row(db)
    if row is None:
        return {"status": "absent"}
    if row[0] != invocation.epoch:
        raise ValueError("account_result_identity_mismatch")
    if row[2] is None:
        return {"status": "pending"}
    result = ActivityResult.model_validate_json(row[2])
    if result.invocation != invocation or result.operation_id != row[1]:
        raise ValueError("account_result_identity_mismatch")
    return {"status": "recorded", "result": result.model_dump(mode="json")}


class AssertionFailed(Exception):
    pass


def _assert_account(request, check_active, outcomes):
    username = "verify-" + secrets.token_hex(8)
    password = secrets.token_urlsafe(30)

    def call(*args, **kwargs):
        check_active()
        status, body = request(*args, **kwargs)
        if status >= 500:
            raise ValueError("application_response_unknown")
        return status, body

    def check(name, condition):
        outcomes[name] = "passed" if condition else "failed"
        if not condition:
            raise AssertionFailed()

    def basic(value):
        return "Basic " + base64.b64encode(f"{username}:{value}".encode()).decode()

    status, body = call("POST", "/users", {"username": username, "password": password})
    check("account_create", status == 201 and body == {"username": username})
    status, body = call("POST", "/auth/native/login", authorization=basic(password))
    access = body.get("accessToken") if isinstance(body, dict) else None
    check(
        "login_success",
        status == 200
        and isinstance(access, str)
        and re.fullmatch(r"bp_a1_[A-Za-z0-9_-]{43}", access) is not None,
    )
    status, body = call("GET", "/users/me", authorization="Bearer " + access)
    check(
        "authenticated_identity",
        status == 200 and body == {"username": username, "impersonation": None},
    )
    status, body = call("POST", "/auth/native/login", authorization=basic(password + "x"))
    check(
        "invalid_credentials_rejected",
        status == 401 and body == {"error": {"code": "invalid_credentials"}},
    )
    status, body = call("GET", "/users/me")
    check(
        "unauthenticated_access_rejected",
        status == 401 and body == {"error": {"code": "invalid_session"}},
    )


class AccountActivity:
    def __init__(self, installation: ActivityInstallation, journal: Journal, target: PodTarget):
        self.installation = installation
        self.journal = journal
        self.target = target
        if installation.profile.suite_sha256 != suite_sha256():
            raise ValueError("installed_suite_mismatch")

    def _active(self, db, invocation):
        row = self.journal._epoch(db, invocation.epoch)
        owned_pods = db.execute(
            "SELECT json_extract(data,'$.request.name'), "
            "json_extract(data,'$.evidence.object_uid') "
            "FROM ownership_slots JOIN intents ON uid=review_uid "
            "WHERE json_extract(data,'$.state')='settled' AND json_extract(data,'$.epoch')=? "
            "AND json_extract(data,'$.request.operation')='CREATE' "
            "AND json_extract(data,'$.request.kind.kind')='Pod' "
            "AND json_extract(data,'$.request.namespace')=?",
            (invocation.epoch, self.installation.request.target.namespace),
        ).fetchall()
        if not {(pin.name, pin.uid) for pin in self.installation.pods}.issubset(owned_pods):
            raise ValueError("unsettled_workloads")
        if (
            row["state"] != "active"
            or row["request_id"] != invocation.request_id
            or row["request_sha256"] != invocation.request_sha256
            or datetime.now(UTC) >= self.installation.request.deadline
        ):
            raise ValueError("inactive_request")

    def execute(self, invocation: Invocation, cancelled: Event | None = None):
        request = self.installation.request
        if invocation.request_id != request.request_id or invocation.request_sha256 != digest(
            request
        ):
            raise ValueError("unapproved_request")
        operation_id = digest(
            {
                "invocation": invocation.model_dump(mode="json"),
                "installation": digest(self.installation),
            }
        )
        with self.journal._transaction() as db:
            row = db.execute(
                "SELECT operation_id, result FROM deployment_account_operation WHERE slot=1"
            ).fetchone()
            if row:
                if row[0] != operation_id:
                    raise ValueError("operation_identity_mismatch")
                if row[1] is None:
                    raise ValueError("operation_in_progress_or_unknown")
                return ActivityResult.model_validate_json(row[1]).model_dump(mode="json")
            self._active(db, invocation)
            db.execute(
                "INSERT INTO deployment_account_operation VALUES(1, ?, ?, NULL)",
                (invocation.epoch, operation_id),
            )

        def check_active():
            if cancelled is not None and cancelled.is_set():
                raise ValueError("activity_cancelled")
            with self.journal._transaction() as db:
                self._active(db, invocation)

        started = datetime.now(UTC)
        assertions = Assertions().model_dump()
        workloads = ()
        outcome = "unknown"
        try:
            with self.target.connect() as connection:
                workloads = self.target.observe()
                try:
                    _assert_account(connection.request, check_active, assertions)
                    outcome = "passed"
                except AssertionFailed:
                    outcome = "failed"
                if self.target.observe() != workloads:
                    outcome = "unknown"
        except Exception:
            # A timeout can follow a committed registration. Never replay it.
            outcome = "unknown"
        with self.journal._transaction() as db:
            try:
                self._active(db, invocation)
            except ValueError:
                outcome = "unknown"
            if cancelled is not None and cancelled.is_set():
                outcome = "unknown"
            body = dict(
                schema_version="birbverify.deployment.account-auth.result.v1",
                invocation=invocation.model_dump(mode="json"),
                operation_id=operation_id,
                profile=self.installation.profile.model_dump(mode="json"),
                workloads=[pod.model_dump(mode="json") for pod in workloads],
                started_at=started.isoformat().replace("+00:00", "Z"),
                completed_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                outcome=outcome,
                assertions=assertions,
            )
            result = ActivityResult(**body, result_sha256=digest(body))
            saved = db.execute(
                "UPDATE deployment_account_operation SET result=? "
                "WHERE slot=1 AND operation_id=? AND result IS NULL",
                (result.model_dump_json(), operation_id),
            )
            if saved.rowcount != 1:
                raise ValueError("operation_not_reserved")
        return result.model_dump(mode="json")

    @activity.defn(name=ACTIVITY)
    async def run(self, raw: dict) -> dict:
        try:
            invocation = Invocation.model_validate(raw)
            if activity.info().workflow_id != self.installation.request.workflow_id:
                raise ValueError("unapproved_workflow")
            cancelled = Event()
            work = asyncio.create_task(asyncio.to_thread(self.execute, invocation, cancelled))
            try:
                while not work.done():
                    activity.heartbeat()
                    await asyncio.wait({work}, timeout=1)
                return work.result()
            finally:
                cancelled.set()
                await asyncio.shield(work)
        except Exception:
            # Temporal failures are durable and visible to consumers.
            raise ApplicationError("account_operation_unavailable", non_retryable=True) from None


async def _serve(args):
    installation = ActivityInstallation.model_validate_json(args.installation.read_bytes())
    ca = args.server_ca.read_bytes()
    if digest(ca) != installation.profile.temporal_server_ca_sha256:
        raise ValueError("temporal_server_ca_mismatch")
    cert = args.client_cert.read_bytes()
    if digest(ssl.PEM_cert_to_DER_cert(cert.decode())) != installation.profile.worker_cert_sha256:
        raise ValueError("installed_worker_identity_mismatch")
    if not args.database.is_file():
        raise ValueError("existing_journal_required")
    request = installation.request
    journal = Journal(
        args.database,
        request.installation_sha256,
        installation.webhook_name,
        request.target.namespace,
        expected_epoch=args.epoch,
    )
    target = PodTarget(KubernetesAPI(args.kubeconfig, args.context), installation)
    target.require_verified_transport()
    service = AccountActivity(installation, journal, target)
    client = await Client.connect(
        args.address,
        namespace=installation.profile.temporal_namespace,
        identity=installation.profile.verifier_identity,
        tls=TLSConfig(
            server_root_ca_cert=ca,
            client_cert=cert,
            client_private_key=args.client_key.read_bytes(),
        ),
    )
    await Worker(client, task_queue=installation.profile.task_queue, activities=[service.run]).run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("installation", "database", "client-cert", "client-key", "server-ca", "kubeconfig"):
        parser.add_argument("--" + key, type=Path, required=True)
    for key in ("address", "context", "epoch"):
        parser.add_argument("--" + key, required=True)
    os.umask(0o077)
    asyncio.run(_serve(parser.parse_args()))


if __name__ == "__main__":
    main()
