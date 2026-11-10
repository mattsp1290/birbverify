"""Dispatch the packaged worker through mutual TLS before any workload has settled."""

import asyncio
import base64
import json
import os
import shutil
import sqlite3
import ssl
import subprocess
import sys
import uuid
from contextlib import ExitStack, closing
from datetime import timedelta
from pathlib import Path

import pytest
from temporalio import workflow
from temporalio.client import Client, TLSConfig, WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.worker import Worker
from test_deployment_activity import installation

from birbverify.contract import digest
from birbverify.deployment_activity import ACTIVITY
from birbverify.deployment_bootstrap import provision

ROOT = Path(__file__).resolve().parents[1]
PROXY_IMAGE = "haproxy@sha256:1c3568e520453cc8ba98c39501febcf450429c80e6cc27ecad779961d76e597c"
pytestmark = pytest.mark.skipif(
    not os.environ.get("BIRBVERIFY_DISPATCH_EVIDENCE"),
    reason="requires local Docker and Temporal CLI",
)


@workflow.defn(sandboxed=False)
class DispatchWorkflow:
    @workflow.run
    async def run(self, invocation: dict):
        return await workflow.execute_activity(
            ACTIVITY,
            invocation,
            task_queue="assertions",
            schedule_to_close_timeout=timedelta(seconds=30),
            start_to_close_timeout=timedelta(seconds=15),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


def run(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True, timeout=300).strip()


async def connect(endpoint, tls):
    return await Client.connect(endpoint, namespace="default", tls=tls)


async def test_packaged_worker_denies_without_settled_workloads(tmp_path):
    evidence = Path(os.environ["BIRBVERIFY_DISPATCH_EVIDENCE"]).resolve()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    temporal = ROOT / ".proof/bin/temporal"
    image = run("docker", "build", "-q", "-f", ROOT / "fixtures/deployment.Dockerfile", ROOT)
    prefix = "bv-dispatch-" + uuid.uuid4().hex[:12]
    pki = tmp_path / "pki"
    run(sys.executable, ROOT / "fixtures/deployment_audit_pki.py", pki, prefix)
    proxy = tmp_path / "proxy"
    worker = tmp_path / "worker"
    state = tmp_path / "state"
    for d in (proxy, worker, state):
        d.mkdir(mode=0o700)
    ca = (pki / "ca.crt").read_bytes()
    cert = (pki / "apiserver.crt").read_text()
    cert_pin = digest(ssl.PEM_cert_to_DER_cert(cert))
    for name in ("ca.crt", "apiserver.crt", "apiserver.key"):
        shutil.copyfile(pki / name, worker / name)
    (proxy / "ca.crt").write_bytes(ca)
    (proxy / "server.pem").write_bytes(
        (pki / "server.crt").read_bytes() + (pki / "server.key").read_bytes()
    )
    (proxy / "haproxy.cfg").write_text(
        "global\n  maxconn 32\ndefaults\n  mode tcp\n  timeout connect 5s\n"
        "  timeout client 1m\n  timeout server 1m\nlisten temporal\n"
        "  bind :8443 ssl crt /tls/server.pem ca-file /tls/ca.crt verify required alpn h2\n"
        "  server frontend 127.0.0.1:7233\n"
    )
    installed = installation()
    installed = installed.model_copy(
        update={
            "profile": installed.profile.model_copy(
                update={
                    "worker_cert_sha256": cert_pin,
                    "temporal_server_ca_sha256": digest(ca),
                    "temporal_namespace": "default",
                    "task_queue": "assertions",
                }
            ),
        }
    )
    (worker / "installation.json").write_text(installed.model_dump_json())
    (worker / "kubeconfig").write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "current-context": "fixture",
                "contexts": [
                    {"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}
                ],
                "clusters": [
                    {
                        "name": "fixture",
                        "cluster": {
                            "server": "https://127.0.0.1:1",
                            "certificate-authority-data": base64.b64encode(ca).decode(),
                        },
                    }
                ],
                "users": [{"name": "fixture", "user": {}}],
            }
        )
    )
    req = installed.request
    req_sha = digest(req)
    database = state / "journal.sqlite"
    epoch = provision(
        database,
        req.installation_sha256,
        installed.webhook_name,
        req.target.namespace,
        req.target.cluster_uid,
        "1" * 64,
        req.request_id,
        req_sha,
    )
    invocation = {"request_id": req.request_id, "request_sha256": req_sha, "epoch": epoch}
    with ExitStack() as stack:
        run("docker", "network", "create", prefix)
        stack.callback(run, "docker", "network", "rm", prefix)

        def start(*args):
            cid = run(
                "docker",
                "create",
                "-e",
                "USER=fixture",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                *args,
            )
            stack.callback(run, "docker", "rm", "-f", cid)
            run("docker", "start", cid)
            return cid

        backend = start(
            "--network",
            prefix,
            "--name",
            prefix,
            "-p",
            "127.0.0.1::8443",
            "-v",
            f"{temporal}:/bin/temporal:ro",
            "--entrypoint",
            "/bin/temporal",
            image,
            "server",
            "start-dev",
            "--ip",
            "127.0.0.1",
            "--port",
            "7233",
            "--headless",
        )
        start(
            "--network",
            "container:" + backend,
            "-v",
            f"{proxy}:/tls:ro",
            "--entrypoint",
            "haproxy",
            PROXY_IMAGE,
            "-f",
            "/tls/haproxy.cfg",
            "-db",
        )
        port = run("docker", "port", backend, "8443/tcp").split(":")[-1]
        endpoint = "127.0.0.1:" + port
        caller = TLSConfig(
            server_root_ca_cert=ca,
            verification_server_name=prefix,
            client_cert=(pki / "unassigned.crt").read_bytes(),
            client_private_key=(pki / "unassigned.key").read_bytes(),
        )
        for _ in range(80):
            try:
                client = await asyncio.wait_for(connect(endpoint, caller), 2)
                break
            except (RuntimeError, TimeoutError):
                await asyncio.sleep(0.2)
        else:
            pytest.fail("Temporal frontend did not become ready")
        with pytest.raises((RuntimeError, TimeoutError)):
            await asyncio.wait_for(
                connect(
                    endpoint,
                    TLSConfig(
                        server_root_ca_cert=ca,
                        verification_server_name=prefix,
                    ),
                ),
                4,
            )
        start(
            "--network",
            prefix,
            "-v",
            f"{worker}:/worker:ro",
            "-v",
            f"{state}:/state",
            image,
            "birbverify.deployment_activity",
            "--address",
            prefix + ":8443",
            "--installation",
            "/worker/installation.json",
            "--database",
            "/state/journal.sqlite",
            "--epoch",
            epoch,
            "--client-cert",
            "/worker/apiserver.crt",
            "--client-key",
            "/worker/apiserver.key",
            "--server-ca",
            "/worker/ca.crt",
            "--kubeconfig",
            "/worker/kubeconfig",
            "--context",
            "fixture",
        )
        async with Worker(client, task_queue="coordinator", workflows=[DispatchWorkflow]):
            handle = await client.start_workflow(
                DispatchWorkflow.run, invocation, id=req.workflow_id, task_queue="coordinator"
            )
            with pytest.raises(WorkflowFailureError):
                await asyncio.wait_for(handle.result(), 40)
            history = await handle.fetch_history()
        (failed,) = [
            e.activity_task_failed_event_attributes
            for e in history.events
            if e.HasField("activity_task_failed_event_attributes")
        ]
        assert failed.identity == installed.profile.verifier_identity
        assert failed.failure.message == "account_operation_unavailable"
        assert failed.failure.application_failure_info.non_retryable
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as db:
            assert db.execute("SELECT COUNT(*) FROM deployment_account_operation").fetchone() == (
                0,
            )
            assert db.execute("SELECT COUNT(*) FROM ownership_slots").fetchone() == (0,)
    evidence.write_text(
        json.dumps(
            {
                "scope": "Authenticated packaged activity rejection with zero settled workloads",
                "temporal_cli_sha256": digest(temporal.read_bytes()),
                "tls_frontend_image": PROXY_IMAGE,
                "worker_image": image,
                "worker_cert_sha256": cert_pin,
                "worker_identity": failed.identity,
                "workflow_id": req.workflow_id,
                "workflow_run_id": history.run_id,
                "epoch": epoch,
                "request_sha256": req_sha,
                "operation_count": 0,
                "unauthenticated_client_denied": True,
                "result": failed.failure.message,
                "source_revision": run("git", "-C", ROOT, "rev-parse", "HEAD"),
                "source_dirty": bool(run("git", "-C", ROOT, "status", "--porcelain")),
            },
            indent=2,
        )
        + "\n"
    )
