import json
import socket
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from birbverify.kubernetes_service import Command, TargetService, call_target


def payload():
    return {
        "request_id": "00000000-0000-4000-8000-000000000001",
        "candidate_revision": "a" * 40,
        "producer_revision": "b" * 40,
        "policy_revision": "c" * 40,
        "plan_sha256": "d" * 64,
        "target": {
            "target_id": "fixture",
            "cluster_uid": "cluster",
            "namespace": "fixture",
            "namespace_uid": "namespace",
        },
        "image": "fixture@sha256:" + "e" * 64,
        "deadline": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    }


class Target:
    def __init__(self):
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        return {"state": "running", "receipt": {"request_id": request.request_id}}

    def close(self, request, reason):
        return {"state": "quarantined", "reason": reason}


@pytest.fixture
def service():
    with TemporaryDirectory(dir="/tmp", prefix="bv-") as directory:
        path = Path(directory) / "target.sock"
        target = Target()
        with TargetService(path, target) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                yield path, target
            finally:
                server.shutdown()
                thread.join()


def test_transport_returns_exact_target_receipt_and_private_socket(service):
    path, target = service
    request = payload()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert call_target(path, "execute", request) == {
        "state": "running",
        "receipt": {"request_id": request["request_id"]},
    }
    assert len(target.calls) == 1
    assert call_target(path, "close", request, reason="worker_lost") == {
        "state": "quarantined",
        "reason": "worker_lost",
    }


def test_invalid_envelope_never_dispatches(service):
    path, target = service
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(str(path))
        connection.sendall(b'{"method":"execute","schema_version":"wrong"}\n')
        response = json.loads(connection.makefile("rb").readline())
    assert response == {"ok": False, "error": "ValidationError"}
    assert target.calls == []


def test_rejects_public_directory(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        TargetService(tmp_path / "target.sock", Target())


@pytest.mark.parametrize("method,reason", [("execute", "completed"), ("close", None)])
def test_reason_only_exists_for_close(method, reason):
    with pytest.raises(ValueError):
        Command.model_validate(
            {
                "schema_version": "birbverify.kubernetes.transport.v1",
                "method": method,
                "request": payload(),
                "reason": reason,
            }
        )


async def test_activity_preserves_receipt_and_attempts_closure_on_cancel(monkeypatch):
    import asyncio

    from birbverify.kubernetes_worker import KubernetesActivities

    monkeypatch.setattr("birbverify.kubernetes_worker.activity.heartbeat", lambda: None)
    activities = KubernetesActivities(Path("/unused"))
    submitted = asyncio.Event()
    calls = []

    async def call(method, request, **kwargs):
        calls.append((method, kwargs))
        if method == "execute":
            submitted.set()
            await asyncio.Event().wait()
        return {"state": "quarantined"}

    monkeypatch.setattr(activities, "_call", call)
    task = asyncio.create_task(activities.execute(payload()))
    await submitted.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == [
        ("begin", {}),
        ("execute", {}),
        ("close", {"reason": "cancelled"}),
    ]


async def test_activity_does_not_upgrade_target_result(monkeypatch):
    from birbverify.kubernetes_worker import KubernetesActivities

    monkeypatch.setattr("birbverify.kubernetes_worker.activity.heartbeat", lambda: None)
    activities = KubernetesActivities(Path("/unused"))
    result = {"state": "quarantined", "receipt": None}

    async def call(method, request, **kwargs):
        return result

    monkeypatch.setattr(activities, "_call", call)
    assert await activities.execute(payload()) is result
    assert await activities.close({"request": payload(), "reason": "worker_lost"}) is result
