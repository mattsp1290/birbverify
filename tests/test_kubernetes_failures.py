"""Real API failure proof for independently owned Kubernetes closure."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from test_kubernetes_journeys import CONFIG, command, request_for, wait_for
from test_kubernetes_journeys import installation as installation

from birbverify.kubernetes_service import TargetService, call_target
from birbverify.kubernetes_target import KubernetesTarget

pytestmark = pytest.mark.skipif(not CONFIG, reason="requires disposable kind fixture")


def ready_pod(admin, installed):
    path = f"/api/v1/namespaces/{installed.binding.namespace}/pods/account-auth"

    def probe():
        pod = admin.request("GET", path)
        return (
            pod
            if any(
                item["type"] == "Ready" and item["status"] == "True"
                for item in pod.get("status", {}).get("conditions", [])
            )
            else None
        )

    return wait_for(probe)


def release(target, request, reason):
    def probe():
        result = target.close(request, reason)
        assert result["state"] != "quarantined", result
        return result if result["state"] == "released" else None

    return wait_for(probe)


def evidence(case, result):
    output = Path(
        os.environ.get("BIRBVERIFY_KUBE_FAILURE_EVIDENCE", ".proof/kubernetes-failures.json")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    records = json.loads(output.read_text()) if output.exists() else {}
    records[case] = result
    output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")


@pytest.mark.parametrize("reason", ["worker_lost", "cancelled"])
def test_worker_failure_closes_independently(installation, tmp_path, reason):
    installed, clients, admin, _ = installation
    target = KubernetesTarget(tmp_path / "target.db", clients["target"], installed)
    request = request_for(installed, reason)
    with tempfile.TemporaryDirectory(prefix="bv-") as directory:
        socket = Path(directory) / "target.sock"
        with TargetService(socket, target) as service:
            thread = threading.Thread(target=service.serve_forever)
            thread.start()
            script = """
import json, sys, time
from pathlib import Path
from birbverify.kubernetes_service import call_target
request = json.loads(sys.stdin.readline())
for method in ('begin', 'execute'):
    result = call_target(Path(sys.argv[1]), method, request)
    assert result['state'] == 'active', result
print(json.dumps(result), flush=True)
time.sleep(120)
"""
            worker = subprocess.Popen(
                [sys.executable, "-c", script, str(socket)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={"PATH": os.environ["PATH"]},
            )
            try:
                worker.stdin.write(request.model_dump_json() + "\n")
                worker.stdin.flush()
                execution = json.loads(worker.stdout.readline())
                pod = ready_pod(admin, installed)
                with pytest.raises(ValueError, match="retained"):
                    target.begin(request_for(installed, reason + "-early-successor"))
                if reason == "worker_lost":
                    worker.kill()
                    assert worker.wait(timeout=10) == -signal.SIGKILL
                first = call_target(socket, "close", request.model_dump(mode="json"), reason=reason)
                assert first["state"] in {"closing", "released"}, first
                closed = release(target, request, reason)
                assert closed["receipt"]["reason"] == reason
                assert closed["receipt"]["pod_uid"] == pod["metadata"]["uid"]
                containers = json.loads(
                    command(["docker", "exec", installed.node_name, "crictl", "ps", "-o", "json"])
                )
                assert not [
                    c
                    for c in containers.get("containers", [])
                    if c.get("labels", {}).get("io.kubernetes.pod.uid") == pod["metadata"]["uid"]
                ]
                successor = request_for(installed, reason + "-successor")
                assert target.begin(successor)["state"] == "active"
                assert release(target, successor, "cancelled")["state"] == "released"
                evidence(
                    reason,
                    {
                        "execution": execution,
                        "closure": closed,
                        "worker_returncode": worker.poll(),
                        "successor_admitted": True,
                        "runtime_running_containers_after_close": 0,
                    },
                )
            finally:
                if worker.poll() is None:
                    worker.kill()
                worker.communicate(timeout=10)
                service.shutdown()
                thread.join(timeout=10)


def test_close_waits_for_real_api_response(installation, tmp_path):
    installed, clients, admin, _ = installation
    accepted = threading.Event()
    deliver = threading.Event()

    class HeldResponse:
        def request(self, method, path, body=None):
            response = clients["target"].request(method, path, body)
            if method == "POST" and path.endswith("/pods"):
                accepted.set()
                assert deliver.wait(90), "real POST response was not released"
            return response

    target = KubernetesTarget(tmp_path / "target.db", HeldResponse(), installed)
    request = request_for(installed, "held-response")
    target.begin(request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        execution = pool.submit(target.execute, request)
        try:
            assert accepted.wait(30)
            ready_pod(admin, installed)
            entered = threading.Event()

            def close():
                entered.set()
                return target.close(request, "cancelled")

            closing = pool.submit(close)
            assert entered.wait(10)
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.5)
        finally:
            deliver.set()
        assert execution.result(timeout=30)["state"] == "active"
        assert closing.result(timeout=30)["state"] in {"closing", "released"}
    closed = release(target, request, "cancelled")
    evidence("held_response", {"closure_blocked_until_response": True, "closure": closed})


def test_lost_real_api_response_retains_quarantine_after_restart(installation, tmp_path):
    installed, clients, admin, _ = installation

    class LostResponse:
        def request(self, method, path, body=None):
            response = clients["target"].request(method, path, body)
            if method == "POST" and path.endswith("/pods"):
                raise ConnectionError("fixture discarded accepted POST response")
            return response

    database = tmp_path / "target.db"
    target = KubernetesTarget(database, LostResponse(), installed)
    request = request_for(installed, "lost-response")
    target.begin(request)
    executed = target.execute(request)
    assert executed["state"] == "quarantined"
    pod = ready_pod(admin, installed)
    restarted = KubernetesTarget(database, clients["target"], installed)
    closed = restarted.close(request, "worker_lost")
    assert closed["state"] == "quarantined"
    assert closed["receipt"] is None
    assert closed["operations"]["create-pod"]["state"] == "pending"
    assert restarted.inspect(request)["state"] == "quarantined"
    with pytest.raises(ValueError, match="retained"):
        restarted.begin(request_for(installed, "lost-response-successor"))
    evidence(
        "lost_response",
        {
            "execution": executed,
            "after_restart": closed,
            "accepted_pod_uid": pod["metadata"]["uid"],
            "successor_denied": True,
        },
    )
