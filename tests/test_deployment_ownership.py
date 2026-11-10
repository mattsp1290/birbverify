import copy
import hashlib
import http.client
import json
import ssl
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Thread

import pytest
from test_deployment_audit import pki  # noqa: F401
from test_deployment_journal import event, request

from birbverify.contract import digest
from birbverify.deployment_http import server_context
from birbverify.deployment_journal import Journal
from birbverify.deployment_ownership import (
    CloseCommand,
    ClosureProgress,
    InstalledRequest,
    Owner,
    OwnershipJournal,
    OwnershipPolicy,
    object_shape_sha256,
)
from birbverify.deployment_ownership_server import OwnershipServer


def slot(name, req, *, parent=None, generated=False):
    obj = req["object"]
    return {
        "slot": name,
        "kind": obj["kind"],
        **({"parent_slot": parent} if parent else {}),
        **(
            {"generate_name": obj["metadata"]["generateName"]}
            if generated
            else {"name": req["name"]}
        ),
        "principal_sha256": digest(req["userInfo"]),
        "object_sha256": object_shape_sha256(obj, generated=generated, owned=bool(parent)),
    }


def install(path, rules, **changes):
    policy = OwnershipPolicy.model_validate(
        {
            "schema_version": "birbverify.deployment.ownership.v1",
            "cluster_uid": "cluster",
            "namespace": "app",
            "namespace_uid": "ns-uid",
            "webhook_name": "proof.test",
            "admission_client_sha256": "a" * 64,
            "audit_client_sha256": "b" * 64,
            "closure_client_sha256": "c" * 64,
            "rules": rules,
        }
        | changes
    )
    journal = Journal(
        path, digest(policy.model_dump(mode="json", exclude_none=True)), "proof.test", "app"
    )
    journal.bind_audit_source(policy.cluster_uid, policy.audit_client_sha256)
    return OwnershipJournal(path, policy)


def close(journal, epoch, reason):
    return journal.close_owned(
        CloseCommand(
            epoch=epoch,
            request_id="r",
            request_sha256="d" * 64,
            reason=reason,
        )
    )


def batch(journal, epoch, req):
    ev = event(epoch, req)
    ev["auditID"] = "audit-" + req["uid"]
    ev["objectRef"].update(
        apiGroup=req["resource"]["group"],
        apiVersion=req["resource"]["version"],
        resource=req["resource"]["resource"],
        name=req["name"],
    )
    ev["responseObject"]["metadata"]["uid"] = "uid-" + req["name"]
    journal.ingest_audit_batch("cluster", journal.policy.audit_client_sha256, [ev])


def test_cancel_then_late_completion_and_restart(tmp_path):
    req = request()
    j = install(tmp_path / "db", [slot("root", req)])
    epoch = j.begin("r", "d" * 64)["epoch"]
    assert j.admit(epoch, req)["allowed"]
    assert j.admit(epoch, req)["allowed"]
    held = close(j, epoch, "cancelled")
    assert held["effects"] == [
        {
            "slot": "root",
            "object_uid": None,
            "state": "pending",
            "obligations": ["api_completion"],
            "terminal_status_sha256": None,
            "audit_id": None,
            "event_sha256": None,
        }
    ]
    assert not j.admit(epoch, request(uid="later"))["allowed"]
    batch(j, epoch, req)
    restarted = OwnershipJournal(j.path, j.policy)
    report = close(restarted, epoch, "worker_lost")
    assert report["effects"] == [
        {
            "slot": "root",
            "object_uid": "uid-config",
            "state": "settled",
            "obligations": ["object_cleanup"],
            "terminal_status_sha256": None,
            "audit_id": "audit-review-1",
            "event_sha256": j.snapshot(epoch)["intents"][0]["event_sha256"],
        }
    ]
    assert report["state"] == "sealed"
    assert report["reason"] == "cancelled"
    assert report["account_activity_state"] == "absent"
    assert report["release_authorized"] is False
    assert close(restarted, epoch, "completed") == report
    with pytest.raises(ValueError, match="another request"):
        restarted.begin("next", "e" * 64)


def test_slot_reserved_at_most_once(tmp_path):
    j = install(tmp_path / "db", [slot("one", request())])
    epoch = j.begin("r", "d" * 64)["epoch"]
    with ThreadPoolExecutor(8) as pool:
        admitted = list(
            pool.map(lambda n: j.admit(epoch, request(uid=f"req-{n}"))["allowed"], range(8))
        )
    assert admitted.count(True) == 1
    assert len(j.snapshot(epoch)["pending"]) == 1


@pytest.mark.parametrize(
    "drift",
    [
        lambda r: r.update(userInfo={"username": "another"}),
        lambda r: r.update(namespace="other"),
        lambda r: r.update(
            requestResource={"group": "other", "version": "v1", "resource": "configmaps"}
        ),
        lambda r: r.update(subResource="status"),
        lambda r: r.update(operation="DELETE"),
        lambda r: r["object"].update(data={"value": "other"}),
        lambda r: r["object"]["metadata"].update(finalizers=["other"]),
    ],
)
def test_unreviewed_writes_denied(tmp_path, drift):
    j = install(tmp_path / "db", [slot("root", request())])
    epoch = j.begin("r", "d" * 64)["epoch"]
    req = request()
    drift(req)
    assert not j.admit(epoch, req)["allowed"]
    assert not j.snapshot(epoch)["intents"]


def test_child_requires_settled_exact_parent_incarnation(tmp_path):
    root = request("root")
    root["name"] = "service"
    root["object"] = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "service", "namespace": "app"},
        "spec": {"selector": {"app": "my-app"}, "ports": [{"port": 80}]},
    }
    root["kind"]["kind"] = "Service"
    root["resource"]["resource"] = "services"
    child = request("child")
    child["kind"] = {"group": "discovery.k8s.io", "version": "v1", "kind": "EndpointSlice"}
    child["resource"] = {"group": "discovery.k8s.io", "version": "v1", "resource": "endpointslices"}
    child["name"] = "service-xyz"
    child["object"] = {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": child["name"],
            "generateName": "service-",
            "namespace": "app",
            "ownerReferences": [
                {
                    "controller": True,
                    "apiVersion": "v1",
                    "kind": "Service",
                    "name": "service",
                    "uid": "uid-service",
                    "blockOwnerDeletion": True,
                }
            ],
        },
        "addressType": "IPv4",
        "ports": [{"port": 8080}],
        "endpoints": [{"addresses": ["192.0.2.1"]}],
    }
    j = install(
        tmp_path / "db",
        [slot("service", root), slot("routes", child, parent="service", generated=True)],
    )
    epoch = j.begin("r", "d" * 64)["epoch"]
    assert j.admit(epoch, root)["allowed"]
    assert not j.admit(epoch, child)["allowed"]
    batch(j, epoch, root)
    for key, value in (("uid", "other"), ("name", "other"), ("kind", "Pod")):
        wrong = copy.deepcopy(child)
        wrong["object"]["metadata"]["ownerReferences"][0][key] = value
        assert not j.admit(epoch, wrong)["allowed"]
    assert j.admit(epoch, child)["allowed"]
    batch(j, epoch, child)
    assert [e["state"] for e in close(j, epoch, "worker_lost")["effects"]] == ["settled", "settled"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(suspend=False),
        lambda s: s["jobTemplate"]["spec"]["template"]["spec"]["containers"][0].update(
            image="api:v1"
        ),
    ],
)
def test_even_reviewed_seed_cannot_schedule_or_use_mutable_images(tmp_path, mutate):
    req = request()
    req["kind"] = {"group": "batch", "version": "v1", "kind": "CronJob"}
    req["resource"] = {"group": "batch", "version": "v1", "resource": "cronjobs"}
    req["object"].update(
        apiVersion="batch/v1",
        kind="CronJob",
        spec={
            "suspend": True,
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{"name": "seed", "image": "api@sha256:" + "0" * 64}]
                        }
                    }
                }
            },
        },
    )
    mutate(req["object"]["spec"])
    j = install(tmp_path / "db", [slot("seed", req)])
    epoch = j.begin("r", "d" * 64)["epoch"]
    assert not j.admit(epoch, req)["allowed"]


def test_https_role_separation_and_seal(tmp_path, pki):  # noqa: F811
    def pin(name):
        der = ssl.PEM_cert_to_DER_cert((pki / (name + ".crt")).read_text())
        return hashlib.sha256(der).hexdigest()

    j = install(
        tmp_path / "db",
        [slot("root", request())],
        admission_client_sha256=pin("apiserver"),
        closure_client_sha256=pin("unassigned"),
    )
    tls = server_context(pki / "ca.crt", pki / "server.crt", pki / "server.key")
    j.begin("r", "d" * 64)
    with OwnershipServer(("localhost", 0), tls, j, "r", "d" * 64) as server:

        def post(peer, path, payload):
            ctx = ssl.create_default_context(cafile=pki / "ca.crt")
            ctx.load_cert_chain(pki / (peer + ".crt"), pki / (peer + ".key"))
            conn = http.client.HTTPSConnection(
                "localhost", server.server_port, context=ctx, timeout=5
            )
            try:
                conn.request(
                    "POST", path, json.dumps(payload), {"Content-Type": "application/json"}
                )
                response = conn.getresponse()
                data = response.read()
                return response.status, json.loads(data) if data else None
            finally:
                conn.close()

        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            admit = {
                "kind": "AdmissionReview",
                "apiVersion": "admission.k8s.io/v1",
                "request": request(),
            }
            command = {
                "epoch": server.epoch,
                "reason": "worker_lost",
                "request_id": "r",
                "request_sha256": "d" * 64,
            }
            bound_request = {"request_id": "r", "request_sha256": "d" * 64}
            assert post("apiserver", "/v1/observe", bound_request)[0] == 403
            assert (
                post("unassigned", "/v1/observe", bound_request | {"request_id": "another"})[0]
                == 400
            )
            owner = post("unassigned", "/v1/observe", bound_request)[1]
            assert owner["epoch"] == server.epoch and owner["state"] == "active"
            invocation = {k: command[k] for k in ("epoch", "request_id", "request_sha256")}
            assert post("apiserver", "/v1/account-result", invocation)[0] == 403
            assert post("unassigned", "/v1/account-result", invocation) == (
                200,
                {"status": "absent"},
            )
            assert (
                post("unassigned", "/v1/account-result", invocation | {"epoch": "other"})[0] == 400
            )
            assert (
                post("unassigned", "/v1/account-result", invocation | {"reason": "read"})[0] == 400
            )
            assert post("unassigned", "/v1/admit", admit)[0] == 403
            assert post("apiserver", "/v1/admit?wrong=1", admit)[0] == 400
            assert post("apiserver", "/v1/close", command)[0] == 403
            assert post("unassigned", "/v1/close", command | {"request_id": "other"})[0] == 400
            assert post("apiserver", "/v1/admit?timeout=10s", admit)[1]["response"]["allowed"]
            result = post("unassigned", "/v1/close", command)[1]
            assert result["release_authorized"] is False and result["state"] == "sealed"
            assert not post("apiserver", "/v1/admit?timeout=10s", admit)[1]["response"]["allowed"]
        finally:
            server.shutdown()
            worker.join()


def test_checked_in_schemas_match_runtime():
    path = Path(__file__).resolve().parents[1] / "contracts/deployment/v1"
    for name, model in (
        ("ownership", OwnershipPolicy),
        ("installed-request", InstalledRequest),
        ("owner", Owner),
        ("closure-command", CloseCommand),
        ("closure-progress", ClosureProgress),
    ):
        assert json.loads((path / f"{name}.schema.json").read_text()) == model.model_json_schema()


def test_pod_terminal_status_retention(tmp_path):
    from birbverify.deployment_ownership_observe import observe_terminal

    req = request()
    req["resource"]["resource"] = "pods"
    req["kind"]["kind"] = "Pod"
    image = "test/helper@sha256:" + "0" * 64
    req["object"] = {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": "config", "namespace": "app"},
        "spec": {
            "containers": [{"name": "app", "image": image}],
            "initContainers": [{"name": "init", "image": image}],
        },
    }
    j = install(
        tmp_path / "db",
        [slot("hook", req)],
        terminal_observer={
            "node_name": "node",
            "node_uid": "node-uid",
            "context": "local",
            "kubeconfig_sha256": "f" * 64,
        },
    )
    epoch = j.begin("r", "d" * 64)["epoch"]
    assert j.admit(epoch, req)["allowed"]
    batch(j, epoch, req)
    before = close(j, epoch, "completed")
    assert before["effects"][0]["obligations"] == ["object_cleanup", "terminal_status"]

    def status(name, cid):
        cid = "containerd://" + cid * 64
        return {
            "name": name,
            "containerID": cid,
            "state": {
                "terminated": {
                    "containerID": cid,
                    "startedAt": "2026-01-01T10:30:00Z",
                    "finishedAt": "2026-01-01T10:32:01Z",
                    "exitCode": 0,
                    "message": "do not publish",
                }
            },
        }

    pod = copy.deepcopy(req["object"])
    pod["spec"]["nodeName"] = "node"
    pod["metadata"].update(uid="uid-config", resourceVersion="9")
    pod["status"] = {
        "phase": "Succeeded",
        "containerStatuses": [status("app", "0")],
        "initContainerStatuses": [status("init", "1")],
    }
    truth = {
        "/api/v1/namespaces/kube-system": {"metadata": {"name": "kube-system", "uid": "cluster"}},
        "/api/v1/namespaces/app": {"metadata": {"name": "app", "uid": "ns-uid"}},
        "/api/v1/nodes/node": {
            "metadata": {"name": "node", "uid": "node-uid"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        },
        "/api/v1/namespaces/app/pods/config": pod,
    }

    class Reader:
        def __init__(self, objects):
            self.objects = objects

        def request(self, method, path):
            assert method == "GET"
            return self.objects[path]

    for key, mutate in [
        ("/api/v1/namespaces/app", lambda o: o["metadata"].update(uid="changed")),
        ("/api/v1/nodes/node", lambda o: o["status"].update(conditions=[])),
        ("/api/v1/namespaces/app/pods/config", lambda o: o["metadata"].update(uid="replaced")),
        ("/api/v1/namespaces/app/pods/config", lambda o: o["status"].update(phase="Running")),
        (
            "/api/v1/namespaces/app/pods/config",
            lambda o: o["status"].update(initContainerStatuses=[]),
        ),
        (
            "/api/v1/namespaces/app/pods/config",
            lambda o: o["status"]["containerStatuses"][0].update(containerID="other"),
        ),
    ]:
        changed = copy.deepcopy(truth)
        mutate(changed[key])
        with pytest.raises(ValueError):
            observe_terminal(j, epoch, "hook", Reader(changed))
        assert close(j, epoch, "completed") == before
    observation = observe_terminal(j, epoch, "hook", Reader(truth))
    restarted = OwnershipJournal(j.path, j.policy)
    after = close(restarted, epoch, "completed")
    assert after["effects"][0]["terminal_status_sha256"] == observation
    assert after["effects"][0]["obligations"] == ["object_cleanup"]
    assert after["release_authorized"] is False
    assert observe_terminal(restarted, epoch, "hook", Reader({})) == observation
    assert "do not publish" not in j.path.read_bytes().decode(errors="replace")
