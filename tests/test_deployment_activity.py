import base64
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from birbverify.contract import digest
from birbverify.deployment_activity import AccountActivity, account_activity_state, suite_sha256
from birbverify.deployment_activity_contract import ActivityInstallation, Invocation
from birbverify.deployment_activity_runtime import PodTarget
from birbverify.deployment_journal import Journal

ROLES = ("api", "ui", "openfga", "busybox", "postgres")
LAYOUTS = {
    "api": ({"authz-state-init": "busybox", "authz-bootstrap": "api"}, {"api": "api"}),
    "ui": ({}, {"ui": "ui"}),
    "openfga": ({"migrate-database": "openfga"}, {"openfga": "openfga"}),
    "application-postgres": ({"volume-permissions": "busybox"}, {"postgresql": "postgres"}),
    "openfga-postgres": ({"volume-permissions": "busybox"}, {"postgresql": "postgres"}),
}


def installation():
    revision = "c" * 40
    sha = "a" * 64
    runtime_image = "sha256:" + sha
    pins = [
        dict(
            name=w,
            workload=w,
            uid=w + "-uid",
            controller_uid=w + "-parent",
            node_name="node",
            node_uid="node-uid",
        )
        for w in LAYOUTS
    ]
    return ActivityInstallation.model_validate(
        dict(
            schema_version="birbverify.deployment.account-auth.installation.v1",
            request=dict(
                schema_version="birbverify.deployment.account-auth.request.v1",
                request_id="request-a",
                workflow_id="workflow",
                repository="birbparty/birbparty",
                candidate_revision=revision,
                authored_revision=revision,
                beans_issue="fixture-1",
                producer_revision=revision,
                policy_revision=revision,
                plan_sha256=sha,
                installation_sha256=sha,
                target=dict(
                    target_id="target",
                    cluster_uid="cluster",
                    namespace_uid="namespace-uid",
                    namespace="test",
                ),
                artifacts=dict(
                    data_chart_sha256=sha,
                    application_chart_sha256=sha,
                    openfga_chart_sha256=sha,
                    render_sha256=sha,
                ),
                images={
                    r: dict(
                        reference=r + "@" + runtime_image,
                        platform_manifest=runtime_image,
                        config_digest=runtime_image,
                    )
                    for r in ROLES
                },
                deadline=datetime.now(UTC) + timedelta(hours=1),
            ),
            profile=dict(
                verifier_identity="worker",
                verifier_revision=revision,
                reviewer_identity="owner",
                suite_sha256=suite_sha256(),
                worker_cert_sha256=sha,
                temporal_server_ca_sha256=sha,
                temporal_namespace="private",
                task_queue="verify",
            ),
            pods=pins,
            api_port=3000,
            webhook_name="fixture.verify",
        )
    )


class Cluster:
    def __init__(self, installed):
        self.pods = []
        for pin in installed.pods:
            spec = {"nodeName": pin.node_name}
            status = {"phase": "Running"}
            for is_init, names in zip((True, False), LAYOUTS[pin.workload], strict=True):
                spec_key, status_key = (
                    ("initContainers", "initContainerStatuses")
                    if is_init
                    else ("containers", "containerStatuses")
                )
                spec[spec_key] = []
                status[status_key] = []
                for name, role in names.items():
                    image = installed.request.images[role]
                    spec[spec_key].append(dict(name=name, image=image.reference))
                    status[status_key].append(
                        dict(
                            name=name,
                            imageID=image.reference,
                            containerID="containerd://" + "9" * 64,
                            state={"terminated": {"exitCode": 0}} if is_init else {"running": {}},
                            ready=not is_init,
                        )
                    )
            if pin.workload == "api":
                spec["containers"][0]["ports"] = [
                    dict(name="http", protocol="TCP", containerPort=3000)
                ]
            self.pods.append(
                dict(
                    metadata=dict(
                        name=pin.name,
                        uid=pin.uid,
                        namespace="test",
                        ownerReferences=[
                            dict(
                                uid=pin.controller_uid,
                                controller=True,
                                apiVersion="apps/v1",
                                kind="StatefulSet"
                                if pin.workload.endswith("postgres")
                                else "ReplicaSet",
                            )
                        ],
                    ),
                    spec=spec,
                    status=status,
                )
            )

    def request(self, method, path):
        assert method == "GET"
        if path.endswith("/pods"):
            return {"metadata": {}, "items": self.pods}
        uid = {
            "/api/v1/namespaces/kube-system": "cluster",
            "/api/v1/namespaces/test": "namespace-uid",
            "/api/v1/nodes/node": "node-uid",
        }[path]
        return {"metadata": {"uid": uid}}


class Target(PodTarget):
    def __init__(self, installed):
        super().__init__(Cluster(installed), installed)
        self.created = []
        self.token = "bp_a1_" + "a" * 43

    @contextmanager
    def connect(self):
        yield self

    def request(self, method, path, body=None, authorization=None):
        if (method, path) == ("POST", "/users"):
            self.created.append(body)
            return 201, {"username": body["username"]}
        account = self.created[0]
        if (method, path) == ("POST", "/auth/native/login"):
            expected = f"{account['username']}:{account['password']}".encode()
            if base64.b64decode(authorization.removeprefix("Basic ")) != expected:
                return 401, {"error": {"code": "invalid_credentials"}}
            return 200, {"accessToken": self.token}
        assert (method, path) == ("GET", "/users/me")
        if authorization == "Bearer " + self.token:
            return 200, {"username": account["username"], "impersonation": None}
        assert authorization is None
        return 401, {"error": {"code": "invalid_session"}}


@pytest.fixture
def active(tmp_path):
    installed = installation()
    journal = Journal(
        tmp_path / "journal.sqlite",
        installed.request.installation_sha256,
        installed.webhook_name,
        installed.request.target.namespace,
    )
    journal.bind_audit_source(installed.request.target.cluster_uid, "a" * 64)
    sid = digest(installed.request)
    epoch = journal.begin(installed.request.request_id, sid)["epoch"]
    invocation = Invocation(
        request_id=installed.request.request_id, request_sha256=sid, epoch=epoch
    )
    with journal._transaction() as db:
        for pod in installed.pods:
            db.execute("INSERT INTO ownership_slots VALUES(?, ?)", (pod.workload, pod.uid))
            data = {
                "uid": pod.uid,
                "epoch": epoch,
                "state": "settled",
                "request": {
                    "operation": "CREATE",
                    "namespace": "test",
                    "name": pod.name,
                    "kind": {"kind": "Pod"},
                },
                "evidence": {"object_uid": pod.uid},
            }
            db.execute("INSERT INTO intents VALUES(?, ?)", (pod.uid, json.dumps(data)))
    return AccountActivity(installed, journal, Target(installed)), invocation


def test_success_is_immutable_and_sanitized_after_reply_loss(active):
    service, invocation = active
    result = service.execute(invocation)
    assert result["outcome"] == "passed"
    assert set(result["assertions"].values()) == {"passed"}
    assert len(result["workloads"]) == 5
    service.journal.seal(invocation.epoch)
    reopened = AccountActivity(service.installation, service.journal, service.target)
    assert reopened.execute(invocation) == result
    assert len(service.target.created) == 1
    values = [*service.target.created[0].values(), service.target.token]
    for value in values:
        assert value.encode() not in service.journal.path.read_bytes()
        assert value not in json.dumps(result)
    with service.journal._transaction() as db:
        assert account_activity_state(db, invocation.epoch) == "passed"


def test_worker_loss_after_registration_retains(active):
    service, invocation = active
    request = service.target.request

    def interrupted(*args, **kwargs):
        request(*args, **kwargs)
        raise SystemExit()

    service.target.request = interrupted
    with pytest.raises(SystemExit):
        service.execute(invocation)
    with pytest.raises(ValueError, match="in_progress_or_unknown"):
        AccountActivity(service.installation, service.journal, service.target).execute(invocation)
    assert len(service.target.created) == 1
    with service.journal._transaction() as db:
        assert account_activity_state(db, invocation.epoch) == "running"


def test_concurrent_retry_and_seal(active):
    service, invocation = active
    entered, finish = Event(), Event()
    request = service.target.request

    def paused(*args, **kwargs):
        entered.set()
        assert finish.wait(5)
        return request(*args, **kwargs)

    service.target.request = paused
    with ThreadPoolExecutor() as pool:
        future = pool.submit(service.execute, invocation)
        assert entered.wait(5)
        try:
            with pytest.raises(ValueError, match="in_progress_or_unknown"):
                service.execute(invocation)
            service.journal.seal(invocation.epoch)
        finally:
            finish.set()
        result = future.result()
    assert result["outcome"] == "unknown"
    assert result["assertions"]["login_success"] == "unknown"
    assert len(service.target.created) == 1


@pytest.mark.parametrize("drift", ["pod", "parent", "image", "missing", "extra"])
def test_incomplete_incarnation_denies_mutation(active, drift):
    service, invocation = active
    pods = service.target.api.pods
    if drift == "pod":
        pods[0]["metadata"]["uid"] = "different"
    elif drift == "parent":
        pods[0]["metadata"]["ownerReferences"][0]["uid"] = "different"
    elif drift == "image":
        pods[0]["status"]["initContainerStatuses"][0]["imageID"] = "sha256:" + "f" * 64
    elif drift == "missing":
        pods.pop()
    else:
        pods.append({"metadata": {"name": "other"}})
    assert service.execute(invocation)["outcome"] == "unknown"
    assert not service.target.created


def test_failed_assertion_is_durable(active):
    service, invocation = active
    request = service.target.request

    def unexpected_identity(method, path, *args, **kwargs):
        if path == "/users/me":
            return 200, {"username": "other", "impersonation": None}
        return request(method, path, *args, **kwargs)

    service.target.request = unexpected_identity
    result = service.execute(invocation)
    assert result["outcome"] == "failed"
    assert result["assertions"]["authenticated_identity"] == "failed"
    assert result["assertions"]["invalid_credentials_rejected"] == "unknown"
    assert service.execute(invocation) == result


def test_mismatched_invocation_and_seal_never_start(active):
    service, invocation = active
    with pytest.raises(ValueError, match="unapproved_request"):
        service.execute(invocation.model_copy(update={"request_sha256": "0" * 64}))
    service.journal.seal(invocation.epoch)
    with pytest.raises(ValueError, match="inactive_request"):
        service.execute(invocation)
    assert not service.target.created


def test_unsettled_owned_pod_blocks_registration(active):
    service, invocation = active
    with service.journal._transaction() as db:
        db.execute("DELETE FROM ownership_slots WHERE slot='api'")
    with pytest.raises(ValueError, match="unsettled_workloads"):
        service.execute(invocation)
    assert not service.target.created


def test_restart_during_assertions_invalidates_pass(active):
    service, invocation = active
    request = service.target.request

    def change_incarnation(*args, **kwargs):
        reply = request(*args, **kwargs)
        service.target.api.pods[0]["status"]["containerStatuses"][0]["containerID"] = (
            "containerd://" + "b" * 64
        )
        return reply

    service.target.request = change_incarnation
    result = service.execute(invocation)
    assert all(v == "passed" for v in result["assertions"].values())
    assert result["outcome"] == "unknown"
    assert service.execute(invocation) == result
    assert len(service.target.created) == 1


def test_exported_schemas_match_runtime():
    from pathlib import Path

    from birbverify.deployment_activity_contract import ActivityRequest, ActivityResult

    root = Path(__file__).resolve().parents[1] / "contracts/deployment/v1"
    for name, model in (
        ("request", ActivityRequest),
        ("result", ActivityResult),
        ("installation", ActivityInstallation),
        ("invocation", Invocation),
    ):
        assert (
            json.loads((root / f"activity.{name}.schema.json").read_text())
            == model.model_json_schema()
        )


def test_readonly_lookup_across_restart_and_ambiguous_reservation(active):
    import sqlite3

    from birbverify.deployment_activity import lookup_account_result

    service, invocation = active

    def lookup(key):
        with sqlite3.connect(service.journal.path.as_uri() + "?mode=ro", uri=True) as db:
            return lookup_account_result(db, key)

    assert lookup(invocation) == {"status": "absent"}
    with pytest.raises(ValueError, match="account_result_identity_mismatch"):
        lookup(invocation.model_copy(update={"epoch": "unrelated"}))
    request = service.target.request

    def while_running(*args, **kwargs):
        assert lookup(invocation) == {"status": "pending"}
        return request(*args, **kwargs)

    service.target.request = while_running
    result = service.execute(invocation)
    service.journal.seal(invocation.epoch)
    assert lookup(invocation) == {"status": "recorded", "result": result}
    assert len(service.target.created) == 1


def test_result_lookup_before_worker_registration(tmp_path):
    from birbverify.deployment_activity import lookup_account_result

    j = Journal(tmp_path / "j", "e" * 64, "fixture.verify", "test")
    key = j.begin("once", "0" * 64)
    with j._transaction() as db:
        invocation = Invocation(**{name: key[name] for name in Invocation.model_fields})
        assert lookup_account_result(db, invocation) == {"status": "absent"}
        assert not db.execute(
            "SELECT 1 FROM sqlite_schema WHERE name='deployment_account_operation'"
        ).fetchone()
