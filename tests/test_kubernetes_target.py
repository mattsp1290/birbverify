import copy
from datetime import UTC, datetime, timedelta

import pytest

from birbverify.contract import digest
from birbverify.kubernetes_contract import (
    KubernetesBinding,
    KubernetesInstallation,
    KubernetesRequest,
)
from birbverify.kubernetes_target import KubernetesTarget


class Missing(Exception):
    status = 404


class FakeAPI:
    def __init__(self):
        self.objects = {
            "/apis/admissionregistration.k8s.io": {"versions": [{"version": "v1"}]},
            "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations": {"items": []},
            "/api/v1/namespaces/kube-system": {"metadata": {"uid": "cluster"}},
            "/api/v1/namespaces/app": {"metadata": {"uid": "namespace"}},
            "/api/v1/nodes/node": {"metadata": {"uid": "node-uid"}},
            "/api/v1/namespaces/app/configmaps/revision": {
                "metadata": {"name": "revision", "uid": "cm", "resourceVersion": "1"},
                "data": {"old": "value"},
            },
        }
        self.calls = []
        self.fail = None

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if self.fail == method:
            raise TimeoutError("response lost")
        if method == "GET":
            if path not in self.objects:
                raise Missing()
            return copy.deepcopy(self.objects[path])
        if method == "POST":
            path += "/" + body["metadata"]["name"]
            body = copy.deepcopy(body)
            body["metadata"].update(uid="pod", resourceVersion="1")
        elif method == "DELETE":
            self.objects[path]["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
            return copy.deepcopy(self.objects[path])
        elif method == "PUT":
            if (
                body["metadata"]["resourceVersion"]
                != self.objects[path]["metadata"]["resourceVersion"]
            ):
                raise ValueError("conflict")
        body = copy.deepcopy(body)
        body["metadata"]["resourceVersion"] = str(
            int(body["metadata"].get("resourceVersion", "0")) + 1
        )
        self.objects[path] = body
        if "/pods/" in path and not body["metadata"].get("finalizers"):
            del self.objects[path]
        return copy.deepcopy(body)


@pytest.fixture
def setup(tmp_path):
    api = FakeAPI()
    binding = KubernetesBinding(
        target_id="target", cluster_uid="cluster", namespace="app", namespace_uid="namespace"
    )
    policies = {
        f"/apis/admissionregistration.k8s.io/v1/{resource}/birbverify-app{suffix}": {
            "spec_sha256": digest({"fixture": True}),
            "uid": resource + suffix,
            "generation": 1,
        }
        for resource in ("validatingadmissionpolicies", "validatingadmissionpolicybindings")
        for suffix in ("", "-identity")
    }
    api.objects.update(
        {
            path: {"spec": {"fixture": True}, "metadata": {"uid": pin["uid"], "generation": 1}}
            for path, pin in policies.items()
        }
    )
    installation = KubernetesInstallation(
        producer_revision="b" * 40,
        admission_specs=policies,
        policy_revision="c" * 40,
        binding=binding,
        pod_name="candidate",
        configmap_name="revision",
        node_name="node",
        node_uid="node-uid",
        pod_template={"spec": {"containers": [{"name": "app", "image": "old"}]}},
    )
    request = KubernetesRequest(
        request_id="r1",
        candidate_revision="a" * 40,
        producer_revision="b" * 40,
        policy_revision="c" * 40,
        plan_sha256=digest(installation.pod_template),
        target=binding,
        image="example/app@sha256:" + "e" * 64,
        deadline=datetime.now(UTC) + timedelta(hours=1),
    )
    return KubernetesTarget(tmp_path / "journal.db", api, installation), api, request


def test_release_waits_for_terminal_proof_and_restores_baseline(setup):
    target, api, request = setup
    target.begin(request)
    assert target.execute(request)["state"] == "active"
    assert target.close(request, "cancelled")["state"] == "closing"
    pod = api.objects["/api/v1/namespaces/app/pods/candidate"]
    pod["status"] = {
        "phase": "Failed",
        "containerStatuses": [{"name": "app", "state": {"terminated": {"exitCode": 143}}}],
    }
    released = target.close(request, "cancelled")
    assert released["state"] == "released"
    assert api.objects["/api/v1/namespaces/app/configmaps/revision"]["data"] == {"old": "value"}
    assert target.close(request)["receipt"] == released["receipt"]
    assert sum(method == "POST" for method, _, _ in api.calls) == 1
    writes = [(method, path) for method, path, _ in api.calls if method != "GET"]
    assert writes[-2:] == [
        ("PUT", "/api/v1/namespaces/app/pods/candidate"),
        ("PUT", "/api/v1/namespaces/app/configmaps/revision"),
    ]


def test_unknown_survives_restart_and_blocks_successor(setup):
    target, api, request = setup
    target.begin(request)
    api.fail = "POST"
    assert target.execute(request)["state"] == "quarantined"
    api.fail = None
    restarted = KubernetesTarget(target.path, api, target.installation)
    assert restarted.close(request)["state"] == "quarantined"
    with pytest.raises(ValueError, match="retained"):
        restarted.begin(request.model_copy(update={"request_id": "r2"}))
    assert sum(method == "POST" for method, _, _ in api.calls) == 1


def test_stale_namespace_and_conflicting_configmap_quarantine(setup):
    target, api, request = setup
    target.begin(request)
    api.objects["/api/v1/namespaces/app"]["metadata"]["uid"] = "replacement"
    assert target.execute(request)["state"] == "quarantined"
    assert not any(method == "PUT" for method, _, _ in api.calls)


def test_request_replay_and_conflict(setup):
    target, api, request = setup
    target.begin(request)
    target.execute(request)
    target.execute(request)
    assert sum(method == "POST" for method, _, _ in api.calls) == 1
    with pytest.raises(ValueError, match="reused"):
        target.begin(request.model_copy(update={"candidate_revision": "f" * 40}))


def test_resource_version_conflict_never_releases(setup):
    target, api, request = setup
    target.begin(request)
    api.objects["/api/v1/namespaces/app/configmaps/revision"]["metadata"]["resourceVersion"] = "99"
    assert target.execute(request)["state"] == "quarantined"
    assert target.close(request)["receipt"] is None


def test_absence_without_terminal_proof_is_not_release(setup):
    target, api, request = setup
    target.begin(request)
    target.execute(request)
    del api.objects["/api/v1/namespaces/app/pods/candidate"]
    assert target.close(request)["state"] == "quarantined"


def test_pending_intent_after_crash_is_never_replayed(setup):
    target, api, request = setup
    target.begin(request)
    with target._locked() as db:
        row = target._load(db, request)
        row["operations"]["apply-revision"] = {"state": "pending", "body_sha256": "a" * 64}
        target._save(db, row)
    restarted = KubernetesTarget(target.path, api, target.installation)
    assert restarted.execute(request)["state"] == "quarantined"
    assert restarted.close(request)["receipt"] is None
    assert not any(method != "GET" for method, _, _ in api.calls)


def test_terminal_phase_without_terminated_container_retains_target(setup):
    target, api, request = setup
    target.begin(request)
    target.execute(request)
    pod = api.objects["/api/v1/namespaces/app/pods/candidate"]
    pod["status"] = {
        "phase": "Failed",
        "containerStatuses": [{"name": "app", "state": {"running": {}}}],
    }
    assert target.close(request)["state"] == "closing"
    assert pod["metadata"]["finalizers"] == ["birbverify.dev/cleanup"]
    with pytest.raises(ValueError, match="retained"):
        target.begin(request.model_copy(update={"request_id": "r2"}))


def test_close_before_admission_seals_late_worker(setup):
    target, api, request = setup
    assert target.close(request, "worker_lost")["state"] == "sealed_unadmitted"
    assert target.begin(request)["state"] == "sealed_unadmitted"
    assert target.execute(request)["state"] == "sealed_unadmitted"
    assert not api.calls

    successor = request.model_copy(update={"request_id": "r2"})
    assert target.begin(successor)["state"] == "active"
    assert target.close(request)["state"] == "sealed_unadmitted"
    assert target.inspect(successor)["state"] == "active"


def test_installed_producer_is_authoritative(setup):
    target, api, request = setup
    with pytest.raises(ValueError, match="producer"):
        target.begin(request.model_copy(update={"producer_revision": "f" * 40}))
    assert not api.calls


def test_installed_service_selector_survives_candidate_creation(setup):
    target, api, request = setup
    installation = target.installation.model_copy(deep=True)
    installation.pod_template["metadata"] = {"labels": {"app": "account"}}
    target = KubernetesTarget(target.path.parent / "labels.db", api, installation)
    request = request.model_copy(update={"plan_sha256": digest(installation.pod_template)})
    target.begin(request)
    target.execute(request)
    labels = api.objects["/api/v1/namespaces/app/pods/candidate"]["metadata"]["labels"]
    assert labels["app"] == "account"
    assert labels["birbverify.dev/revision"] == request.candidate_revision


def test_removed_admission_policy_blocks_every_effect(setup):
    target, api, request = setup
    target.begin(request)
    del api.objects[next(iter(target.installation.admission_specs))]
    assert target.execute(request)["state"] == "quarantined"
    assert not any(method != "GET" for method, _, _ in api.calls)


@pytest.mark.parametrize("field,value", [("policy_revision", "f" * 40), ("plan_sha256", "f" * 64)])
def test_unapproved_plan_and_policy_rejected_before_effect(setup, field, value):
    target, api, request = setup
    with pytest.raises(ValueError):
        target.begin(request.model_copy(update={field: value}))
    assert not api.calls


def test_mutating_webhook_installation_is_rejected(setup):
    target, api, request = setup
    api.objects["/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"] = {
        "items": [{"metadata": {"name": "injector"}}]
    }
    with pytest.raises(ValueError, match="webhooks"):
        target.begin(request)


def test_quarantine_does_not_return_private_transport_errors(setup):
    target, api, request = setup
    target.begin(request)
    api.fail = "PUT"
    result = target.execute(request)
    assert result["error"] == "TimeoutError"
    assert "response lost" not in str(result)


def test_admitted_image_substitution_quarantines(setup):
    target, api, request = setup
    target.begin(request)
    original = api.request

    def substitute(method, path, body=None):
        result = original(method, path, body)
        if method == "POST":
            result["spec"]["containers"][0]["image"] = "other@sha256:" + "f" * 64
        return result

    api.request = substitute
    assert target.execute(request)["state"] == "quarantined"
    assert target.close(request)["receipt"] is None


@pytest.mark.parametrize("field,value", [("uid", "recreated"), ("generation", 3)])
def test_recreated_or_reverted_admission_policy_is_rejected(setup, field, value):
    target, api, request = setup
    target.begin(request)
    api.objects[next(iter(target.installation.admission_specs))]["metadata"][field] = value
    assert target.execute(request)["state"] == "quarantined"
    assert not any(method != "GET" for method, _, _ in api.calls)


@pytest.mark.parametrize(
    "change",
    [
        {"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}},
        {"ports": [{"containerPort": 8080, "hostPort": 8080}]},
        {"securityContext": {"procMount": "Unmasked"}},
        {"securityContext": {"seccompProfile": {"type": "Unconfined"}}},
    ],
)
def test_privileged_template_rejected_before_api(setup, change):
    target, api, request = setup
    installed = target.installation.model_copy(deep=True)
    installed.pod_template["spec"]["containers"][0].update(change)
    with pytest.raises(ValueError, match="privileges"):
        KubernetesTarget(target.path.parent / "unsafe.db", api, installed)
    assert not api.calls


def test_mutating_admission_policy_is_rejected(setup):
    target, api, request = setup
    api.objects["/apis/admissionregistration.k8s.io/v1/mutatingadmissionpolicies"] = {
        "items": [{"metadata": {"name": "inject"}}]
    }
    with pytest.raises(ValueError, match="mutating admission"):
        target.begin(request)


@pytest.mark.parametrize(
    "change",
    [
        {"securityContext": {"sysctls": [{"name": "kernel.shm_rmid_forced", "value": "1"}]}},
        {"securityContext": {"seccompProfile": {"type": "Unconfined"}}},
        {"securityContext": {"appArmorProfile": {"type": "Unconfined"}}},
    ],
)
def test_pod_level_privileges_rejected(setup, change):
    target, api, request = setup
    installed = target.installation.model_copy(deep=True)
    installed.pod_template["spec"].update(change)
    with pytest.raises(ValueError, match="privileges"):
        KubernetesTarget(target.path.parent / "unsafe.db", api, installed)


def test_legacy_apparmor_annotation_rejected(setup):
    target, api, request = setup
    installed = target.installation.model_copy(deep=True)
    installed.pod_template["metadata"] = {
        "annotations": {"container.apparmor.security.beta.kubernetes.io/app": "unconfined"}
    }
    with pytest.raises(ValueError, match="profile"):
        KubernetesTarget(target.path.parent / "unsafe.db", api, installed)


def test_policy_change_during_cleanup_cannot_release(setup):
    target, api, request = setup
    target.begin(request)
    original = api.request

    def changed(method, path, body=None):
        result = original(method, path, body)
        if method == "PUT":
            api.objects[next(iter(target.installation.admission_specs))]["metadata"]["uid"] = "new"
        return result

    api.request = changed
    closed = target.close(request, "cancelled")
    assert closed["state"] == "quarantined"
    assert closed["receipt"] is None
