"""Opt-in real API proof, restricted to the disposable kind fixture."""

import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from birbverify.contract import digest
from birbverify.kubernetes_admission import admission_objects, target_role
from birbverify.kubernetes_api import ApiError, KubernetesAPI

CONFIG = os.environ.get("BIRBVERIFY_KUBE_FIXTURE")
pytestmark = pytest.mark.skipif(not CONFIG, reason="requires disposable kind fixture")
ROOT = Path(__file__).resolve().parents[1]
IMAGE = "python@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285"


def command(args, *, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def wait_for(probe, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.5)
    raise AssertionError("fixture condition timed out")


@pytest.fixture
def installation(tmp_path):
    context = os.environ["BIRBVERIFY_KUBE_CONTEXT"]
    assert context.startswith("kind-birbverify-r5rh")
    config = Path(CONFIG).resolve()
    admin = KubernetesAPI(config, context)
    suffix = os.urandom(4).hex()
    namespace = "bv-app-" + suffix
    control = "bv-control-" + suffix
    node = admin.request("GET", "/api/v1/nodes")["items"][0]
    assert node["metadata"]["name"].startswith("birbverify-r5rh")
    base = ["kubectl", "--kubeconfig", str(config), "--context", context]

    def apply(obj):
        command(base + ["apply", "-f", "-"], data=json.dumps(obj))

    for name in (namespace, control):
        apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}})
    for name in ("target", "outsider"):
        apply(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": name, "namespace": control},
            }
        )
    apply(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "revision", "namespace": namespace},
            "data": {"baseline": "clean"},
        }
    )
    apply(target_role(namespace, "account-auth", "revision"))
    for name in ("target", "outsider"):
        apply(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": name, "namespace": namespace},
                "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": control}],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "birbverify-target",
                },
            }
        )
    reader = "bv-reader-" + suffix
    apply(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": reader},
            "rules": [
                {
                    "apiGroups": ["admissionregistration.k8s.io"],
                    "resources": ["mutatingwebhookconfigurations"],
                    "verbs": ["list"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["namespaces"],
                    "resourceNames": ["kube-system", namespace],
                    "verbs": ["get"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["nodes"],
                    "resourceNames": [node["metadata"]["name"]],
                    "verbs": ["get"],
                },
                {
                    "apiGroups": ["admissionregistration.k8s.io"],
                    "resources": [
                        "validatingadmissionpolicies",
                        "validatingadmissionpolicybindings",
                    ],
                    "resourceNames": [
                        f"birbverify-{namespace}",
                        f"birbverify-{namespace}-identity",
                    ],
                    "verbs": ["get"],
                },
            ],
        }
    )
    apply(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": reader},
            "subjects": [{"kind": "ServiceAccount", "name": "target", "namespace": control}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": reader,
            },
        }
    )
    namespace_uid = admin.request("GET", f"/api/v1/namespaces/{namespace}")["metadata"]["uid"]
    command(
        base + ["annotate", "namespace", namespace, "birbverify.dev/namespace-uid=" + namespace_uid]
    )
    cluster_uid = admin.request("GET", "/api/v1/namespaces/kube-system")["metadata"]["uid"]
    policies = admission_objects(
        namespace=namespace,
        namespace_uid=namespace_uid,
        node_name=node["metadata"]["name"],
        pod_name="account-auth",
        configmap_name="revision",
        target_username=f"system:serviceaccount:{control}:target",
    )
    for policy in policies:
        apply(policy)
    clients = {}
    for name in ("target", "outsider"):
        token = command(base + ["-n", control, "create", "token", name]).strip()
        local = json.loads(command(base + ["config", "view", "--raw", "-o", "json"]))
        local["users"] = [{"name": name, "user": {"token": token}}]
        local["contexts"] = [
            {"name": context, "context": {"cluster": local["clusters"][0]["name"], "user": name}}
        ]
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(local))
        path.chmod(0o600)
        clients[name] = KubernetesAPI(path, context)
    marker_path = f"/api/v1/namespaces/{namespace}/configmaps/revision"
    marker = clients["outsider"].request("GET", marker_path)

    def denied():
        try:
            clients["outsider"].request("PUT", marker_path, marker)
        except ApiError as error:
            if "birbverify writer or object outside inventory" in str(error):
                return str(error)
            raise
        return None

    denial = wait_for(denied)
    from birbverify.kubernetes_contract import KubernetesBinding, KubernetesInstallation

    binding = KubernetesBinding(
        target_id="kind-account-auth",
        cluster_uid=cluster_uid,
        namespace=namespace,
        namespace_uid=namespace_uid,
    )
    template = {
        "metadata": {"labels": {"app": "account-auth"}},
        "spec": {
            "containers": [
                {
                    "name": "account-auth",
                    "image": IMAGE,
                    "command": [
                        "python",
                        "-u",
                        "-c",
                        (ROOT / "fixtures/kubernetes_auth.py").read_text(),
                    ],
                    "ports": [{"containerPort": 8080}],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "readinessProbe": {
                        "httpGet": {"path": "/health", "port": 8080},
                        "periodSeconds": 1,
                    },
                }
            ],
            "nodeName": node["metadata"]["name"],
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 5,
        },
    }
    admission_specs = {}
    for obj in policies:
        resource = (
            "validatingadmissionpolicies"
            if obj["kind"] == "ValidatingAdmissionPolicy"
            else "validatingadmissionpolicybindings"
        )
        path = f"/apis/admissionregistration.k8s.io/v1/{resource}/{obj['metadata']['name']}"
        admission_specs[path] = digest(admin.request("GET", path)["spec"])
    installed = KubernetesInstallation(
        binding=binding,
        admission_specs=admission_specs,
        policy_revision=command(["git", "rev-parse", "HEAD"]).strip(),
        producer_revision=command(["git", "rev-parse", "HEAD"]).strip(),
        pod_name="account-auth",
        configmap_name="revision",
        node_name=node["metadata"]["name"],
        node_uid=node["metadata"]["uid"],
        pod_template=template,
    )
    return installed, clients, admin, denial


def request_for(installed, identity):
    from birbverify.kubernetes_contract import KubernetesRequest

    return KubernetesRequest(
        request_id=identity,
        candidate_revision=installed.producer_revision,
        producer_revision=installed.producer_revision,
        policy_revision=installed.policy_revision,
        plan_sha256=digest(installed.pod_template),
        target=installed.binding,
        image=IMAGE,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_real_application_and_closure(installation, tmp_path):
    from birbverify.kubernetes_target import KubernetesTarget

    installed, clients, admin, denial = installation
    target = KubernetesTarget(tmp_path / "target.db", clients["target"], installed)
    request = request_for(installed, "real-application")
    begun = target.begin(request)
    executed = target.execute(request)
    assert executed["state"] == "active", executed
    pod_path = f"/api/v1/namespaces/{installed.binding.namespace}/pods/account-auth"

    def ready():
        pod = admin.request("GET", pod_path)
        return (
            pod
            if any(
                c["type"] == "Ready" and c["status"] == "True"
                for c in pod.get("status", {}).get("conditions", [])
            )
            else None
        )

    pod = wait_for(ready)
    observation = target.inspect(request)["observation"]
    assert observation["ready"] and observation["pod_uid"] == pod["metadata"]["uid"]
    assert pod["status"]["containerStatuses"][0]["imageID"].endswith(IMAGE.split("@")[1])
    url = f"http://{pod['status']['podIP']}:8080"

    def http(path, body=None, token=None):
        args = ["docker", "exec", installed.node_name, "curl", "--fail", "-sS", url + path]
        if body is not None:
            args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        if token:
            args += ["-H", "Authorization: " + token]
        return json.loads(command(args))

    with pytest.raises(ApiError, match="outside inventory"):
        clients["target"].request(
            "POST",
            f"/api/v1/namespaces/{installed.binding.namespace}/pods",
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "unlisted"},
                "spec": pod["spec"],
            },
        )
    namespace_path = f"/api/v1/namespaces/{installed.binding.namespace}"
    with pytest.raises(ApiError, match="namespace identity is pinned"):
        admin.request("PUT", namespace_path, admin.request("GET", namespace_path))
    with pytest.raises(RuntimeError, match="outside inventory"):
        command(
            [
                "kubectl",
                "--kubeconfig",
                str(admin.kubeconfig),
                "--context",
                admin.context,
                "-n",
                installed.binding.namespace,
                "exec",
                "account-auth",
                "--",
                "true",
            ]
        )
    account = {"name": "fixture-user", "password": "disposable-fixture-only"}
    assert http("/accounts", account) == {"account": "fixture-user"}
    token = http("/login", account)["token"]
    assert http("/me", token=token) == {"account": "fixture-user"}

    def release():
        result = target.close(request, "completed")
        assert result["state"] != "quarantined", result
        return result if result["state"] == "released" else None

    closed = wait_for(release)
    assert closed["state"] == "released", closed
    from birbverify.kubernetes_contract import KubernetesReceipt

    receipt = KubernetesReceipt.model_validate(closed["receipt"])
    assert receipt.request_sha256 == digest(request)
    assert receipt.operations_sha256 == digest(closed["operations"])
    assert receipt.image == request.image
    assert receipt.candidate_revision == request.candidate_revision
    assert target.close(request, "completed") == closed
    assert target.execute(request)["state"] == "released"
    containers = json.loads(
        command(["docker", "exec", installed.node_name, "crictl", "ps", "-o", "json"])
    )
    assert not [
        c
        for c in containers.get("containers", [])
        if c.get("labels", {}).get("io.kubernetes.pod.uid") == pod["metadata"]["uid"]
    ]
    marker = clients["target"].request(
        "GET", f"/api/v1/namespaces/{installed.binding.namespace}/configmaps/revision"
    )
    assert marker["data"] == {"baseline": "clean"}
    evidence = {
        "profile": "disposable-kind-bare-pod",
        "request": request.model_dump(mode="json"),
        "request_sha256": digest(request),
        "admission_denial": denial,
        "begin": begun,
        "execution": executed,
        "closure": closed,
        "observation": observation,
        "pod_uid": pod["metadata"]["uid"],
        "account_auth": "passed",
        "denied_routes": ["outsider-configmap", "target-unlisted-pod", "namespace-update", "exec"],
        "runtime_running_containers_after_close": 0,
        "kubernetes": admin.request("GET", "/version"),
    }
    output = Path(os.environ.get("BIRBVERIFY_KUBE_EVIDENCE", tmp_path / "evidence.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
