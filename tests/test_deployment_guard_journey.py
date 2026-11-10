"""Guard proof for one explicitly named, disposable Kubernetes API server."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from birbverify.contract import digest
from birbverify.deployment_guard import (
    NAME_LABEL,
    VERSION,
    inventory,
    manifests,
    verify_initial_installation,
)
from birbverify.kubernetes_api import KubernetesAPI

NODE = (
    "kindest/node:v1.33.1@sha256:050072256b9a903bd914c0b2866828150cb229cea0efe5892e2b644d5dd3b34f"
)


def configuration(kind, name, target):
    return {
        "apiVersion": VERSION,
        "kind": kind,
        "metadata": {"name": name},
        "webhooks": [
            {
                "name": name + ".guard.test",
                "admissionReviewVersions": ["v1"],
                "sideEffects": "None",
                "failurePolicy": "Fail",
                "clientConfig": {"service": {"name": "unused", "namespace": "default"}},
                "namespaceSelector": {
                    "matchExpressions": [
                        {"key": NAME_LABEL, "operator": "NotIn", "values": [target]}
                    ]
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": ["pods"],
                        "scope": "Namespaced",
                    }
                ],
            }
        ],
    }


@pytest.mark.skipif("BIRBVERIFY_GUARD_ROOT" not in os.environ, reason="requires disposable kind")
def test_guard_protects_pins_and_allows_disjoint_config():
    root = Path(os.environ["BIRBVERIFY_GUARD_ROOT"]).resolve()
    assert root.parent == Path(__file__).resolve().parents[1] / ".proof"
    assert root.name.startswith("bv-guard-")
    cluster = root.name.lower()
    config = root / "kubeconfig"
    context = "kind-" + cluster
    api = KubernetesAPI(config, context)
    node_names = [n["metadata"]["name"] for n in api.request("GET", "/api/v1/nodes")["items"]]
    assert node_names == [cluster + "-control-plane"]

    def kubectl(*args, value=None, denied=None):
        proc = subprocess.run(
            ["kubectl", "--kubeconfig", str(config), "--context", context, *args],
            input=json.dumps(value) if value is not None else None,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if denied:
            assert proc.returncode != 0 and denied in proc.stderr, proc.stderr
        else:
            assert proc.returncode == 0, proc.stderr

    target = "account-target"
    kubectl("create", "namespace", target)
    mutator = configuration("MutatingWebhookConfiguration", "pinned-mutator", target)
    validator = configuration("ValidatingWebhookConfiguration", "owned-validator", target)
    kubectl("create", "-f", "-", value=validator)
    kubectl("create", "-f", "-", value=mutator)
    pins = inventory(api, target, "owned-validator")
    docs = manifests(pins)
    for document in docs:
        kubectl("create", "-f", "-", value=document)
    for _ in range(50):
        try:
            receipt = verify_initial_installation(api, pins)
            kubectl(
                "label",
                "namespace",
                target,
                "proof=test",
                "--dry-run=server",
                denied="bv-account-target-namespace guard",
            )
            break
        except (ValueError, AssertionError):
            time.sleep(0.2)
    else:
        pytest.fail("Guard did not become ready")

    kubectl(
        "delete",
        "namespace",
        target,
        "--dry-run=server",
        denied="bv-account-target-namespace guard",
    )
    patch = json.dumps({"webhooks": [{"name": "pinned-mutator.guard.test", "timeoutSeconds": 4}]})
    kubectl(
        "patch",
        "mutatingwebhookconfiguration",
        "pinned-mutator",
        "-p",
        patch,
        denied="bv-account-target-mutators guard",
    )
    kubectl(
        "delete",
        "validatingwebhookconfiguration",
        "owned-validator",
        denied="bv-account-target-validator guard",
    )

    disjoint = configuration("MutatingWebhookConfiguration", "disjoint", target)
    kubectl("create", "-f", "-", value=disjoint)
    disjoint["webhooks"][0]["namespaceSelector"] = {}
    kubectl(
        "patch",
        "mutatingwebhookconfiguration",
        "disjoint",
        "--type=merge",
        "-p",
        json.dumps({"webhooks": disjoint["webhooks"]}),
        denied="bv-account-target-mutators guard",
    )
    disjoint["metadata"]["name"] = "matching"
    kubectl("create", "-f", "-", value=disjoint, denied="bv-account-target-mutators guard")
    kubectl("create", "configmap", "outside", "--from-literal=value=ok", "-n", "default")
    kubectl("create", "configmap", "inside", "--from-literal=value=ok", "-n", target)
    kubectl("delete", "mutatingwebhookconfiguration", "disjoint")
    assert verify_initial_installation(api, pins) == receipt
    receipt.update(
        {
            "scope": "namespace and admission configuration guard",
            "node_image": NODE,
            "cluster_uid": pins["cluster_uid"],
            "namespace_uid": pins["namespace_uid"],
            "manifest_sha256": digest(docs),
            "source_revision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"])),
            "source_sha256": {
                name: digest(Path(name).read_bytes())
                for name in [
                    "src/birbverify/deployment_guard.py",
                    "src/birbverify/deployment_mutators.py",
                    "tests/test_deployment_guard_journey.py",
                    "scripts/verify-deployment-guard",
                ]
            },
        }
    )
    (root / "guard-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
