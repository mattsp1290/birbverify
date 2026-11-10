"""Actual native-controller persistence after seal, observed through trusted audit."""

import base64
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from birbverify.deployment_mutators import (
    MutatorRejected,
    WriteScope,
    snapshot_mutators,
    verify_mutators,
)

ROOT = Path(__file__).resolve().parents[1]
PROOF = os.environ.get("BIRBVERIFY_SETTLEMENT_ROOT")
pytestmark = pytest.mark.skipif(not PROOF, reason="requires disposable settlement kind fixture")


def command(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def wait_for(probe, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("fixture barrier did not arrive")


def test_native_controller_persists_after_seal_and_audit_settles_exact_uid():
    source_paths = [
        "src/birbverify/deployment_journal.py",
        "src/birbverify/deployment_mutators.py",
        "src/birbverify/contract.py",
        "fixtures/deployment_admission_fixture.py",
        "tests/test_deployment_settlement_journey.py",
        "scripts/verify-deployment-settlement",
    ]
    source_hashes = {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in source_paths
    }
    root = Path(PROOF).resolve()
    cluster = os.environ["BIRBVERIFY_SETTLEMENT_CLUSTER"]
    assert cluster.startswith("birbverify-bsmn-")
    assert root.name == cluster and root.parent == ROOT / ".proof" / "bsmn"
    base = ["kubectl", "--kubeconfig", str(root / "kubeconfig"), "--context", "kind-" + cluster]
    nodes = json.loads(command(base + ["get", "nodes", "-o", "json"]).stdout)["items"]
    assert [node["metadata"]["name"] for node in nodes] == [cluster + "-control-plane"]
    mailbox = root / "mailbox"
    mailbox.mkdir()
    name = cluster + "-webhook"
    command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(mailbox / "tls.key"),
            "-out",
            str(mailbox / "tls.crt"),
            "-subj",
            "/CN=" + name,
            "-addext",
            "subjectAltName=DNS:" + name,
        ]
    )
    image = os.environ["BIRBVERIFY_SETTLEMENT_IMAGE"]
    image_id = command(["docker", "image", "inspect", image, "--format", "{{.Id}}"]).stdout.strip()
    pause = (
        "registry.k8s.io/pause:3.10@"
        "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
    )
    command(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "kind",
            "--user",
            "0",
            "-v",
            str(mailbox) + ":/proof",
            "-v",
            str(ROOT) + ":/repo:ro",
            "-e",
            "SETTLEMENT_ROOT=/proof",
            "-e",
            "PYTHONPATH=/repo/src",
            "-e",
            "SETTLEMENT_PAUSE_IMAGE=" + pause,
            "--entrypoint",
            "python",
            image,
            "/repo/fixtures/deployment_admission_fixture.py",
        ]
    )

    def control(action, **fields):
        key = str(uuid.uuid4())
        path = mailbox / ("command-" + key + ".json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"action": action, **fields}))
        temporary.replace(path)
        response = mailbox / ("result-" + key + ".json")
        wait_for(response.exists)
        result = json.loads(response.read_text())
        assert "error" not in result, result
        return result["value"]

    def apply(obj):
        return command(base + ["create", "-f", "-"], data=json.dumps(obj))

    def mutator_inventory():
        configurations = json.loads(
            command(base + ["get", "mutatingwebhookconfigurations", "-o", "json"]).stdout
        )["items"]
        namespace = json.loads(
            command(base + ["get", "namespace", "settlement-proof", "-o", "json"]).stdout
        )
        return configurations, namespace

    try:
        wait_for((mailbox / "ready.json").exists)
        apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "settlement-proof"}})
        apply(
            {
                "apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "MutatingWebhookConfiguration",
                "metadata": {"name": "unreachable-nonmatching-proof"},
                "webhooks": [
                    {
                        "name": "unreachable.birbverify.test",
                        "admissionReviewVersions": ["v1"],
                        "sideEffects": "None",
                        "failurePolicy": "Fail",
                        "timeoutSeconds": 1,
                        "clientConfig": {"url": "https://127.0.0.1:1/unreachable"},
                        "namespaceSelector": {"matchLabels": {"birbverify.dev/mutate": "yes"}},
                        "rules": [
                            {
                                "apiGroups": [""],
                                "apiVersions": ["v1"],
                                "resources": ["pods"],
                                "operations": ["CREATE"],
                            }
                        ],
                    }
                ],
            }
        )
        apply(
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "mutator-control",
                    "labels": {"birbverify.dev/mutate": "yes"},
                },
            }
        )

        def matching_mutator_is_active():
            result = command(
                base + ["create", "--dry-run=server", "-f", "-"],
                data=json.dumps(
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "activation-probe", "namespace": "mutator-control"},
                        "spec": {"containers": [{"name": "pause", "image": pause}]},
                    }
                ),
                check=False,
            )
            return (
                result.returncode != 0
                and 'failed calling webhook "unreachable.birbverify.test"' in result.stderr
            )

        wait_for(matching_mutator_is_active)
        discovery = json.loads(
            command(base + ["get", "--raw", "/apis/admissionregistration.k8s.io"]).stdout
        )
        discovered = set()
        for version in discovery["versions"]:
            resources = json.loads(
                command(base + ["get", "--raw", "/apis/" + version["groupVersion"]]).stdout
            )["resources"]
            discovered.update(resource["name"] for resource in resources)
        assert not discovered.intersection(
            {
                "mutatingadmissionpolicies",
                "mutatingadmissionpolicybindings",
            }
        ), "this fixture requires the pinned cluster's policy-free admission configuration"
        configurations, namespace = mutator_inventory()
        mutator_snapshot = snapshot_mutators(
            configurations,
            namespace,
            (WriteScope("", "v1", "pods", "CREATE"),),
            policies=(),
            bindings=(),
        )
        apply(
            {
                "apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingWebhookConfiguration",
                "metadata": {"name": "settlement-proof"},
                "webhooks": [
                    {
                        "name": "settlement.birbverify.test",
                        "admissionReviewVersions": ["v1"],
                        "sideEffects": "NoneOnDryRun",
                        "failurePolicy": "Fail",
                        "timeoutSeconds": 30,
                        "clientConfig": {
                            "url": "https://" + name + ":8443/admit",
                            "caBundle": base64.b64encode(
                                (mailbox / "tls.crt").read_bytes()
                            ).decode(),
                        },
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "settlement-proof"}
                        },
                        "rules": [
                            {
                                "apiGroups": [""],
                                "apiVersions": ["v1"],
                                "resources": ["pods"],
                                "operations": ["CREATE"],
                                "scope": "Namespaced",
                            }
                        ],
                    }
                ],
            }
        )
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "settlement-proof",
                "namespace": "settlement-proof",
                "labels": {"app": "settlement-proof"},
            },
            "spec": {
                "replicas": 0,
                "selector": {"matchLabels": {"app": "settlement-proof"}},
                "template": {
                    "metadata": {"labels": {"app": "settlement-proof"}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [{"name": "pause", "image": pause}],
                    },
                },
            },
        }
        apply(deployment)

        def replicasets():
            return json.loads(
                command(base + ["-n", "settlement-proof", "get", "rs", "-o", "json"]).stdout
            )["items"]

        owner = wait_for(replicasets)[0]
        deployment_uid = json.loads(
            command(
                base
                + ["-n", "settlement-proof", "get", "deployment", "settlement-proof", "-o", "json"]
            ).stdout
        )["metadata"]["uid"]
        assert owner["metadata"]["ownerReferences"][0]["uid"] == deployment_uid
        (mailbox / "allowed-owner.json").write_text(json.dumps(owner["metadata"]))
        command(
            base
            + ["-n", "settlement-proof", "scale", "deployment/settlement-proof", "--replicas=1"]
        )
        wait_for((mailbox / "held.json").exists, seconds=60)
        held = json.loads((mailbox / "held.json").read_text())
        sealed = control("seal")
        assert sealed["pending"] == [held["uid"]]
        assert sealed["state"] == "sealed"
        pods_at_seal = json.loads(
            command(base + ["-n", "settlement-proof", "get", "pods", "-o", "json"]).stdout
        )
        assert pods_at_seal["items"] == []
        assert control("restart")["pending"] == [held["uid"]]
        (mailbox / "unblock").touch()

        def pods():
            return json.loads(
                command(base + ["-n", "settlement-proof", "get", "pods", "-o", "json"]).stdout
            )["items"]

        persisted = wait_for(pods)[0]
        (mailbox / "ready.json").unlink()
        command(["docker", "restart", name])
        wait_for((mailbox / "ready.json").exists)
        assert control("snapshot")["pending"] == [held["uid"]]
        annotation = "settlement.birbverify.test/intent-" + held["uid"]

        def completion():
            lines = (root / "audit" / "events.jsonl").read_text().splitlines()
            for line in lines:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    annotation in event.get("annotations", {})
                    and event.get("stage") == "ResponseComplete"
                ):
                    return event
            return None

        event = wait_for(completion)
        assert event["responseStatus"]["code"] == 201
        assert event["responseObject"]["metadata"]["uid"] == persisted["metadata"]["uid"]
        settled = control("ingest", event=event)
        assert settled["pending"] == [] and settled["quarantined"] == []
        assert settled["settled"] == [held["uid"]]
        intent = settled["intents"][0]
        assert intent["evidence"]["object_uid"] == persisted["metadata"]["uid"]
        assert intent["evidence"]["termination_proven"] is False
        assert control("restart")["settled"] == [held["uid"]]
        denied_pod = json.loads(json.dumps(held["request"]["object"]))
        denied_pod["metadata"].pop("uid", None)
        denied_pod["metadata"].pop("creationTimestamp", None)
        denied_pod["metadata"].pop("generateName", None)
        denied_pod["metadata"]["name"] = "after-seal"
        denied = command(
            base
            + ["--as=system:serviceaccount:kube-system:replicaset-controller", "create", "-f", "-"],
            data=json.dumps(denied_pod),
            check=False,
        )
        assert denied.returncode != 0 and "epoch sealed" in denied.stderr, denied.stderr
        outsider = command(base + ["create", "-f", "-"], data=json.dumps(denied_pod), check=False)
        assert outsider.returncode != 0 and "outside disposable proof policy" in outsider.stderr
        assert len(pods()) == 1
        configurations, namespace = mutator_inventory()
        verify_mutators(mutator_snapshot, configurations, namespace, policies=(), bindings=())
        command(
            base
            + [
                "patch",
                "mutatingwebhookconfiguration",
                "unreachable-nonmatching-proof",
                "--type=json",
                "-p",
                json.dumps(
                    [
                        {
                            "op": "replace",
                            "path": "/webhooks/0/namespaceSelector",
                            "value": {},
                        }
                    ]
                ),
            ]
        )
        configurations, namespace = mutator_inventory()
        with pytest.raises(MutatorRejected, match="potentially matching mutator"):
            verify_mutators(mutator_snapshot, configurations, namespace, policies=(), bindings=())
        assert source_hashes == {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in source_paths
        }, "proof source changed during execution"
        evidence = {
            "scope": "native ReplicaSet controller Pod CREATE settlement only",
            "cluster": cluster,
            "epoch": sealed["epoch"],
            "admission_uid": held["uid"],
            "empty_pod_list_while_sealed_pending": True,
            "restart_preserved_pending": True,
            "persisted_after_seal": True,
            "missing_audit_kept_pending": True,
            "terminal_audit_id": event["auditID"],
            "terminal_audit_stage": event["stage"],
            "terminal_audit_level": event["level"],
            "terminal_audit_annotation": annotation,
            "persisted_pod_uid": persisted["metadata"]["uid"],
            "settled": intent["evidence"],
            "matching_control_confirmed_mutator_active": True,
            "nonmatching_unreachable_mutator_coexisted": True,
            "mutator_pins_rechecked": True,
            "mutator_selector_drift_rejected_by_classifier": True,
            "mutator_drift_admission_enforcement_proven": False,
            "mutator_configuration_uids": [pin.uid for pin in mutator_snapshot.configurations],
            "postseal_create_denied": True,
            "outsider_denied": True,
            "release_proven": False,
            "termination_proven": False,
            "fixture_image_id": image_id,
            "source_sha256": source_hashes,
            "deployment_uid": deployment_uid,
            "replicaset_uid": owner["metadata"]["uid"],
            "pause_image": pause,
            "source_revision": command(["git", "rev-parse", "HEAD"]).stdout.strip(),
            "source_dirty": bool(command(["git", "status", "--porcelain"]).stdout),
        }
        (root / "settlement.json").write_text(json.dumps(evidence, indent=2) + "\n")
    finally:
        command(["docker", "logs", name], check=False)
        command(["docker", "rm", "-f", name], check=False)
