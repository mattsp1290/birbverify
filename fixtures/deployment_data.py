"""Exercise the source-locked Birbparty data chart under the complete namespace fence."""

import json
import shutil
import subprocess
from functools import partial
from pathlib import Path

import yaml

from birbverify.account_auth_inventory import locked_source
from birbverify.contract import digest
from birbverify.deployment_helm import release_content_sha256
from birbverify.deployment_ownership import object_shape_sha256

TARGET = "proof-target"
RELEASE = "birbparty-data"
RESOURCES = {
    "PersistentVolumeClaim": "persistentvolumeclaims",
    "Service": "services",
    "StatefulSet": "statefulsets.apps",
    "NetworkPolicy": "networkpolicies.networking.k8s.io",
}
HELM_DIGESTS = {
    "b9fa0498b0eef0a2ff912c98fd6bbaba1b9e2c7a6e42063e406f1e4676272db9",
    "2bd1b649ef89175bc0ae1e0fa7de7e0583a5b0401de9896b644b8acbcae1ba64",
}


def prepare(root, candidate, fixture):
    helm = Path(shutil.which("helm") or "helm").resolve(strict=True)
    binary_hash = digest(helm.read_bytes())
    if (
        binary_hash not in HELM_DIGESTS
        or fixture.run(helm, "version", "--short") != "v3.22.1+gd6c1a0e"
    ):
        raise ValueError("expected a reviewed Helm v3.22.1 binary on PATH")
    source = root / "source"
    raw = (fixture.REPO / "contracts/deployment/v1alpha1/source-lock.json").read_bytes()
    lock = json.loads(raw)
    commit = lock["candidateCommit"]
    files = locked_source(candidate, commit, lock, source)
    images = yaml.safe_load((source / "infra/images.lock.yaml").read_text())["images"]
    overlay = {
        role: {"repository": images[role]["repository"], "digest": images[role]["digest"]}
        for role in ("postgresql", "volumePermissions")
    }
    overlay_file = root / "image-values.json"
    fixture.write(overlay_file, {"images": overlay})
    args = [
        "install",
        RELEASE,
        source / "infra/charts" / RELEASE,
        "--namespace",
        TARGET,
        "--values",
        source / "infra/environments/staging/data-values.yaml",
        "--values",
        overlay_file,
    ]
    return (
        helm,
        args,
        dict(
            candidate_commit=commit,
            source_lock_sha256=digest(raw),
            verified_source_files=files,
            helm_version="v3.22.1+gd6c1a0e",
            helm_binary_sha256=binary_hash,
            image_overlay=overlay,
        ),
    )


def configure(root, kubectl, release, evidence, fixture):
    user = fixture.release_identity(root, kubectl)
    principal = digest(user)
    objects = [obj for obj in yaml.safe_load_all(release["manifest"]) if obj]
    allowed = sorted({"secrets"} | {RESOURCES[obj["kind"]] for obj in objects})
    kubectl(
        "-n",
        TARGET,
        "create",
        "role",
        "data-installer",
        "--resource=" + ",".join(allowed),
        "--verb=get,list,watch,create,update",
    )
    kubectl(
        "-n",
        TARGET,
        "create",
        "rolebinding",
        "data-installer",
        "--role=data-installer",
        "--user=" + user["username"],
    )
    rules = []
    sets = []
    for index, obj in enumerate(objects):
        meta = obj["metadata"]
        meta.setdefault("annotations", {}).update(
            {"meta.helm.sh/release-name": RELEASE, "meta.helm.sh/release-namespace": TARGET}
        )
        meta.setdefault("labels", {})["app.kubernetes.io/managed-by"] = "Helm"
        if obj["kind"] == "StatefulSet":
            pod = obj["spec"]["template"]["spec"]
            images = [c["image"] for c in pod["containers"] + pod["initContainers"]]
            assert sorted(images) == sorted(
                i["repository"] + "@" + i["digest"] for i in evidence["image_overlay"].values()
            )
            sets.append(meta["name"])
        final = json.loads(
            kubectl(
                "create",
                "--dry-run=server",
                "-n",
                TARGET,
                "-f",
                "-",
                "-o",
                "json",
                data=json.dumps(obj),
            )
        )
        rules.append(
            dict(
                slot=f"chart-object-{index}",
                name=meta["name"],
                kind=obj["kind"],
                principal_sha256=principal,
                object_sha256=object_shape_sha256(final, generated=False, owned=False),
            )
        )
    assert len(sets) == 2

    def namespace_uid(name):
        return kubectl("get", "namespace/" + name, "-o", "jsonpath={.metadata.uid}")

    return dict(
        schema_version="birbverify.deployment.ownership.v1",
        cluster_uid=namespace_uid("kube-system"),
        namespace=TARGET,
        namespace_uid=namespace_uid(TARGET),
        webhook_name=fixture.WEBHOOK,
        admission_client_sha256=fixture.pin(root / "admission/apiserver.crt"),
        closure_client_sha256=fixture.pin(root / "admission/unassigned.crt"),
        audit_client_sha256=fixture.pin(root / "audit/apiserver.crt"),
        helm_releases=[
            dict(
                release_name=RELEASE,
                source_revision=evidence["candidate_commit"],
                principal_sha256=principal,
                content_sha256=release_content_sha256(release),
            )
        ],
        rules=rules,
    )


def exercise(root, cluster, stack, image, *, candidate, fixture):
    helm, install, evidence = prepare(root, candidate, fixture)
    kubectl = partial(fixture.run, "kubectl", "--kubeconfig", root / "kubeconfig")
    for namespace in (TARGET, "proof-control"):
        kubectl("create", "namespace", namespace)
    release = json.loads(
        fixture.run(
            helm, "--kubeconfig", root / "kubeconfig", *install, "--dry-run=client", "--output=json"
        )
    )
    policy = configure(root, kubectl, release, evidence, fixture)
    fixture.write(root / "policy.json", policy)
    policy_hash = digest(policy)
    request_sha = digest({"candidate": evidence["candidate_commit"], "installation": policy_hash})
    server = fixture.start_services(
        root, policy, request_sha, partial(fixture.start_container, cluster, stack, image)
    )
    guard = fixture.guard_installation(
        root,
        cluster,
        kubectl,
        server,
        TARGET,
        rules=[
            dict(
                apiGroups=["*"],
                apiVersions=["*"],
                operations=["*"],
                resources=["*/*"],
                scope="Namespaced",
            )
        ],
    )
    attempt = subprocess.run(
        [helm, "--kubeconfig", root / "release.kubeconfig", *install],
        text=True,
        capture_output=True,
        timeout=90,
    )
    reason = (
        f'admission webhook "{fixture.WEBHOOK}" denied the request: no unique approved CREATE slot'
    )
    errors = [
        line.strip()[2:] for line in attempt.stderr.splitlines() if line.strip().startswith("* ")
    ]
    assert attempt.returncode and errors and all(error == reason for error in errors)

    post = partial(fixture.post_closure, root / "admission", server)
    request = {"request_id": "flux-proof", "request_sha256": request_sha}
    owner = post("observe", request)
    assert owner["installation_sha256"] == policy_hash
    command = request | {"epoch": owner["epoch"]}
    assert post("account-result", command) == {"status": "absent"}
    progress = post("close", command | {"reason": "cancelled"})
    assert progress["state"] == "sealed" and not progress["release_authorized"]
    secret = "secret/sh.helm.release.v1." + RELEASE + ".v1"
    phase = kubectl("-n", TARGET, "get", secret, "-o", "jsonpath={.metadata.labels.status}")
    assert phase == "pending-install"
    live = {
        "helm-" + RELEASE + "-create": kubectl(
            "-n", TARGET, "get", secret, "-o", "jsonpath={.metadata.uid}"
        )
    }
    absent = []
    for rule in policy["rules"]:
        resource = RESOURCES[rule["kind"]] + "/" + rule["name"]
        uid = kubectl(
            "-n", TARGET, "get", resource, "--ignore-not-found", "-o", "jsonpath={.metadata.uid}"
        )
        if uid:
            live[rule["slot"]] = uid
        else:
            absent.append(resource)
    assert len(policy["rules"]) == 10
    assert set(absent) == {
        "persistentvolumeclaims/birbparty-authz-runtime",
        "services/birbparty-data-birbparty-data-application-postgresql",
        "services/birbparty-data-birbparty-data-openfga-postgresql",
    }
    assert len(errors) == len(absent) == 3 and len(live) == 8
    assert all(
        e["state"] == "settled" and e["audit_id"] and e["event_sha256"] for e in progress["effects"]
    )
    assert {e["slot"]: e["object_uid"] for e in progress["effects"]} == live
    pods = json.loads(kubectl("-n", TARGET, "get", "pods", "-o", "json"))["items"]
    assert not pods
    fixture.write(
        root / "receipt.json",
        dict(
            scope="Direct Helm data chart, all namespaced writes fenced on disposable Kubernetes",
            source_revision=fixture.run("git", "-C", fixture.REPO, "rev-parse", "HEAD"),
            source_dirty=bool(fixture.run("git", "-C", fixture.REPO, "status", "--porcelain")),
            image_id=image,
            kind_node=fixture.NODE,
            **evidence,
            installation_sha256=policy_hash,
            release_content_sha256=release_content_sha256(release),
            manifest_sha256=digest(release["manifest"].encode()),
            guard=guard,
            data_resource_count=len(policy["rules"]),
            resources_absent=absent,
            create_slot_denials=len(errors),
            release_secret_phase=phase,
            target_pods=len(pods),
            account_activity_state="absent",
            closure=progress,
        ),
    )
