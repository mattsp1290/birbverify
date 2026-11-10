"""Offline, source-locked account/auth chart inventory. No Kubernetes client is used."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

CHARTS = (
    ("birbparty", "application"),
    ("birbparty-data", "data"),
)
POD_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
NAMESPACED_KINDS = {
    "NetworkPolicy",
    "PersistentVolumeClaim",
    "Service",
    "ServiceAccount",
    *POD_PATHS,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def locked_source(repo, revision, lock, destination):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full commit SHA")
    if lock["procedureCommit"] != revision or lock["candidateCommit"] != revision:
        raise ValueError("source revision differs from source lock")
    if git(repo, "rev-parse", f"{revision}^{{commit}}").decode().strip() != revision:
        raise ValueError("source revision is not a commit")
    files = lock["files"]
    roots = [f"infra/charts/{chart}" for chart, _ in CHARTS]
    roots.append("infra/environments/staging")
    render_files = git(repo, "ls-tree", "-r", "--name-only", revision, "--", *roots)
    missing = set(render_files.decode().splitlines()) - set(files)
    if missing:
        raise ValueError(f"render source is absent from lock: {sorted(missing)}")
    for name, expected in sorted(files.items()):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise ValueError(f"unsafe locked path: {name}")
        data = git(repo, "show", f"{revision}:{name}")
        if digest(data) != expected:
            raise ValueError(f"source hash mismatch: {name}")
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
    return len(files)


def inventory(documents, namespace):
    objects = []
    seen = set()
    for obj in documents:
        if obj is None:
            continue
        kind = obj["kind"]
        if kind not in NAMESPACED_KINDS:
            raise ValueError(f"unclassified object kind: {kind}")
        metadata = obj["metadata"]
        actual_namespace = metadata.get("namespace", namespace)
        if actual_namespace != namespace:
            raise ValueError(f"object escapes expected namespace: {metadata['name']}")
        identity = (obj["apiVersion"], kind, actual_namespace, metadata["name"])
        if identity in seen:
            raise ValueError(f"duplicate object: {identity}")
        seen.add(identity)
        pod = obj
        for key in POD_PATHS.get(kind, ()):
            pod = pod[key]
        if kind not in POD_PATHS:
            pod = None
        annotations = metadata.get("annotations", {})
        item = dict(zip(("api_version", "kind", "namespace", "name"), identity, strict=True))
        item.update(
            manifest_sha256=digest(json.dumps(obj, sort_keys=True).encode()),
            hooks={k: v for k, v in annotations.items() if k.startswith("helm.sh/hook")},
            pod_spec=pod,
            images=[
                {"container": c["name"], "image": c["image"], "role": role}
                for role in ("initContainers", "containers", "ephemeralContainers")
                for c in (pod or {}).get(role, [])
            ],
            volumes=(pod or {}).get("volumes", []),
            volume_claim_templates=obj.get("spec", {}).get("volumeClaimTemplates", []),
        )
        objects.append(item)
    return sorted(objects, key=lambda o: (o["namespace"], o["kind"], o["name"]))


def unresolved_claims(objects):
    claims = {(o["namespace"], o["name"]) for o in objects if o["kind"] == "PersistentVolumeClaim"}
    return [
        {"namespace": o["namespace"], "workload": o["name"], "claim": claim["claimName"]}
        for o in objects
        for volume in o["volumes"]
        if (claim := volume.get("persistentVolumeClaim"))
        and (o["namespace"], claim["claimName"]) not in claims
    ]


def inspect(args):
    import yaml

    lock_bytes = args.source_lock.read_bytes()
    lock = json.loads(lock_bytes)
    for path, expected, label in (
        (args.helm, args.helm_sha256, "Helm binary"),
        (args.dependency_archive, args.dependency_sha256, "dependency archive"),
    ):
        if digest(path.read_bytes()) != expected:
            raise ValueError(f"{label} hash mismatch")
    helm = str(args.helm.resolve())
    helm_version = subprocess.check_output([helm, "version", "--short"]).decode().strip()
    with tempfile.TemporaryDirectory(prefix="birbverify-inventory-") as temporary:
        root = Path(temporary)
        count = locked_source(args.source_repo, args.source_revision, lock, root)
        dependency_dir = root / "infra/charts/birbparty/charts"
        dependency_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.dependency_archive, dependency_dir / "openfga-0.3.12.tgz")
        documents = []
        renders = {}
        for chart, values in CHARTS:
            output = subprocess.check_output(
                [
                    helm,
                    "template",
                    chart,
                    str(root / "infra/charts" / chart),
                    "--namespace",
                    args.namespace,
                    "--kube-version",
                    "1.35.0",
                    "-f",
                    str(root / f"infra/environments/staging/{values}-values.yaml"),
                ]
            )
            renders[chart] = digest(output)
            documents.extend(yaml.safe_load_all(output))
        objects = inventory(documents, args.namespace)
    return {
        "schema_version": "birbverify.deployment.inventory.v1alpha1",
        "inspector_sha256": digest(Path(__file__).read_bytes()),
        "pyyaml_version": yaml.__version__,
        "offline_only": True,
        "runtime_proof": False,
        "deployment_approved": False,
        "source_revision": args.source_revision,
        "namespace": args.namespace,
        "source_lock_sha256": digest(lock_bytes),
        "verified_source_files": count,
        "helm_version": helm_version,
        "helm_sha256": args.helm_sha256,
        "kubernetes_render_version": "1.35.0",
        "dependency_sha256": args.dependency_sha256,
        "render_sha256": renders,
        "object_count": len(objects),
        "objects": objects,
        "pvc_references_absent_from_render": unresolved_claims(objects),
        "unproven_effect_requirements": [
            "All writers and admission-time mutations require runtime fencing proof.",
            "Controllers, generated Pods and Helm test hooks require closure proof.",
            "PVCs, dynamic PV provisioning and retained database writes require storage proof.",
            "Referenced Secrets, service accounts and namespace-local PVCs require resolution.",
            "Mutable image tags require resolved digests before execution approval.",
            "Service, network-policy and external database effects require runtime proof.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--helm", required=True, type=Path)
    parser.add_argument("--helm-sha256", required=True)
    parser.add_argument("--dependency-archive", required=True, type=Path)
    parser.add_argument("--dependency-sha256", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args), indent=2, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"inventory failed: {error}\n")
