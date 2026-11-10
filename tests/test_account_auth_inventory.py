import subprocess

import pytest

from birbverify.account_auth_inventory import digest, inventory, locked_source, unresolved_claims


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()

    git("init", "-q")
    path = "infra/charts/birbparty/Chart.yaml"
    chart = repo / path
    chart.parent.mkdir(parents=True)
    chart.write_text("name: birbparty\n")
    git("add", ".")
    git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "fixture")
    revision = git("rev-parse", "HEAD")
    lock = {
        "procedureCommit": revision,
        "candidateCommit": revision,
        "files": {path: digest(chart.read_bytes())},
    }
    return repo, revision, lock, chart


def test_source_uses_commit_not_dirty_checkout(source, tmp_path):
    repo, revision, lock, chart = source
    chart.write_text("untrusted working copy")
    destination = tmp_path / "extracted"
    assert locked_source(repo, revision, lock, destination) == 1
    assert (destination / chart.relative_to(repo)).read_text() == "name: birbparty\n"
    assert chart.read_text() == "untrusted working copy"


def test_altered_hash_fails(source, tmp_path):
    repo, revision, lock, chart = source
    lock["files"][chart.relative_to(repo).as_posix()] = "0" * 64
    with pytest.raises(ValueError, match="source hash mismatch"):
        locked_source(repo, revision, lock, tmp_path / "extracted")


def test_omitted_render_source_fails(source, tmp_path):
    repo, revision, lock, _ = source
    lock["files"] = {}
    with pytest.raises(ValueError, match="absent from lock"):
        locked_source(repo, revision, lock, tmp_path / "extracted")


def test_different_source_revision_fails(source, tmp_path):
    repo, revision, lock, _ = source
    lock["candidateCommit"] = "0" * 40
    with pytest.raises(ValueError, match="differs from source lock"):
        locked_source(repo, revision, lock, tmp_path / "extracted")


def pod():
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test", "annotations": {"helm.sh/hook": "test"}},
        "spec": {
            "initContainers": [{"name": "init", "image": "init@sha256:123"}],
            "containers": [{"name": "main", "image": "app:dev"}],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}],
        },
    }


def test_inventory_preserves_hooks_init_images_and_claims():
    obj = pod()
    result = inventory([None, obj], "birbparty")[0]
    assert result["namespace"] == "birbparty"
    assert result["hooks"] == {"helm.sh/hook": "test"}
    assert result["images"] == [
        {"container": "init", "image": "init@sha256:123", "role": "initContainers"},
        {"container": "main", "image": "app:dev", "role": "containers"},
    ]
    assert result["volumes"] == obj["spec"]["volumes"]
    before = result["manifest_sha256"]
    obj["spec"]["containers"][0]["image"] = "app:changed"
    assert inventory([obj], "birbparty")[0]["manifest_sha256"] != before


def test_unknown_kind_and_namespace_escape_fail():
    obj = pod()
    obj["kind"] = "ClusterRole"
    with pytest.raises(ValueError, match="unclassified object"):
        inventory([obj], "birbparty")
    obj["kind"] = "Pod"
    obj["metadata"]["namespace"] = "other"
    with pytest.raises(ValueError, match="escapes expected namespace"):
        inventory([obj], "birbparty")


def test_duplicate_identity_fails():
    with pytest.raises(ValueError, match="duplicate object"):
        inventory([pod(), pod()], "birbparty")


def test_pvc_in_other_namespace_does_not_resolve_pod_claim():
    objects = inventory([pod()], "birbparty")
    objects += inventory(
        [
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": "data"},
                "spec": {},
            }
        ],
        "birbparty-data",
    )
    assert unresolved_claims(objects) == [
        {"namespace": "birbparty", "workload": "test", "claim": "data"},
    ]
    objects[-1]["namespace"] = "birbparty"
    assert unresolved_claims(objects) == []


def test_both_releases_use_the_target_namespace(source, tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    from birbverify.account_auth_inventory import inspect

    repo, revision, lock, _ = source
    lock_path = tmp_path / "source-lock.json"
    lock_path.write_text(json.dumps(lock))
    helm = tmp_path / "helm"
    helm.write_bytes(b"fixture helm")
    archive = tmp_path / "dependency.tgz"
    archive.write_bytes(b"fixture dependency")
    original = subprocess.check_output
    seen = []

    def output(command):
        if command[0] != str(helm):
            return original(command)
        if command[1] == "version":
            return b"v3.22.1"
        namespace = command[command.index("--namespace") + 1]
        seen.append((command[2], namespace))
        obj = (
            pod()
            if command[2] == "birbparty"
            else {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": "data"},
                "spec": {},
            }
        )
        return json.dumps(obj).encode()

    monkeypatch.setattr(subprocess, "check_output", output)
    args = SimpleNamespace(
        source_repo=repo,
        source_revision=revision,
        source_lock=lock_path,
        namespace="birbparty-staging",
        helm=helm,
        helm_sha256=digest(helm.read_bytes()),
        dependency_archive=archive,
        dependency_sha256=digest(archive.read_bytes()),
    )
    receipt = inspect(args)
    assert seen == [
        ("birbparty", "birbparty-staging"),
        ("birbparty-data", "birbparty-staging"),
    ]
    assert receipt["pvc_references_absent_from_render"] == []
    assert {obj["namespace"] for obj in receipt["objects"]} == {"birbparty-staging"}
    assert receipt["runtime_proof"] is False
    assert receipt["deployment_approved"] is False
