"""Durable single-writer Kubernetes gateway with conservative unknown settlement."""

import copy
import fcntl
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from birbverify.contract import digest
from birbverify.kubernetes_contract import (
    KubernetesClosureReceipt,
    KubernetesInstallation,
    KubernetesRequest,
)

FINALIZER = "birbverify.dev/cleanup"


class KubernetesAPI(Protocol):
    def request(self, method: str, path: str, body: dict | None = None) -> dict: ...


class KubernetesTarget:
    def __init__(self, path: str | Path, api: KubernetesAPI, installation: KubernetesInstallation):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.api = api
        self.installation = installation.model_copy(deep=True)
        admission_root = "/apis/admissionregistration.k8s.io/v1/"
        names = (
            f"birbverify-{installation.binding.namespace}",
            f"birbverify-{installation.binding.namespace}-identity",
        )
        expected = {
            admission_root + resource + "/" + name
            for name in names
            for resource in ("validatingadmissionpolicies", "validatingadmissionpolicybindings")
        }
        if set(installation.admission_specs) != expected:
            raise ValueError("installation requires both admission policies and bindings")
        template = self.installation.pod_template
        spec = template.get("spec", {})
        if (
            template.get("metadata", {}).get("ownerReferences")
            or any(
                key.startswith("container.apparmor.security.beta.kubernetes.io/")
                for key in template.get("metadata", {}).get("annotations", {})
            )
            or spec.get("volumes")
            or len(spec.get("containers", [])) != 1
            or spec.get("initContainers")
            or spec.get("ephemeralContainers")
            or spec.get("hostNetwork")
            or spec.get("hostPID")
            or spec.get("hostIPC")
        ):
            raise ValueError("unsupported installed pod profile")
        container = spec["containers"][0]
        security = container.get("securityContext", {})
        if (
            security.get("capabilities", {}).get("add")
            or any(port.get("hostPort", 0) for port in container.get("ports", []))
            or security.get("procMount") == "Unmasked"
            or spec.get("securityContext", {}).get("sysctls")
            or any(
                context.get(kind, {}).get("type") == "Unconfined"
                for context in (security, spec.get("securityContext", {}))
                for kind in ("seccompProfile", "appArmorProfile")
            )
        ):
            raise ValueError("unsupported installed pod privileges")
        with self._locked() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS installation "
                "(id INTEGER PRIMARY KEY, digest TEXT NOT NULL)"
            )
            saved = db.execute("SELECT digest FROM installation WHERE id=1").fetchone()
            identity = digest(installation)
            if saved and saved[0] != identity:
                raise ValueError("journal belongs to a different installation")
            db.execute("INSERT OR IGNORE INTO installation VALUES (1, ?)", (identity,))
            db.commit()

    @contextmanager
    def _locked(self):
        with self.path.with_suffix(self.path.suffix + ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with sqlite3.connect(self.path) as db:
                db.execute("PRAGMA synchronous=FULL")
                yield db

    def _save(self, db, row):
        db.execute(
            "INSERT OR REPLACE INTO requests VALUES (?, ?)", (row["request_id"], json.dumps(row))
        )
        db.commit()

    def _load(self, db, request):
        saved = db.execute("SELECT data FROM requests WHERE id=?", (request.request_id,)).fetchone()
        if not saved:
            raise ValueError("request has not been admitted")
        row = json.loads(saved[0])
        if row["request_sha256"] != digest(request):
            raise ValueError("request identity was reused")
        if any(op["state"] == "pending" for op in row["operations"].values()):
            row["state"] = "quarantined"
            row["error"] = "unsettled durable intent; operator reconciliation required"
            self._save(db, row)
        return row

    def _path(self, resource, name=""):
        return f"/api/v1/namespaces/{self.installation.binding.namespace}/{resource}" + (
            f"/{name}" if name else ""
        )

    def _get(self, path):
        try:
            return self.api.request("GET", path)
        except Exception as error:
            if getattr(error, "status", None) == 404:
                return None
            raise

    def _verify(self):
        installation = self.installation
        for path, uid in (
            ("/api/v1/namespaces/kube-system", installation.binding.cluster_uid),
            (
                f"/api/v1/namespaces/{installation.binding.namespace}",
                installation.binding.namespace_uid,
            ),
            (f"/api/v1/nodes/{installation.node_name}", installation.node_uid),
        ):
            obj = self._get(path)
            if obj is None or obj["metadata"]["uid"] != uid:
                raise ValueError("installation UID mismatch")

        webhooks = self.api.request(
            "GET", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"
        )
        if webhooks["items"]:
            raise ValueError("mutating webhooks are outside the bounded target profile")
        group = self.api.request("GET", "/apis/admissionregistration.k8s.io")
        for version in group["versions"]:
            policies = self._get(
                f"/apis/admissionregistration.k8s.io/{version['version']}/mutatingadmissionpolicies"
            )
            if policies and policies["items"]:
                raise ValueError("mutating admission policies are outside the bounded profile")
        for path, expected in installation.admission_specs.items():
            policy = self._get(path)
            if (
                policy is None
                or digest(policy["spec"]) != expected.spec_sha256
                or policy["metadata"]["uid"] != expected.uid
                or policy["metadata"]["generation"] != expected.generation
            ):
                raise ValueError("admission policy missing or changed")

    def _effect(self, db, row, operation, method, path, body):
        previous = row["operations"].get(operation)
        if previous:
            if previous["state"] != "settled":
                raise ValueError("effect settlement unknown")
            return previous["response"]
        self._verify()
        row["operations"][operation] = {
            "state": "pending",
            "body_sha256": digest(body),
            "expected_uid": body.get("metadata", {}).get("uid")
            or body.get("preconditions", {}).get("uid"),
            "expected_resource_version": body.get("metadata", {}).get("resourceVersion"),
        }
        self._save(db, row)
        response = self.api.request(method, path, body)
        row["operations"][operation].update(state="settled", response=response)
        self._save(db, row)
        return response

    def _quarantine(self, db, row, error):
        row.update(state="quarantined", error=type(error).__name__)
        self._save(db, row)
        return row

    def begin(self, request: KubernetesRequest):
        with self._locked() as db:
            if db.execute("SELECT 1 FROM requests WHERE id=?", (request.request_id,)).fetchone():
                return self._load(db, request)
            if request.policy_revision != self.installation.policy_revision:
                raise ValueError("request policy differs from installation")
            if request.plan_sha256 != digest(self.installation.pod_template):
                raise ValueError("request plan differs from installed pod template")
            if request.target != self.installation.binding:
                raise ValueError("request target differs from installation")
            if request.producer_revision != self.installation.producer_revision:
                raise ValueError("request producer differs from installed adapter")
            if request.deadline <= datetime.now(UTC):
                raise ValueError("request deadline expired")
            for (data,) in db.execute("SELECT data FROM requests"):
                if json.loads(data)["state"] not in {"released", "sealed_unadmitted"}:
                    raise ValueError("target retained by another request")
            self._verify()
            baseline = self._get(self._path("configmaps", self.installation.configmap_name))
            if not baseline or self._get(self._path("pods", self.installation.pod_name)):
                raise ValueError("installation inventory is not clean")
            row = dict(
                request_id=request.request_id,
                request_sha256=digest(request),
                state="active",
                baseline=baseline,
                operations={},
                receipt=None,
            )
            self._save(db, row)
            return row

    def execute(self, request: KubernetesRequest):
        with self._locked() as db:
            row = self._load(db, request)
            if row["state"] != "active":
                return row
            try:
                if request.deadline <= datetime.now(UTC):
                    raise ValueError("request deadline expired")
                configmap = copy.deepcopy(row["baseline"])
                configmap["data"] = {
                    "request_id": request.request_id,
                    "candidate_revision": request.candidate_revision,
                    "request_sha256": digest(request),
                }
                self._effect(
                    db,
                    row,
                    "apply-revision",
                    "PUT",
                    self._path("configmaps", self.installation.configmap_name),
                    configmap,
                )
                pod = copy.deepcopy(self.installation.pod_template)
                pod.update(apiVersion="v1", kind="Pod")
                pod["metadata"] = {
                    "name": self.installation.pod_name,
                    "namespace": request.target.namespace,
                    "labels": {
                        **pod.get("metadata", {}).get("labels", {}),
                        "birbverify.dev/request": request.request_id,
                        "birbverify.dev/revision": request.candidate_revision,
                    },
                    "annotations": {
                        **pod.get("metadata", {}).get("annotations", {}),
                        "birbverify.dev/request-sha256": digest(request),
                    },
                    "finalizers": [FINALIZER],
                }
                spec = pod["spec"]
                if (
                    len(spec["containers"]) != 1
                    or spec.get("initContainers")
                    or spec.get("ephemeralContainers")
                ):
                    raise ValueError(
                        "profile requires one container without init or ephemeral containers"
                    )
                spec.update(
                    nodeName=self.installation.node_name,
                    automountServiceAccountToken=False,
                    restartPolicy="Never",
                )
                spec["containers"][0]["image"] = request.image
                created = self._effect(db, row, "create-pod", "POST", self._path("pods"), pod)
                actual = created["spec"]["containers"]
                expected = spec["containers"]
                if len(actual) != len(expected) or any(
                    actual[0].get(key) != expected[0].get(key)
                    for key in ("name", "image", "command", "args", "env", "envFrom")
                ):
                    raise ValueError("admitted workload differs from approved container")
                row["pod_uid"] = created["metadata"]["uid"]
                self._save(db, row)
                return row
            except Exception as error:
                return self._quarantine(db, row, error)

    def inspect(self, request: KubernetesRequest):
        with self._locked() as db:
            row = self._load(db, request)
            if row["state"] == "active" and row.get("pod_uid"):
                self._verify()
                pod = self._get(self._path("pods", self.installation.pod_name))
                if not pod or pod["metadata"]["uid"] != row["pod_uid"]:
                    return self._quarantine(db, row, ValueError("pod identity changed"))
                status = pod.get("status", {})
                row["observation"] = {
                    "pod_uid": row["pod_uid"],
                    "pod_ip": status.get("podIP"),
                    "ready": any(
                        c["type"] == "Ready" and c["status"] == "True"
                        for c in status.get("conditions", [])
                    ),
                    "containers": status.get("containerStatuses", []),
                }
            return row

    def _terminal(self, pod):
        statuses = pod.get("status", {}).get("containerStatuses", [])
        expected = {container["name"] for container in pod["spec"]["containers"]}
        return (
            bool(pod.get("metadata", {}).get("deletionTimestamp"))
            and pod.get("status", {}).get("phase") in {"Succeeded", "Failed"}
            and {status["name"] for status in statuses} == expected
            and all(set(status.get("state", {})) == {"terminated"} for status in statuses)
            and not pod["spec"].get("initContainers")
            and not pod["spec"].get("ephemeralContainers")
        )

    def close(self, request: KubernetesRequest, reason: str = "completed"):
        if reason not in {"completed", "cancelled", "worker_lost"}:
            raise ValueError("invalid closure reason")
        with self._locked() as db:
            if not db.execute(
                "SELECT 1 FROM requests WHERE id=?", (request.request_id,)
            ).fetchone():
                if request.target != self.installation.binding:
                    raise ValueError("request target differs from installation")
                row = dict(
                    request_id=request.request_id,
                    request_sha256=digest(request),
                    state="sealed_unadmitted",
                    reason=reason,
                    error="closed before admission; late admission prohibited",
                    operations={},
                    receipt=None,
                )
                self._save(db, row)
                return row
            row = self._load(db, request)
            if row["state"] in {"released", "quarantined", "sealed_unadmitted"}:
                return row
            row.update(state="closing", reason=row.get("reason", reason))
            self._save(db, row)
            try:
                self._verify()
                pod_path = self._path("pods", self.installation.pod_name)
                pod = self._get(pod_path)
                created = row["operations"].get("create-pod")
                if created:
                    uid = created["response"]["metadata"]["uid"]
                    row["pod_uid"] = uid
                    if not pod and "remove-finalizer" not in row["operations"]:
                        raise ValueError("pod disappeared without terminal proof")
                    if pod:
                        if pod["metadata"]["uid"] != uid:
                            raise ValueError("pod UID mismatch")
                        if (
                            FINALIZER not in pod["metadata"].get("finalizers", [])
                            and "remove-finalizer" not in row["operations"]
                        ):
                            raise ValueError("pod cleanup finalizer was removed externally")
                        self._effect(
                            db,
                            row,
                            "delete-pod",
                            "DELETE",
                            pod_path,
                            {
                                "apiVersion": "v1",
                                "kind": "DeleteOptions",
                                "preconditions": {"uid": uid},
                                "gracePeriodSeconds": 30,
                            },
                        )
                        pod = self._get(pod_path)
                        if not pod or pod["metadata"]["uid"] != uid:
                            raise ValueError("pod lost before terminal proof")
                        if not self._terminal(pod):
                            return row
                        row["terminal_proof"] = copy.deepcopy(pod["status"])
                        pod["metadata"]["finalizers"] = [
                            item
                            for item in pod["metadata"].get("finalizers", [])
                            if item != FINALIZER
                        ]
                        self._effect(db, row, "remove-finalizer", "PUT", pod_path, pod)
                        if self._get(pod_path):
                            self._effect(
                                db,
                                row,
                                "finalize-delete",
                                "DELETE",
                                pod_path,
                                {
                                    "apiVersion": "v1",
                                    "kind": "DeleteOptions",
                                    "preconditions": {"uid": uid},
                                    "gracePeriodSeconds": 0,
                                },
                            )
                        if self._get(pod_path):
                            return row
                elif pod:
                    raise ValueError("unexpected pod blocks closure")
                current = self._get(self._path("configmaps", self.installation.configmap_name))
                if not current or current["metadata"]["uid"] != row["baseline"]["metadata"]["uid"]:
                    raise ValueError("configmap UID mismatch")
                restored = copy.deepcopy(row["baseline"])
                restored["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
                self._effect(
                    db,
                    row,
                    "restore-revision",
                    "PUT",
                    self._path("configmaps", self.installation.configmap_name),
                    restored,
                )
                receipt = {
                    "schema_version": "birbverify.kubernetes.closure.v1",
                    "request_id": request.request_id,
                    "request_sha256": digest(request),
                    "candidate_revision": request.candidate_revision,
                    "producer_revision": self.installation.producer_revision,
                    "image": request.image,
                    "installation_sha256": digest(self.installation),
                    "pod_uid": row.get("pod_uid"),
                    "effects": {
                        name: {
                            "body_sha256": effect["body_sha256"],
                            "object_uid": effect["response"].get("metadata", {}).get("uid")
                            or effect.get("expected_uid"),
                            "expected_resource_version": effect.get("expected_resource_version"),
                            "resource_version": effect["response"]
                            .get("metadata", {})
                            .get("resourceVersion"),
                        }
                        for name, effect in row["operations"].items()
                    },
                    "policy_revision": request.policy_revision,
                    "plan_sha256": request.plan_sha256,
                    "target": request.target.model_dump(),
                    "reason": row["reason"],
                    "state": "released",
                    "terminal_proof": row.get("terminal_proof"),
                    "operations_sha256": digest(row["operations"]),
                }
                self._verify()
                receipt = KubernetesClosureReceipt.model_validate(receipt).model_dump(mode="json")
                row.update(state="released", receipt={**receipt, "receipt_sha256": digest(receipt)})
                self._save(db, row)
                return row
            except Exception as error:
                return self._quarantine(db, row, error)
