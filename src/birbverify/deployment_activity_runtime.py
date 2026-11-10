"""Inspect the installed Pod set and address the API over an authenticated Pod tunnel."""

import json
import re
import select
import subprocess
from contextlib import contextmanager
from http.client import HTTPConnection

from birbverify.deployment_activity_contract import ActivityInstallation, PodIncarnation
from birbverify.deployment_http import strict_json
from birbverify.kubernetes_api import KubernetesAPI

# Container names and roles come from the accepted account/auth Helm releases.
_LAYOUT = {
    "api": ({"authz-state-init": "busybox", "authz-bootstrap": "api"}, {"api": "api"}),
    "ui": ({}, {"ui": "ui"}),
    "openfga": ({"migrate-database": "openfga"}, {"openfga": "openfga"}),
    "application-postgres": ({"volume-permissions": "busybox"}, {"postgresql": "postgres"}),
    "openfga-postgres": ({"volume-permissions": "busybox"}, {"postgresql": "postgres"}),
}


class PodTarget:
    def __init__(self, api: KubernetesAPI, installation: ActivityInstallation):
        self.api = api
        self.installation = installation

    def require_verified_transport(self):
        view = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(self.api.kubeconfig),
                "--context",
                self.api.context,
                "config",
                "view",
                "--minify",
                "-o",
                "json",
            ],
            capture_output=True,
            timeout=10,
            check=True,
        )
        clusters = json.loads(view.stdout)["clusters"]
        if len(clusters) != 1:
            raise ValueError("explicit_cluster_required")
        cluster = clusters[0]["cluster"]
        if (
            not cluster["server"].startswith("https://")
            or cluster.get("insecure-skip-tls-verify")
            or not (
                cluster.get("certificate-authority") or cluster.get("certificate-authority-data")
            )
        ):
            raise ValueError("authenticated_cluster_required")

    def observe(self):
        request = self.installation.request
        binding = request.target
        for ns, uid in (
            ("kube-system", binding.cluster_uid),
            (binding.namespace, binding.namespace_uid),
        ):
            if self.api.request("GET", f"/api/v1/namespaces/{ns}")["metadata"]["uid"] != uid:
                raise ValueError("namespace_identity_mismatch")
        listing = self.api.request("GET", f"/api/v1/namespaces/{binding.namespace}/pods")
        pins = {pin.name: pin for pin in self.installation.pods}
        if listing["metadata"].get("continue") or set(pins) != {
            pod["metadata"]["name"] for pod in listing["items"]
        }:
            raise ValueError("unexpected_pod_inventory")
        result = []
        nodes = {}
        for pod in listing["items"]:
            metadata, spec, status = pod["metadata"], pod["spec"], pod["status"]
            pin = pins[metadata["name"]]
            if pin.node_name not in nodes:
                node = self.api.request("GET", f"/api/v1/nodes/{pin.node_name}")
                nodes[pin.node_name] = node["metadata"]["uid"]
            owners = [owner for owner in metadata["ownerReferences"] if owner.get("controller")]
            expected_parent = "StatefulSet" if pin.workload.endswith("postgres") else "ReplicaSet"
            if (
                metadata.get("deletionTimestamp")
                or metadata["uid"] != pin.uid
                or metadata["namespace"] != binding.namespace
                or len(owners) != 1
                or owners[0]["uid"] != pin.controller_uid
                or owners[0]["kind"] != expected_parent
                or owners[0]["apiVersion"] != "apps/v1"
                or spec["nodeName"] != pin.node_name
                or nodes[pin.node_name] != pin.node_uid
                or status["phase"] != "Running"
                or spec.get("ephemeralContainers")
            ):
                raise ValueError("pod_incarnation_mismatch")
            if pin.workload == "api" and not any(
                port.get("name") == "http"
                and port.get("protocol", "TCP") == "TCP"
                and port.get("containerPort") == self.installation.api_port
                for container in spec["containers"]
                if container["name"] == "api"
                for port in container.get("ports", [])
            ):
                raise ValueError("api_port_mismatch")
            containers = []
            for is_init, names in zip((True, False), _LAYOUT[pin.workload], strict=True):
                spec_key, status_key = (
                    ("initContainers", "initContainerStatuses")
                    if is_init
                    else ("containers", "containerStatuses")
                )
                observed = {c["name"]: c for c in status.get(status_key, [])}
                declared = {c["name"]: c for c in spec.get(spec_key, [])}
                if set(declared) != set(names) or set(observed) != set(names):
                    raise ValueError("container_inventory_mismatch")
                for name, role in names.items():
                    image = request.images[role]
                    container = observed[name]
                    image_id = container["imageID"]
                    runtime_digest = image_id.rsplit("@", 1)[-1]
                    if (
                        declared[name]["image"] != image.reference
                        or runtime_digest not in {image.platform_manifest, image.config_digest}
                        or (
                            is_init
                            and container["state"].get("terminated", {}).get("exitCode") != 0
                        )
                        or (
                            not is_init
                            and ("running" not in container["state"] or not container["ready"])
                        )
                    ):
                        raise ValueError("container_incarnation_mismatch")
                    containers.append(
                        dict(
                            role=role,
                            name=name,
                            runtime_image_digest=runtime_digest,
                            container_id=container["containerID"],
                        )
                    )
            result.append(PodIncarnation(**pin.model_dump(), containers=tuple(containers)))
        return tuple(sorted(result, key=lambda p: p.workload))

    @contextmanager
    def connect(self):
        pin = next(p for p in self.installation.pods if p.workload == "api")
        port = self.installation.api_port
        command = [
            "kubectl",
            "--kubeconfig",
            str(self.api.kubeconfig),
            "--context",
            self.api.context,
            "--namespace",
            self.installation.request.target.namespace,
            "port-forward",
            "--address",
            "127.0.0.1",
            f"pod/{pin.name}",
            f":{port}",
        ]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            try:
                if not select.select([proc.stdout], [], [], 15)[0]:
                    raise RuntimeError("pod_tunnel_unavailable")
                bound = re.fullmatch(
                    rb"Forwarding from 127\.0\.0\.1:(\d+) -> (\d+)\n", proc.stdout.readline(128)
                )
                if not bound or int(bound[2]) != port:
                    raise RuntimeError("pod_tunnel_unavailable")
                yield LocalPodConnection(int(bound[1]))
            finally:
                proc.terminate()
                try:
                    proc.wait(3)
                except subprocess.TimeoutExpired:
                    proc.kill()


class LocalPodConnection:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, body=None, authorization=None):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if authorization:
            headers["Authorization"] = authorization
        connection = HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            connection.request(
                method, path, json.dumps(body) if body is not None else None, headers
            )
            response = connection.getresponse()
            raw = response.read(8193)
            if len(raw) > 8192:
                raise ValueError("oversize_application_response")
            return response.status, strict_json(raw)
        finally:
            connection.close()
