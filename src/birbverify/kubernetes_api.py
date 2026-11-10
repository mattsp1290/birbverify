"""Pinned Kubernetes transport for the credential-owning target process."""

import json
import subprocess
from pathlib import Path


class ApiError(RuntimeError):
    def __init__(self, message: str, *, not_found: bool = False):
        super().__init__(message)
        self.not_found = not_found
        self.status = 404 if not_found else None


class KubernetesAPI:
    def __init__(self, kubeconfig: Path, context: str):
        self.kubeconfig = kubeconfig.resolve(strict=True)
        self.context = context

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        args = [
            "kubectl",
            "--kubeconfig",
            str(self.kubeconfig),
            "--context",
            self.context,
            "--request-timeout=15s",
        ]
        match method:
            case "GET":
                args += ["get", "--raw", path]
            case "POST":
                args += ["create", "--raw", path, "-f", "-"]
            case "PUT":
                args += ["replace", "--raw", path, "-f", "-"]
            case "DELETE":
                args += ["delete", "--raw", path, "-f", "-"]
            case _:
                raise ValueError("unsupported_kubernetes_method")
        try:
            result = subprocess.run(
                args,
                input=json.dumps(body) if body is not None else None,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except subprocess.TimeoutExpired as error:
            raise ApiError("kubernetes_response_unknown") from error
        if result.returncode:
            raise ApiError(result.stderr.strip(), not_found="(NotFound)" in result.stderr)
        return json.loads(result.stdout)
