"""Private local transport for the independently durable Kubernetes target."""

import argparse
import json
import os
import socket
import socketserver
import stat
from pathlib import Path
from typing import Literal

from pydantic import model_validator

from birbverify.contract import Record
from birbverify.kubernetes_api import KubernetesAPI
from birbverify.kubernetes_contract import KubernetesInstallation, KubernetesRequest
from birbverify.kubernetes_target import KubernetesTarget

MAX_MESSAGE = 1024 * 1024


class Command(Record):
    schema_version: Literal["birbverify.kubernetes.transport.v1"]
    method: Literal["begin", "execute", "inspect", "close"]
    request: KubernetesRequest
    reason: Literal["completed", "cancelled", "worker_lost"] | None = None

    @model_validator(mode="after")
    def closure_reason(self):
        if (self.method == "close") != (self.reason is not None):
            raise ValueError("reason_required_only_for_close")
        return self


class TargetService(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, path: Path, target: KubernetesTarget):
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = parent.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("socket_directory_must_be_private_and_owned")
        self.target = target
        super().__init__(str(path), Handler, bind_and_activate=False)
        try:
            self.server_bind()
            os.chmod(path, 0o600)
            self.server_activate()
        except BaseException:
            self.server_close()
            raise


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(30)
        try:
            raw = self.rfile.readline(MAX_MESSAGE + 1)
            if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                raise ValueError("invalid_message_size")
            command = Command.model_validate_json(raw)
            target = self.server.target
            if command.method == "close":
                result = target.close(command.request, reason=command.reason)
            else:
                result = getattr(target, command.method)(command.request)
            response = {"ok": True, "result": result}
        except Exception as error:
            # Kubernetes client errors can include credentials or installation paths.
            response = {"ok": False, "error": type(error).__name__}
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")


def call_target(path: Path, method: str, request: dict, *, reason: str | None = None) -> dict:
    command = Command.model_validate(
        {
            "schema_version": "birbverify.kubernetes.transport.v1",
            "method": method,
            "request": request,
            "reason": reason,
        }
    )
    message = command.model_dump_json().encode() + b"\n"
    if len(message) > MAX_MESSAGE:
        raise ValueError("invalid_message_size")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(120)
        connection.connect(str(path))
        connection.sendall(message)
        with connection.makefile("rb") as stream:
            raw = stream.readline(MAX_MESSAGE + 1)
    if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
        raise RuntimeError("invalid_target_response")
    response = json.loads(raw)
    if response.get("ok") is not True:
        raise RuntimeError("target_rejected:" + str(response.get("error", "unknown")))
    if not isinstance(response.get("result"), dict):
        raise RuntimeError("invalid_target_result")
    return response["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--context", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    installation = KubernetesInstallation.model_validate_json(args.installation.read_text())
    target = KubernetesTarget(
        args.database, KubernetesAPI(args.kubeconfig, args.context), installation
    )
    with TargetService(args.socket, target) as server:
        try:
            server.serve_forever()
        finally:
            args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
