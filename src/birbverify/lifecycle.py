import asyncio
import base64
import http.client
import json
import os
import re
import socket
import tempfile
from pathlib import Path
from urllib.parse import quote

from birbverify.closure import EvidenceRef, HttpCommand, LifecycleIntent
from birbverify.contract import digest

CHECKER = "fixture-engine-http-v1"
ADAPTER = digest(
    {
        name: digest((Path(__file__).parent / name).read_bytes())
        for name in ("lifecycle.py", "closure_target.py", "fixture_launcher.py")
    }
)
CLEANUP = digest(b"fixture-reset-v1:sealed-owner-transaction")


class UnknownDelivery(RuntimeError):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save_evidence(root: Path, kind: str, value: dict) -> dict:
    content = encoded(value)
    identity = digest(content)
    directory = root / "lifecycle-evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
        temporary = stream.name
    path = directory / f"{identity}.json"
    os.replace(temporary, path)
    path.chmod(0o600)
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return EvidenceRef(id=identity, sha256=identity, kind=kind, checker_id=CHECKER).model_dump(
        mode="json"
    )


def load_evidence(root: Path, reference: dict) -> dict:
    ref = EvidenceRef.model_validate(reference)
    if ref.checker_id != CHECKER:
        raise ValueError("checker_identity_mismatch")
    path = root / "lifecycle-evidence" / f"{ref.id}.json"
    if path.is_symlink():
        raise ValueError("evidence_symlink")
    content = path.read_bytes()
    if len(content) > 1048576 or digest(content) != ref.sha256:
        raise ValueError("evidence_corrupt")
    return json.loads(content)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Engine:
    def __init__(self, socket_path="/var/run/docker.sock", timeout=65):
        self.socket_path = socket_path
        self.timeout = timeout

    def send(self, command: HttpCommand) -> dict:
        connection = UnixConnection(self.socket_path, self.timeout)
        body = encoded(command.body) if command.body is not None else None
        try:
            connection.request(
                command.method,
                command.path,
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            content = response.read(65537)
            if len(content) > 65536:
                raise UnknownDelivery("output_bound")
            if response.getheader("Content-Length") is not None and len(content) != int(
                response.getheader("Content-Length")
            ):
                raise UnknownDelivery("reply_truncated")
            return {
                "kind": "daemon_reply",
                "command": command.model_dump(mode="json"),
                "command_sha256": digest(command),
                "status": response.status,
                "body_base64": base64.b64encode(content).decode(),
                "body_sha256": digest(content),
            }
        except (OSError, ValueError, http.client.HTTPException, UnknownDelivery) as error:
            return {
                "kind": "delivery_unknown",
                "command": command.model_dump(mode="json"),
                "command_sha256": digest(command),
                "cause": type(error).__name__,
            }
        finally:
            connection.close()

    def raw(self, method, path, body=None):
        result = self.send(HttpCommand(method=method, path=path, body=body))
        if result["kind"] != "daemon_reply":
            raise UnknownDelivery(result["cause"])
        return result["status"], base64.b64decode(result["body_base64"], validate=True)

    def identity(self):
        status, content = self.raw("GET", "/info")
        if status != 200:
            raise UnknownDelivery("daemon_identity_unavailable")
        return json.loads(content)["ID"]


def classify(verb: str, response: dict) -> str:
    if response.get("kind") != "daemon_reply":
        return "unknown"
    try:
        content = base64.b64decode(response["body_base64"], validate=True)
        if digest(content) != response["body_sha256"]:
            return "unknown"
        status = response["status"]
        if verb == "create":
            if status == 201 and re.fullmatch(r"[0-9a-f]{64}", json.loads(content)["Id"]):
                return "effect"
            return "no_effect" if status in {400, 404} else "unknown"
        if verb == "start":
            return "effect" if status == 204 else "no_effect" if status in {304, 404} else "unknown"
        if verb == "remove":
            return "effect" if status == 204 else "no_effect" if status == 404 else "unknown"
        if verb in {"inspect", "list", "logs", "wait"}:
            return "observation" if status in {200, 404} else "unknown"
    except (KeyError, TypeError, ValueError):
        pass
    return "unknown"


class GatedDocker:
    def __init__(
        self,
        root,
        client,
        request_id,
        epoch,
        attempt_id,
        registration,
        owner=None,
        closure_id=None,
        recovery_key=None,
        engine=None,
    ):
        self.root = root
        self.client = client
        self.request_id = request_id
        self.epoch = epoch
        self.attempt_id = attempt_id
        self.registration = registration
        self.owner = owner or {}
        self.closure_id = closure_id
        self.recovery_key = recovery_key
        self.engine = engine or Engine(
            json.loads((root / "installation.json").read_text()).get(
                "fixture_daemon_socket", "/var/run/docker.sock"
            )
        )

    def command(self, operation_id, verb, container, method, path, body=None):
        command = HttpCommand(method=method, path=path, body=body)
        intent = LifecycleIntent(
            operation_id=operation_id,
            request_id=self.request_id,
            execution_epoch=self.epoch,
            attempt_id=self.attempt_id,
            worker_execution_id=self.registration["worker_execution_id"],
            authority="closure" if self.closure_id else "worker",
            closure_id=self.closure_id,
            verb=verb,
            container=container,
            command=command,
            arguments_sha256=digest(command),
        )
        data = {"intent": intent.model_dump(mode="json"), **self.owner}
        if self.recovery_key:
            data["recovery_key"] = self.recovery_key
        daemon_id = self.engine.identity()
        host_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if (
            daemon_id != self.registration["group"]["daemon_id"]
            or host_boot_id != self.registration["group"]["host_boot_id"]
        ):
            raise UnknownDelivery("execution_host_binding_mismatch")
        try:
            acknowledgement = self.client("lifecycle_intent", **data)
        except (ValueError, OSError) as error:
            raise UnknownDelivery("intent_ack_unknown") from error
        if not acknowledgement.get("send_authorized"):
            raise UnknownDelivery("intent_not_newly_acknowledged")
        response = self.engine.send(command)
        evidence = {
            "intent_sha256": digest(intent),
            "daemon_id": daemon_id,
            "host_boot_id": host_boot_id,
            "response": response,
        }
        reference = save_evidence(self.root, "daemon", evidence)
        self.client(
            "lifecycle_completion",
            operation_id=operation_id,
            evidence_ref=reference,
            checker_key=(self.root / "checker.key").read_text(),
        )
        if classify(verb, response) == "unknown":
            raise UnknownDelivery("daemon_delivery_unknown")
        return response

    async def async_command(self, *args, **kwargs):
        return await asyncio.to_thread(self.command, *args, **kwargs)

    def settled_command(self, operation_id, verb, container, method, path, body=None):
        records = self.client(
            "lifecycle_records", recovery_key=self.recovery_key, request_id=self.request_id
        )
        previous = next(
            (row for row in records if row["intent"]["operation_id"] == operation_id), None
        )
        if previous:
            wanted = HttpCommand(method=method, path=path, body=body)
            if previous["intent"]["arguments_sha256"] != digest(wanted):
                raise ValueError("operation_identity_conflict")
            if previous["settlement"] == "unknown" or previous["completion"] is None:
                raise UnknownDelivery("prior_command_unsettled")
            return load_evidence(self.root, previous["completion"])["response"]
        return self.command(operation_id, verb, container, method, path, body)


def container_path(container):
    return "/containers/" + quote(container, safe="")
