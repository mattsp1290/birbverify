import asyncio
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from birbverify.contract import (
    Artifact,
    CheckRecord,
    Id,
    Manifest,
    Request,
    digest,
    eligible,
)
from birbverify.lifecycle import GatedDocker, UnknownDelivery, container_path
from birbverify.policy import CAPABILITIES, authorize
from birbverify.target import TargetError, rpc

IMAGE = "python@sha256:a58daefb915e1e03ad48f3ca4df8832065412c5c35cacb9d39f4229184de12b6"
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


def now():
    return datetime.now(UTC)


def git(repository: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repository), *args], env=SAFE_ENV)


class Busy(RuntimeError):
    pass


@dataclass
class ExecutionState:
    stopped: bool = True
    cancellation_requested: bool = False


async def settle(task: asyncio.Task, state: ExecutionState):
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            state.cancellation_requested = True
            if task.cancelled():
                raise RuntimeError("control_task_interrupted") from None


class Runner:
    def __init__(self, root: Path):
        self.root = root
        self.config = json.loads((root / "installation.json").read_text())
        self.binding = None
        self.registration = None
        if self.config.get("closure_binding"):
            launch_path = os.environ.get("BIRBVERIFY_LAUNCH")
            if not launch_path:
                raise ValueError("launcher_binding_required")
            launch = json.loads(Path(launch_path).read_text())
            self.binding = launch["binding"]
            self.registration = launch["registration"]
            if self.binding != self.config["closure_binding"]:
                raise ValueError("launcher_binding_mismatch")

    def call(self, method, **data):
        return rpc(self.root, method, binding=self.binding, **data)

    def validate(self, request: Request):
        authorize(request, self.config)

    def diagnostic(self, request: Request, attempt_id: str, event: str):
        allowed = {
            "running",
            "operation_reconciled",
            "cancel_requested",
            "terminal",
            "infrastructure_uncertain",
            "evidence_missing",
        }
        if event not in allowed:
            raise ValueError("unknown diagnostic event")
        record = {
            "at": now().isoformat(),
            "event": event,
            "request_id": request.request_id,
            "attempt_id": attempt_id,
            "correlation_id": request.correlation_id,
            "telemetry_correlation": request.evidence.telemetry_correlation,
            "candidate": request.candidate.commit,
        }
        with (self.root / "diagnostics.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")

    def artifact(self, request: Request, kind: str, content: bytes) -> Artifact:
        if len(content) > 65536:
            raise ValueError("artifact_too_large")
        identity = digest(content)
        path = self.root / "artifacts" / identity
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if path.exists() and path.read_bytes() != content:
            raise ValueError("artifact_corrupt")
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        path.chmod(0o600)
        return Artifact(
            id=identity,
            kind=kind,
            sha256=identity,
            size=len(content),
            captured_at=now(),
            classification="private",
            retention=request.evidence.retention,
        )

    def read_artifact(self, artifact: Artifact) -> bytes | None:
        path = self.root / "artifacts" / artifact.id
        try:
            return path.read_bytes() if path.is_file() else None
        except OSError:
            return None

    def artifacts_available(self, result: Manifest) -> bool:
        return all(
            (content := self.read_artifact(artifact)) is not None
            and len(content) == artifact.size
            and digest(content) == artifact.sha256
            for check in result.checks
            for artifact in check.artifacts
        )

    def prepare(self, request: Request, attempt_id: str) -> Path:
        repository = Path(self.config["repository"])
        commit = request.candidate.commit
        if subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                request.candidate.base,
                commit,
            ],
            env=SAFE_ENV,
            capture_output=True,
        ).returncode:
            raise ValueError("base_not_ancestor")
        if git(repository, "rev-parse", f"{commit}^{{commit}}").decode().strip() != commit:
            raise ValueError("candidate_not_exact")
        directory = self.root / "checkouts" / attempt_id
        directory.mkdir(parents=True, mode=0o755)
        directory.chmod(0o755)
        # Only the approved fixture procedure and data enter the candidate container.
        for filename in ("check.py", "value.json"):
            content = git(repository, "show", f"{commit}:{filename}")
            if len(content) > 65536:
                raise ValueError("candidate_file_too_large")
            (directory / filename).write_bytes(content)
            (directory / filename).chmod(0o644)
        for check in request.plan.checks:
            if digest((directory / check.procedure_path).read_bytes()) != check.procedure_sha256:
                raise ValueError("candidate_weakened_approved_procedure")
            trusted = git(repository, "show", f"{check.procedure_revision}:{check.procedure_path}")
            if digest(trusted) != check.procedure_sha256:
                raise ValueError("trusted_procedure_mismatch")
        return directory

    async def docker(self, *args):
        process = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            env=SAFE_ENV,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            async with asyncio.timeout(65 if args[0] == "start" else 10):
                output = b""
                while chunk := await process.stdout.read(8192):
                    output += chunk
                    if len(output) > 65536:
                        raise ValueError("output_bound_exceeded")
                await process.wait()
            return process.returncode, output
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def stop_container(self, name: str) -> bool:
        await self.docker("rm", "-f", name)
        code, output = await self.docker("container", "inspect", name)
        return code != 0 and b"No such container" in output

    async def check(
        self, request: Request, attempt_id: str, directory: Path, owner: dict, state: ExecutionState
    ):
        if self.binding:
            return await self.closure_check(request, attempt_id, directory, owner, state)
        name = f"birbverify-{attempt_id}"
        state.stopped = False
        creation_settled = False
        creation = asyncio.create_task(
            self.docker(
                "create",
                "--pull=never",
                "--label",
                f"birbverify.attempt={attempt_id}",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "128m",
                "--cpus",
                "1",
                "--user",
                "65534:65534",
                "--log-driver",
                "none",
                "--mount",
                f"type=bind,src={directory},dst=/candidate,readonly",
                IMAGE,
                "python",
                "-I",
                "-S",
                "/candidate/check.py",
            )
        )
        try:
            code, _ = await settle(creation, state)
            creation_settled = True
            if state.cancellation_requested:
                raise asyncio.CancelledError
            if code:
                raise RuntimeError("container_create_failed")
            self.call("assert_active", **owner)
            seconds = min(
                request.resources.timeout_seconds,
                max(0.01, (request.resources.deadline - now()).total_seconds()),
            )
            async with asyncio.timeout(seconds):
                start_code, observation = await self.docker("start", "-a", name)
            code, raw_status = await self.docker("inspect", "--format", "{{json .State}}", name)
            if code:
                raise RuntimeError("container_start_or_status_failed")
            status = json.loads(raw_status)
            if status["Status"] != "exited" or status["StartedAt"].startswith("0001-"):
                raise RuntimeError("container_never_executed")
            exit_code = status["ExitCode"]
            if exit_code not in (0, 1) or start_code != exit_code:
                raise RuntimeError("procedure_infrastructure_error")
            observed = json.loads(observation)
            if not isinstance(observed, dict):
                raise RuntimeError("invalid_procedure_observation")
            if observed.get("assertion") != request.plan.checks[0].assertion or observed.get(
                "passed"
            ) is not (exit_code == 0):
                raise RuntimeError("invalid_procedure_observation")
            return exit_code, observation
        except asyncio.CancelledError:
            state.cancellation_requested = True
            raise
        finally:
            cleanup = asyncio.create_task(self.stop_container(name))
            stopped = await settle(cleanup, state)
            state.stopped = bool(stopped and creation_settled)
            if not state.stopped:
                raise RuntimeError("container_stop_unknown")
            if state.cancellation_requested:
                raise asyncio.CancelledError

    async def closure_check(self, request, attempt_id, directory, owner, state):
        import base64
        import struct

        name = f"birbverify-{attempt_id}"
        controls = GatedDocker(
            self.root,
            self.call,
            request.request_id,
            owner["execution_epoch"],
            attempt_id,
            self.registration,
            owner=owner,
        )
        body = {
            "Image": IMAGE,
            "Cmd": ["python", "-I", "-S", "/candidate/check.py"],
            "User": "65534:65534",
            "AttachStdout": True,
            "AttachStderr": True,
            "Labels": {
                "birbverify.attempt": attempt_id,
                "birbverify.incarnation": self.binding["target_incarnation"],
                "birbverify.worker_execution": self.registration["worker_execution_id"],
                "proof": "contextless-20261108",
            },
            "HostConfig": {
                "Binds": [f"{directory}:/candidate:ro"],
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "PidsLimit": 32,
                "Memory": 134217728,
                "NanoCpus": 1000000000,
                "LogConfig": {"Type": "json-file", "Config": {"max-size": "64k", "max-file": "1"}},
            },
        }
        state.stopped = False

        async def command(suffix, verb, method, path, payload=None):
            task = asyncio.create_task(
                controls.async_command(
                    attempt_id + "." + suffix,
                    verb,
                    name,
                    method,
                    path,
                    payload,
                )
            )
            result = await settle(task, state)
            if state.cancellation_requested:
                raise asyncio.CancelledError
            return result

        try:
            response = await command(
                "create", "create", "POST", "/containers/create?name=" + name, body
            )
            if response["status"] != 201:
                raise RuntimeError("container_create_failed")
            seconds = min(
                request.resources.timeout_seconds,
                max(0.01, (request.resources.deadline - now()).total_seconds()),
            )
            end = asyncio.get_running_loop().time() + seconds
            controls.engine.timeout = seconds
            response = await command("start", "start", "POST", container_path(name) + "/start")
            if response["status"] != 204:
                raise RuntimeError("container_start_failed")
            controls.engine.timeout = end - asyncio.get_running_loop().time()
            if controls.engine.timeout <= 0:
                raise TimeoutError("procedure_timeout")
            response = await command(
                "wait", "wait", "POST", container_path(name) + "/wait?condition=not-running"
            )
            if asyncio.get_running_loop().time() >= end:
                raise TimeoutError("procedure_timeout")
            controls.engine.timeout = 65
            status = json.loads(base64.b64decode(response["body_base64"]))
            exit_code = status["StatusCode"]
            if exit_code not in {0, 1}:
                raise RuntimeError("procedure_infrastructure_error")
            response = await command(
                "logs", "logs", "GET", container_path(name) + "/logs?stdout=true&stderr=true"
            )
            raw = base64.b64decode(response["body_base64"])
            output = b""
            while raw:
                if len(raw) < 8:
                    raise RuntimeError("truncated_container_output")
                size = struct.unpack(">I", raw[4:8])[0]
                if len(raw) < 8 + size:
                    raise RuntimeError("truncated_container_output")
                output += raw[8 : 8 + size]
                raw = raw[8 + size :]
            observation = json.loads(output)
            if (
                not isinstance(observation, dict)
                or observation.get("assertion") != request.plan.checks[0].assertion
                or observation.get("passed") is not (exit_code == 0)
            ):
                raise RuntimeError("invalid_procedure_observation")
            return exit_code, output
        finally:
            controls.engine.timeout = 65
            try:
                task = asyncio.create_task(
                    controls.async_command(
                        attempt_id + ".remove",
                        "remove",
                        name,
                        "DELETE",
                        container_path(name) + "?force=true",
                    )
                )
                await settle(task, state)
                task = asyncio.create_task(
                    controls.async_command(
                        attempt_id + ".absent",
                        "inspect",
                        name,
                        "GET",
                        container_path(name) + "/json",
                    )
                )
                absent = await settle(task, state)
                state.stopped = absent["status"] == 404
            except (TargetError, UnknownDelivery, OSError):
                state.stopped = False
            if state.cancellation_requested:
                raise asyncio.CancelledError

    def context_path(self, attempt_id):
        directory = self.root / "contexts" if self.binding else self.root
        return directory / f"{attempt_id}.context.json"

    def context(self, attempt_id):
        return json.loads(self.context_path(attempt_id).read_text())

    def finalize(
        self,
        request: Request,
        context: dict,
        checks: list[CheckRecord],
        outcome: str,
        *,
        reconciled=False,
        cancellation="none",
        termination="confirmed",
        before=None,
        reason=None,
    ):
        owner = context["owner"]
        environment = self.call("inspect")["environment"]
        after = environment["candidate"]
        previous = self.call("snapshot", attempt_id=owner["attempt_id"])
        if previous and previous["manifest"]:
            return Manifest.model_validate_json(previous["manifest"])
        if environment["state"] == "quarantined":
            if outcome != "failed":
                outcome = "inconclusive"
            termination = "unknown"
            if cancellation != "none":
                cancellation = "requested"
        elif outcome == "passed" and environment["state"] != "active":
            outcome = "inconclusive"
        if termination == "confirmed":
            self.call("stop", **owner)
            self.call("cleanup", **owner)
        else:
            self.call("uncertain", **owner)
        existing = {check.check_id for check in checks}
        checks.extend(
            CheckRecord(
                check_id=check.id,
                outcome="not_run",
                observation="check did not finish before " + outcome,
                duration_ms=0,
                artifacts=(),
            )
            for check in request.plan.checks
            if check.id not in existing
        )
        result = Manifest(
            contract_version="birbverify.v1",
            request_id=request.request_id,
            request_sha256=digest(request),
            attempt_id=owner["attempt_id"],
            attempt_number=context["attempt_number"],
            retry_reason=context["retry_reason"],
            prior_attempt_id=context["prior_attempt_id"],
            correlation_id=request.correlation_id,
            telemetry_correlation=request.evidence.telemetry_correlation,
            candidate=request.candidate,
            plan_sha256=request.plan_sha256,
            policy_revision=request.authority.policy_revision,
            environment=request.authority.environment,
            worker_id="fixture-linux-worker",
            worker_capabilities=CAPABILITIES,
            tools=(
                f"python-{platform.python_version()}",
                "temporalio-" + importlib.metadata.version("temporalio"),
                IMAGE,
            ),
            started_at=context["started_at"],
            finished_at=now(),
            observed_before=before,
            observed_after=after,
            checks=tuple(checks),
            operation_id=f"{request.request_id}.apply",
            operation_reconciled=reconciled,
            outcome=outcome,
            cleanup="complete" if termination == "confirmed" else "unknown",
            cancellation=cancellation,
            termination=termination,
            environment_release="released" if termination == "confirmed" else "quarantined",
            reason=reason
            or (
                "cancellation_acknowledged"
                if outcome == "cancelled"
                else "termination_unknown"
                if termination == "unknown"
                else "infrastructure_error"
                if outcome == "inconclusive"
                else "checks_completed"
            ),
        )
        if result.outcome == "passed" and (
            not eligible(request, result, request.candidate, self.read_artifact)
        ):
            self.diagnostic(request, owner["attempt_id"], "evidence_missing")
            result = result.model_copy(
                update={"outcome": "inconclusive", "reason": "required_evidence_missing"}
            )
        try:
            self.call(
                "finish",
                **owner,
                manifest=result.model_dump(mode="json"),
                lose_reply=request.request_id in self.config.get("lose_finish_reply", []),
            )
        except (ValueError, OSError):
            committed = self.call("result", request_id=request.request_id)
            if committed is None:
                raise RuntimeError("manifest_commit_unknown") from None
            result = Manifest.model_validate(committed)
        self.diagnostic(request, owner["attempt_id"], "terminal")
        return result

    async def execute(self, payload: dict, attempt_id: str, heartbeat=lambda: None):
        request = Request.model_validate(payload)
        TypeAdapter(Id).validate_python(attempt_id)
        self.validate(request)
        admission = self.call(
            "admit",
            request=payload,
            **(
                {
                    "admission_target_incarnation": self.binding["target_incarnation"],
                }
                if self.binding
                else {}
            ),
        )
        reservation_binding = (
            {
                "execution_epoch": admission["execution_epoch"],
                "worker_execution_id": self.registration["worker_execution_id"],
            }
            if self.binding
            else {}
        )
        prior = self.call("result", request_id=request.request_id)
        if prior:
            return Manifest.model_validate(prior).model_dump(mode="json")
        reservation = self.call(
            "reserve", request_id=request.request_id, attempt_id=attempt_id, **reservation_binding
        )
        if reservation.get("busy"):
            raise Busy("environment_wait")
        if "result" in reservation:
            return reservation["result"]
        owner = {"attempt_id": attempt_id, "token": reservation["token"]}
        if self.binding:
            owner["execution_epoch"] = reservation["execution_epoch"]
        if self.binding and self.config.get("fixture_pause_before_context"):
            (self.root / "launch" / "reserved.ready").touch()
            until = time.monotonic() + 30
            while not (self.root / "launch" / "reserved.continue").exists():
                if time.monotonic() >= until:
                    raise RuntimeError("fixture_barrier_timeout")
                heartbeat()
                await asyncio.sleep(0.025)
        context = {
            "owner": owner,
            "attempt_number": reservation["attempt_number"],
            "started_at": now().isoformat(),
            "request": payload,
            "retry_reason": "initial"
            if reservation["attempt_number"] == 1
            else "infrastructure_recovery",
            "prior_attempt_id": reservation["prior_attempt_id"],
        }
        self.context_path(attempt_id).write_text(json.dumps(context))
        self.diagnostic(request, attempt_id, "running")
        operation = {
            **owner,
            "operation_id": f"{request.request_id}.apply",
            "request_id": request.request_id,
            "candidate": request.candidate.commit,
            "payload_sha256": digest(
                {"request": digest(request), "candidate": request.candidate.commit}
            ),
        }
        state = ExecutionState()
        checks = []
        reconciled = False
        before = None
        try:
            directory = self.prepare(request, attempt_id)
            receipt = self.call("receipt", **operation)
            reconciled = receipt is not None
            if reconciled:
                self.diagnostic(request, attempt_id, "operation_reconciled")
            else:
                try:
                    receipt = self.call(
                        "apply",
                        **operation,
                        lose_reply=request.request_id
                        in self.config.get("lose_operation_reply", []),
                    )
                except (ValueError, OSError):
                    receipt = self.call("receipt", **operation)
                    if receipt is None:
                        raise RuntimeError("operation_result_unknown") from None
                    reconciled = True
                    self.diagnostic(request, attempt_id, "operation_reconciled")
            before = self.call("inspect")["environment"]["candidate"]
            if before != receipt["candidate"]:
                raise RuntimeError("receipt_target_mismatch")
            if request.request_id in self.config.get("pause_after_effect", []):
                (self.root / f"{attempt_id}.effect-committed").touch()
                while not (self.root / f"{attempt_id}.resume").exists():
                    heartbeat()
                    await asyncio.sleep(0.1)
            for check in request.plan.checks:
                started = time.monotonic()
                heartbeat()
                code, observation = await self.check(request, attempt_id, directory, owner, state)
                command = json.dumps(
                    {
                        "request_id": request.request_id,
                        "attempt_id": attempt_id,
                        "argv": ["python", "-I", "-S", "/candidate/check.py"],
                        "candidate": request.candidate.commit,
                        "procedure_sha256": check.procedure_sha256,
                        "image": IMAGE,
                        "exit_code": code,
                    }
                ).encode()
                artifacts = (
                    self.artifact(request, "observation", observation),
                    self.artifact(request, "command", command),
                )
                if request.request_id in self.config.get("drop_evidence", []):
                    artifacts = artifacts[:1]
                checks.append(
                    CheckRecord(
                        check_id=check.id,
                        outcome="passed" if code == 0 else "failed",
                        observation=observation.decode(errors="replace")[:1024],
                        duration_ms=int((time.monotonic() - started) * 1000),
                        artifacts=artifacts,
                    )
                )
            outcome = "failed" if any(check.outcome == "failed" for check in checks) else "passed"
            return self.finalize(
                request, context, checks, outcome, reconciled=reconciled, before=before
            ).model_dump(mode="json")
        except asyncio.CancelledError:
            self.diagnostic(request, attempt_id, "cancel_requested")
            self.call("cancel", **owner)
            return self.finalize(
                request,
                context,
                checks,
                "cancelled" if state.stopped else "inconclusive",
                reconciled=reconciled,
                termination="confirmed" if state.stopped else "unknown",
                cancellation="acknowledged" if state.stopped else "requested",
                before=before,
            ).model_dump(mode="json")
        except (RuntimeError, ValueError, OSError, TimeoutError, TargetError, KeyError) as error:
            if isinstance(error, TargetError) and str(error) == "request_closed":
                raise
            (self.root / f"{attempt_id}.error.txt").write_text(repr(error))
            self.diagnostic(request, attempt_id, "infrastructure_uncertain")
            if state.cancellation_requested:
                self.call("cancel", **owner)
            return self.finalize(
                request,
                context,
                checks,
                "inconclusive",
                reconciled=reconciled,
                termination="confirmed" if state.stopped else "unknown",
                cancellation="requested" if state.cancellation_requested else "none",
                before=before,
            ).model_dump(mode="json")


if __name__ == "__main__":
    os.umask(0o077)
    root, request_file, attempt_id = sys.argv[1:]
    result = asyncio.run(
        Runner(Path(root)).execute(json.loads(Path(request_file).read_text()), attempt_id)
    )
    print(json.dumps(result))
