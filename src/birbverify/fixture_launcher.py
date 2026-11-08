import json
import os
import secrets
import sys
import time
import uuid
from pathlib import Path

from birbverify.closure import Binding, Registration
from birbverify.contract import digest
from birbverify.lifecycle import Engine, container_path, save_evidence
from birbverify.runner import IMAGE
from birbverify.target import rpc


def enable(root: Path, producer_revision: str):
    config = json.loads((root / "installation.json").read_text())
    binding = Binding(
        protocol="birbverify.target.v2", target_id="fixture-local", target_incarnation=uuid.uuid4()
    )
    key = secrets.token_hex(32)
    (root / "checker.key").write_text(key)
    (root / "checker.key").chmod(0o600)
    (root / "transport").mkdir(mode=0o700, exist_ok=True)
    config.update(
        closure_binding=binding.model_dump(mode="json"),
        closure_actor="fixture-supervisor",
        closure_grant="fixture-closure-grant",
        checker_key_sha256=digest(key.encode()),
        producer_revision=producer_revision,
        candidate_image=IMAGE,
    )
    (root / "installation.json").write_text(json.dumps(config))
    return config


def worker_configuration_violations(inspection):
    host = inspection["HostConfig"]
    return [
        name
        for name, bad in {
            "privileged": host.get("Privileged"),
            "pid_namespace": host.get("PidMode"),
            "capabilities": bool(host.get("CapAdd")) or "ALL" not in host.get("CapDrop", []),
            "restart": host.get("RestartPolicy", {}).get("Name") not in {"no", ""},
            "new_privileges": "no-new-privileges" not in host.get("SecurityOpt", []),
        }.items()
        if bad
    ]


class WorkerGroup:
    def __init__(self, root: Path, command: list[str], *, image=None, engine=None):
        self.root = root
        self.engine = engine or Engine()
        self.config = json.loads((root / "installation.json").read_text())
        self.binding = self.config["closure_binding"]
        self.identity = "worker-" + uuid.uuid4().hex
        self.container_id = None
        self.registration = None
        image = image or os.environ.get("BIRBVERIFY_WORKER_IMAGE")
        if not image:
            raise RuntimeError("BIRBVERIFY_WORKER_IMAGE_required")
        source = Path(__file__).resolve().parents[2]
        directories = ["checkouts", "artifacts", "lifecycle-evidence", "launch", "contexts"]
        for name in directories:
            (root / name).mkdir(mode=0o700, exist_ok=True)
        binds = [
            f"{source}:{source}:ro",
            f"{self.config['repository']}:{self.config['repository']}:ro",
            "/var/run/docker.sock:/var/run/docker.sock",
            f"{root}/installation.json:{root}/installation.json:ro",
            f"{root}/checker.key:{root}/checker.key:ro",
            f"{root}/transport:{root}/transport",
        ]
        binds.extend(f"{root}/{name}:{root}/{name}" for name in directories)
        body = {
            "Image": image,
            "Entrypoint": [sys.executable],
            "Cmd": [
                "-m",
                "birbverify.fixture_launcher",
                "wait",
                str(root),
                self.identity,
                *command,
            ],
            "WorkingDir": str(source),
            "Env": [f"PYTHONPATH={source}/src", "PYTHONUNBUFFERED=1"],
            "Labels": {
                "birbverify.worker_execution": self.identity,
                "proof": "contextless-20261108",
            },
            "HostConfig": {
                "Binds": binds,
                "Tmpfs": {str(root): "rw,mode=0700"},
                "NetworkMode": "host",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "RestartPolicy": {"Name": "no"},
            },
        }
        status, response = self.engine.raw("POST", "/containers/create?name=" + self.identity, body)
        if status != 201:
            raise RuntimeError("worker_create_failed")
        self.container_id = json.loads(response)["Id"]
        try:
            status, _ = self.engine.raw("POST", container_path(self.container_id) + "/start")
            if status != 204:
                raise RuntimeError("worker_start_failed")
            status, response = self.engine.raw("GET", container_path(self.container_id) + "/json")
            if status != 200:
                raise RuntimeError("worker_inspect_failed")
            inspection = json.loads(response)
            if worker_configuration_violations(inspection):
                raise RuntimeError("invalid_worker_execution_group")
            pid = inspection["State"]["Pid"]
            start = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            daemon = self.engine.identity()
            reference = save_evidence(
                root,
                "registration",
                {
                    "inspection": inspection,
                    "host_boot_id": boot,
                    "worker_start_ticks": start,
                    "daemon_id": daemon,
                },
            )
            self.registration = Registration(
                worker_execution_id=self.identity,
                target_id=self.binding["target_id"],
                target_incarnation=self.binding["target_incarnation"],
                launcher_id="fixture-launcher",
                group={
                    "kind": "docker_container",
                    "daemon_id": daemon,
                    "host_boot_id": boot,
                    "container_id": self.container_id,
                    "worker_pid": pid,
                    "worker_start_ticks": start,
                    "config_sha256": digest(inspection),
                },
                evidence_ref=reference,
            ).model_dump(mode="json")
            rpc(
                root,
                "register_worker",
                binding=self.binding,
                registration=self.registration,
                recovery_key=(root / "supervisor.key").read_text(),
            )
            (root / "launch" / self.identity).write_text(
                json.dumps(
                    {
                        "registration": self.registration,
                        "binding": self.binding,
                    }
                )
            )
        except BaseException:
            self.remove()
            raise

    def remove(self):
        if self.container_id:
            status, _ = self.engine.raw("DELETE", container_path(self.container_id) + "?force=true")
            if status not in {204, 404}:
                raise RuntimeError("worker_removal_unknown")
            status, _ = self.engine.raw("GET", container_path(self.container_id) + "/json")
            if status != 404:
                raise RuntimeError("worker_absence_unconfirmed")


def wait_for_registration(root, identity, command):
    launch = root / "launch" / identity
    deadline = time.monotonic() + 30
    while not launch.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("launcher_registration_timeout")
        time.sleep(0.02)
    os.environ["BIRBVERIFY_LAUNCH"] = str(launch)
    os.execv(command[0], command)


if __name__ == "__main__":
    if sys.argv[1] == "wait":
        wait_for_registration(Path(sys.argv[2]), sys.argv[3], sys.argv[4:])
