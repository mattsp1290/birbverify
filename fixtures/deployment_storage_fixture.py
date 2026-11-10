"""Offline restore checks for the disposable Birbparty Compose journey."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

ARCHIVER = "python@sha256:a58daefb915e1e03ad48f3ca4df8832065412c5c35cacb9d39f4229184de12b6"
VOLUMES = {"postgres-data", "openfga-postgres-data", "openfga-bootstrap-data"}
MOUNTS = {
    "postgres": [("postgres-data", "/var/lib/postgresql/data", True)],
    "openfga-postgres": [("openfga-postgres-data", "/var/lib/postgresql/data", True)],
    "authz-state-init": [("openfga-bootstrap-data", "/var/lib/birbparty-authz", True)],
    "authz-bootstrap": [("openfga-bootstrap-data", "/var/lib/birbparty-authz", True)],
    "api": [("openfga-bootstrap-data", "/var/lib/birbparty-authz", False)],
    "openfga-migrate": [],
    "openfga": [],
}


def output(command, env):
    return subprocess.check_output(command, env=env, text=True).strip()


class DisposableProject:
    def __init__(self, name, root, env):
        if not re.fullmatch(r"aftl-auth-[a-f0-9]{16}(?:-restore)?", name):
            raise ValueError("unexpected disposable project name")
        self.name = name
        self.env = env
        self.compose = [
            "docker",
            "compose",
            "--project-name",
            name,
            "--project-directory",
            str(root),
            "--file",
            str(root / "compose.yaml"),
            "--env-file",
            str(root / "disposable.env"),
        ]
        project_label = "label=com.docker.compose.project=" + name
        existing = output(["docker", "ps", "-aq", "--filter", project_label], env)
        networks = output(["docker", "network", "ls", "-q", "--filter", project_label], env)
        names = set(output(["docker", "volume", "ls", "-q"], env).splitlines())
        if existing or networks or any(n.startswith(name + "_") for n in names):
            raise RuntimeError("disposable project must be newly allocated")
        self.volumes = None

    def run(self, *args):
        return output([*self.compose, *args], self.env)

    def start(self):
        self.run("up", "-d", "--wait", "--wait-timeout", "150", "--no-build", "api")

    def accounts_and_sessions(self):
        counts = self.run(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-XAt",
            "-U",
            "birbparty",
            "-d",
            "birbparty",
            "-c",
            "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM auth_sessions)",
        )
        users, sessions = counts.split("|")
        return {"accounts": int(users), "sessions": int(sessions)}

    def quiescent_writers(self, *, before_start=False):
        if not before_start:
            self.run("stop", "--timeout", "3", "api", "openfga")
            self.run("stop", "--timeout", "30")
        ids = self.run("ps", "-aq").splitlines()
        writers = {}
        for cid in ids:
            # Inspect only public identity and lifecycle fields; never copy container environments.
            identity = output(
                [
                    "docker",
                    "inspect",
                    "-f",
                    '{{.Id}} {{index .Config.Labels "com.docker.compose.service"}} '
                    '{{index .Config.Labels "com.docker.compose.project"}} {{.Image}} '
                    "{{.State.Status}} {{.State.Pid}} {{.State.ExitCode}} "
                    "{{.State.OOMKilled}} {{.State.FinishedAt}}",
                    cid,
                ],
                self.env,
            ).split()
            cid, service, project, image, status, pid, exit_code, oom, finished = identity
            if project != self.name or service in writers or pid != "0" or oom != "false":
                raise RuntimeError("container ownership or stop state changed")
            if before_start:
                if status != "created":
                    raise RuntimeError("restore requires never-started containers")
            else:
                allowed_codes = {"0", "143", "137"} if service in {"api", "openfga"} else {"0"}
                if (
                    status != "exited"
                    or finished.startswith("0001-")
                    or exit_code not in allowed_codes
                ):
                    raise RuntimeError(f"{service} lacks an attributable stop")
            mounts = (
                json.loads(output(["docker", "inspect", "-f", "{{json .Mounts}}", cid], self.env))
                or []
            )
            expected = {(self.name + "_" + role, path, rw) for role, path, rw in MOUNTS[service]}
            actual = {(m.get("Name"), m["Destination"], m["RW"]) for m in mounts}
            if any(m["Type"] != "volume" for m in mounts) or actual != expected:
                raise RuntimeError("container mount inventory changed")
            writers[service] = {
                "container_id": cid,
                "image": image,
                "state": status,
                "exit_code": int(exit_code),
                "finished_at": finished,
            }
        if set(writers) != set(MOUNTS):
            raise RuntimeError("incomplete Compose writer set")
        return writers

    def offline_volumes(self):
        volumes = {}
        for role in sorted(VOLUMES):
            name = self.name + "_" + role
            (info,) = json.loads(output(["docker", "volume", "inspect", name], self.env))
            labels = info["Labels"]
            if (
                info["Name"] != name
                or info["Driver"] != "local"
                or info["Options"]
                or labels.get("com.docker.compose.project") != self.name
                or labels.get("com.docker.compose.volume") != role
                or output(["docker", "ps", "-q", "--filter", "volume=" + name], self.env)
            ):
                raise RuntimeError("volume ownership or quiescence check failed")
            volumes[role] = {"name": name, "created_at": info["CreatedAt"]}
        if self.volumes and self.volumes != volumes:
            raise RuntimeError("volume incarnation changed")
        self.volumes = volumes
        return volumes

    def volume_command(self, role, writable=False):
        if role not in VOLUMES:
            raise ValueError("unknown disposable volume")
        volume = self.offline_volumes()[role]["name"]
        mount = f"type=volume,source={volume},target=/volume,volume-nocopy"
        base = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network=none",
            "--read-only",
            "--security-opt=no-new-privileges",
            "--cap-drop=ALL",
            "--cap-add=DAC_OVERRIDE",
        ]
        if writable:
            base.extend(["--cap-add=CHOWN", "--cap-add=FOWNER"])
        else:
            mount += ",readonly"
        return [*base, "--mount", mount, ARCHIVER]


def capture(project, role, archive):
    command = [
        *project.volume_command(role),
        "tar",
        "--create",
        "--directory=/volume",
        "--file=-",
        "--sort=name",
        "--format=posix",
        "--numeric-owner",
        "--acls",
        "--xattrs",
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
        ".",
    ]
    with archive.open("xb") as out:
        subprocess.run(command, env=project.env, stdout=out, check=True)
    with archive.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def restore(project, role, archive):
    command = [
        *project.volume_command(role, writable=True),
        "sh",
        "-ec",
        'test -z "$(ls -A /volume)" && exec tar --extract --directory=/volume --file=- '
        "--numeric-owner --same-owner --same-permissions --delay-directory-restore --acls --xattrs",
    ]
    with archive.open("rb") as source:
        subprocess.run(command, env=project.env, stdin=source, check=True)


def baseline_snapshot(project, root: Path):
    baseline = project.accounts_and_sessions()
    if baseline != {"accounts": 0, "sessions": 0}:
        raise RuntimeError("fresh database has unexpected accounts or sessions")
    writers = project.quiescent_writers()
    hashes = {role: capture(project, role, root / f"{role}.tar") for role in sorted(VOLUMES)}
    return {
        "baseline_counts": baseline,
        "baseline_stops": writers,
        "source_volumes": project.volumes,
        "archive_sha256": hashes,
        "archiver": ARCHIVER,
    }


def verify_restore(original, recovered, root, evidence):
    after = original.accounts_and_sessions()
    if after != {"accounts": 1, "sessions": 1}:
        raise RuntimeError("expected a single committed registration and native session")
    stops = original.quiescent_writers()
    original.offline_volumes()
    for name, stop in stops.items():
        if stop["container_id"] != evidence["baseline_stops"][name]["container_id"]:
            raise RuntimeError("writer incarnation changed")
    recovered.run("create", "--no-build", "api")
    recovered.quiescent_writers(before_start=True)
    restored = {}
    for role in sorted(VOLUMES):
        restore(recovered, role, root / f"{role}.tar")
        restored[role] = capture(recovered, role, root / f"{role}.restored.tar")
    if restored != evidence["archive_sha256"]:
        raise RuntimeError("restored bytes or filesystem metadata differ")
    recovered.start()
    counts = recovered.accounts_and_sessions()
    if counts != evidence["baseline_counts"]:
        raise RuntimeError("restored application database differs after restart")
    return evidence | {
        "scope": "disposable Compose restore to new volumes",
        "release_authorized": False,
        "post_assertion_counts": after,
        "writer_stops": stops,
        "restored_counts": counts,
        "restored_volumes": recovered.volumes,
        "restored_sha256": restored,
    }
