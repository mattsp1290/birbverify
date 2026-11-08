"""Synthetic local installation setup."""

import json
import os
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from birbverify.contract import Plan, Request, digest
from birbverify.runner import SAFE_ENV, git

ROOT = Path(__file__).resolve().parents[2]
PROCESS_ENV = {**SAFE_ENV, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}


def initialize(root: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    repository = root / "repository"
    repository.mkdir()
    environment = {
        **SAFE_ENV,
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@localhost",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@localhost",
    }
    subprocess.run(["git", "init", "-q", str(repository)], env=environment, check=True)
    (repository / "check.py").write_bytes((ROOT / "fixtures/check.py").read_bytes())
    (repository / "value.json").write_text('{"value":42}\n')
    subprocess.run(["git", "-C", str(repository), "add", "."], env=environment, check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Fixture passing candidate"],
        env=environment,
        check=True,
    )
    passing = git(repository, "rev-parse", "HEAD").decode().strip()
    (repository / "value.json").write_text('{"value":7}\n')
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qam", "Fixture assertion failure"],
        env=environment,
        check=True,
    )
    failing = git(repository, "rev-parse", "HEAD").decode().strip()
    (repository / "value.json").write_text('{"value":42,"delay":20}\n')
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qam", "Fixture slow check"],
        env=environment,
        check=True,
    )
    slow = git(repository, "rev-parse", "HEAD").decode().strip()
    template = json.loads((ROOT / "contracts/v1/request.example.json").read_text())
    plan = Plan.model_validate(
        {
            **template["plan"],
            "revision": passing,
            "checks": [{**template["plan"]["checks"][0], "procedure_revision": passing}],
        }
    )
    config = {
        "repository": str(repository),
        "passing": passing,
        "failing": failing,
        "slow": slow,
        "plan": plan.model_dump(mode="json"),
        "plan_sha256": digest(plan),
        "policy_revision": template["authority"]["policy_revision"],
    }
    recovery_key = secrets.token_hex(32)
    (root / "supervisor.key").write_text(recovery_key)
    (root / "supervisor.key").chmod(0o600)
    config.update(fixture_mode=True, recovery_key_sha256=digest(recovery_key.encode()))
    (root / "installation.json").write_text(json.dumps(config))
    return config


def request(root: Path, name: str, *, failing=False, slow=False, timeout=30):
    config = json.loads((root / "installation.json").read_text())
    payload = json.loads((ROOT / "contracts/v1/request.example.json").read_text())
    commit = config["slow" if slow else "failing" if failing else "passing"]
    payload.update(
        request_id=name,
        idempotency_key=name,
        plan=config["plan"],
        plan_sha256=config["plan_sha256"],
    )
    payload["candidate"].update(commit=commit, pr_head=commit, base=config["passing"])
    payload["resources"].update(
        deadline=(datetime.now(UTC) + timedelta(seconds=150)).isoformat(),
        timeout_seconds=timeout,
        max_attempts=3,
    )
    return Request.model_validate(payload)


def spawn(root: Path, module: str, *args: str):
    log = (root / f"{module.rsplit('.', 1)[-1]}.log").open("ab")
    process = subprocess.Popen(
        [sys.executable, "-m", module, str(root), *args], env=PROCESS_ENV, stdout=log, stderr=log
    )
    log.close()
    return process


def start_target(root):
    process = spawn(root, "birbverify.target")
    config = json.loads((root / "installation.json").read_text())
    address = (
        root / "transport" / "target.sock"
        if config.get("closure_binding")
        else root / "target.sock"
    )
    for _ in range(100):
        if address.exists():
            return process
        if process.poll() is not None:
            raise RuntimeError("target failed to start")
        time.sleep(0.05)
    raise RuntimeError("target startup timeout")


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(initialize(Path(sys.argv[1]))))
