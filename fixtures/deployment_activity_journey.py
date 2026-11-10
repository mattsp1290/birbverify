"""Run the assertion suite against the accepted Birbparty source in disposable Compose."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import tarfile
import tempfile
from pathlib import Path

from deployment_storage_fixture import DisposableProject, baseline_snapshot, verify_restore

from birbverify.deployment_activity import _assert_account, suite_sha256
from birbverify.deployment_activity_runtime import LocalPodConnection

REVISION = "503d3bc238e2093eb0e098ecbe87b7e11ed16b4f"


def run(command, **kwargs):
    return (
        subprocess.run(list(map(str, command)), check=True, stdout=subprocess.PIPE, **kwargs)
        .stdout.decode()
        .strip()
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fixture_hashes():
    return {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("deployment_activity_journey.py", "deployment_storage_fixture.py")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    suite = suite_sha256()
    hashes = fixture_hashes()
    project = "aftl-auth-" + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix=project) as directory:
        root = Path(directory)
        with subprocess.Popen(
            ["git", "-C", str(args.source_repo), "archive", REVISION], stdout=subprocess.PIPE
        ) as export:
            with tarfile.open(fileobj=export.stdout, mode="r|") as archive:
                archive.extractall(root, filter="data")
            if export.wait():
                raise RuntimeError("source_export_failed")
        port = free_port()
        inputs = dict(
            POSTGRES_PASSWORD=secrets.token_urlsafe(32),
            OPENFGA_POSTGRES_PASSWORD=secrets.token_urlsafe(32),
            OPENFGA_PRESHARED_KEY=secrets.token_urlsafe(32),
            JWT_AUTH_KEY=secrets.token_urlsafe(32),
            API_HOST_PORT=str(port),
            API_PUBLIC_ORIGIN=f"http://127.0.0.1:{port}",
            POSTGRES_HOST_PORT=str(free_port()),
            OPENFGA_HOST_PORT=str(free_port()),
            HOST_BIND_ADDRESS="127.0.0.1",
            API_IMAGE_TAG=project,
            BIRBPARTY_REVISION=REVISION,
        )
        config = root / "disposable.env"
        config.write_text("".join(f"{key}={value}\n" for key, value in inputs.items()))
        config.chmod(0o600)
        env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"]}
        tag = "birbparty-api:" + project
        original = DisposableProject(project, root, env)
        recovered = DisposableProject(project + "-restore", root, env)
        try:
            run(
                [
                    "docker",
                    "build",
                    "--build-arg",
                    "BIRBPARTY_REVISION=" + REVISION,
                    "-f",
                    root / "crates/api/Dockerfile",
                    "-t",
                    tag,
                    root,
                ],
                env=env,
            )
            original.start()
            baseline = baseline_snapshot(original, root)
            original.start()
            assertions = {}
            _assert_account(LocalPodConnection(port).request, lambda: None, assertions)
            images = {}
            for service in ("api", "openfga", "postgres", "openfga-postgres"):
                cid = original.run("ps", "-q", service)
                images[service] = run(["docker", "inspect", "-f", "{{.Image}}", cid], env=env)
            storage = verify_restore(original, recovered, root, baseline)
        finally:
            try:
                recovered.run("down", "--volumes")
            finally:
                original.run("down", "--volumes")
            if (
                subprocess.run(
                    ["docker", "image", "inspect", tag],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                ).returncode
                == 0
            ):
                run(["docker", "image", "rm", tag], env=env)
    if suite_sha256() != suite or fixture_hashes() != hashes:
        raise RuntimeError("suite_changed_during_proof")
    print(
        json.dumps(
            dict(
                source_revision=REVISION,
                fixture_sha256=hashes,
                platform=os.uname().machine,
                images=images,
                suite_sha256=suite,
                assertions=assertions,
                storage=storage,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
