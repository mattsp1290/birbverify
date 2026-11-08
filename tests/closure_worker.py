import asyncio
import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

from birbverify.lifecycle import Engine
from birbverify.runner import Runner

root, mode, request_name, attempt = Path(sys.argv[1]), *sys.argv[2:]
payload = json.loads((root / "launch" / request_name).read_text())


def barrier(name):
    (root / "launch" / (name + ".ready")).write_text("ready")
    deadline = time.monotonic() + 40
    while not (root / "launch" / (name + ".continue")).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("fixture_barrier_timeout")
        time.sleep(0.02)


if mode == "before_admit":
    barrier("before-admit")
if mode == "before_start":
    original = Engine.send

    def send(self, command):
        if command.path.endswith("/start"):
            barrier("before-start")
        return original(self, command)

    Engine.send = send


class FixtureRunner(Runner):
    def call(self, method, **data):
        if mode == "before_reserve" and method == "reserve":
            barrier("before-reserve")
        return super().call(method, **data)

    def prepare(self, request, attempt_id):
        if mode == "acquired":
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import os,time,pathlib;os.setsid();"
                    f"root=pathlib.Path({str(root / 'launch')!r});"
                    "(root/'child-writes').write_text('waiting');"
                    "\nwhile not (root/'child-release').exists():time.sleep(.01)"
                    "\n(root/'child-after-release').write_text('escaped')",
                ]
            )
            barrier("acquired")
        return super().prepare(request, attempt_id)


if mode == "wrong_peer":
    launch = json.loads(Path(os.environ["BIRBVERIFY_LAUNCH"]).read_text())
    launch["registration"] = json.loads((root / "launch" / "other-registration.json").read_text())
    forged = root / "launch" / "wrong-peer-binding.json"
    forged.write_text(json.dumps(launch))
    os.environ["BIRBVERIFY_LAUNCH"] = str(forged)
if (root / "supervisor.key").exists() or (root / "target.sqlite").exists():
    raise RuntimeError("worker_mount_exposes_supervisor_authority")

try:
    result = asyncio.run(FixtureRunner(root).execute(payload, attempt))
    (root / "launch" / "worker-result.json").write_text(json.dumps(result))
except BaseException as error:
    (root / "launch" / "worker-traceback.txt").write_text(traceback.format_exc())
    (root / "launch" / "worker-error.json").write_text(
        json.dumps({"type": type(error).__name__, "error": str(error)})
    )
    raise
finally:
    (root / "launch" / "worker-ended").touch()
