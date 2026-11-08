"""Disposable process which attempts a target mutation after its owner is revoked."""

import json
import sys
import time
from pathlib import Path

from birbverify.target import TargetError, rpc

root = Path(sys.argv[1])
operation = json.loads((root / "stale-operation.json").read_text())
(root / "stale-ready").touch()
while not (root / "stale-go").exists():
    time.sleep(0.05)
try:
    rpc(root, "apply", **operation)
except TargetError as error:
    (root / "stale-result").write_text(str(error))
    raise SystemExit(0 if str(error) == "fenced" else 2)
raise SystemExit("stale mutation was accepted")
