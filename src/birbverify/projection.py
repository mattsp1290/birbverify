from pathlib import Path

from ag_ui.core import EventType, RunFinishedEvent, RunStartedEvent, StateSnapshotEvent

from birbverify.contract import Manifest
from birbverify.target import rpc


def observe(root: Path, attempt_id: str):
    snapshot = rpc(root, "snapshot", attempt_id=attempt_id)
    if snapshot is None:
        raise ValueError("unknown attempt")
    request_id = snapshot["request"]
    yield RunStartedEvent(type=EventType.RUN_STARTED, thread_id=request_id, run_id=attempt_id)
    manifest = (
        Manifest.model_validate_json(snapshot["manifest"]).model_dump(mode="json")
        if snapshot["manifest"]
        else None
    )
    state = {
        "verification": {
            "contract_version": "birbverify.v1",
            "request_id": request_id,
            "attempt_id": attempt_id,
            "state": snapshot["state"],
            "manifest": manifest,
        }
    }
    yield StateSnapshotEvent(type=EventType.STATE_SNAPSHOT, snapshot=state)
    if manifest:
        yield RunFinishedEvent(type=EventType.RUN_FINISHED, thread_id=request_id, run_id=attempt_id)
