import json
from pathlib import Path

import pytest

from birbverify.contract import Request, digest
from birbverify.target import Target, TargetError


def test_target_transactions(tmp_path):
    request = Request.model_validate_json(Path("contracts/v1/request.example.json").read_text())
    target = Target(
        tmp_path / "target.sqlite",
        {
            "policy_revision": request.authority.policy_revision,
            "fixture_mode": True,
            "recovery_key_sha256": digest(b"synthetic-supervisor"),
            "plan_sha256": request.plan_sha256,
        },
    )
    payload = request.model_dump(mode="json")
    assert target.call("admit", {"request": payload}) == payload
    assert target.call("admit", {"request": payload}) == payload
    with pytest.raises(TargetError, match="identity_conflict"):
        target.call("admit", {"request": {**payload, "goal_id": "changed"}})
    reservation = target.call(
        "reserve", {"request_id": request.request_id, "attempt_id": "attempt-1"}
    )
    owner = {"attempt_id": "attempt-1", "token": reservation["token"]}
    operation = {
        **owner,
        "operation_id": "request-example.apply",
        "request_id": request.request_id,
        "candidate": request.candidate.commit,
        "payload_sha256": digest(
            {"request": digest(request), "candidate": request.candidate.commit}
        ),
    }
    assert target.call("receipt", operation) is None
    assert target.call("apply", operation)["value"] == 1
    assert target.call("receipt", operation)["value"] == 1
    assert target.call("apply", operation)["value"] == 1
    assert target.call("reserve", {"request_id": request.request_id, "attempt_id": "attempt-2"})[
        "busy"
    ]
    target.call("uncertain", owner)
    with pytest.raises(TargetError, match="fenced"):
        target.call("apply", operation)
    with pytest.raises(TargetError, match="termination_unknown"):
        target.call("cleanup", owner)
    with pytest.raises(TargetError, match="supervisor_required"):
        target.call("stop", owner)
    target.call("recover", {**owner, "recovery_key": "synthetic-supervisor"})
    target.call("cleanup", owner)
    with pytest.raises(TargetError, match="terminal_manifest_required"):
        target.call("release", {**owner, "recovery_key": "synthetic-supervisor"})
    assert target.call("inspect", {})["environment"]["state"] == "revoked"
    assert len(target.call("inspect", {})["operations"]) == 1
    assert json.loads(target.call("inspect", {})["operations"][0]["receipt"])["value"] == 1
