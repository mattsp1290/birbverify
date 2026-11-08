import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest

from birbverify.closure import BeginClosure, ClosureReceipt, Progress
from birbverify.contract import Request, digest
from birbverify.fixture import initialize, request
from birbverify.fixture_launcher import enable
from birbverify.lifecycle import save_evidence
from birbverify.target import Target, TargetError


class Fixture:
    def __init__(self, root):
        self.root = root
        initialize(root)
        self.config = enable(root, "8" * 40)
        self.binding = self.config["closure_binding"]
        self.target = Target(root / "target.sqlite", self.config)
        self.key = (root / "supervisor.key").read_text()
        self.request = self.new_request("closure-first")
        self.peer = {
            "container_id": "a" * 64,
            "worker_pid": 100,
            "worker_start_ticks": 1234,
            "host_boot_id": str(uuid.uuid4()),
        }
        inspection = {
            "Id": self.peer["container_id"],
            "State": {"Pid": 100, "Running": True},
            "HostConfig": {
                "Privileged": False,
                "PidMode": "",
                "CapDrop": ["ALL"],
                "RestartPolicy": {"Name": "no"},
                "SecurityOpt": ["no-new-privileges"],
            },
            "Config": {"Labels": {"birbverify.worker_execution": "unit-worker"}},
        }
        reference = save_evidence(
            root,
            "registration",
            {
                "inspection": inspection,
                "daemon_id": "unit-daemon",
                "host_boot_id": self.peer["host_boot_id"],
                "worker_start_ticks": 1234,
            },
        )
        self.registration = {
            "worker_execution_id": "unit-worker",
            "target_id": "fixture-local",
            "target_incarnation": self.binding["target_incarnation"],
            "launcher_id": "unit-launcher",
            "group": {
                "kind": "docker_container",
                **self.peer,
                "daemon_id": "unit-daemon",
                "config_sha256": digest(inspection),
            },
            "evidence_ref": reference,
        }
        self.call("register_worker", registration=self.registration, recovery_key=self.key)

    def new_request(self, name):
        payload = request(self.root, name).model_dump(mode="json")
        payload["resources"]["max_attempts"] = 1
        return Request.model_validate(payload)

    def call(self, method, **data):
        return self.target.call(method, data, binding=self.binding, peer=self.peer)

    def admit(self, candidate=None):
        candidate = candidate or self.request
        return self.call(
            "admit",
            request=candidate.model_dump(mode="json"),
            admission_target_incarnation=self.binding["target_incarnation"],
        )

    def reserve(self, candidate=None, attempt="unit-attempt"):
        candidate = candidate or self.request
        admitted = self.admit(candidate)
        result = self.call(
            "reserve",
            request_id=candidate.request_id,
            attempt_id=attempt,
            execution_epoch=admitted["execution_epoch"],
            worker_execution_id="unit-worker",
        )
        return {
            "attempt_id": attempt,
            "token": result["token"],
            "execution_epoch": result["execution_epoch"],
        }

    def command(self, candidate=None):
        candidate = candidate or self.request
        return BeginClosure(
            closure_id=uuid.uuid4(),
            target_id="fixture-local",
            target_incarnation=self.binding["target_incarnation"],
            request=candidate,
            request_sha256=digest(candidate),
            expected_attempt_id=None,
            expected_execution_epoch=None,
            authorization={
                "principal": candidate.authority.principal,
                "workflow": candidate.authority.workflow,
                "policy_revision": candidate.authority.policy_revision,
                "admission_target_incarnation": self.binding["target_incarnation"],
                "closure_actor": "fixture-supervisor",
                "grant_reference": "fixture-closure-grant",
            },
            reason="context_lost",
        ).model_dump(mode="json")

    def begin(self, command):
        return self.call("begin_closure", command=command, recovery_key=self.key)

    def read(self, command):
        return self.call("read_closure", closure_id=command["closure_id"], recovery_key=self.key)

    def finish_never(self, command):
        self.begin(command)
        view = self.read(command)
        self.call(
            "cleanup_closure",
            closure_id=command["closure_id"],
            recovery_key=self.key,
            cleanup_payload_sha256=view["cleanup_payload_sha256"],
            expected_revision=view["record_revision"],
        )
        view = self.read(command)
        return self.call(
            "release_closure",
            closure_id=command["closure_id"],
            recovery_key=self.key,
            expected_revision=view["record_revision"],
        )

    def snapshot(self, *requests):
        return self.call(
            "observe_closure_state", request_ids=list(requests or [self.request.request_id])
        )


@pytest.fixture
def fixture(tmp_path):
    return Fixture(tmp_path / "fixture")


def test_f01_f02_f19_never_acquired_is_permanently_closed(fixture):
    f = fixture
    command = f.command()
    receipt = f.finish_never(command)
    assert receipt["acquisition"]["kind"] == "never_acquired"
    assert receipt["history"] == {"manifest_status": "unavailable", "manifest_sha256": None}
    assert ClosureReceipt.model_validate(receipt)
    admitted = f.admit()
    assert admitted["sealed"]
    with pytest.raises(TargetError, match="request_closed"):
        f.reserve()
    changed = f.request.model_copy(update={"goal_id": "changed"})
    with pytest.raises(TargetError, match="identity_conflict"):
        f.admit(changed)
    assert f.snapshot()["requests"][0]["terminal"] == "closed_without_verification"
    assert f.snapshot()["environment"]["owner"]["kind"] == "none"
    second = f.new_request("second")
    epoch = f.admit(second)["execution_epoch"]
    second_command = f.command(second)
    f.finish_never(second_command)
    assert f.admit(second)["execution_epoch"] == epoch
    with pytest.raises(TargetError, match="request_closed"):
        f.reserve(second)


def test_f12_f13_f14_f15_f16_durable_replay_and_successor(fixture):
    f = fixture
    command = f.command()
    original = f.begin(command)
    f.target = Target(f.root / "target.sqlite", f.config)
    assert f.begin(command) == original
    view = f.read(command)
    args = {
        "closure_id": command["closure_id"],
        "recovery_key": f.key,
        "cleanup_payload_sha256": view["cleanup_payload_sha256"],
        "expected_revision": view["record_revision"],
    }
    cleaned = f.call("cleanup_closure", **args)
    assert f.call("cleanup_closure", **args) == cleaned
    with pytest.raises(TargetError, match="cleanup_payload_conflict"):
        f.call("cleanup_closure", **{**args, "cleanup_payload_sha256": "0" * 64})
    receipt = f.call(
        "release_closure",
        closure_id=command["closure_id"],
        recovery_key=f.key,
        expected_revision=cleaned["record_revision"],
    )
    successor = f.new_request("successor")
    owner = f.reserve(successor, "successor-attempt")
    before = f.snapshot(successor.request_id)
    assert (
        f.call(
            "release_closure",
            closure_id=command["closure_id"],
            recovery_key=f.key,
            expected_revision=0,
        )
        == receipt
    )
    assert f.snapshot(successor.request_id) == before
    f.call("assert_active", **owner)
    for update in (
        {"reason": "dispatch_unknown"},
        {"expected_execution_epoch": 1},
        {"expected_attempt_id": "filled-in"},
    ):
        with pytest.raises(TargetError, match="closure_identity_conflict"):
            f.begin({**command, **update})
    with pytest.raises(TargetError, match="request_already_closing"):
        f.begin({**command, "closure_id": str(uuid.uuid4())})


@pytest.mark.parametrize("first", ["reserve", "begin_closure"])
def test_f05_actual_transaction_orders(fixture, first):
    f = fixture
    epoch = f.admit()["execution_epoch"]
    command = f.command()
    entered, release = threading.Event(), threading.Event()
    original = f.target.closure.reserve if first == "reserve" else f.target.closure.begin

    def blocked(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return result

    setattr(f.target.closure, "reserve" if first == "reserve" else "begin", blocked)
    second = Target(f.root / "target.sqlite", f.config)
    calls = {
        "reserve": {
            "request_id": f.request.request_id,
            "attempt_id": "race-attempt",
            "execution_epoch": epoch,
            "worker_execution_id": "unit-worker",
        },
        "begin_closure": {"command": command, "recovery_key": f.key},
    }
    other = "begin_closure" if first == "reserve" else "reserve"
    with ThreadPoolExecutor(2) as executor:
        one = executor.submit(f.target.call, first, calls[first], binding=f.binding, peer=f.peer)
        assert entered.wait(5)
        two = executor.submit(second.call, other, calls[other], binding=f.binding, peer=f.peer)
        release.set()
        one.result()
        if first == "reserve":
            assert two.result()["progress"]["acquisition"]["kind"] == "acquired"
        else:
            with pytest.raises(TargetError, match="request_closed"):
                two.result()
    assert f.snapshot()["environment"]["state"] == "quarantined"


@pytest.mark.parametrize("first", ["apply", "begin_closure"])
def test_f06_apply_and_closure_transaction_orders(fixture, first):
    f = fixture
    owner = f.reserve()
    operation = {
        **owner,
        "operation_id": f.request.request_id + ".apply",
        "request_id": f.request.request_id,
        "candidate": f.request.candidate.commit,
        "payload_sha256": digest(
            {"request": digest(f.request), "candidate": f.request.candidate.commit}
        ),
    }
    command = f.command()
    entered, release, competing = threading.Event(), threading.Event(), threading.Event()
    attribute = "legacy_call" if first == "apply" else "begin"
    holder = f.target if first == "apply" else f.target.closure
    original = getattr(holder, attribute)

    def blocked(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return result

    setattr(holder, attribute, blocked)
    second = Target(f.root / "target.sqlite", f.config)
    calls = {
        "apply": operation,
        "begin_closure": {"command": command, "recovery_key": f.key},
    }
    other = "begin_closure" if first == "apply" else "apply"

    def compete():
        competing.set()
        return second.call(other, calls[other], binding=f.binding, peer=f.peer)

    with ThreadPoolExecutor(2) as executor:
        one = executor.submit(f.target.call, first, calls[first], binding=f.binding, peer=f.peer)
        assert entered.wait(5)
        two = executor.submit(compete)
        assert competing.wait(5)
        release.set()
        result = one.result()
        if first == "apply":
            assert result["value"] == 1
            assert two.result()["progress"]["acquisition"]["kind"] == "acquired"
        else:
            with pytest.raises(TargetError, match="request_closed"):
                two.result()
    setattr(holder, attribute, original)
    before = f.snapshot()
    assert before["environment"]["value"] == (1 if first == "apply" else 0)
    with f.target.connect() as db:
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == (
            1 if first == "apply" else 0
        )
    with pytest.raises(TargetError, match="request_closed"):
        f.call("apply", **operation)
    assert f.snapshot() == before
    if first == "apply":
        assert f.call("receipt", **operation) == result


def test_f06_f07_f21_f28_f29_seal_is_common_mutation_boundary(fixture):
    f = fixture
    owner = f.reserve()
    operation = {
        **owner,
        "operation_id": f.request.request_id + ".apply",
        "request_id": f.request.request_id,
        "candidate": f.request.candidate.commit,
        "payload_sha256": digest(
            {"request": digest(f.request), "candidate": f.request.candidate.commit}
        ),
    }
    receipt = f.call("apply", **operation)
    assert receipt["value"] == 1
    command = f.command()
    f.begin(command)
    before = f.snapshot()
    for method in (
        "apply",
        "assert_active",
        "revoke",
        "uncertain",
        "cancel",
        "stop",
        "cleanup",
        "recover",
        "release",
        "finish",
    ):
        with pytest.raises(TargetError, match="request_closed"):
            data = operation if method == "apply" else {**owner}
            if method in {"recover", "release"}:
                data["recovery_key"] = f.key
            if method == "finish":
                data["manifest"] = {}
            f.call(method, **data)
    assert f.snapshot() == before
    assert f.call("receipt", **operation) == receipt
    with pytest.raises(TargetError, match="request_closed"):
        f.reserve()
    with pytest.raises(TargetError, match="stale_owner"):
        f.call("cleanup", attempt_id=None, token=None, execution_epoch=1)
    with pytest.raises(TargetError, match="supervisor_required"):
        f.call("read_closure", closure_id=command["closure_id"])
    for method in ("confirm_closure_stop", "cleanup_closure", "release_closure"):
        with pytest.raises(TargetError, match="supervisor_required"):
            f.call(method, closure_id=command["closure_id"])


def test_f08_f17_f22_missing_provenance_and_evidence_quarantine(fixture):
    f = fixture
    f.reserve()
    with f.target.connect() as db:
        db.execute("DELETE FROM reservation_provenance")
    command = f.command()
    result = f.begin(command)
    assert result["progress"]["blocking_reason"] == "legacy_provenance_unavailable"
    f.call(
        "confirm_closure_stop",
        closure_id=command["closure_id"],
        recovery_key=f.key,
        expected_revision=result["record_revision"],
        evidence_ref={"sha256": "0" * 64},
    )
    view = f.read(command)
    assert view["progress"]["stop"] is None
    with pytest.raises(TargetError, match="stop_and_cleanup_required"):
        f.call(
            "release_closure",
            closure_id=command["closure_id"],
            recovery_key=f.key,
            expected_revision=view["record_revision"],
        )
    with pytest.raises(TargetError, match="stop_confirmation_required"):
        f.call(
            "cleanup_closure",
            closure_id=command["closure_id"],
            recovery_key=f.key,
            expected_revision=view["record_revision"],
            cleanup_payload_sha256=view["cleanup_payload_sha256"],
        )
    assert f.snapshot()["environment"]["state"] == "quarantined"


def test_f20_f23_f24_wrong_incarnation_dirty_target_and_restore(fixture):
    f = fixture
    with f.target.connect() as db:
        db.execute("UPDATE environment SET value=7")
    with pytest.raises(TargetError, match="dirty_target_conflict"):
        f.begin(f.command())
    assert f.snapshot()["environment"]["value"] == 7
    with f.target.connect() as db:
        assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
        db.execute("UPDATE environment SET value=0")
    f.admit()
    old_binding = f.binding
    f.config["closure_binding"] = {**old_binding, "target_incarnation": str(uuid.uuid4())}
    f.target = Target(f.root / "target.sqlite", f.config)
    for method in ("admit", "reserve", "apply"):
        with pytest.raises(TargetError, match="target_binding_mismatch"):
            f.target.call(method, {}, binding=old_binding)
        with pytest.raises(TargetError, match="target_binding_mismatch"):
            f.target.call(method, {})
    f.binding = f.config["closure_binding"]
    with pytest.raises(TargetError, match="restore_reconciliation_required"):
        f.admit(f.new_request("replacement"))
    command = f.command()
    command["authorization"]["admission_target_incarnation"] = old_binding["target_incarnation"]
    with pytest.raises(TargetError, match="legacy_provenance_unavailable"):
        f.begin(command)


def test_f11_queue_predicate_requires_exact_receipt_and_current_free(fixture):
    f = fixture
    owner = f.reserve()
    command = f.command()
    f.begin(command)

    def next_may_dispatch(snapshot):
        row = snapshot["requests"][0]
        closure = row["closure"]
        if not closure or not closure["receipt"]:
            return False
        receipt = ClosureReceipt.model_validate(closure["receipt"])
        validation = f.call("validate_closure_receipt", closure_id=str(receipt.closure_id))
        return (
            snapshot["target_id"] == receipt.target_id == f.binding["target_id"]
            and snapshot["target_incarnation"]
            == str(receipt.target_incarnation)
            == f.binding["target_incarnation"]
            and receipt.request_sha256 == digest(f.request)
            and validation.get("valid") is True
            and validation.get("receipt_sha256") == receipt.receipt_sha256
            and receipt.release.environment_revision <= snapshot["record_revision"]
            and snapshot["environment"]["state"] == "free"
            and snapshot["environment"]["owner"]["kind"] == "none"
        )

    assert not next_may_dispatch(f.snapshot())
    stopped = confirm_unit_stop(f, owner, command)
    view = f.read(command)
    cleaned = f.call(
        "cleanup_closure",
        closure_id=command["closure_id"],
        recovery_key=f.key,
        cleanup_payload_sha256=view["cleanup_payload_sha256"],
        expected_revision=view["record_revision"],
    )
    receipt = f.call(
        "release_closure",
        closure_id=command["closure_id"],
        recovery_key=f.key,
        expected_revision=cleaned["record_revision"],
    )
    snapshot = f.snapshot()
    assert next_may_dispatch(snapshot)
    assert not next_may_dispatch({**snapshot, "target_id": "wrong-target"})
    assert not next_may_dispatch({**snapshot, "target_incarnation": str(uuid.uuid4())})
    reference = stopped["progress"]["stop"]["evidence_refs"][0]
    artifact = f.root / "lifecycle-evidence" / (reference["id"] + ".json")
    evidence = artifact.read_bytes()
    artifact.unlink()
    assert not next_may_dispatch(snapshot)
    assert f.read(command)["progress"]["receipt"] == receipt
    artifact.write_bytes(b"corrupt")
    assert not next_may_dispatch(snapshot)
    assert f.read(command)["progress"]["receipt"] == receipt
    artifact.write_bytes(evidence)
    assert next_may_dispatch(snapshot)
    f.reserve(f.new_request("next"), "next-attempt")
    assert not next_may_dispatch(f.snapshot())


def test_strict_extension_models(fixture):
    command = fixture.command()
    for update in (
        {"unknown": 1},
        {"expected_execution_epoch": True},
        {"expected_execution_epoch": "1"},
    ):
        with pytest.raises(ValueError):
            BeginClosure.model_validate({**command, **update})
    view = fixture.begin(command)
    invalid = deepcopy(view["progress"])
    invalid["stop"] = None
    with pytest.raises(ValueError, match="confirmed_stop_required"):
        Progress.model_validate(invalid)
    golden = Path("contracts/closure/v1/begin.example.json")
    if golden.exists():
        assert BeginClosure.model_validate_json(golden.read_text())


def daemon_observation(f, owner, verb, suffix, *, status, body=b"", closure=None, worker=False):
    import base64

    from birbverify.closure import HttpCommand, LifecycleIntent

    name = f.peer["container_id"] if worker else "birbverify-" + owner["attempt_id"]
    paths = {
        "inspect": ("GET", f"/containers/{name}/json"),
        "remove": ("DELETE", f"/containers/{name}?force=true"),
        "start": ("POST", f"/containers/{name}/start"),
        "create": ("POST", f"/containers/create?name={name}"),
    }
    method, path = paths[verb]
    configuration = None
    if verb == "create":
        configuration = {
            "Image": f.config["candidate_image"],
            "Cmd": ["python", "-I", "-S", "/candidate/check.py"],
            "Labels": {
                "birbverify.attempt": owner["attempt_id"],
                "birbverify.incarnation": f.binding["target_incarnation"],
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "Binds": [f"{f.root}/checkouts/{owner['attempt_id']}:/candidate:ro"],
            },
        }
    command = HttpCommand(method=method, path=path, body=configuration)
    intent = LifecycleIntent(
        operation_id="unit-" + suffix,
        request_id=f.request.request_id,
        execution_epoch=owner["execution_epoch"],
        attempt_id=owner["attempt_id"],
        worker_execution_id="unit-worker",
        authority="closure" if closure else "worker",
        closure_id=closure,
        verb=verb,
        container=name,
        command=command,
        arguments_sha256=digest(command),
    )
    authority = {"recovery_key": f.key} if closure else owner
    assert f.call("lifecycle_intent", intent=intent.model_dump(mode="json"), **authority)[
        "send_authorized"
    ]
    reference = save_evidence(
        f.root,
        "daemon",
        {
            "intent_sha256": digest(intent),
            "daemon_id": "unit-daemon",
            "host_boot_id": f.peer["host_boot_id"],
            "response": {
                "kind": "daemon_reply",
                "command": command.model_dump(mode="json"),
                "command_sha256": digest(command),
                "status": status,
                "body_base64": base64.b64encode(body).decode(),
                "body_sha256": digest(body),
            },
        },
    )
    f.call(
        "lifecycle_completion",
        operation_id=intent.operation_id,
        evidence_ref=reference,
        checker_key=(f.root / "checker.key").read_text(),
    )
    return intent, reference


def confirm_unit_stop(f, owner, command):
    identity = command["closure_id"]
    daemon_observation(
        f, owner, "remove", "worker-remove", status=204, closure=identity, worker=True
    )
    daemon_observation(
        f, owner, "inspect", "worker-absent", status=404, closure=identity, worker=True
    )
    daemon_observation(f, owner, "remove", "candidate-remove", status=204, closure=identity)
    daemon_observation(f, owner, "inspect", "candidate-absent", status=404, closure=identity)
    records = f.call("lifecycle_records", request_id=f.request.request_id, recovery_key=f.key)
    view = f.read(command)
    reference = save_evidence(
        f.root,
        "stop",
        {
            "closure_id": identity,
            "reservation_sha256": digest(view["reservation"]),
            "command_evidence": [item["completion"] for item in records],
        },
    )
    return f.call(
        "confirm_closure_stop",
        closure_id=identity,
        evidence_ref=reference,
        expected_revision=view["record_revision"],
        recovery_key=f.key,
    )


def test_normal_stop_rejects_absence_before_later_mutation(fixture):
    f = fixture
    owner = f.reserve()
    daemon_observation(f, owner, "inspect", "too-early-absence", status=404)
    daemon_observation(
        f, owner, "create", "late-create", status=201, body=json.dumps({"Id": "b" * 64}).encode()
    )
    with pytest.raises(TargetError, match="container_absence_unconfirmed"):
        f.call("stop", **owner)
    daemon_observation(f, owner, "remove", "remove", status=204)
    daemon_observation(f, owner, "inspect", "final-absence", status=404)
    assert f.call("stop", **owner)["termination"] == "confirmed"


def test_f17_cleanup_rolls_back_and_stop_set_freezes(fixture):
    f = fixture
    owner = f.reserve()
    operation = {
        **owner,
        "operation_id": f.request.request_id + ".apply",
        "request_id": f.request.request_id,
        "candidate": f.request.candidate.commit,
        "payload_sha256": digest(
            {"request": digest(f.request), "candidate": f.request.candidate.commit}
        ),
    }
    f.call("apply", **operation)
    command = f.command()
    f.begin(command)
    confirmed = confirm_unit_stop(f, owner, command)
    assert confirmed["progress"]["stop"]["kind"] == "confirmed"
    with pytest.raises(TargetError, match="closure_stop_already_confirmed"):
        daemon_observation(
            f, owner, "remove", "new-command", status=204, closure=command["closure_id"]
        )
    view = f.read(command)
    args = {
        "closure_id": command["closure_id"],
        "recovery_key": f.key,
        "expected_revision": view["record_revision"],
        "cleanup_payload_sha256": view["cleanup_payload_sha256"],
    }
    original = f.target.closure.write_progress

    def fail_before_commit(*args):
        raise RuntimeError("fixture_before_commit")

    f.target.closure.write_progress = fail_before_commit
    with pytest.raises(RuntimeError, match="fixture_before_commit"):
        f.call("cleanup_closure", **args)
    assert f.snapshot()["environment"]["value"] == 1
    assert f.read(command)["progress"]["cleanup"] is None
    f.target.closure.write_progress = original
    f.call("cleanup_closure", **args)
    assert f.snapshot()["environment"]["value"] == 0
    reference = confirmed["progress"]["stop"]["evidence_refs"][0]
    artifact = f.root / "lifecycle-evidence" / (reference["id"] + ".json")
    original_bytes = artifact.read_bytes()
    artifact.write_bytes(b"tampered")
    view = f.read(command)
    with pytest.raises(ValueError, match="evidence_corrupt"):
        f.call(
            "release_closure",
            closure_id=command["closure_id"],
            recovery_key=f.key,
            expected_revision=view["record_revision"],
        )
    assert f.snapshot()["environment"]["state"] == "quarantined"
    artifact.write_bytes(original_bytes)
    receipt = f.call(
        "release_closure",
        closure_id=command["closure_id"],
        recovery_key=f.key,
        expected_revision=view["record_revision"],
    )
    assert receipt["acquisition"]["attempt_id"] == owner["attempt_id"]


def inconclusive_manifest(f, owner):
    from birbverify.contract import Manifest

    template = json.loads(Path("contracts/v1/manifest.example.json").read_text())
    template.update(
        request_id=f.request.request_id,
        request_sha256=digest(f.request),
        attempt_id=owner["attempt_id"],
        attempt_number=1,
        prior_attempt_id=None,
        retry_reason="initial",
        candidate=f.request.candidate.model_dump(mode="json"),
        plan_sha256=f.request.plan_sha256,
        policy_revision=f.request.authority.policy_revision,
        environment=f.request.authority.environment,
        correlation_id=f.request.correlation_id,
        telemetry_correlation=f.request.evidence.telemetry_correlation,
        operation_id=f.request.request_id + ".apply",
        outcome="inconclusive",
        cleanup="unknown",
        termination="unknown",
        environment_release="quarantined",
        cancellation="none",
        reason="worker_lost",
    )
    return Manifest.model_validate(template).model_dump(mode="json")


def test_f07_f18_known_context_release_and_claim_arbitrate(fixture):
    f = fixture
    owner = f.reserve()
    f.call("uncertain", **owner)
    manifest = inconclusive_manifest(f, owner)
    assert f.call("finish", **owner, manifest=manifest) == manifest
    f.call("recover", **owner, recovery_key=f.key)
    f.call("cleanup", **owner)
    f.call("release", **owner, recovery_key=f.key)
    command = f.command()
    assert f.begin(command)["status"] == "already_released"
    assert f.call("result", request_id=f.request.request_id) == manifest
    successor = f.new_request("new-after-legacy")
    f.reserve(successor, "new-attempt")
    before = f.snapshot(successor.request_id)
    assert f.call("finish", **owner, manifest=manifest) == manifest
    assert f.snapshot(successor.request_id) == before
    second_command = f.command(successor)
    f.begin(second_command)
    with pytest.raises(TargetError, match="request_closed"):
        f.call(
            "recover", attempt_id="new-attempt", token="old", execution_epoch=2, recovery_key=f.key
        )


def test_f26_post_seal_completion_is_evidence_only(fixture):
    import base64

    from birbverify.closure import HttpCommand, LifecycleIntent

    f = fixture
    owner = f.reserve()
    name = "birbverify-" + owner["attempt_id"]
    command = HttpCommand(method="POST", path=f"/containers/{name}/start", body=None)
    intent = LifecycleIntent(
        operation_id="acknowledged-start",
        request_id=f.request.request_id,
        execution_epoch=owner["execution_epoch"],
        attempt_id=owner["attempt_id"],
        worker_execution_id="unit-worker",
        authority="worker",
        closure_id=None,
        verb="start",
        container=name,
        command=command,
        arguments_sha256=digest(command),
    )
    assert f.call("lifecycle_intent", intent=intent.model_dump(mode="json"), **owner)[
        "send_authorized"
    ]
    assert not f.call("lifecycle_intent", intent=intent.model_dump(mode="json"), **owner)[
        "send_authorized"
    ]
    closure = f.command()
    f.begin(closure)
    reference = save_evidence(
        f.root,
        "daemon",
        {
            "intent_sha256": digest(intent),
            "daemon_id": "unit-daemon",
            "host_boot_id": f.peer["host_boot_id"],
            "response": {
                "kind": "daemon_reply",
                "status": 204,
                "command": command.model_dump(mode="json"),
                "command_sha256": digest(command),
                "body_base64": base64.b64encode(b"").decode(),
                "body_sha256": digest(b""),
            },
        },
    )
    assert (
        f.call(
            "lifecycle_completion",
            operation_id=intent.operation_id,
            evidence_ref=reference,
            checker_key=(f.root / "checker.key").read_text(),
        )["settlement"]
        == "effect"
    )
    with pytest.raises(TargetError, match="request_closed"):
        f.call("lifecycle_intent", intent=intent.model_dump(mode="json"), **owner)
    assert f.snapshot()["environment"]["state"] == "quarantined"


def test_published_extension_schema_and_independent_golden_digests():
    import hashlib

    from birbverify.closure import Envelope, LifecycleIntent, Registration, Snapshot

    directory = Path("contracts/closure/v1")
    for name, model in (
        ("begin", BeginClosure),
        ("receipt", ClosureReceipt),
        ("progress", Progress),
        ("snapshot", Snapshot),
    ):
        assert (
            json.loads((directory / f"{name}.schema.json").read_text()) == model.model_json_schema()
        )
    for name, model in (
        ("envelope", Envelope),
        ("registration", Registration),
        ("intent", LifecycleIntent),
    ):
        assert (
            json.loads(Path(f"contracts/target/v2/{name}.schema.json").read_text())
            == model.model_json_schema()
        )
    golden = json.loads((directory / "golden-digests.json").read_text())
    command = json.loads((directory / "begin.example.json").read_text())
    receipt = json.loads((directory / "receipt.example.json").read_text())
    assert ClosureReceipt.model_validate(receipt)
    for value, expected in (
        (command, golden["begin_sha256"]),
        (command["request"], golden["request_sha256"]),
        (
            {key: value for key, value in receipt.items() if key != "receipt_sha256"},
            golden["receipt_sha256"],
        ),
    ):
        assert (
            hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            == expected
        )
    with pytest.raises(ValueError):
        Envelope.model_validate(
            {
                "target_id": "fixture-local",
                "target_incarnation": command["target_incarnation"],
                "method": "inspect",
                "data": {},
            }
        )
