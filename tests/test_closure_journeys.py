import asyncio
import http.server
import json
import os
import socketserver
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from temporalio.testing import WorkflowEnvironment

from birbverify.closure import BeginClosure
from birbverify.closure_supervisor import Supervisor
from birbverify.contract import Request, digest
from birbverify.fixture import initialize, request, start_target, stop
from birbverify.fixture_launcher import WorkerGroup, enable
from birbverify.lifecycle import Engine, GatedDocker, container_path, save_evidence
from birbverify.target import rpc
from birbverify.temporal_worker import FixtureWorkflow


class Runtime:
    def __init__(self, root):
        self.root = root
        initialize(root)
        self.config = enable(root, os.environ.get("BIRBVERIFY_SOURCE_REVISION", "8" * 40))
        self.binding = self.config["closure_binding"]
        (root / "launch").mkdir()
        self.process = None
        self.groups = []
        self.candidates = []
        self.engine = Engine()
        self.request = self.new_request("request-" + uuid.uuid4().hex[:12])

    def new_request(self, name, **kwargs):
        payload = request(self.root, name, **kwargs).model_dump(mode="json")
        payload["resources"]["max_attempts"] = 1
        return Request.model_validate(payload)

    def start(self):
        (self.root / "installation.json").write_text(json.dumps(self.config))
        self.process = start_target(self.root)
        self.supervisor = Supervisor(self.root)

    def call(self, method, **data):
        return rpc(self.root, method, binding=self.binding, **data)

    def worker(self, mode="normal", candidate=None):
        candidate = candidate or self.request
        filename = candidate.request_id + ".json"
        (self.root / "launch" / filename).write_text(candidate.model_dump_json())
        attempt = candidate.request_id + ".attempt"
        self.candidates.append("birbverify-" + attempt)
        command = [
            sys.executable,
            str(Path(__file__).with_name("closure_worker.py")),
            str(self.root),
            mode,
            filename,
            attempt,
        ]
        group = WorkerGroup(self.root, command)
        self.groups.append(group)
        return group

    def command(self):
        candidate = self.request
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

    def wait_file(self, name):
        wait_for(lambda: (self.root / "launch" / name).exists())

    def snapshot(self):
        return self.call("observe_closure_state", request_ids=[self.request.request_id])

    def close(self):
        for group in self.groups:
            group.remove()
        for candidate in self.candidates:
            status, content = self.engine.raw("GET", container_path(candidate) + "/json")
            if status == 200:
                identity = json.loads(content)["Id"]
                status, _ = self.engine.raw("DELETE", container_path(identity) + "?force=true")
                assert status in {204, 404}
                assert self.engine.raw("GET", container_path(identity) + "/json")[0] == 404
        if self.process:
            stop(self.process)


def wait_for(predicate, timeout=25):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("fixture boundary not observed")
        time.sleep(0.025)


@pytest.fixture
def runtime(tmp_path):
    fixture = Runtime(tmp_path / "r")
    try:
        yield fixture
    finally:
        fixture.close()


def publish(name, record):
    directory = Path(os.environ["BIRBVERIFY_CLOSURE_EVIDENCE"])
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(record, indent=2))


@pytest.mark.parametrize("mode", ["before_admit", "before_reserve"])
def test_f01_f02_f29_real_delayed_worker_cannot_acquire(runtime, mode):
    r = runtime
    r.start()
    r.worker(mode)
    barrier = mode.replace("_", "-")
    r.wait_file(barrier + ".ready")
    command = r.command()
    r.supervisor.begin(command)
    closed = r.supervisor.reconcile(command["closure_id"])
    assert closed["progress"]["receipt"]["acquisition"]["kind"] == "never_acquired"
    (r.root / "launch" / (barrier + ".continue")).touch()
    r.wait_file("worker-ended")
    error = json.loads((r.root / "launch" / "worker-error.json").read_text())
    assert error["error"] == "request_closed"
    assert r.call("current_attempt", request_id=r.request.request_id) is None
    publish(
        "delayed-" + mode,
        {"receipt": closed["progress"]["receipt"], "error": error, "snapshot": r.snapshot()},
    )


def test_f03_f04_f08_f25_f27_actual_worker_and_escaped_child_stop(runtime):
    r = runtime
    r.start()
    group = r.worker("acquired")
    r.wait_file("acquired.ready")
    r.wait_file("child-writes")
    cache = r.root / "contexts" / (r.request.request_id + ".attempt.context.json")
    assert cache.exists()
    cache.unlink()
    command = r.command()
    r.supervisor.begin(command)
    view = r.supervisor.read(command["closure_id"])
    reservation = view["reservation"]
    controls = GatedDocker(
        r.root,
        r.call,
        r.request.request_id,
        reservation["execution_epoch"],
        reservation["attempt_id"],
        reservation["registration"],
        closure_id=command["closure_id"],
        recovery_key=r.supervisor.key,
    )
    alive = controls.command(
        "live-worker-evidence",
        "inspect",
        group.container_id,
        "GET",
        container_path(group.container_id) + "/json",
    )
    assert alive["status"] == 200
    records = r.call(
        "lifecycle_records", request_id=r.request.request_id, recovery_key=r.supervisor.key
    )
    view = r.supervisor.read(command["closure_id"])
    fake = save_evidence(
        r.root,
        "stop",
        {
            "closure_id": command["closure_id"],
            "reservation_sha256": digest(view["reservation"]),
            "command_evidence": [record["completion"] for record in records],
        },
    )
    rejected = r.call(
        "confirm_closure_stop",
        closure_id=command["closure_id"],
        evidence_ref=fake,
        expected_revision=view["record_revision"],
        recovery_key=r.supervisor.key,
    )
    assert rejected["progress"]["stop"] is None
    assert rejected["observations"][-1]["accepted"] is False
    finished = Supervisor(r.root).reconcile(command["closure_id"])
    assert finished["progress"]["receipt"]["stop"]["kind"] == "confirmed"
    after = (r.root / "launch" / "child-writes").read_bytes()
    assert r.engine.raw("GET", container_path(group.container_id) + "/json")[0] == 404
    assert r.snapshot()["environment"]["state"] == "free"
    (r.root / "launch" / "child-release").touch()
    import subprocess

    subprocess.run(
        [
            sys.executable,
            "-c",
            "import pathlib,sys,time;assert pathlib.Path(sys.argv[1]).exists();time.sleep(.2)",
            str(r.root / "launch" / "child-release"),
        ],
        check=True,
        timeout=5,
    )
    assert not (r.root / "launch" / "child-after-release").exists()
    assert (r.root / "launch" / "child-writes").read_bytes() == after
    assert finished["progress"]["receipt"]["history"]["manifest_status"] == "unavailable"
    assert (
        Supervisor(r.root).reconcile(command["closure_id"])["progress"]["receipt"]
        == finished["progress"]["receipt"]
    )
    publish("acquired-stop", {"view": finished, "snapshot": r.snapshot(), "worker_removed": True})


def test_f03_lost_reservation_reply_has_durable_provenance(runtime):
    r = runtime
    r.config["fixture_drop_reply"] = ["reserve"]
    r.start()
    r.worker()
    r.wait_file("reserve.reply-dropped")
    r.wait_file("worker-ended")
    command = r.command()
    begun = r.supervisor.begin(command)
    assert begun["progress"]["acquisition"]["kind"] == "acquired"
    view = Supervisor(r.root).reconcile(command["closure_id"])
    assert view["progress"]["receipt"]["history"]["manifest_status"] == "unavailable"
    publish(
        "reservation-reply-lost", {"receipt": view["progress"]["receipt"], "snapshot": r.snapshot()}
    )


def test_f09_previously_acknowledged_start_keeps_quarantine_until_settled(runtime):
    r = runtime
    r.start()
    r.worker("before_start")
    r.wait_file("before-start.ready")
    command = r.command()
    r.supervisor.begin(command)
    records = r.call(
        "lifecycle_records", request_id=r.request.request_id, recovery_key=r.supervisor.key
    )
    assert any(item["intent"]["verb"] == "start" and item["completion"] is None for item in records)
    assert r.snapshot()["environment"]["state"] == "quarantined"
    (r.root / "launch" / "before-start.continue").touch()
    r.wait_file("worker-ended")
    view = r.supervisor.reconcile(command["closure_id"])
    assert view["progress"]["receipt"] is not None
    publish("start-across-seal", {"receipt": view["progress"]["receipt"], "snapshot": r.snapshot()})


class DaemonGate(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def gate(root, forward, entered, counter):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_command(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else None
            if self.path.startswith("/containers/create"):
                counter.append(self.path)
                entered.set()
                assert forward.wait(30)
            status, response = Engine().raw(self.command, self.path, body)
            self.send_response(status)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except BrokenPipeError:
                pass

        do_GET = handle_command
        do_POST = handle_command
        do_DELETE = handle_command

    path = root / "launch" / "gate.sock"
    server = DaemonGate(str(path), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, path


def test_f10_real_delayed_create_after_worker_death_stays_quarantined(runtime):
    r = runtime
    forward, entered, counter = threading.Event(), threading.Event(), []
    server, path = gate(r.root, forward, entered, counter)
    r.config["fixture_daemon_socket"] = str(path)
    r.start()
    try:
        group = r.worker()
        assert entered.wait(20)
        command = r.command()
        r.supervisor.begin(command)
        group.remove()
        candidate = r.candidates[0]
        assert r.engine.raw("GET", container_path(candidate) + "/json")[0] == 404
        unresolved = r.supervisor.reconcile(command["closure_id"])
        assert unresolved["progress"]["receipt"] is None
        assert r.snapshot()["environment"]["state"] == "quarantined"
        forward.set()
        wait_for(lambda: r.engine.raw("GET", container_path(candidate) + "/json")[0] == 200)
        unresolved = Supervisor(r.root).reconcile(command["closure_id"])
        assert unresolved["progress"]["receipt"] is None
        assert r.snapshot()["environment"]["state"] == "quarantined"
        assert len(counter) == 1
        waiter = r.new_request("waiting-" + uuid.uuid4().hex[:12])
        r.worker(candidate=waiter)
        r.wait_file("worker-ended")
        error = json.loads((r.root / "launch" / "worker-error.json").read_text())
        assert error["error"] == "environment_wait"
        assert r.call("current_attempt", request_id=waiter.request_id) is None
        publish(
            "unknown-create",
            {
                "snapshot": r.snapshot(),
                "delayed_container_appeared": True,
                "receipt": None,
                "create_sends": len(counter),
            },
        )
    finally:
        forward.set()
        server.shutdown()
        server.server_close()


def test_f26_unknown_intent_ack_never_sends(runtime):
    r = runtime
    forward, entered, counter = threading.Event(), threading.Event(), []
    forward.set()
    server, path = gate(r.root, forward, entered, counter)
    r.config.update(fixture_daemon_socket=str(path), fixture_drop_reply=["lifecycle_intent"])
    r.start()
    try:
        r.worker()
        r.wait_file("lifecycle_intent.reply-dropped")
        r.wait_file("worker-ended")
        assert counter == []
        command = r.command()
        r.supervisor.begin(command)
        view = r.supervisor.reconcile(command["closure_id"])
        assert view["progress"]["receipt"] is None
        assert counter == []
        publish("intent-ack-lost", {"daemon_create_sends": 0, "snapshot": r.snapshot()})
    finally:
        server.shutdown()
        server.server_close()


def test_normal_v2_worker_preserves_manifest(runtime):
    r = runtime
    r.start()
    r.worker()
    r.wait_file("worker-ended")
    result = r.call("result", request_id=r.request.request_id)
    assert result is not None, (r.root / "launch" / "worker-error.json").read_text()
    assert result["outcome"] == "passed"
    assert r.snapshot()["environment"]["state"] == "free"
    command = r.command()
    assert r.supervisor.begin(command)["status"] == "already_released"
    assert r.call("result", request_id=r.request.request_id) == result
    publish("normal-v2", {"manifest": result, "snapshot": r.snapshot()})


@pytest.mark.asyncio
async def test_real_temporal_worker_loss_resolves_without_context(runtime):
    r = runtime
    r.request = r.new_request("temporal-" + uuid.uuid4().hex[:12], slow=True)
    r.config["fixture_pause_before_context"] = True
    r.start()
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=str(Path(".proof/bin/temporal").resolve())
    ) as temporal:
        address = temporal.client.service_client.config.target_host
        group = WorkerGroup(
            r.root, [sys.executable, "-m", "birbverify.temporal_worker", str(r.root), address]
        )
        r.groups.append(group)
        handle = await temporal.client.start_workflow(
            FixtureWorkflow.run,
            r.request.model_dump(mode="json"),
            id=r.request.request_id,
            task_queue="birbverify-fixture",
        )
        deadline = time.monotonic() + 25
        attempt = None
        while attempt is None:
            attempt = r.call("current_attempt", request_id=r.request.request_id)
            if time.monotonic() > deadline:
                raise AssertionError("Temporal activity never reserved")
            await asyncio.sleep(0.025)
        r.candidates.append("birbverify-" + attempt)
        await asyncio.to_thread(r.wait_file, "reserved.ready")
        command = r.command()
        r.supervisor.begin(command)
        view = await asyncio.to_thread(r.supervisor.reconcile, command["closure_id"])
        assert view["progress"]["acquisition"]["attempt_id"] == attempt
        assert r.engine.raw("GET", container_path(group.container_id) + "/json")[0] == 404
        assert view["progress"]["receipt"]["stop"]["kind"] == "confirmed"
        assert r.snapshot()["environment"]["state"] == "free"
        await handle.cancel()
        publish("temporal-worker-loss", {"snapshot": r.snapshot(), "progress": view["progress"]})


@pytest.mark.parametrize(
    "step,acquired",
    [
        ("begin_closure", False),
        ("cleanup_closure", False),
        ("release_closure", False),
        ("begin_closure", True),
        ("confirm_closure_stop", True),
        ("cleanup_closure", True),
        ("release_closure", True),
    ],
)
@pytest.mark.parametrize("boundary", ["before_commit", "after_commit"])
def test_f20_process_crash_at_each_transaction_boundary(runtime, step, boundary, acquired):
    r = runtime
    r.start()
    if acquired:
        r.worker("acquired")
        r.wait_file("acquired.ready")
    command = r.command()
    stop_args = None
    if step != "begin_closure":
        r.supervisor.begin(command)
        if acquired:
            stop_args = acquired_stop_arguments(r, command)
            if step != "confirm_closure_stop":
                r.call("confirm_closure_stop", **stop_args)
    if step == "release_closure":
        view = r.supervisor.read(command["closure_id"])
        r.call(
            "cleanup_closure",
            closure_id=command["closure_id"],
            recovery_key=r.supervisor.key,
            expected_revision=view["record_revision"],
            cleanup_payload_sha256=view["cleanup_payload_sha256"],
        )
    stop(r.process)
    (r.root / "transport" / "target.sock").unlink()
    r.config["fixture_crash"] = step + "." + boundary
    r.start()
    if step == "begin_closure":
        args = {"command": command, "recovery_key": r.supervisor.key}
    else:
        view = r.supervisor.read(command["closure_id"])
        args = {
            "closure_id": command["closure_id"],
            "recovery_key": r.supervisor.key,
            "expected_revision": view["record_revision"],
        }
        if step == "cleanup_closure":
            args["cleanup_payload_sha256"] = view["cleanup_payload_sha256"]
        if step == "confirm_closure_stop":
            args["evidence_ref"] = stop_args["evidence_ref"]
    with pytest.raises((ValueError, OSError)):
        r.call(step, **args)
    r.process.wait(timeout=5)
    assert r.process.returncode in {91, 92}
    (r.root / "transport" / "target.sock").unlink()
    r.config.pop("fixture_crash")
    r.start()
    snapshot = r.snapshot()
    row = snapshot["requests"][0]
    if boundary == "before_commit" and step == "begin_closure":
        assert row["closure"] is None
    elif step == "release_closure" and boundary == "after_commit":
        assert row["closure"]["receipt"] is not None
        assert snapshot["environment"]["state"] == "free"
    else:
        assert snapshot["environment"]["state"] == "quarantined"
        assert row["closure"]["receipt"] is None
    r.supervisor.begin(command)
    final = Supervisor(r.root).reconcile(command["closure_id"])
    assert final["progress"]["receipt"] is not None
    publish(
        "crash-" + ("acquired-" if acquired else "never-") + step + "-" + boundary,
        {"after_restart": snapshot, "receipt": final["progress"]["receipt"]},
    )


@pytest.mark.parametrize("acquired", [False, True])
def test_f12_f13_f14_f16_lost_step_replies_resume_from_target(runtime, acquired):
    r = runtime
    r.config["fixture_drop_reply"] = [
        "begin_closure",
        "confirm_closure_stop",
        "cleanup_closure",
        "release_closure",
    ]
    r.start()
    if acquired:
        r.worker("acquired")
        r.wait_file("acquired.ready")
    command = r.command()
    with pytest.raises(ValueError):
        r.supervisor.begin(command)
    view = Supervisor(r.root).read(command["closure_id"])
    fence = view["progress"]["fence"]
    if acquired:
        args = acquired_stop_arguments(r, command)
        with pytest.raises(ValueError):
            r.call("confirm_closure_stop", **args)
        view = Supervisor(r.root).read(command["closure_id"])
        assert view["progress"]["stop"]["kind"] == "confirmed"
    with pytest.raises(ValueError):
        r.call(
            "cleanup_closure",
            closure_id=command["closure_id"],
            recovery_key=r.supervisor.key,
            expected_revision=view["record_revision"],
            cleanup_payload_sha256=view["cleanup_payload_sha256"],
        )
    view = Supervisor(r.root).read(command["closure_id"])
    assert view["progress"]["cleanup"] is not None
    with pytest.raises(ValueError):
        r.call(
            "release_closure",
            closure_id=command["closure_id"],
            recovery_key=r.supervisor.key,
            expected_revision=view["record_revision"],
        )
    final = Supervisor(r.root).read(command["closure_id"])
    assert final["progress"]["fence"] == fence
    assert final["progress"]["receipt"] is not None
    assert (
        Supervisor(r.root).reconcile(command["closure_id"])["progress"]["receipt"]
        == final["progress"]["receipt"]
    )
    publish(
        "step-replies-lost-" + ("acquired" if acquired else "never"),
        {"receipt": final["progress"]["receipt"], "snapshot": r.snapshot()},
    )


def test_registered_identity_from_another_worker_is_not_authority(runtime):
    r = runtime
    r.start()
    first = r.worker("before_admit")
    r.wait_file("before-admit.ready")
    (r.root / "launch" / "other-registration.json").write_text(json.dumps(first.registration))
    r.worker("wrong_peer")
    r.wait_file("worker-ended")
    error = json.loads((r.root / "launch" / "worker-error.json").read_text())
    assert error["error"] == "worker_peer_mismatch"
    assert r.call("current_attempt", request_id=r.request.request_id) is None
    assert r.snapshot()["environment"]["state"] == "free"
    publish("wrong-worker-identity", {"error": error, "snapshot": r.snapshot()})


def acquired_stop_arguments(r, command):
    saved = {}
    original = r.supervisor.call

    def capture(method, **data):
        if method == "confirm_closure_stop":
            saved.update(data)
            raise RuntimeError("fixture_stop_arguments_captured")
        return original(method, **data)

    r.supervisor.call = capture
    try:
        with pytest.raises(RuntimeError, match="fixture_stop_arguments_captured"):
            r.supervisor.reconcile(command["closure_id"])
    finally:
        r.supervisor.call = original
    return saved


def test_v2_check_timeout_is_inconclusive_and_releases_after_confirmed_absence(runtime):
    r = runtime
    r.request = r.new_request("slow-" + uuid.uuid4().hex[:12], slow=True, timeout=1)
    r.start()
    r.worker()
    r.wait_file("worker-ended")
    result = r.call("result", request_id=r.request.request_id)
    assert result is not None, (r.root / "launch" / "worker-error.json").read_text()
    assert result["outcome"] == "inconclusive"
    assert result["termination"] == "confirmed"
    assert result["environment_release"] == "released"
    assert r.snapshot()["environment"]["state"] == "free"
    records = r.call(
        "lifecycle_records", request_id=r.request.request_id, recovery_key=r.supervisor.key
    )
    assert any(
        row["intent"]["verb"] == "wait" and row["settlement"] == "unknown" for row in records
    )
    assert all(
        row["settlement"] != "unknown"
        for row in records
        if row["intent"]["verb"] in {"create", "start", "remove"}
    )
    candidate = "birbverify-" + r.request.request_id + ".attempt"
    assert r.engine.raw("GET", container_path(candidate) + "/json")[0] == 404
    publish("v2-check-timeout", {"manifest": result, "snapshot": r.snapshot()})


@pytest.mark.parametrize("budget", ["procedure", "near-deadline"])
def test_delayed_start_reply_settles_after_budget_and_releases(runtime, budget):
    r = runtime
    r.request = r.new_request("delayed-start-" + uuid.uuid4().hex[:12], timeout=1)
    if budget == "near-deadline":
        payload = r.request.model_dump(mode="json")
        payload["resources"].update(
            timeout_seconds=30,
            deadline=(datetime.now(UTC) + timedelta(seconds=8)).isoformat(),
        )
        r.request = Request.model_validate(payload)
    abort = threading.Event()
    replied = threading.Event()
    replies = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_command(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else None
            status, response = Engine().raw(self.command, self.path, body)
            if self.path.startswith("/containers/create") and budget == "near-deadline":
                abort.wait(max(0, r.request.resources.deadline.timestamp() - time.time() - 1.0))
            if self.path.endswith("/start"):
                received = time.monotonic()
                remaining_deadline = r.request.resources.deadline.timestamp() - time.time()
                abort.wait(1.5)
                replies.append(
                    {
                        "status": status,
                        "held_seconds": time.monotonic() - received,
                        "remaining_deadline_seconds": remaining_deadline,
                    }
                )
                replied.set()
            self.send_response(status)
            self.send_header("Content-Length", str(len(response)))
            try:
                self.end_headers()
                self.wfile.write(response)
            except BrokenPipeError:
                pass

        do_GET = handle_command
        do_POST = handle_command
        do_DELETE = handle_command

    path = r.root / "launch" / "delayed-start.sock"
    server = DaemonGate(str(path), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    r.config["fixture_daemon_socket"] = str(path)
    try:
        r.start()
        r.worker()
        r.wait_file("worker-ended")
        assert replied.wait(5)
        result = r.call("result", request_id=r.request.request_id)
        assert result is not None, (r.root / "launch" / "worker-error.json").read_text()
        assert len(replies) == 1 and replies[0]["status"] == 204
        assert replies[0]["held_seconds"] >= 1.5
        if budget == "near-deadline":
            assert replies[0]["remaining_deadline_seconds"] <= 1.0
        assert result["outcome"] == "inconclusive"
        records = r.call(
            "lifecycle_records", request_id=r.request.request_id, recovery_key=r.supervisor.key
        )
        starts = [row for row in records if row["intent"]["verb"] == "start"]
        assert len(starts) == 1 and starts[0]["settlement"] == "effect"
        assert not any(row["intent"]["verb"] == "wait" for row in records)
        assert all(
            row["settlement"] != "unknown"
            for row in records
            if row["intent"]["verb"] in {"create", "start", "remove"}
        )
        closure = None
        if budget == "near-deadline":
            assert result["termination"] == "unknown"
            assert result["environment_release"] == "quarantined"
            assert r.snapshot()["environment"]["state"] == "quarantined"
            command = r.command()
            r.supervisor.begin(command)
            closure = r.supervisor.reconcile(command["closure_id"])
            assert closure["progress"]["receipt"] is not None
            assert r.call("result", request_id=r.request.request_id) == result
        else:
            assert result["termination"] == "confirmed"
            assert result["environment_release"] == "released"
        assert r.snapshot()["environment"]["state"] == "free"
        candidate = "birbverify-" + r.request.request_id + ".attempt"
        assert r.engine.raw("GET", container_path(candidate) + "/json")[0] == 404
        publish(
            "delayed-start-" + budget,
            {
                "manifest": result,
                "snapshot": r.snapshot(),
                "start": starts[0],
                "proxy_replies": replies,
                "closure": closure,
            },
        )
    finally:
        abort.set()
        server.shutdown()
        server.server_close()


def test_transport_rejects_delayed_v1_envelope(runtime):
    import socket

    r = runtime
    r.start()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(r.root / "transport" / "target.sock"))
        client.sendall(
            json.dumps(
                {"method": "admit", "data": {"request": r.request.model_dump(mode="json")}}
            ).encode()
            + b"\n"
        )
        with client.makefile("rb") as response:
            result = json.loads(response.readline())
    assert "validation errors for Envelope" in result["error"]
    assert "protocol" in result["error"]
    assert r.snapshot()["requests"][0]["execution_epoch"] is None


@pytest.mark.asyncio
async def test_temporal_closed_request_is_nonretryable_terminal(runtime):
    from temporalio.client import WorkflowFailureError
    from temporalio.exceptions import ActivityError, ApplicationError

    r = runtime
    r.start()
    command = r.command()
    r.supervisor.begin(command)
    r.supervisor.reconcile(command["closure_id"])
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=str(Path(".proof/bin/temporal").resolve())
    ) as temporal:
        group = WorkerGroup(
            r.root,
            [
                sys.executable,
                "-m",
                "birbverify.temporal_worker",
                str(r.root),
                temporal.client.service_client.config.target_host,
            ],
        )
        r.groups.append(group)
        handle = await temporal.client.start_workflow(
            FixtureWorkflow.run,
            r.request.model_dump(mode="json"),
            id=r.request.request_id,
            task_queue="birbverify-fixture",
        )
        with pytest.raises(WorkflowFailureError) as error:
            await handle.result()
        assert isinstance(error.value.cause, ActivityError)
        cause = error.value.cause.cause
        assert isinstance(cause, ApplicationError)
        assert cause.type == "RequestClosed" and cause.non_retryable
        assert r.call("current_attempt", request_id=r.request.request_id) is None
        assert r.snapshot()["environment"]["state"] == "free"
