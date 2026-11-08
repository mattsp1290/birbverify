import asyncio
import json
import os
from pathlib import Path

import pytest
from temporalio.client import WorkflowFailureError
from temporalio.testing import WorkflowEnvironment

from birbverify.contract import Manifest, Request, digest, eligible
from birbverify.fixture import ROOT, initialize, request, spawn, start_target, stop
from birbverify.projection import observe
from birbverify.runner import Busy, Runner
from birbverify.target import TargetError, rpc
from birbverify.temporal_worker import FixtureWorkflow


async def until(predicate, seconds=20):
    async with asyncio.timeout(seconds):
        while not predicate():
            await asyncio.sleep(0.05)


@pytest.fixture
async def installation(tmp_path):
    root = tmp_path / "proof"
    initialize(root)
    target = start_target(root)
    try:
        yield root
    finally:
        stop(target)


@pytest.mark.asyncio
async def test_candidate_evidence_and_compatibility(installation):
    root = installation
    runner = Runner(root)
    req = request(root, "pass")
    payload = req.model_dump(mode="json")
    assert rpc(root, "admit", request=payload) == rpc(root, "admit", request=payload)
    with pytest.raises(TargetError, match="identity_conflict"):
        rpc(root, "admit", request={**payload, "goal_id": "changed"})
    result = Manifest.model_validate(await runner.execute(payload, "pass-a1"))
    assert eligible(req, result, req.candidate, runner.read_artifact)
    assert runner.artifacts_available(result)
    assert Manifest.model_validate(await runner.execute(payload, "pass-a1")) == result
    changed = request(root, "new-head", failing=True)
    assert not eligible(req, result, changed.candidate, runner.read_artifact)
    with pytest.raises(TargetError, match="manifest_identity_conflict"):
        rpc(
            root,
            "finish",
            attempt_id="pass-a1",
            manifest={
                **result.model_dump(mode="json"),
                "candidate": changed.candidate.model_dump(),
            },
        )
    artifact = result.checks[0].artifacts[0]
    original_bytes = (root / "artifacts" / artifact.id).read_bytes()
    (root / "artifacts" / artifact.id).unlink()
    assert not runner.artifacts_available(result)
    assert not eligible(req, result, req.candidate, runner.read_artifact)
    (root / "artifacts" / artifact.id).write_bytes(b"corrupt")
    assert not eligible(req, result, req.candidate, runner.read_artifact)
    (root / "artifacts" / artifact.id).write_bytes(original_bytes)
    missing = request(root, "missing")
    runner.config["drop_evidence"] = ["missing"]
    incomplete = Manifest.model_validate(
        await runner.execute(missing.model_dump(mode="json"), "missing-a1")
    )
    assert incomplete.outcome == "inconclusive"
    assert not eligible(missing, incomplete, missing.candidate, runner.read_artifact)
    failed = request(root, "assert-failed", failing=True)
    failure = Manifest.model_validate(
        await runner.execute(failed.model_dump(mode="json"), "assert-failed-a1")
    )
    assert failure.outcome == "failed"
    assert failure.checks[0].outcome == "failed"
    assert result.candidate.commit != failure.candidate.commit
    report = {
        "journeys": [1, 2, 3, 8],
        "pass": result.model_dump(mode="json"),
        "missing": incomplete.model_dump(mode="json"),
        "assertion_failed": failure.model_dump(mode="json"),
    }
    publish("candidate-evidence.json", report)


def publish(name, value):
    directory = os.environ.get("BIRBVERIFY_SAFE_EVIDENCE")
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / name).write_text(json.dumps(value, indent=2) + "\n")


@pytest.mark.asyncio
async def test_lost_reply(installation):
    root = installation
    runner = Runner(root)
    req = request(root, "lost-reply")
    runner.config["lose_operation_reply"] = ["lost-reply"]
    result = Manifest.model_validate(
        await runner.execute(req.model_dump(mode="json"), "lost-reply-a1")
    )
    assert result.outcome == "passed"
    assert result.operation_reconciled
    operations = rpc(root, "inspect")["operations"]
    assert len(operations) == 1
    assert json.loads(operations[0]["receipt"])["value"] == 1
    assert (root / "lost-operation-reply").exists()
    publish(
        "lost-reply.json",
        {
            "journey": 4,
            "result": result.model_dump(mode="json"),
            "operation_count": len(operations),
            "target_value_at_commit": 1,
        },
    )


@pytest.mark.asyncio
async def test_stale_process_and_quarantine(installation):
    root = installation
    runner = Runner(root)
    first = request(root, "first")
    runner.config["pause_after_effect"] = ["first"]
    task = asyncio.create_task(runner.execute(first.model_dump(mode="json"), "first-a1"))
    await until(lambda: (root / "first-a1.effect-committed").exists())
    context = runner.context("first-a1")
    owner = context["owner"]
    operation = {
        **owner,
        "operation_id": "first.apply",
        "request_id": "first",
        "candidate": first.candidate.commit,
        "payload_sha256": digest({"request": digest(first), "candidate": first.candidate.commit}),
    }
    (root / "stale-operation.json").write_text(json.dumps(operation))
    stale = spawn(root, "birbverify.stale_probe")
    await until(lambda: (root / "stale-ready").exists())
    second = request(root, "second")
    with pytest.raises(Busy):
        await runner.execute(second.model_dump(mode="json"), "second-a1")
    assert stale.poll() is None
    rpc(root, "uncertain", **owner)
    with pytest.raises(TargetError, match="termination_unknown"):
        rpc(root, "cleanup", **owner)
    with pytest.raises(TargetError, match="stop_and_cleanup_required"):
        rpc(root, "release", **owner)
    assert rpc(root, "inspect")["environment"]["state"] == "quarantined"
    with pytest.raises(Busy):
        await runner.execute(second.model_dump(mode="json"), "second-a1")
    (root / "stale-go").touch()
    await until(lambda: stale.poll() is not None)
    assert stale.returncode == 0
    assert (root / "stale-result").read_text() == "fenced"
    assert len(rpc(root, "inspect")["operations"]) == 1
    (root / "first-a1.resume").touch()
    result = Manifest.model_validate(await task)
    assert result.outcome == "inconclusive"
    with pytest.raises(TargetError, match="supervisor_required"):
        rpc(root, "stop", **owner)
    rpc(root, "recover", **owner, recovery_key=(root / "supervisor.key").read_text())
    rpc(root, "cleanup", **owner)
    rpc(root, "release", **owner, recovery_key=(root / "supervisor.key").read_text())
    runner.config["pause_after_effect"] = ["second"]
    second_task = asyncio.create_task(runner.execute(second.model_dump(mode="json"), "second-a1"))
    await until(lambda: (root / "second-a1.effect-committed").exists())
    with pytest.raises(TargetError, match="stale_owner"):
        rpc(root, "apply", **operation)
    (root / "second-a1.resume").touch()
    result2 = Manifest.model_validate(await second_task)
    assert result2.outcome == "passed"
    events = rpc(root, "inspect")["events"]
    assert sum(event["event"] == "environment_wait" for event in events) == 2
    publish(
        "fencing.json",
        {
            "journeys": [6, 7],
            "stale_process_exit": stale.returncode,
            "stale_mutation": "fenced",
            "quarantine_blocked_release": True,
            "waiting_events": events,
            "first": result.model_dump(mode="json"),
            "second": result2.model_dump(mode="json"),
        },
    )


@pytest.mark.asyncio
async def test_temporal_worker_loss_cancel_and_observer(installation):
    root = installation
    config = json.loads((root / "installation.json").read_text())
    config["pause_after_effect"] = ["worker-loss"]
    (root / "installation.json").write_text(json.dumps(config))
    runner = Runner(root)
    async with await WorkflowEnvironment.start_local(
        dev_server_existing_path=str(ROOT / ".proof/bin/temporal"),
        dev_server_database_filename=str(root / "temporal.sqlite"),
        dev_server_log_level="error",
    ) as environment:
        worker = spawn(
            root, "birbverify.temporal_worker", environment.client.service_client.config.target_host
        )
        try:
            req = request(root, "worker-loss")
            handle = await environment.client.start_workflow(
                FixtureWorkflow.run,
                req.model_dump(mode="json"),
                id="worker-loss",
                task_queue="birbverify-fixture",
            )
            await until(lambda: list(root.glob("worker-loss-*.effect-committed")), 40)
            loss_attempt = rpc(root, "current_attempt", request_id="worker-loss")
            observer = observe(root, loss_attempt)
            next(observer)
            snapshot = next(observer)
            assert snapshot.snapshot["verification"]["state"] == "running"
            observer.close()
            observation_close_cancelled = (
                rpc(root, "snapshot", attempt_id=loss_attempt)["state"] != "running"
            )
            assert not observation_close_cancelled
            waiting_req = request(root, "temporal-waiter")
            waiting = await environment.client.start_workflow(
                FixtureWorkflow.run,
                waiting_req.model_dump(mode="json"),
                id="temporal-waiter",
                task_queue="birbverify-fixture",
            )
            async with asyncio.timeout(20):
                while await waiting.query(FixtureWorkflow.state) != "waiting_for_test_supervisor":
                    await asyncio.sleep(0.1)
            assert rpc(root, "current_attempt", request_id="temporal-waiter") is None
            stop(worker)
            assert worker.returncode == -9
            context = runner.context(loss_attempt)
            owner = context["owner"]
            rpc(root, "uncertain", **owner)
            assert (
                rpc(root, "snapshot", attempt_id=loss_attempt)["state"]
                == "infrastructure_uncertain"
            )
            observed_before_loss = rpc(root, "inspect")["environment"]["candidate"]
            assert observed_before_loss == req.candidate.commit
            rpc(root, "recover", **owner, recovery_key=(root / "supervisor.key").read_text())
            rpc(root, "cleanup", **owner)
            with pytest.raises(TargetError, match="terminal_manifest_required"):
                rpc(root, "release", **owner, recovery_key=(root / "supervisor.key").read_text())
            rpc(root, "uncertain", **owner)
            uncertain = runner.finalize(
                req,
                context,
                [],
                "inconclusive",
                termination="unknown",
                before=observed_before_loss,
                reason="worker_lost",
            )
            assert uncertain.outcome == "inconclusive"
            assert uncertain.checks[0].outcome == "not_run"
            assert uncertain.cleanup == "unknown"
            await handle.terminate("fixture explicitly reconciles killed worker")
            with pytest.raises(TargetError, match="supervisor_required"):
                rpc(root, "stop", **owner)
            rpc(root, "recover", **owner, recovery_key=(root / "supervisor.key").read_text())
            rpc(root, "cleanup", **owner)
            rpc(root, "release", **owner, recovery_key=(root / "supervisor.key").read_text())
            worker = spawn(
                root,
                "birbverify.temporal_worker",
                environment.client.service_client.config.target_host,
            )
            await waiting.signal(FixtureWorkflow.environment_available)
            waited_result = await asyncio.wait_for(waiting.result(), 40)
            assert waited_result["outcome"] == "passed"
            assert waited_result["attempt_number"] == 1
            cancelled = request(root, "cancelled", slow=True)
            cancel_handle = await environment.client.start_workflow(
                FixtureWorkflow.run,
                cancelled.model_dump(mode="json"),
                id="cancelled",
                task_queue="birbverify-fixture",
            )

            async def container_running():
                attempt = rpc(root, "current_attempt", request_id="cancelled")
                if not attempt:
                    return False
                code, output = await runner.docker(
                    "inspect", "--format", "{{.State.Running}}", f"birbverify-{attempt}"
                )
                return code == 0 and output.strip() == b"true"

            async with asyncio.timeout(40):
                while not await container_running():
                    await asyncio.sleep(0.1)
            cancel_attempt = rpc(root, "current_attempt", request_id="cancelled")
            cancel_owner = runner.context(cancel_attempt)["owner"]
            rpc(root, "cancel", **cancel_owner)
            assert rpc(root, "snapshot", attempt_id=cancel_attempt)["state"] == "cancel_requested"
            with pytest.raises(TargetError, match="stop_and_cleanup_required"):
                rpc(root, "release", **cancel_owner)
            await cancel_handle.cancel()
            try:
                await asyncio.wait_for(cancel_handle.result(), 30)
            except WorkflowFailureError:
                pass
            await until(
                lambda: rpc(root, "snapshot", attempt_id=cancel_attempt)["manifest"] is not None
            )
            result = Manifest.model_validate_json(
                rpc(root, "snapshot", attempt_id=cancel_attempt)["manifest"]
            )
            assert result.cancellation == "acknowledged"
            assert result.outcome == "cancelled"
            assert result.cleanup == "complete"
            assert result.environment_release == "released"
            assert not await container_running()
            events = [
                event.model_dump(mode="json", by_alias=True)
                for event in observe(root, cancel_attempt)
            ]
            assert [event["type"] for event in events] == [
                "RUN_STARTED",
                "STATE_SNAPSHOT",
                "RUN_FINISHED",
            ]
            assert rpc(root, "inspect")["environment"]["state"] == "free"
            history = await cancel_handle.fetch_history()
            publish(
                "temporal-interruption.json",
                {
                    "journeys": [5, 9],
                    "worker_exit": -9,
                    "temporal_waiter": waited_result,
                    "observation_close_cancelled": observation_close_cancelled,
                    "loss": uncertain.model_dump(mode="json"),
                    "cancel": result.model_dump(mode="json"),
                    "events": events,
                    "temporal_history_event_types": [event.event_type for event in history.events],
                },
            )
        finally:
            stop(worker)


@pytest.mark.asyncio
async def test_expiry_and_concurrent_duplicate_do_not_release(installation):
    from datetime import UTC, datetime, timedelta

    root = installation
    runner = Runner(root)
    payload = request(root, "expiry").model_dump(mode="json")
    payload["resources"]["deadline"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    req = Request.model_validate(payload)
    rpc(root, "admit", request=payload)
    reservation = rpc(root, "reserve", request_id=req.request_id, attempt_id="expiry-a1")
    owner = {"attempt_id": "expiry-a1", "token": reservation["token"]}
    with pytest.raises(Busy):
        await runner.execute(payload, "expiry-a1")
    await asyncio.sleep(1.05)
    with pytest.raises(TargetError, match="fenced"):
        rpc(
            root,
            "apply",
            **owner,
            operation_id="expiry.apply",
            request_id=req.request_id,
            candidate=req.candidate.commit,
            payload_sha256=digest({"request": digest(req), "candidate": req.candidate.commit}),
        )
    assert rpc(root, "inspect")["environment"]["state"] == "quarantined"
    next_request = request(root, "after-expiry")
    with pytest.raises(Busy):
        await runner.execute(next_request.model_dump(mode="json"), "after-expiry-a1")
    rpc(root, "uncertain", **owner)
    assert rpc(root, "inspect")["environment"]["state"] == "quarantined"
    publish(
        "expiry.json",
        {
            "expired_owner_mutation": "fenced",
            "automatic_release": False,
            "unknown_termination": "quarantined",
        },
    )


@pytest.mark.asyncio
async def test_delayed_original_effect_and_policy_boundary(installation):
    root = installation
    req = request(root, "race")
    payload = req.model_dump(mode="json")
    bad = {**payload, "authority": {**payload["authority"], "principal": "unapproved"}}
    with pytest.raises(TargetError, match="installation_denied"):
        rpc(root, "admit", request=bad)
    rpc(root, "admit", request=payload)
    reserved = rpc(root, "reserve", request_id=req.request_id, attempt_id="race-a1")
    owner = {"attempt_id": "race-a1", "token": reserved["token"]}
    operation = {
        **owner,
        "operation_id": "race.apply",
        "request_id": req.request_id,
        "candidate": req.candidate.commit,
        "payload_sha256": digest({"request": digest(req), "candidate": req.candidate.commit}),
    }
    assert rpc(root, "receipt", **operation) is None
    first, delayed = await asyncio.gather(
        asyncio.to_thread(rpc, root, "apply", **operation),
        asyncio.to_thread(rpc, root, "apply", **operation),
    )
    assert first == delayed
    assert first["value"] == 1
    rpc(root, "revoke", **owner)
    assert rpc(root, "receipt", **operation) == first
    with pytest.raises(TargetError, match="operation_identity_conflict"):
        rpc(root, "receipt", **{**operation, "payload_sha256": "0" * 64})
    assert len(rpc(root, "inspect")["operations"]) == 1
    publish(
        "operation-race.json",
        {
            "same_operation_results_equal": True,
            "effect_count": 1,
            "receipt_read_after_revoke": True,
            "unapproved_principal": "denied_at_target",
        },
    )


@pytest.mark.asyncio
async def test_concurrent_duplicate_and_lost_finish_reply(installation):
    root = installation
    runner = Runner(root)
    runner.config["lose_finish_reply"] = ["atomic-finish"]
    req = request(root, "atomic-finish")
    payload = req.model_dump(mode="json")

    async def duplicate():
        while True:
            try:
                return await Runner(root).execute(payload, "atomic-finish-duplicate")
            except Busy:
                await asyncio.sleep(0.05)

    original = asyncio.create_task(runner.execute(payload, "atomic-finish-a1"))
    await until(lambda: rpc(root, "current_attempt", request_id=req.request_id) is not None)
    first, second = await asyncio.gather(original, duplicate())
    assert first == second
    assert first["outcome"] == "passed"
    assert (root / "lost-finish-reply").exists()
    assert rpc(root, "inspect")["environment"]["state"] == "free"
    assert "token" not in rpc(root, "inspect")["environment"]
    assert len(rpc(root, "inspect")["operations"]) == 1
    assert rpc(root, "snapshot", attempt_id="atomic-finish-duplicate") is None
    replay = rpc(root, "reserve", request_id=req.request_id, attempt_id="after-cleanup")
    assert replay["result"] == first
    publish(
        "atomic-finish.json",
        {
            "concurrent_duplicate_results_equal": True,
            "lost_finish_reply_reconciled": True,
            "effect_count": 1,
            "new_attempt_after_terminal": False,
        },
    )


@pytest.mark.asyncio
async def test_repeated_cancellation_during_create_and_cleanup(installation):
    root = installation
    created, allow_create_reply = asyncio.Event(), asyncio.Event()
    cleaning, allow_cleanup = asyncio.Event(), asyncio.Event()

    class DelayedControls(Runner):
        async def docker(self, *args):
            result = await super().docker(*args)
            if args[0] == "create":
                created.set()
                await allow_create_reply.wait()
            return result

        async def stop_container(self, name):
            cleaning.set()
            await allow_cleanup.wait()
            return await super().stop_container(name)

    runner = DelayedControls(root)
    req = request(root, "double-cancel")
    task = asyncio.create_task(runner.execute(req.model_dump(mode="json"), "double-cancel-a1"))
    await asyncio.wait_for(created.wait(), 20)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert rpc(root, "inspect")["environment"]["state"] == "active"
    allow_create_reply.set()
    await asyncio.wait_for(cleaning.wait(), 20)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    allow_cleanup.set()
    result = await asyncio.wait_for(task, 20)
    assert result["cancellation"] == "acknowledged"
    assert result["termination"] == "confirmed"
    assert result["environment_release"] == "released"
    assert await Runner(root).stop_container("birbverify-double-cancel-a1")
    publish(
        "repeated-cancellation.json",
        {
            "cancel_after_create_before_reply": True,
            "repeated_cancel_during_cleanup": True,
            "release_before_stop": False,
            "result": result,
        },
    )


@pytest.mark.asyncio
async def test_unknown_container_stop_retains_cancellation_and_quarantine(installation):
    root = installation

    class StopUnavailable(Runner):
        async def stop_container(self, name):
            return False

    runner = StopUnavailable(root)
    req = request(root, "unknown-stop", slow=True)
    task = asyncio.create_task(runner.execute(req.model_dump(mode="json"), "unknown-stop-a1"))
    actual = Runner(root)
    async with asyncio.timeout(20):
        while True:
            code, output = await actual.docker(
                "inspect", "--format", "{{.State.Running}}", "birbverify-unknown-stop-a1"
            )
            if code == 0 and output.strip() == b"true":
                break
            await asyncio.sleep(0.05)
    task.cancel()
    result = await asyncio.wait_for(task, 20)
    assert result["outcome"] == "inconclusive"
    assert result["cancellation"] == "requested"
    assert result["termination"] == "unknown"
    assert result["environment_release"] == "quarantined"
    owner = runner.context("unknown-stop-a1")["owner"]
    with pytest.raises(TargetError, match="supervisor_required"):
        rpc(root, "stop", **owner)
    rpc(root, "cancel", **owner)
    assert rpc(root, "inspect")["environment"]["state"] == "quarantined"
    assert await actual.stop_container("birbverify-unknown-stop-a1")
    rpc(root, "recover", **owner, recovery_key=(root / "supervisor.key").read_text())
    rpc(root, "cleanup", **owner)
    rpc(root, "release", **owner, recovery_key=(root / "supervisor.key").read_text())
    assert rpc(root, "result", request_id=req.request_id) == result
    publish(
        "unknown-stop.json",
        {
            "unconfirmed_stop_did_not_acknowledge": True,
            "quarantine_worker_stop": "denied",
            "supervisor_confirmed_container_removal": True,
            "historical_result": result,
        },
    )
