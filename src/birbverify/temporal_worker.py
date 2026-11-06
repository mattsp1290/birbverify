import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.worker import Worker

with workflow.unsafe.imports_passed_through():
    from birbverify.contract import digest
    from birbverify.runner import Busy, Runner
    from birbverify.target import TargetError


@workflow.defn
class FixtureWorkflow:
    """Test adapter only. Birbforge supplies the production workflow and queue."""

    def __init__(self):
        self.available = False
        self.phase = "dispatching"

    @workflow.signal
    def environment_available(self):
        self.available = True

    @workflow.query
    def state(self) -> str:
        return self.phase

    @workflow.run
    async def run(self, payload: dict) -> dict:
        while True:
            try:
                self.phase = "dispatching"
                return await workflow.execute_activity(
                    "verify_candidate",
                    payload,
                    start_to_close_timeout=timedelta(seconds=90),
                    schedule_to_close_timeout=timedelta(seconds=180),
                    heartbeat_timeout=timedelta(seconds=15),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=1),
                        maximum_interval=timedelta(seconds=2),
                        maximum_attempts=payload["resources"]["max_attempts"],
                    ),
                    cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                )
            except ActivityError as error:
                if (
                    not isinstance(error.cause, ApplicationError)
                    or error.cause.type != "EnvironmentBusy"
                ):
                    raise
                self.phase = "waiting_for_test_supervisor"
                deadline = datetime.fromisoformat(payload["resources"]["deadline"])
                await workflow.wait_condition(
                    lambda: self.available, timeout=deadline - workflow.now()
                )
                self.available = False


class Activities:
    def __init__(self, root: Path):
        self.runner = Runner(root)

    @activity.defn(name="verify_candidate")
    async def verify(self, payload: dict) -> dict:
        info = activity.info()
        identity = (
            payload["request_id"]
            + "-"
            + digest(
                {
                    "run": info.workflow_run_id,
                    "activity": info.activity_id,
                    "retry": info.attempt,
                }
            )[:16]
        )

        async def heartbeat():
            while True:
                activity.heartbeat(identity)
                await asyncio.sleep(0.5)

        task = asyncio.create_task(heartbeat())
        try:
            return await self.runner.execute(
                payload, identity, lambda: activity.heartbeat(identity)
            )
        except Busy as error:
            raise ApplicationError(
                "environment_wait", type="EnvironmentBusy", non_retryable=True
            ) from error
        except (ValueError, TargetError) as error:
            raise ApplicationError(str(error), non_retryable=True) from error
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def main(root: Path, address: str):
    client = await Client.connect(address)
    worker = Worker(
        client,
        task_queue="birbverify-fixture",
        workflows=[FixtureWorkflow],
        activities=[Activities(root).verify],
    )
    await worker.run()


if __name__ == "__main__":
    os.umask(0o077)
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2]))
