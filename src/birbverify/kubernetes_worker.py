"""Credentialless Kubernetes activities. Birbforge owns workflows and scheduling."""

import argparse
import asyncio
from pathlib import Path

from temporalio import activity
from temporalio.client import Client
from temporalio.worker import Worker

from birbverify.kubernetes_service import call_target


class KubernetesActivities:
    def __init__(self, socket_path: Path):
        self.socket_path = socket_path

    async def _call(self, method: str, payload: dict, **kwargs) -> dict:
        return await asyncio.to_thread(call_target, self.socket_path, method, payload, **kwargs)

    @activity.defn(name="birbverify_kubernetes_execute")
    async def execute(self, payload: dict) -> dict:
        async def heartbeat():
            while True:
                activity.heartbeat()
                await asyncio.sleep(1)

        pulse = asyncio.create_task(heartbeat())
        try:
            await self._call("begin", payload)
            return await self._call("execute", payload)
        except asyncio.CancelledError:
            # The target owns any in-flight API call after this worker disappears.
            cleanup = asyncio.create_task(self._call("close", payload, reason="cancelled"))
            try:
                await asyncio.shield(cleanup)
            except Exception:
                pass
            raise
        finally:
            pulse.cancel()
            await asyncio.gather(pulse, return_exceptions=True)

    @activity.defn(name="birbverify_kubernetes_observe")
    async def observe(self, payload: dict) -> dict:
        return await self._call("inspect", payload)

    @activity.defn(name="birbverify_kubernetes_close")
    async def close(self, payload: dict) -> dict:
        if set(payload) != {"request", "reason"}:
            raise ValueError("close_requires_request_and_reason")
        return await self._call("close", payload["request"], reason=payload["reason"])


async def run(address: str, queue: str, socket_path: Path, namespace: str):
    client = await Client.connect(address, namespace=namespace)
    activities = KubernetesActivities(socket_path)
    worker = Worker(
        client,
        task_queue=queue,
        activities=[activities.execute, activities.observe, activities.close],
    )
    await worker.run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--queue", required=True)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--namespace", default="default")
    args = parser.parse_args()
    asyncio.run(run(args.address, args.queue, args.socket, args.namespace))


if __name__ == "__main__":
    main()
