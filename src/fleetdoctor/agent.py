"""Unprivileged host agent with independent collection and bounded delivery."""

import argparse
import asyncio
import logging
import os
import signal
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from pydantic import SecretStr

from fleetdoctor.collection import CollectionWorker
from fleetdoctor.cpu import CpuCollectionWorker
from fleetdoctor.delivery import DeliveryQueue, Outcome, send, uploader
from fleetdoctor.schema import UNITS, UNITS_V2, CpuObservation, Filesystem, Sample

LOG = logging.getLogger(__name__)


def configured_cpu_pids(raw: str) -> tuple[int, ...]:
    if not raw:
        return ()
    values = raw.split(",")
    if len(values) > 16 or any(not value.isdigit() for value in values):
        raise ValueError("FLEETDOCTOR_CPU_PIDS requires at most 16 comma-separated numeric PIDs")
    result = tuple(int(value) for value in values)
    if len(set(result)) != len(result) or any(value < 1 or value > 2**31 - 1 for value in result):
        raise ValueError("FLEETDOCTOR_CPU_PIDS requires unique positive PIDs")
    return result


def make_sample(
    node: str,
    boot: UUID,
    session: UUID,
    sequence: int,
    filesystems: list[Filesystem],
    observed_at: datetime | None = None,
    cpu: CpuObservation | None = None,
) -> Sample:
    return Sample(
        schema_version=2 if cpu is not None else 1,
        node_id=node,
        boot_id=boot,
        agent_session_id=session,
        sequence=sequence,
        observed_at=observed_at or datetime.now(UTC),
        units=UNITS_V2 if cpu is not None else UNITS,
        filesystems=filesystems,
        cpu=cpu,
    )


async def upload(
    client: httpx.AsyncClient, url: str, token: SecretStr, sample: Sample, deadline: float = 2.0
) -> Outcome:
    return await send(client, url, token, sample.model_dump_json().encode("utf-8"), deadline)


def next_tick(scheduled: float, now: float, interval: float = 5.0) -> float:
    candidate = scheduled + interval
    return candidate if candidate > now else now + interval


async def run(node: str, url: str, token: SecretStr, paths: tuple[str, ...], once: bool) -> None:
    boot = UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    session = uuid4()
    worker = CollectionWorker()
    cpu_worker = CpuCollectionWorker() if os.name == "posix" else None
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    try:
        await collect_loop(
            node,
            boot,
            session,
            worker,
            url,
            token,
            paths,
            once,
            stopped,
            cpu_worker=cpu_worker,
        )
    finally:
        worker.close()
        if cpu_worker is not None:
            cpu_worker.close()


async def collect_loop(
    node: str,
    boot: UUID,
    session: UUID,
    worker: CollectionWorker,
    url: str,
    token: SecretStr,
    paths: tuple[str, ...],
    once: bool,
    stopped: asyncio.Event,
    *,
    cpu_worker: CpuCollectionWorker | None = None,
) -> None:
    """Also used by the service proof with an ordinary synthetic collection worker."""
    sequence = 0
    queue = DeliveryQueue()
    async with httpx.AsyncClient(
        timeout=2,
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=2),
    ) as client:
        tick = time.monotonic()
        upload_task = None if once else asyncio.create_task(uploader(queue, client, url, token))
        try:
            while not stopped.is_set():
                observed_at = datetime.now(UTC)
                collection = asyncio.create_task(asyncio.to_thread(worker.collect, paths))
                try:
                    filesystems = await asyncio.shield(collection)
                except asyncio.CancelledError:
                    # The worker cannot be closed concurrently with its outstanding call.
                    await collection
                    raise
                cpu = None
                if cpu_worker is not None:
                    configured = configured_cpu_pids(os.getenv("FLEETDOCTOR_CPU_PIDS", ""))
                    cpu_collection = asyncio.create_task(
                        asyncio.to_thread(cpu_worker.collect, configured)
                    )
                    try:
                        cpu = await asyncio.shield(cpu_collection)
                    except asyncio.CancelledError:
                        await cpu_collection
                        raise
                sample = make_sample(
                    node, boot, session, sequence, filesystems, observed_at, cpu=cpu
                )
                queue.enqueue(sample, datetime.now(UTC))
                if once:
                    entry = queue.select(datetime.now(UTC))
                    if entry is not None:
                        try:
                            result = await send(client, url, token, entry.body)
                        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
                            LOG.warning("upload failed: %s", type(exc).__name__)
                            result = "retry"
                        queue.complete(entry, result, datetime.now(UTC))
                    return
                sequence += 1
                tick = next_tick(tick, time.monotonic())
                try:
                    await asyncio.wait_for(stopped.wait(), timeout=max(0, tick - time.monotonic()))
                except TimeoutError:
                    pass
        finally:
            if upload_task is not None:
                upload_task.cancel()
                with suppress(asyncio.CancelledError):
                    await upload_task


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    node = os.environ["FLEETDOCTOR_NODE_ID"]
    url = os.environ["FLEETDOCTOR_COLLECTOR_URL"].rstrip("/")
    credential = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "ingest-token"
    token = SecretStr(credential.read_text().strip())
    paths = tuple(os.environ.get("FLEETDOCTOR_FILESYSTEMS", "/").split(","))
    if not token.get_secret_value() or not url.startswith("http://"):
        raise ValueError("configure a token and private-IP HTTP collector URL")
    configured_cpu_pids(os.getenv("FLEETDOCTOR_CPU_PIDS", ""))
    make_sample(
        node,
        uuid4(),
        uuid4(),
        0,
        [Filesystem(mountpoint=p, errors=["initializing"]) for p in paths],
    )
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run(node, url, token, paths, args.once))


if __name__ == "__main__":
    main()
