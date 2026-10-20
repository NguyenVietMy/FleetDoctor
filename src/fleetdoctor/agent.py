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
from typing import Literal
from uuid import UUID, uuid4

import httpx
from pydantic import SecretStr, ValidationError

from fleetdoctor.collection import CollectionWorker
from fleetdoctor.cpu import CpuCollectionWorker
from fleetdoctor.delivery import MAX_BODY, MAX_TOTAL, DeliveryQueue, Outcome, send, uploader
from fleetdoctor.fd import (
    MAX_WATCH_RESPONSE,
    FdCollectionWorker,
    WatchIdentity,
    WatchResponse,
)
from fleetdoctor.memory import MemoryCollectionWorker, validate_cgroup_paths
from fleetdoctor.schema import (
    UNITS,
    UNITS_V2,
    UNITS_V3,
    UNITS_V4,
    CpuObservation,
    Delivery,
    FdObservation,
    FdProcessObservation,
    Filesystem,
    MemoryObservation,
    Sample,
)

LOG = logging.getLogger(__name__)


class PayloadTooLarge(ValueError):
    """A valid sample whose required telemetry cannot fit the delivery request."""


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
    memory: MemoryObservation | None = None,
    fd: FdObservation | None = None,
) -> Sample:
    if fd is not None and (memory is None or cpu is None):
        raise ValueError("schema v4 FD samples require CPU and memory telemetry")
    if memory is not None and cpu is None:
        raise ValueError("schema v3 memory samples require CPU telemetry")
    return Sample(
        schema_version=4
        if fd is not None
        else (3 if memory is not None else (2 if cpu is not None else 1)),
        node_id=node,
        boot_id=boot,
        agent_session_id=session,
        sequence=sequence,
        observed_at=observed_at or datetime.now(UTC),
        units=UNITS_V4
        if fd is not None
        else (UNITS_V3 if memory is not None else (UNITS_V2 if cpu is not None else UNITS)),
        filesystems=filesystems,
        cpu=cpu,
        memory=memory,
        fd=fd,
    )


async def fetch_fd_watch(
    client: httpx.AsyncClient, url: str, node: str, token: SecretStr
) -> WatchResponse:
    async def bounded_fetch() -> WatchResponse:
        base = url[: -len("/ingest")] if url.endswith("/ingest") else url.rstrip("/")
        async with client.stream(
            "GET",
            f"{base}/nodes/{node}/fd-watch",
            headers={"Authorization": "Bearer " + token.get_secret_value()},
            timeout=1,
        ) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > MAX_WATCH_RESPONSE:
                    raise ValueError("FD watch response exceeds 16KiB")
                body.extend(chunk)
        result = WatchResponse.model_validate_json(body)
        if result.node_id != node or not result.complete:
            raise ValueError("FD watch response identity mismatch")
        return result

    return await asyncio.wait_for(bounded_fetch(), timeout=1)


async def refresh_fd_watch(
    client: httpx.AsyncClient,
    url: str,
    node: str,
    token: SecretStr,
    cached: WatchResponse | None,
) -> tuple[
    WatchResponse | None,
    Literal["available", "degraded", "unavailable"],
    str | None,
]:
    try:
        return await fetch_fd_watch(client, url, node, token), "available", None
    except (httpx.HTTPError, TimeoutError, ValueError, ValidationError) as exc:
        return (
            cached,
            "degraded" if cached is not None else "unavailable",
            f"watch_{type(exc).__name__}",
        )


def _max_enveloped_payload_size(sample: Sample) -> int:
    """Return the wire size after reserving the largest valid delivery counter."""
    snapshot = sample.model_copy(update={"delivery": Delivery(discard_total=MAX_TOTAL)})
    return len(snapshot.model_dump_json().encode("utf-8"))


def payload_bounded_sample(sample: Sample) -> Sample:
    if _max_enveloped_payload_size(sample) <= MAX_BODY:
        return sample
    if sample.fd is None:
        raise PayloadTooLarge("sample exceeds 64KiB without optional FD context")
    retained = []
    for item in sample.fd.observations:
        if not item.watched:
            continue
        retained.append(
            FdProcessObservation(
                identity=item.identity,
                status=item.status,
                watched=True,
                configured=item.configured,
                descriptor_count=item.descriptor_count,
                soft_limit=item.soft_limit,
                limit_unlimited=item.limit_unlimited,
                pressure_ratio=item.pressure_ratio,
                errors=item.errors,
            )
        )
    errors = [*sample.fd.errors]
    if "payload_budget" not in errors:
        errors.append("payload_budget")
    fd = FdObservation(
        observations=retained,
        watch_coverage=sample.fd.watch_coverage,
        watch_revision=sample.fd.watch_revision,
        selected_identities=sample.fd.selected_identities,
        configured_pids=sample.fd.configured_pids,
        context_trimmed=True,
        errors=errors[:8],
    )
    compact = sample.model_copy(update={"fd": fd})
    if _max_enveloped_payload_size(compact) > MAX_BODY:
        raise PayloadTooLarge("required sample telemetry exceeds 64KiB")
    return compact


def enqueue_bounded_sample(queue: DeliveryQueue, sample: Sample, now: datetime) -> None:
    """Compact optional FD context, or let the queue count an unavoidable oversize drop."""
    try:
        bounded = payload_bounded_sample(sample)
    except PayloadTooLarge as exc:
        if queue.enqueue(sample, now) is None:
            LOG.warning("delivery dropped oversized sample: %s", exc)
    else:
        queue.enqueue(bounded, now)


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
    memory_worker = MemoryCollectionWorker() if os.name == "posix" else None
    fd_worker = FdCollectionWorker() if os.name == "posix" else None
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
            memory_worker=memory_worker,
            fd_worker=fd_worker,
        )
    finally:
        worker.close()
        if cpu_worker is not None:
            cpu_worker.close()
        if memory_worker is not None:
            memory_worker.close()
        if fd_worker is not None:
            fd_worker.close()


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
    memory_worker: MemoryCollectionWorker | None = None,
    fd_worker: FdCollectionWorker | None = None,
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
        watch_cache: WatchResponse | None = None
        watch_client = (
            httpx.AsyncClient(
                timeout=1,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(
                    max_connections=1, max_keepalive_connections=1, keepalive_expiry=2
                ),
            )
            if fd_worker is not None
            else None
        )
        try:
            while not stopped.is_set():
                watch_coverage: Literal["available", "degraded", "unavailable"] = "unavailable"
                watch_error = None
                if fd_worker is not None:
                    assert watch_client is not None
                    watch_cache, watch_coverage, watch_error = await refresh_fd_watch(
                        watch_client, url, node, token, watch_cache
                    )
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
                memory = None
                if memory_worker is not None:
                    cgroups = validate_cgroup_paths(os.getenv("FLEETDOCTOR_CGROUPS", ""))
                    memory_collection = asyncio.create_task(
                        asyncio.to_thread(memory_worker.collect, cgroups)
                    )
                    try:
                        memory = await asyncio.shield(memory_collection)
                    except asyncio.CancelledError:
                        await memory_collection
                        raise
                fd = None
                if fd_worker is not None and cpu is not None:
                    configured = configured_cpu_pids(os.getenv("FLEETDOCTOR_CPU_PIDS", ""))
                    cached_watches: tuple[WatchIdentity, ...] = (
                        tuple(watch_cache.watches) if watch_cache is not None else ()
                    )
                    fd_collection = asyncio.create_task(
                        asyncio.to_thread(
                            fd_worker.collect,
                            boot,
                            cpu,
                            configured,
                            cached_watches,
                            watch_coverage,
                            watch_cache.revision if watch_cache is not None else None,
                            watch_error,
                        )
                    )
                    try:
                        fd = await asyncio.shield(fd_collection)
                    except asyncio.CancelledError:
                        await fd_collection
                        raise
                sample = make_sample(
                    node,
                    boot,
                    session,
                    sequence,
                    filesystems,
                    observed_at,
                    cpu=cpu,
                    memory=memory,
                    fd=fd,
                )
                enqueue_bounded_sample(queue, sample, datetime.now(UTC))
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
            if watch_client is not None:
                await watch_client.aclose()
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
    validate_cgroup_paths(os.getenv("FLEETDOCTOR_CGROUPS", ""))
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
