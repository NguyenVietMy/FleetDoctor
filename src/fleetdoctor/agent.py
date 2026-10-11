"""Unprivileged host agent. Outage queue/replay support belongs to task 03."""

import argparse
import asyncio
import logging
import os
import signal
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from pydantic import SecretStr

from fleetdoctor.collection import CollectionWorker
from fleetdoctor.schema import UNITS, Filesystem, Sample

LOG = logging.getLogger(__name__)


def make_sample(
    node: str,
    boot: UUID,
    session: UUID,
    sequence: int,
    filesystems: list[Filesystem],
    observed_at: datetime | None = None,
) -> Sample:
    return Sample(
        schema_version=1,
        node_id=node,
        boot_id=boot,
        agent_session_id=session,
        sequence=sequence,
        observed_at=observed_at or datetime.now(UTC),
        units=UNITS,
        filesystems=filesystems,
    )


async def upload(
    client: httpx.AsyncClient, url: str, token: SecretStr, sample: Sample, deadline: float = 2.0
) -> None:
    async def request() -> None:
        async with client.stream(
            "POST",
            url + "/ingest",
            content=sample.model_dump_json(),
            headers={
                "Authorization": "Bearer " + token.get_secret_value(),
                "Content-Type": "application/json",
            },
        ) as response:
            response.raise_for_status()
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 16384:
                    raise ValueError("ingest response too large")

    await asyncio.wait_for(request(), timeout=deadline)


def next_tick(scheduled: float, now: float, interval: float = 5.0) -> float:
    candidate = scheduled + interval
    return candidate if candidate > now else now + interval


async def run(node: str, url: str, token: SecretStr, paths: tuple[str, ...], once: bool) -> None:
    boot = UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    session = uuid4()
    worker = CollectionWorker()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    tick = time.monotonic()
    sequence = 0
    try:
        # A five-second upload period must not reuse a connection at Uvicorn's
        # five-second idle cutoff. Expire our idle sockets well before that edge.
        async with httpx.AsyncClient(
            timeout=2,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(keepalive_expiry=2),
        ) as client:
            while not stopped.is_set():
                observed_at = datetime.now(UTC)
                filesystems = worker.collect(paths)
                sample = make_sample(node, boot, session, sequence, filesystems, observed_at)
                try:
                    await upload(client, url, token, sample)
                except (httpx.HTTPError, TimeoutError, ValueError) as exc:
                    LOG.warning("upload failed: %s (sequence %d)", type(exc).__name__, sequence)
                sequence += 1
                if once:
                    break
                tick = next_tick(tick, time.monotonic())
                try:
                    await asyncio.wait_for(stopped.wait(), timeout=max(0, tick - time.monotonic()))
                except TimeoutError:
                    pass
    finally:
        worker.close()


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
