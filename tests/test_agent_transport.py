import asyncio
import socket
import time
from collections.abc import Awaitable, Callable
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest
import uvicorn
from pydantic import SecretStr
from starlette.requests import Request
from starlette.responses import Response

from fleetdoctor import agent
from fleetdoctor.collector import create_app
from fleetdoctor.schema import Filesystem
from fleetdoctor.store import FixtureStore


def test_production_agent_uploads_at_five_seconds_without_reusing_idle_sockets(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    worker = Mock()
    worker.collect.return_value = [Filesystem(mountpoint="/", errors=["test_fixture"])]
    monkeypatch.setattr(agent, "CollectionWorker", lambda: worker)
    monkeypatch.setattr(agent, "Path", lambda _: Mock(read_text=Mock(return_value=str(uuid4()))))

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        # Signals and /proc belong to the Linux service; exercise transport on either OS.
        monkeypatch.setattr(loop, "add_signal_handler", lambda *args: None)
        token = SecretStr("a" * 40)
        app = create_app({"node-a": token}, store=FixtureStore())
        received: list[int] = []
        ports: list[int] = []
        times: list[float] = []
        complete = asyncio.Event()

        @app.middleware("http")
        async def observe(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            if request.url.path != "/ingest":
                return await call_next(request)
            value = await request.json()
            response = await call_next(request)
            assert response.status_code == 200
            assert request.client is not None
            received.append(value["sequence"])
            ports.append(request.client.port)
            times.append(time.monotonic())
            # A response takes time, so the next scheduled upload has <5s of idle time.
            # The old default pool would reuse the socket near the server's 5s cutoff.
            await asyncio.sleep(0.1)
            if len(received) == 4:
                complete.set()
            return response

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            address = f"http://127.0.0.1:{sock.getsockname()[1]}"
            server = uvicorn.Server(
                uvicorn.Config(app, log_config=None, access_log=False, timeout_keep_alive=5)
            )
            server_task = asyncio.create_task(server.serve(sockets=[sock]))
            agent_task: asyncio.Task[None] | None = None
            try:

                async def ready() -> None:
                    while not server.started:
                        if server_task.done():
                            await server_task
                            raise RuntimeError("server exited before readiness")
                        await asyncio.sleep(0.01)

                await asyncio.wait_for(ready(), timeout=5)
                agent_task = asyncio.create_task(agent.run("node-a", address, token, ("/",), False))
                await asyncio.wait_for(complete.wait(), timeout=20)
                await asyncio.sleep(0.2)
                assert received == [0, 1, 2, 3]
                assert len(set(ports)) == 4, "scheduled uploads reused an idle socket"
                intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
                assert all(4.5 <= interval <= 5.5 for interval in intervals), intervals
                async with httpx.AsyncClient(trust_env=False) as client:
                    view = (await client.get(address + "/nodes")).json()["nodes"][0]
                    assert view["sample"]["sequence"] == 3 and view["fresh"]
            finally:
                if agent_task is not None:
                    agent_task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await agent_task
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

    asyncio.run(scenario())
    worker.close.assert_called_once()
    assert not any(record.getMessage().startswith("upload failed") for record in caplog.records)
