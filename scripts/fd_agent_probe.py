"""Run the production agent for a bounded disposable FD integration node."""

import asyncio
import os

from pydantic import SecretStr

from fleetdoctor.agent import run


def main() -> None:
    node = os.environ["FLEETDOCTOR_NODE_ID"]
    url = os.environ["FLEETDOCTOR_COLLECTOR_URL"].rstrip("/")
    token = SecretStr(os.environ["FLEETDOCTOR_PROOF_TOKEN"])
    asyncio.run(run(node, url, token, ("/",), False))


if __name__ == "__main__":
    main()
