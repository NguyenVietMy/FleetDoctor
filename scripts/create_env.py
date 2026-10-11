"""Generate secrets into an untracked file; never print their values."""

import argparse
import json
import os
import secrets
from pathlib import Path


def create(
    path: Path, collector_ip: str = "127.0.0.1", ports: tuple[int, int, int] = (8000, 9090, 3000)
) -> dict[str, str]:
    tokens = {node: secrets.token_urlsafe(32) for node in ("node-a", "node-b")}
    values = {
        "FLEETDOCTOR_NODE_TOKENS": json.dumps(tokens, separators=(",", ":")),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "GRAFANA_PASSWORD": secrets.token_urlsafe(32),
        "COLLECTOR_BIND_IP": collector_ip,
        "COLLECTOR_PORT": str(ports[0]),
        "PROMETHEUS_PORT": str(ports[1]),
        "GRAFANA_PORT": str(ports[2]),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        for key, value in values.items():
            stream.write(f"{key}='{value}'\n")
    return values


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--collector-ip", default="127.0.0.1")
    args = parser.parse_args()
    create(args.path, args.collector_ip)
    print(f"Created {args.path}; contains secrets, keep outside source control.")
