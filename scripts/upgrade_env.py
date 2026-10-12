"""Privately upgrade retained env files; preserve all existing secrets and settings."""

import argparse
import os
import secrets
import tempfile
from pathlib import Path

DISK_PATH = "/var/lib/fleetdoctor/chaos/disk"


def upgrade(path: Path, *, disk: bool = False) -> bool:
    original = path.read_text(encoding="utf-8")
    keys = {
        line.split("=", 1)[0]
        for line in original.splitlines()
        if "=" in line and not line.startswith("#")
    }
    additions = {}
    if "GRAFANA_DB_PASSWORD" not in keys:
        additions["GRAFANA_DB_PASSWORD"] = secrets.token_urlsafe(32)
    if "FLEETDOCTOR_FILESYSTEMS" not in keys:
        additions["FLEETDOCTOR_FILESYSTEMS"] = "/," + DISK_PATH if disk else "/"
    if not additions:
        return False
    text = original.rstrip("\n") + "\n" + "".join(f"{k}='{v}'\n" for k, v in additions.items())
    fd, name = tempfile.mkstemp(prefix=".fleetdoctor-env-", dir=path.parent)
    try:
        os.chmod(name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--disk",
        action="store_true",
        help="add both filesystem paths if absent; prepare both nodes before deployment",
    )
    args = parser.parse_args()
    upgrade(args.path, disk=args.disk)
    print("Env upgrade complete (values withheld); existing settings preserved.")
