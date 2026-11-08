"""Assert the production systemd security envelope from inside a real restricted service."""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
from pathlib import Path


def status_fields() -> dict[str, str]:
    wanted = {"Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp"}
    return {
        name: value.strip()
        for line in Path("/proc/self/status").read_text().splitlines()
        for name, separator, value in [line.partition(":")]
        if separator and name in wanted
    }


def socket_result(family: int, kind: int, protocol: int = 0) -> dict[str, object]:
    try:
        handle = socket.socket(family, kind, protocol)
    except OSError as exc:
        return {"created": False, "errno": exc.errno, "error": type(exc).__name__}
    handle.close()
    return {"created": True, "errno": None, "error": None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    if len(args.token) != 32 or any(value not in "0123456789abcdef" for value in args.token):
        raise ValueError("strong lowercase hexadecimal token required")
    temporary = Path("/tmp") / f"fleetdoctor-envelope-{args.token}"
    protected = Path("/usr/local") / f"fleetdoctor-envelope-{args.token}"
    sockets = {
        "AF_UNIX": socket_result(socket.AF_UNIX, socket.SOCK_STREAM),
        "AF_INET": socket_result(socket.AF_INET, socket.SOCK_STREAM),
        "AF_INET6": socket_result(socket.AF_INET6, socket.SOCK_STREAM),
        "AF_NETLINK": socket_result(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE),
        "AF_PACKET": socket_result(socket.AF_PACKET, socket.SOCK_DGRAM),
    }
    protected_errno: int | None = None
    try:
        descriptor = os.open(protected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        protected_errno = exc.errno
    else:
        os.close(descriptor)
        protected.unlink()
        raise AssertionError("ProtectSystem=strict allowed a /usr/local write")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, b"private\n")
    os.close(descriptor)
    status = status_fields()
    result = {
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "status": status,
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "sockets": sockets,
        "protected_write_errno": protected_errno,
        "private_tmp_path": str(temporary),
        "private_tmp_inode": temporary.stat().st_ino,
    }
    if (
        result["uid"] == 0
        or status.get("CapEff") != "0000000000000000"
        or status.get("NoNewPrivs") != "1"
        or not all(sockets[name]["created"] for name in ("AF_UNIX", "AF_INET", "AF_INET6"))
        or sockets["AF_NETLINK"]["created"]
        or sockets["AF_NETLINK"]["errno"] not in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES)
        or sockets["AF_PACKET"]["created"]
        or sockets["AF_PACKET"]["errno"] not in (errno.EAFNOSUPPORT, errno.EPERM, errno.EACCES)
        or protected_errno not in (errno.EROFS, errno.EPERM, errno.EACCES)
    ):
        raise AssertionError(json.dumps(result, sort_keys=True))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
