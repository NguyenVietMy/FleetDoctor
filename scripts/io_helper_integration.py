"""Aggregate owned I/O helper and actual-systemd proof on WSL or direct Linux."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from chaos_harness import source_manifest
from create_env import create

ROOT = Path(__file__).resolve().parents[1]
COMMON_REPO = Path(
    os.getenv(
        "FLEETDOCTOR_COMMON_REPO",
        "C:/Users/VietM/OneDrive/Documents/VietMySpace/FleetDoctor",
    )
)
BASE_REVISION = "5042e86ebc8caac113fc66984ad2cf0f0034f86a"
_HEX = frozenset("0123456789abcdef")


def free_port() -> int:
    with socket.socket() as stream:
        stream.bind(("0.0.0.0", 0))
        return int(stream.getsockname()[1])


def execute(
    argv: list[str], *, cwd: Path = ROOT, timeout: int = 300, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def command_receipt(argv: list[str], result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "argv": argv,
        "exit": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
    }


def atomic_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for attempt in range(5):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05)


def manifest_revision(manifest: dict[str, Any]) -> str:
    revision = manifest.get("revision")
    if (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in _HEX for character in revision)
    ):
        raise ValueError("source manifest has no valid exact revision")
    return revision


def common_repository_preflight(common_repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    target = manifest_revision(manifest)
    common_head = execute(["git", "-C", str(common_repo), "rev-parse", "HEAD"])
    target_exists = execute(["git", "-C", str(common_repo), "cat-file", "-e", target + "^{commit}"])
    review_base_exists = execute(
        ["git", "-C", str(common_repo), "cat-file", "-e", BASE_REVISION + "^{commit}"]
    )
    result = {
        "path": str(common_repo),
        "head": common_head.stdout.strip(),
        "target_revision": target,
        "target_exists": target_exists.returncode == 0,
        "review_base": BASE_REVISION,
        "review_base_exists": review_base_exists.returncode == 0,
    }
    if common_head.returncode or target_exists.returncode:
        raise RuntimeError("selected common repository lacks source manifest revision")
    return result


def manifest_inventory(manifest: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    return {
        item["path"]: (
            item["kind"],
            item["working_tree_sha256"],
            item["git_committed_sha256"],
            item["tracked_at_head"],
        )
        for item in manifest.get("files", [])
    }


def manifests_match(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    return bool(
        actual.get("revision") == manifest_revision(expected)
        and actual.get("sha256") == expected.get("sha256")
        and manifest_inventory(actual) == manifest_inventory(expected)
    )


def windows_source_archive(
    archive: Path, manifest: dict[str, Any], source_root: Path = ROOT
) -> None:
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for item in manifest["files"]:
            if item["kind"] != "file":
                continue
            relative = item["path"]
            source = source_root / relative
            if not source.is_file() or source.is_symlink():
                raise ValueError(f"source archive identity changed: {relative}")
            bundle.write(source, relative)


def overlay_source_archive(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if any(
            not item.filename
            or Path(item.filename).is_absolute()
            or ".." in Path(item.filename).parts
            or item.is_dir()
            for item in entries
        ):
            raise ValueError("unsafe source archive entry")
        targets = [(root / item.filename).resolve() for item in entries]
        if any(root not in target.parents for target in targets):
            raise ValueError("source archive escapes owned root")
        for item, target in zip(entries, targets, strict=True):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(item))


def apply_source_deletions(destination: Path, deleted_paths: list[Any]) -> None:
    root = destination.resolve()
    for relative in deleted_paths:
        if not isinstance(relative, str) or not relative or ".." in Path(relative).parts:
            raise ValueError("unsafe source deletion entry")
        target = (root / relative).resolve()
        if root not in target.parents:
            raise ValueError("source deletion escapes owned root")
        if target.exists() and target.is_file() and not target.is_symlink():
            target.unlink()


def materialize_source(
    common_repo: Path,
    destination: Path,
    archive: Path,
    deleted_paths: list[Any],
    manifest: dict[str, Any],
    command_log: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = manifest_revision(manifest)
    clone = execute(
        ["git", "clone", "--no-hardlinks", str(common_repo), str(destination)], timeout=180
    )
    if command_log is not None:
        command_log.append(
            command_receipt(["git", "clone", "--no-hardlinks", "owned common repo"], clone)
        )
    if clone.returncode:
        raise RuntimeError("owned source clone failed: " + clone.stderr[-2000:])
    checkout = execute(["git", "-C", str(destination), "checkout", "-q", "--detach", target])
    if command_log is not None:
        command_log.append(
            command_receipt(["git", "checkout", "source manifest revision"], checkout)
        )
    if checkout.returncode:
        raise RuntimeError("owned source revision checkout failed: " + checkout.stderr[-2000:])
    overlay_source_archive(archive, destination)
    apply_source_deletions(destination, deleted_paths)
    materialized = source_manifest(destination)
    if not manifests_match(manifest, materialized):
        raise AssertionError("materialized source inventory differs from source manifest")
    return materialized


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    nested = args.output.with_name(args.output.stem + "-systemd.json")
    helper_state = args.output.with_name(args.output.stem + "-helper-state.json")
    if args.output.exists() or nested.exists() or helper_state.exists():
        raise FileExistsError("native aggregate refuses an existing output or nested evidence")

    run_token = secrets.token_hex(16)
    project = "fd11-io-" + uuid4().hex[:10]
    ports = (free_port(), free_port(), free_port())
    native_root = f"/opt/fleetdoctor-io-runtime-{run_token}"
    suffix = run_token[:12]
    units = [
        f"fleetdoctor-io-target-{suffix}.service",
        f"fleetdoctor-io-reference-{suffix}.service",
        f"fleetdoctor-io-envelope-{suffix}.service",
        f"fleetdoctor-io-supervisor-{suffix}.service",
        f"fleetdoctor-io-resource-{suffix}.service",
    ]
    report: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "project": project,
        "run_token": run_token,
        "commands": [],
        "cleanup": [],
        "route": "Windows Docker services plus WSL Ubuntu actual systemd",
        "root_route": (
            "wsl.exe -d Ubuntu -u root; no sudo"
            if os.name == "nt"
            else "direct root on local Linux systemd host"
        ),
    }
    compose_base: list[str] = []
    failure: str | None = None
    cleanup_failures: list[str] = []
    uv_container = f"fd11-uv-{run_token[:12]}"

    with tempfile.TemporaryDirectory(prefix="fleetdoctor-io-services-") as temporary:
        temporary_path = Path(temporary)
        env_path = temporary_path / "services.env"
        archive = temporary_path / "source.zip"
        deletions = temporary_path / "deletions.json"
        uv_host = temporary_path / "uv"

        def compose(*command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
            result = execute(compose_base + list(command), timeout=300)
            report["commands"].append(command_receipt(["docker", "compose", *command], result))
            if check and result.returncode:
                raise RuntimeError(f"compose {' '.join(command)}: {result.stderr[-2000:]}")
            return result

        try:
            report["source_before"] = source_manifest()
            target_revision = manifest_revision(report["source_before"])
            windows_source_archive(archive, report["source_before"])
            deletions.write_text(
                json.dumps(
                    [
                        item["path"]
                        for item in report["source_before"]["files"]
                        if item["kind"] == "deleted"
                    ]
                ),
                encoding="utf-8",
            )
            report["common_repository_preflight"] = common_repository_preflight(
                COMMON_REPO, report["source_before"]
            )
            uv_create = execute(
                ["docker", "create", "--name", uv_container, "ghcr.io/astral-sh/uv:0.11.4"],
                timeout=60,
            )
            report["commands"].append(
                command_receipt(["docker", "create", "owned uv binary container"], uv_create)
            )
            if uv_create.returncode:
                raise RuntimeError("owned uv binary container creation failed")
            uv_copy = execute(["docker", "cp", f"{uv_container}:/uv", str(uv_host)], timeout=60)
            report["commands"].append(
                command_receipt(["docker", "cp", "owned uv 0.11.4 binary"], uv_copy)
            )
            if uv_copy.returncode or not uv_host.is_file():
                raise RuntimeError("owned uv binary extraction failed")
            uv_remove = execute(["docker", "rm", uv_container], timeout=30)
            report["commands"].append(
                command_receipt(["docker", "rm", "owned uv binary container"], uv_remove)
            )
            if uv_remove.returncode:
                raise RuntimeError("owned uv binary container cleanup failed")
            values = create(env_path, collector_ip="0.0.0.0", ports=ports)
            tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
            compose_base = [
                "docker",
                "compose",
                "--project-name",
                project,
                "--env-file",
                str(env_path),
                "-f",
                str(ROOT / "compose.yaml"),
            ]
            compose("up", "-d", "--build", "--wait", "--wait-timeout", "120")
            api_windows = f"http://127.0.0.1:{ports[0]}"
            response = httpx.get(api_windows + "/health", timeout=3, trust_env=False)
            response.raise_for_status()

            if os.name == "nt":

                def linux_mount_path(path: Path) -> str:
                    resolved = path.resolve()
                    drive = resolved.drive
                    if len(drive) != 2 or drive[1] != ":" or not resolved.is_absolute():
                        raise ValueError(f"not an absolute Windows drive path: {resolved}")
                    relative = resolved.relative_to(resolved.anchor).as_posix()
                    return f"/mnt/{drive[0].lower()}/{relative}"

                archive_native = linux_mount_path(archive)
                deletions_native = linux_mount_path(deletions)
                common_native = linux_mount_path(COMMON_REPO)
                uv_native = linux_mount_path(uv_host)
                output_native = linux_mount_path(nested)
                report["path_conversion"] = {
                    "method": "validated explicit Windows drive to /mnt mapping",
                    "source_windows": str(archive.resolve()),
                    "source_linux": archive_native,
                    "deletions_linux": deletions_native,
                    "common_repository_linux": common_native,
                    "uv_windows": str(uv_host.resolve()),
                    "uv_linux": uv_native,
                    "output_windows": str(nested.resolve()),
                    "output_linux": output_native,
                }
                existence = execute(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu",
                        "--",
                        "python3",
                        "-c",
                        "import pathlib,sys; a=pathlib.Path(sys.argv[1]); o=pathlib.Path(sys.argv[2]); "
                        "u=pathlib.Path(sys.argv[3]); x=pathlib.Path(sys.argv[4]); "
                        "c=pathlib.Path(sys.argv[5]); "
                        "raise SystemExit(0 if a.is_file() and u.is_file() and x.is_file() "
                        "and c.is_dir() and (c / '.git').exists() and o.parent.is_dir() "
                        "and all(p.is_absolute() for p in (a,u,x,c,o)) else 2)",
                        archive_native,
                        output_native,
                        uv_native,
                        deletions_native,
                        common_native,
                    ],
                    timeout=30,
                )
                report["commands"].append(
                    command_receipt(["wsl", "validate absolute source/output paths"], existence)
                )
                if existence.returncode:
                    raise RuntimeError("Linux-side source/output path preflight failed")

                route = execute(
                    ["wsl.exe", "-d", "Ubuntu", "--", "sh", "-c", "ip route show default"],
                    timeout=30,
                )
                resolvers = execute(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu",
                        "--",
                        "sh",
                        "-c",
                        "awk '/^nameserver / {print $2}' /etc/resolv.conf",
                    ],
                    timeout=30,
                )
                candidates = ["127.0.0.1"]
                route_parts = route.stdout.split()
                if "via" in route_parts:
                    candidates.append(route_parts[route_parts.index("via") + 1])
                candidates.extend(resolvers.stdout.splitlines())
                api_native = ""
                reachability: list[dict[str, Any]] = []
                for host in dict.fromkeys(item.strip() for item in candidates if item.strip()):
                    candidate = f"http://{host}:{ports[0]}"
                    probe = execute(
                        [
                            "wsl.exe",
                            "-d",
                            "Ubuntu",
                            "--",
                            "python3",
                            "-c",
                            "import sys,urllib.request; "
                            "r=urllib.request.urlopen(sys.argv[1] + '/health', timeout=3); "
                            "raise SystemExit(0 if r.status == 200 else 2)",
                            candidate,
                        ],
                        timeout=10,
                    )
                    reachability.append(command_receipt(["wsl", "API preflight", candidate], probe))
                    if probe.returncode == 0:
                        api_native = candidate
                        break
                report["api_reachability_preflight"] = reachability
                if not api_native:
                    raise RuntimeError(
                        "no WSL-to-Windows API candidate was reachable before provisioning"
                    )

                source_root = f"{native_root}/source"
                native_output = f"{native_root}/native-report.json"
                bootstrap = " ; ".join(
                    [
                        "set -euxo pipefail",
                        f"test ! -e {shlex.quote(native_root)}",
                        f"install -d -m 0755 {shlex.quote(native_root)}",
                        "git "
                        + f"-c safe.directory={shlex.quote(common_native)} "
                        + f"-c safe.directory={shlex.quote(common_native + '/.git')} "
                        + f"clone --no-hardlinks {shlex.quote(common_native)} {shlex.quote(source_root)}",
                        "git -C "
                        + shlex.quote(source_root)
                        + " checkout -q --detach "
                        + shlex.quote(target_revision),
                        "python3 -c "
                        + shlex.quote(
                            "import pathlib,sys,zipfile; root=pathlib.Path(sys.argv[2]).resolve(); "
                            "z=zipfile.ZipFile(sys.argv[1]); entries=z.infolist(); "
                            "assert all(x.filename and not pathlib.PurePosixPath(x.filename).is_absolute() "
                            "and '..' not in pathlib.PurePosixPath(x.filename).parts and not x.is_dir() "
                            "for x in entries); "
                            "targets=[(root / pathlib.PurePosixPath(x.filename)).resolve() for x in entries]; "
                            "assert all(root in t.parents for t in targets); "
                            "[(t.parent.mkdir(parents=True,exist_ok=True),t.write_bytes(z.read(x))) "
                            "for x,t in zip(entries,targets,strict=True)]; "
                            "assert (root / '.git').is_dir()"
                        )
                        + f" {shlex.quote(archive_native)} {shlex.quote(source_root)}",
                        "python3 -c "
                        + shlex.quote(
                            "import json,pathlib,sys; root=pathlib.Path(sys.argv[1]).resolve(); "
                            "paths=json.loads(pathlib.Path(sys.argv[2]).read_text()); "
                            "assert all(isinstance(x,str) and x and not pathlib.PurePosixPath(x).is_absolute() "
                            "and '..' not in pathlib.PurePosixPath(x).parts for x in paths); "
                            "targets=[(root / pathlib.PurePosixPath(x)).resolve() for x in paths]; "
                            "assert all(t == root or root in t.parents for t in targets); "
                            "[(t.unlink() if t.exists() and t.is_file() and not t.is_symlink() else None) "
                            "for t in targets]"
                        )
                        + f" {shlex.quote(source_root)} {shlex.quote(deletions_native)}",
                        f"test -d {shlex.quote(source_root + '/.git')}",
                        "git -C "
                        + shlex.quote(source_root)
                        + " rev-parse HEAD | grep -Fx "
                        + shlex.quote(target_revision),
                        f"install -m 0755 {shlex.quote(uv_native)} {shlex.quote(native_root + '/uv')}",
                        f"UV_PROJECT_ENVIRONMENT={shlex.quote(native_root + '/venv')} "
                        f"{shlex.quote(native_root + '/uv')} sync "
                        f"--project {shlex.quote(source_root)} --python /usr/bin/python3 "
                        "--no-managed-python --locked --all-extras",
                    ]
                )
                provision = execute(
                    ["wsl.exe", "-d", "Ubuntu", "-u", "root", "--", "bash", "-lc", bootstrap],
                    timeout=600,
                )
                report["commands"].append(
                    command_receipt(
                        ["wsl", "-u", "root", "owned source and uv locked sync"], provision
                    )
                )
                report["bootstrap_command"] = bootstrap
                if provision.returncode:
                    raise RuntimeError("owned WSL runtime provisioning failed")
                probe_command = [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "-u",
                    "root",
                    "--",
                    "nsenter",
                    "-t",
                    "1",
                    "-m",
                    "--",
                    f"{native_root}/venv/bin/python",
                    f"{source_root}/scripts/io_native_probe.py",
                    "--output",
                    native_output,
                    "--api",
                    api_native,
                    "--tokens-stdin",
                    "--run-token",
                    run_token,
                ]
            else:
                if os.geteuid() != 0:
                    raise PermissionError("direct Linux native aggregate must run as root")
                owned_root = Path(native_root)
                source_root_path = owned_root / "source"
                native_output_path = owned_root / "native-report.json"
                if owned_root.exists() or owned_root.is_symlink():
                    raise FileExistsError("owned direct-Linux native root already exists")
                owned_root.mkdir(mode=0o755)
                deleted_paths = json.loads(deletions.read_text(encoding="utf-8"))
                materialize_source(
                    COMMON_REPO,
                    source_root_path,
                    archive,
                    deleted_paths,
                    report["source_before"],
                    report["commands"],
                )
                uv_owned = owned_root / "uv"
                shutil.copyfile(uv_host, uv_owned)
                uv_owned.chmod(0o755)
                sync = execute(
                    [
                        str(uv_owned),
                        "sync",
                        "--project",
                        str(source_root_path),
                        "--python",
                        "/usr/bin/python3",
                        "--no-managed-python",
                        "--locked",
                        "--all-extras",
                    ],
                    timeout=600,
                )
                report["commands"].append(command_receipt(["uv", "locked direct-Linux sync"], sync))
                if sync.returncode:
                    raise RuntimeError("owned direct-Linux locked sync failed")
                probe_command = [
                    os.fspath(source_root_path / ".venv/bin/python"),
                    os.fspath(source_root_path / "scripts/io_native_probe.py"),
                    "--output",
                    os.fspath(native_output_path),
                    "--api",
                    api_windows,
                    "--tokens-stdin",
                    "--run-token",
                    run_token,
                ]

            probe = execute(probe_command, timeout=480, input_text=json.dumps(tokens))
            report["commands"].append(
                command_receipt(["actual-systemd", "io_native_probe.py", "--tokens-stdin"], probe)
            )
            if os.name == "nt":
                copy_report = execute(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu",
                        "-u",
                        "root",
                        "--",
                        "python3",
                        "-c",
                        "import os,pathlib,shutil,sys; s=pathlib.Path(sys.argv[1]); "
                        "d=pathlib.Path(sys.argv[2]); t=d.with_suffix(d.suffix + '.tmp'); "
                        "shutil.copyfile(s,t); os.replace(t,d)",
                        native_output,
                        output_native,
                    ],
                    timeout=30,
                )
                report["commands"].append(
                    command_receipt(["wsl", "copy native report to external output"], copy_report)
                )
            else:
                temporary_nested = nested.with_suffix(nested.suffix + ".tmp")
                shutil.copyfile(native_output_path, temporary_nested)
                os.replace(temporary_nested, nested)
            if nested.exists():
                report["native"] = json.loads(nested.read_text(encoding="utf-8"))
                linux_manifest = report["native"].get("linux_source_before", {})
                report["cross_platform_source_match"] = manifests_match(
                    report["source_before"], linux_manifest
                )
                if not report["cross_platform_source_match"]:
                    raise AssertionError("Linux raw source inventory differs from Windows source")
            if probe.returncode or report.get("native", {}).get("status") != "passed":
                raise RuntimeError("actual-systemd native I/O proof failed")
            report["source_after"] = source_manifest()
            if report["source_before"] != report["source_after"]:
                raise AssertionError("Windows source changed during native proof")
        except BaseException as exc:
            failure = type(exc).__name__ + ": " + str(exc)
            report["failure"] = failure
        finally:
            uv_inspect = execute(["docker", "container", "inspect", uv_container], timeout=30)
            if uv_inspect.returncode == 0:
                uv_cleanup = execute(["docker", "rm", "-f", uv_container], timeout=30)
                report["cleanup"].append(
                    command_receipt(["docker", "rm", "exact owned uv container"], uv_cleanup)
                )
                if uv_cleanup.returncode:
                    cleanup_failures.append("owned uv extraction container removal failed")
            if os.name == "nt":
                emergency = (
                    "set -eu; "
                    + " ".join(
                        "systemctl stop " + shlex.quote(unit) + " 2>/dev/null || true;"
                        for unit in units
                    )
                    + " "
                    + " ".join(
                        "test ! -e /run/systemd/system/"
                        + shlex.quote(unit)
                        + " || rm -- /run/systemd/system/"
                        + shlex.quote(unit)
                        + ";"
                        for unit in units
                    )
                    + " systemctl daemon-reload; "
                    + f"if test -x {shlex.quote(native_root + '/venv/bin/python')} && "
                    + f"test -f {shlex.quote(native_root + '/source/deploy/io_resource.py')} && "
                    + f"test -f /var/lib/fleetdoctor/io-resource/run-{run_token}.json; then "
                    + f"{shlex.quote(native_root + '/venv/bin/python')} "
                    + f"{shlex.quote(native_root + '/source/deploy/io_resource.py')} destroy {run_token}; fi; "
                    + "python3 -c "
                    + shlex.quote(
                        "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); token=sys.argv[2]; "
                        "value=json.loads(p.read_text()) if p.exists() else None; "
                        "assert value is None or (value.get('token') == token and "
                        "value.get('phase') == 'destroyed' and value.get('cleanup_complete') is True); "
                        "p.unlink() if p.exists() else None"
                    )
                    + f" /var/lib/fleetdoctor/io-resource/run-{run_token}.json {run_token}; "
                    + "python3 -c "
                    + shlex.quote(
                        "import pathlib,shutil,sys; p=pathlib.Path(sys.argv[1]); "
                        "assert p.parent == pathlib.Path('/opt') and "
                        "p.name.startswith('fleetdoctor-io-runtime-'); "
                        "shutil.rmtree(p) if p.exists() else None"
                    )
                    + f" {shlex.quote(native_root)}"
                )
                cleanup = execute(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu",
                        "-u",
                        "root",
                        "--",
                        "nsenter",
                        "-t",
                        "1",
                        "-m",
                        "--",
                        "bash",
                        "-lc",
                        emergency,
                    ],
                    timeout=120,
                )
                report["cleanup"].append(
                    command_receipt(["wsl", "-u", "root", "exact emergency cleanup"], cleanup)
                )
                if cleanup.returncode:
                    cleanup_failures.append("WSL exact emergency cleanup failed")
                absence_script = (
                    f"test ! -e {shlex.quote(native_root)} && "
                    f"test ! -e /var/lib/fleetdoctor/io-resource/run-{run_token}.json && "
                    f"test ! -e /var/lib/fleetdoctor/io-resource/worker-{run_token}.activate && "
                    f"test ! -e /var/lib/fleetdoctor/io-resource/lease.json && "
                    + " && ".join(
                        f"test ! -e /run/systemd/system/{shlex.quote(unit)}" for unit in units
                    )
                )
                absence = execute(
                    [
                        "wsl.exe",
                        "-d",
                        "Ubuntu",
                        "-u",
                        "root",
                        "--",
                        "nsenter",
                        "-t",
                        "1",
                        "-m",
                        "--",
                        "bash",
                        "-lc",
                        absence_script,
                    ],
                    timeout=30,
                )
                report["cleanup"].append(
                    command_receipt(["wsl", "verify exact owned absence"], absence)
                )
                if absence.returncode:
                    cleanup_failures.append("WSL owned absence verification failed")
            else:
                for unit in units:
                    stopped = execute(["systemctl", "stop", unit], timeout=30)
                    reset = execute(["systemctl", "reset-failed", unit], timeout=30)
                    report["cleanup"].append(
                        {
                            "direct_linux_unit": unit,
                            "stop_exit": stopped.returncode,
                            "reset_failed_exit": reset.returncode,
                        }
                    )
                owned_root = Path(native_root)
                source_root_path = owned_root / "source"
                record_path = Path("/var/lib/fleetdoctor/io-resource") / f"run-{run_token}.json"
                if record_path.exists() and (source_root_path / ".venv/bin/python").is_file():
                    destroy = execute(
                        [
                            str(source_root_path / ".venv/bin/python"),
                            str(source_root_path / "deploy/io_resource.py"),
                            "destroy",
                            run_token,
                        ],
                        timeout=120,
                    )
                    report["cleanup"].append(
                        command_receipt(["direct Linux exact helper destroy", run_token], destroy)
                    )
                    if destroy.returncode:
                        cleanup_failures.append("direct Linux exact helper destroy failed")
                if record_path.exists():
                    record_value = json.loads(record_path.read_text(encoding="utf-8"))
                    if not (
                        record_value.get("token") == run_token
                        and record_value.get("phase") == "destroyed"
                        and record_value.get("cleanup_complete") is True
                    ):
                        cleanup_failures.append("direct Linux helper record not safely destroyed")
                    else:
                        record_path.unlink()
                if owned_root.exists():
                    if owned_root.parent != Path("/opt") or not owned_root.name.startswith(
                        "fleetdoctor-io-runtime-"
                    ):
                        cleanup_failures.append("direct Linux owned runtime identity refused")
                    elif owned_root.is_symlink() or not owned_root.is_dir():
                        cleanup_failures.append("direct Linux owned runtime type refused")
                    else:
                        shutil.rmtree(owned_root)
                owned_remaining = [
                    str(path)
                    for path in (
                        owned_root,
                        record_path,
                        Path("/var/lib/fleetdoctor/io-resource") / f"worker-{run_token}.activate",
                    )
                    if path.exists() or path.is_symlink()
                ]
                owned_remaining.extend(
                    str(path)
                    for path in (Path("/run/systemd/system") / unit for unit in units)
                    if path.exists() or path.is_symlink()
                )
                report["cleanup"].append({"direct_linux_owned_remaining": owned_remaining})
                if owned_remaining:
                    cleanup_failures.append("direct Linux owned resources remain")

            if compose_base:
                logs = compose("logs", "--no-color", check=False)
                report["service_logs"] = logs.stdout[-24000:]
                down = compose("down", "--volumes", "--remove-orphans", check=False)
                report["cleanup"].append(
                    {"owned_compose_project": project, "exit": down.returncode}
                )
                if down.returncode:
                    cleanup_failures.append("Compose exact down failed")
                image_name = f"{project}-collector:latest"
                inspect_image = execute(["docker", "image", "inspect", image_name], timeout=30)
                if inspect_image.returncode == 0:
                    remove_image = execute(["docker", "image", "rm", image_name], timeout=60)
                    report["cleanup"].append(
                        command_receipt(["docker", "image", "rm", image_name], remove_image)
                    )
                    if remove_image.returncode:
                        cleanup_failures.append("owned collector image removal failed")
                checks = {
                    "containers": [
                        "docker",
                        "ps",
                        "-aq",
                        "--filter",
                        f"label=com.docker.compose.project={project}",
                    ],
                    "volumes": [
                        "docker",
                        "volume",
                        "ls",
                        "-q",
                        "--filter",
                        f"label=com.docker.compose.project={project}",
                    ],
                    "networks": [
                        "docker",
                        "network",
                        "ls",
                        "-q",
                        "--filter",
                        f"label=com.docker.compose.project={project}",
                    ],
                }
                for kind, command in checks.items():
                    remaining = execute(command, timeout=30)
                    report["cleanup"].append(
                        command_receipt(["docker", "verify project", kind, "absent"], remaining)
                    )
                    if remaining.returncode or remaining.stdout.strip():
                        cleanup_failures.append(f"owned Compose {kind} remain or are unknown")

            if cleanup_failures:
                report["cleanup_failures"] = cleanup_failures
                failure = failure or "; ".join(cleanup_failures)
            report["status"] = "failed" if failure else "passed"
            report["finished_at"] = datetime.now(UTC).isoformat()
            atomic_report(args.output, report)
            native_value = report.get("native", {})
            atomic_report(
                helper_state,
                {
                    "status": report["status"],
                    "run_token": run_token,
                    "project": project,
                    "source_sha256": report.get("source_before", {}).get("sha256"),
                    "initial_resource": native_value.get("resource"),
                    "workload_cleanup": native_value.get("workload_cleanup"),
                    "partial_activation_rollback": native_value.get(
                        "native_partial_activation_rollback"
                    ),
                    "after_child_start_rollback": native_value.get(
                        "native_after_child_start_rollback"
                    ),
                    "worker_interruption_cleanup": native_value.get(
                        "native_worker_interruption_cleanup"
                    ),
                    "final_resource_destroy": native_value.get("resource_destroy"),
                    "aggregate_cleanup": report["cleanup"],
                    "failure": report.get("failure"),
                },
            )

    if failure:
        raise SystemExit(failure)


if __name__ == "__main__":
    main()
