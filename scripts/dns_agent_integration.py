#!/usr/bin/env python3
"""Real collector plus hardened ordinary agents for the measured DNS lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import platform
import re
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from chaos_harness import source_manifest, write_report
from create_env import create
from dns_harness import DnsHarness
from network_helper_integration import free_port, run, wait_json, write_private

ROOT = Path(__file__).resolve().parents[1]


def _size_bytes(value: str) -> int:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGT]?i?B)", value.strip())
    if match is None:
        raise ValueError(f"unrecognized Docker size: {value}")
    amount, unit = float(match.group(1)), match.group(2)
    factors = {
        "B": 1,
        "kB": 1000,
        "KB": 1000,
        "KiB": 1024,
        "MB": 1000**2,
        "MiB": 1024**2,
        "GB": 1000**3,
        "GiB": 1024**3,
        "TB": 1000**4,
        "TiB": 1024**4,
    }
    return round(amount * factors[unit])


def runtime_stats(name: str) -> dict[str, Any]:
    result = run(["docker", "stats", "--no-stream", "--format", "{{json .}}", name])
    raw: dict[str, Any] = json.loads(result.stdout)
    used, limit = str(raw["MemUsage"]).split("/")
    used_bytes = _size_bytes(used)
    limit_bytes = _size_bytes(limit)
    pids = int(raw["PIDs"])
    value = {
        "raw": raw,
        "memory_used_bytes": used_bytes,
        "memory_limit_bytes": limit_bytes,
        "pids": pids,
    }
    if limit_bytes != 100 * 1024 * 1024 or used_bytes >= limit_bytes or pids > 16:
        raise RuntimeError(f"ordinary agent exceeded its runtime resource envelope: {value}")
    return value


def cadence_observations(scenario: dict[str, Any]) -> dict[str, Any]:
    phases: dict[str, Any] = {}
    for name in ("baseline", "recovery"):
        values = [
            datetime.fromisoformat(str(item["identity"]["observed_at"])) for item in scenario[name]
        ]
        intervals = [
            (values[index] - values[index - 1]).total_seconds() for index in range(1, len(values))
        ]
        if len(values) != 3 or any(not 4 <= interval <= 6.5 for interval in intervals):
            raise RuntimeError(f"ordinary agent cadence left the expected five-second band: {name}")
        phases[name] = {
            "observed_at": [value.isoformat() for value in values],
            "interval_seconds": intervals,
        }
    return phases


def absent(argv: list[str], expected: tuple[str, ...]) -> dict[str, Any]:
    result = run(argv, check=False, timeout=30)
    diagnostic = (result.stderr or "") + "\n" + (result.stdout or "")
    status = (
        "present"
        if result.returncode == 0
        else "absent"
        if any(value in diagnostic for value in expected)
        else "unknown"
    )
    return {"status": status, "exit": result.returncode, "diagnostic": diagnostic[-500:]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    project = "fd10-agent-" + uuid4().hex[:10]
    image = project + ":proof"
    compose_image = project + "-collector:latest"
    names = {
        kind: project + "-" + kind
        for kind in ("authority", "anchor-a", "anchor-b", "agent-a", "agent-b")
    }
    volumes = {suffix: project + "-credentials-" + suffix for suffix in ("a", "b")}
    evidence: dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "source_before": source_manifest(),
        "platform": platform.platform(),
        "topology": "real-compose-collector-two-hardened-agents-separate-root-helper",
        "aws_execution": False,
        "owned": {
            "images": [image, compose_image],
            "containers": list(names.values()),
            "volumes": list(volumes.values()),
            "network": project + "_default",
        },
        "events": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_report(args.output, evidence)

    def persist(event: str, value: dict[str, Any]) -> None:
        evidence["scenario_progress"] = value
        evidence["events"].append(
            {"event": event, "at": datetime.now(UTC).isoformat(), "status": value.get("status")}
        )
        write_report(args.output, evidence)

    cleanup_errors: list[str] = []
    teardown: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        root = Path(temporary)
        env_file = root / "stack.env"
        seccomp = root / "service-seccomp.json"
        seccomp_profile = {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": [
                "SCMP_ARCH_X86_64",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32",
                "SCMP_ARCH_AARCH64",
                "SCMP_ARCH_ARM",
            ],
            "syscalls": [
                {
                    "names": ["socket"],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 97,
                    "args": [{"index": 0, "value": family, "op": "SCMP_CMP_EQ"}],
                }
                for family in [3, 4, 5, 6, 7, 8, 9, *range(11, 46)]
            ],
        }
        write_private(seccomp, json.dumps(seccomp_profile, sort_keys=True), 0o600)
        ports = (free_port(), free_port(), free_port())
        values = create(env_file, ports=ports)
        tokens: dict[str, str] = json.loads(values["FLEETDOCTOR_NODE_TOKENS"])
        compose = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--env-file",
            str(env_file),
            "-f",
            str(ROOT / "compose.yaml"),
        ]
        api = f"http://127.0.0.1:{ports[0]}"
        network = project + "_default"
        resolver_backing: dict[str, dict[str, Any]] = {}
        try:
            run(["docker", "build", "--target", "test", "-t", image, "."], timeout=600)
            for volume in volumes.values():
                run(["docker", "volume", "create", volume])
            run(compose + ["up", "-d", "--build", "--wait", "--wait-timeout", "120"], timeout=600)
            wait_json(api + "/health", lambda value: value.get("status") == "ok")
            network_value = json.loads(run(["docker", "network", "inspect", network]).stdout)[0]
            subnet = next(
                ipaddress.ip_network(item["Subnet"])
                for item in network_value["IPAM"]["Config"]
                if ":" not in item["Subnet"]
            )
            invalid_resolver = str(subnet.broadcast_address - 2)
            collector_id = run(compose + ["ps", "-q", "collector"]).stdout.strip()
            collector_ip = run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                    collector_id,
                ]
            ).stdout.strip()
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    names["authority"],
                    "--network",
                    network,
                    image,
                    "/app/.venv/bin/python",
                    "scripts/dns_authoritative.py",
                    "--answer",
                    collector_ip,
                ]
            )
            authority_ip = run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
                    names["authority"],
                ]
            ).stdout.strip()
            agent_commands: dict[str, list[str]] = {}
            for suffix, node in (("a", "node-a"), ("b", "node-b")):
                anchor = names[f"anchor-{suffix}"]
                agent = names[f"agent-{suffix}"]
                run(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        anchor,
                        "--init",
                        "--network",
                        network,
                        "--sysctl",
                        "net.ipv4.ping_group_range=10001 10001",
                        "--user",
                        "0:0",
                        image,
                        "sleep",
                        "infinity",
                    ]
                )
                resolver_path = run(
                    ["docker", "inspect", "-f", "{{.ResolvConfPath}}", anchor]
                ).stdout.strip()
                run(
                    [
                        "docker",
                        "exec",
                        "--user",
                        "0:0",
                        anchor,
                        "/app/.venv/bin/python",
                        "-c",
                        f"from pathlib import Path;Path('/etc/resolv.conf').write_bytes({('nameserver ' + authority_ip + chr(10)).encode()!r})",
                    ]
                )
                backing_probe = (
                    "import hashlib,json,os,stat;"
                    "p='/etc/resolv.conf';s=os.lstat(p);b=open(p,'rb').read();"
                    "print(json.dumps({'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),"
                    "'type':'regular' if stat.S_ISREG(s.st_mode) else 'other','inode':s.st_ino,"
                    "'device':s.st_dev,'sha256':hashlib.sha256(b).hexdigest(),'bytes':b.decode('ascii')}))"
                )
                before = json.loads(
                    run(
                        [
                            "docker",
                            "exec",
                            "--user",
                            "0:0",
                            anchor,
                            "/app/.venv/bin/python",
                            "-c",
                            backing_probe,
                        ]
                    ).stdout
                )
                resolver_backing[suffix] = {
                    "docker_resolv_conf_path": resolver_path,
                    "before": before,
                }
                token_file = root / f"token-{suffix}"
                write_private(token_file, tokens[node], 0o400)
                run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--user",
                        "0:0",
                        "-v",
                        f"{volumes[suffix]}:/dest",
                        "-v",
                        f"{token_file.parent}:/source:ro",
                        image,
                        "sh",
                        "-c",
                        f"cp /source/{token_file.name} /dest/ingest-token && chown root:10001 /dest /dest/ingest-token && chmod 0750 /dest && chmod 0440 /dest/ingest-token",
                    ]
                )
                env_file_agent = root / f"agent-{suffix}.env"
                write_private(
                    env_file_agent,
                    "".join(
                        [
                            f"FLEETDOCTOR_NODE_ID={node}\n",
                            f"FLEETDOCTOR_COLLECTOR_URL=http://{collector_ip}:8000\n",
                            f"FLEETDOCTOR_NETWORK_TARGET={collector_ip}\n",
                            "FLEETDOCTOR_DNS_HOSTNAME=baseline.fleetdoctor.test.\n",
                            "CREDENTIALS_DIRECTORY=/run/credentials\n",
                            "PATH=/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
                        ]
                    ),
                    0o400,
                )
                command = [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    agent,
                    "--network",
                    "container:" + anchor,
                    "--user",
                    "10001:10001",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--security-opt",
                    "seccomp=" + str(seccomp),
                    "--pids-limit",
                    "16",
                    "--memory",
                    "100m",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,mode=700,uid=10001,gid=10001",
                    "--env-file",
                    str(env_file_agent),
                    "-v",
                    f"{volumes[suffix]}:/run/credentials:ro",
                    "-v",
                    f"{resolver_path}:/etc/resolv.conf:ro",
                    image,
                    "/app/.venv/bin/python",
                    "-m",
                    "fleetdoctor.agent",
                ]
                agent_commands[node] = command
                run(command)
                readable = run(
                    [
                        "docker",
                        "exec",
                        agent,
                        "/app/.venv/bin/python",
                        "-c",
                        "from pathlib import Path;assert Path('/etc/resolv.conf').read_bytes();assert Path('/run/credentials/ingest-token').read_bytes()",
                    ]
                )
                resolver_backing[suffix]["agent_readable"] = readable.returncode == 0
            healthy = wait_json(
                api + "/nodes",
                lambda value: (
                    len(value.get("nodes", [])) == 2
                    and all(
                        item.get("fresh")
                        and (item.get("dns") or {}).get("query", {}).get("status") == "success"
                        and (item.get("network") or {}).get("probe", {}).get("received") == 3
                        for item in value.get("nodes", [])
                    )
                ),
                deadline=90,
            )
            initial_runtime = {
                node: runtime_stats(names[f"agent-{suffix}"])
                for node, suffix in (("node-a", "a"), ("node-b", "b"))
            }
            context_code = """import json,os,socket
def socket_result(f,t=socket.SOCK_STREAM,p=0):
 try:
  s=socket.socket(f,t,p);s.close();return {'allowed':True,'errno':None}
 except OSError as e:return {'allowed':False,'errno':e.errno}
status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in open('/proc/self/status')}
tmp=os.stat('/tmp')
events={line.split()[0]:int(line.split()[1]) for line in open('/sys/fs/cgroup/memory.events') if len(line.split())==2}
credential=os.stat('/run/credentials/ingest-token')
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'nnp':status['NoNewPrivs'],'cap_eff':status['CapEff'],'unix':socket_result(socket.AF_UNIX),'inet':socket_result(socket.AF_INET),'inet6':socket_result(socket.AF_INET6),'netlink':socket_result(socket.AF_NETLINK,socket.SOCK_RAW,0),'bluetooth':socket_result(31,socket.SOCK_RAW,0),'pids_current':open('/sys/fs/cgroup/pids.current').read().strip(),'pids_max':open('/sys/fs/cgroup/pids.max').read().strip(),'memory_current':open('/sys/fs/cgroup/memory.current').read().strip(),'memory_peak':open('/sys/fs/cgroup/memory.peak').read().strip(),'memory_max':open('/sys/fs/cgroup/memory.max').read().strip(),'memory_events':events,'credential':{'uid':credential.st_uid,'gid':credential.st_gid,'mode':oct(credential.st_mode & 0o777),'readable':open('/run/credentials/ingest-token').read()!=''},'tmp':{'uid':tmp.st_uid,'gid':tmp.st_gid,'mode':oct(tmp.st_mode & 0o777),'writable':os.access('/tmp',os.W_OK)}}))
"""
            local_stub_code = """import ipaddress,json
from pathlib import Path
from fleetdoctor.dns import DnsCollector,_local_addresses
addresses=_local_addresses()
if addresses is None: raise RuntimeError('restricted local address inventory unavailable')
local=next((value for value in addresses if ipaddress.ip_address(value).version==4 and not ipaddress.ip_address(value).is_loopback),None)
if local is None: raise RuntimeError('restricted nonloopback local address missing')
path=Path('/tmp/fleetdoctor-local-resolver.conf')
path.write_text('nameserver '+local+'\\n',encoding='ascii')
value=DnsCollector(path).collect('baseline.fleetdoctor.test.','127.0.0.1')
path.unlink()
print(json.dumps({'addresses':sorted(addresses),'selected_local':local,'query':value.query.model_dump(mode='json')}))
"""
            service_context: dict[str, Any] = {}
            for node, suffix in (("node-a", "a"), ("node-b", "b")):
                context = json.loads(
                    run(
                        [
                            "docker",
                            "exec",
                            names[f"agent-{suffix}"],
                            "/app/.venv/bin/python",
                            "-c",
                            context_code,
                        ]
                    ).stdout
                )
                if not (
                    context["uid"] == context["gid"] == 10001
                    and context["nnp"] == "1"
                    and int(context["cap_eff"], 16) == 0
                    and context["unix"]["allowed"]
                    and context["inet"]["allowed"]
                    and context["inet6"]["allowed"]
                    and context["netlink"] == {"allowed": False, "errno": 97}
                    and context["bluetooth"] == {"allowed": False, "errno": 97}
                    and int(context["pids_current"]) <= 16
                    and context["pids_max"] == "16"
                    and int(context["memory_current"]) <= 100 * 1024 * 1024
                    and int(context["memory_peak"]) <= 100 * 1024 * 1024
                    and context["memory_max"] == str(100 * 1024 * 1024)
                    and context["memory_events"].get("oom", 0) == 0
                    and context["memory_events"].get("oom_kill", 0) == 0
                    and context["credential"]
                    == {"uid": 0, "gid": 10001, "mode": "0o440", "readable": True}
                    and context["tmp"]
                    == {"uid": 10001, "gid": 10001, "mode": "0o700", "writable": True}
                ):
                    raise RuntimeError(f"DNS agent service restrictions mismatch: {context}")
                local_stub = json.loads(
                    run(
                        [
                            "docker",
                            "exec",
                            names[f"agent-{suffix}"],
                            "/app/.venv/bin/python",
                            "-c",
                            local_stub_code,
                        ]
                    ).stdout
                )
                if (
                    local_stub["query"]["status"] != "unavailable"
                    or local_stub["query"]["error"] != "unknown_node_local_caching_stub"
                ):
                    raise RuntimeError(
                        f"restricted nonloopback local stub was queried directly: {local_stub}"
                    )
                context["restricted_local_stub_detection"] = local_stub
                service_context[node] = context
            unit = (ROOT / "deploy/fleetdoctor-agent.service").read_text(encoding="utf-8")
            directive = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"
            if directive not in unit:
                raise RuntimeError("production unit address-family restriction is missing")
            service_context.update(
                seccomp_profile=seccomp_profile,
                seccomp_sha256=hashlib.sha256(seccomp.read_bytes()).hexdigest(),
                production_unit_directive=directive,
            )

            def helper(action: str, token: str, invalid: str, duration: int) -> dict[str, Any]:
                argv = [
                    "docker",
                    "exec",
                    "--user",
                    "0:0",
                    names["anchor-a"],
                    "/app/.venv/bin/python",
                    "/app/deploy/dns_resource.py",
                    action,
                    "--token",
                    token,
                ]
                if action == "start":
                    argv += ["--invalid-resolver", invalid, "--duration", str(duration)]
                result = run(argv, timeout=15)
                value: dict[str, Any] = json.loads(result.stdout)
                return value

            scenario = DnsHarness(
                api,
                "node-a",
                "node-b",
                helper=helper,
                recorder=persist,
            ).run(invalid_resolver=invalid_resolver)
            final_runtime = {
                node: runtime_stats(names[f"agent-{suffix}"])
                for node, suffix in (("node-a", "a"), ("node-b", "b"))
            }
            cadence = cadence_observations(scenario)
            for suffix in ("a", "b"):
                after = json.loads(
                    run(
                        [
                            "docker",
                            "exec",
                            "--user",
                            "0:0",
                            names[f"anchor-{suffix}"],
                            "/app/.venv/bin/python",
                            "-c",
                            backing_probe,
                        ]
                    ).stdout
                )
                resolver_backing[suffix]["after"] = after
                resolver_backing[suffix]["exactly_restored"] = (
                    after == resolver_backing[suffix]["before"]
                )
            if not all(value["exactly_restored"] for value in resolver_backing.values()):
                raise AssertionError("Docker-owned resolver backing was not restored exactly")
            runtime: dict[str, Any] = {}
            for node, suffix in (("node-a", "a"), ("node-b", "b")):
                inspect = json.loads(run(["docker", "inspect", names[f"agent-{suffix}"]]).stdout)[0]
                identity = run(
                    [
                        "docker",
                        "exec",
                        names[f"agent-{suffix}"],
                        "/app/.venv/bin/python",
                        "-c",
                        "import json,os;print(json.dumps({'uid':os.getuid(),'gid':os.getgid()}))",
                    ]
                )
                runtime[node] = {
                    "identity": json.loads(identity.stdout),
                    "cap_drop": inspect["HostConfig"]["CapDrop"],
                    "security_opt": inspect["HostConfig"]["SecurityOpt"],
                    "readonly_rootfs": inspect["HostConfig"]["ReadonlyRootfs"],
                    "memory": inspect["HostConfig"]["Memory"],
                    "pids_limit": inspect["HostConfig"]["PidsLimit"],
                }
            evidence.update(
                status="passed",
                completed_at=datetime.now(UTC).isoformat(),
                collector_private_ip=collector_ip,
                authoritative_private_ip=authority_ip,
                initial_healthy_nodes=healthy,
                scenario=scenario,
                hardened_runtime=runtime,
                sample_interval_seconds=5,
                supervisor_budget_seconds=3,
                helper_scope="root exec in persistent anchor outside agent cgroup",
                resolver_backing=resolver_backing,
                actual_runtime_resources={
                    "initial": initial_runtime,
                    "final": final_runtime,
                    "memory_limit_bytes": 100 * 1024 * 1024,
                    "pids_limit": 16,
                },
                actual_cadence=cadence,
                service_context=service_context,
                invalid_resolver=invalid_resolver,
            )
        except BaseException as exc:
            diagnostics: dict[str, Any] = {}
            for key in ("agent-a", "agent-b", "anchor-a", "anchor-b", "authority"):
                name = names[key]
                diagnostics[key] = {
                    "inspect": run(["docker", "inspect", name], check=False).stdout[-4000:],
                    "logs": run(["docker", "logs", "--tail", "200", name], check=False).stdout[
                        -8000:
                    ],
                    "log_errors": run(
                        ["docker", "logs", "--tail", "200", name], check=False
                    ).stderr[-8000:],
                }
            evidence.update(
                status="failed",
                error=f"{type(exc).__name__}:{exc}",
                failure_diagnostics=diagnostics,
            )
        finally:
            for suffix in ("a", "b"):
                name = names[f"agent-{suffix}"]
                if run(["docker", "container", "inspect", name], check=False).returncode == 0:
                    stop_started = time.monotonic()
                    stopped = run(["docker", "stop", "--time", "5", name], check=False, timeout=10)
                    elapsed = time.monotonic() - stop_started
                    state_result = run(
                        ["docker", "inspect", "-f", "{{json .State}}", name], check=False
                    )
                    state = (
                        json.loads(state_result.stdout)
                        if state_result.returncode == 0 and state_result.stdout.strip()
                        else None
                    )
                    teardown[name] = {
                        "returncode": stopped.returncode,
                        "stderr": stopped.stderr[-1000:],
                        "elapsed_seconds": elapsed,
                        "state": state,
                    }
                    if (
                        stopped.returncode
                        or elapsed > 3.5
                        or not isinstance(state, dict)
                        or state.get("Running") is not False
                        or state.get("OOMKilled") is not False
                        or state.get("ExitCode") != 0
                    ):
                        cleanup_errors.append(f"unclean agent teardown {name}: {teardown[name]}")
            for name in (
                names["agent-a"],
                names["agent-b"],
                names["anchor-a"],
                names["anchor-b"],
                names["authority"],
            ):
                result = run(["docker", "rm", "-f", name], check=False, timeout=30)
                if result.returncode and "No such container" not in result.stderr:
                    cleanup_errors.append(f"remove {name}: {result.stderr[-300:]}")
            run(compose + ["down", "-v", "--remove-orphans"], check=False, timeout=180)
            for volume in volumes.values():
                run(["docker", "volume", "rm", volume], check=False, timeout=30)
            image_removals: dict[str, Any] = {}
            for label, tag in (("proof", image), ("compose_collector", compose_image)):
                removed = run(["docker", "image", "rm", "-f", tag], check=False, timeout=60)
                image_removals[label] = {
                    "tag": tag,
                    "returncode": removed.returncode,
                    "stdout": removed.stdout[-1000:],
                    "stderr": removed.stderr[-1000:],
                }
                if removed.returncode and "No such image" not in removed.stderr:
                    cleanup_errors.append(f"remove image {tag}: {removed.stderr[-300:]}")
            verification = {
                name: absent(
                    ["docker", "container", "inspect", name],
                    (f"No such container: {name}", f"No such object: {name}"),
                )
                for name in names.values()
            }
            verification["image"] = absent(
                ["docker", "image", "inspect", image],
                (f"No such image: {image}", f"No such object: {image}"),
            )
            verification["compose-collector-image"] = absent(
                ["docker", "image", "inspect", compose_image],
                (f"No such image: {compose_image}", f"No such object: {compose_image}"),
            )
            verification["network"] = absent(
                ["docker", "network", "inspect", network],
                (f"network {network} not found",),
            )
            for suffix, volume in volumes.items():
                verification["volume-" + suffix] = absent(
                    ["docker", "volume", "inspect", volume],
                    (f"No such volume: {volume}", f"get {volume}: no such volume"),
                )
            evidence["cleanup"] = {
                "status": "passed"
                if not cleanup_errors
                and all(item["status"] == "absent" for item in verification.values())
                else "failed",
                "errors": cleanup_errors,
                "verification": verification,
                "ordinary_agent_teardown": teardown,
                "image_removals": image_removals,
            }
            evidence["source_after"] = source_manifest()
            evidence["source_unchanged"] = evidence["source_after"] == evidence["source_before"]
            if evidence["cleanup"]["status"] != "passed" or not evidence["source_unchanged"]:
                evidence["status"] = "failed"
            write_report(args.output, evidence)
    if evidence["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
