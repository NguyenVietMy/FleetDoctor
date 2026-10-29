"""A bounded fixed-query Prometheus client. No user-supplied PromQL."""

import asyncio
import json
import math
from datetime import UTC, datetime
from typing import Any

import httpx

HISTORY_METRICS = {
    "available_bytes": "fleetdoctor_filesystem_available_bytes",
    "used_bytes": "fleetdoctor_filesystem_used_bytes",
    "block_usage_ratio": "fleetdoctor_filesystem_block_usage_ratio",
    "inodes_total": "fleetdoctor_filesystem_inodes_total",
    "inodes_free": "fleetdoctor_filesystem_inodes_free",
    "inode_usage_ratio": "fleetdoctor_filesystem_inode_usage_ratio",
    "inode_diagnosis_coverage_ratio": "fleetdoctor_inode_diagnosis_coverage_ratio",
    "cpu_busy_ratio": "fleetdoctor_cpu_busy_ratio",
    "cpu_iowait_ratio": "fleetdoctor_cpu_iowait_ratio",
    "cpu_steal_ratio": "fleetdoctor_cpu_steal_ratio",
    "cpu_logical_cores": "fleetdoctor_cpu_logical_cores",
    "cpu_runnable_processes": "fleetdoctor_cpu_runnable_processes",
    "cpu_load_1m": "fleetdoctor_cpu_load_1m",
    "cpu_load_5m": "fleetdoctor_cpu_load_5m",
    "cpu_load_15m": "fleetdoctor_cpu_load_15m",
    "cpu_coverage_ratio": "fleetdoctor_cpu_coverage_ratio",
    "host_memory_available_bytes": "fleetdoctor_host_memory_available_bytes",
    "host_swap_free_bytes": "fleetdoctor_host_swap_free_bytes",
    "host_pgmajfault_per_second": "fleetdoctor_host_pgmajfault_per_second",
    "workload_memory_current_bytes": "fleetdoctor_workload_memory_current_bytes",
    "workload_memory_usage_ratio": "fleetdoctor_workload_memory_usage_ratio",
    "workload_oom_kill_total": "fleetdoctor_workload_memory_oom_kill_total",
    "memory_coverage_ratio": "fleetdoctor_memory_coverage_ratio",
    "fd_pressure_ratio": "fleetdoctor_fd_pressure_ratio",
    "fd_count": "fleetdoctor_fd_count",
    "fd_soft_limit": "fleetdoctor_fd_soft_limit",
    "fd_growth_per_second": "fleetdoctor_fd_growth_per_second",
    "fd_coverage_ratio": "fleetdoctor_fd_coverage_ratio",
    "network_loss_ratio": "fleetdoctor_network_probe_loss_ratio",
    "network_loss_packets": "fleetdoctor_network_probe_loss_packets",
    "network_rtt_seconds": "fleetdoctor_network_probe_median_rtt_seconds",
    "network_probe_coverage_ratio": "fleetdoctor_network_probe_coverage_ratio",
    "network_tcp_retransmits_total": "fleetdoctor_network_tcp_retransmits_total",
    "network_tcp_retransmits_per_second": "fleetdoctor_network_tcp_retransmits_per_second",
    "network_tcp_curr_estab": "fleetdoctor_network_tcp_curr_estab",
    "network_interface_rx_errors_total": "fleetdoctor_network_interface_rx_errors_total",
    "network_interface_rx_errors_per_second": "fleetdoctor_network_interface_rx_errors_per_second",
    "dns_query_success": "fleetdoctor_dns_query_success",
    "dns_query_duration_seconds": "fleetdoctor_dns_query_duration_seconds",
    "dns_probe_coverage_ratio": "fleetdoctor_dns_probe_coverage_ratio",
    "dns_inconclusive": "fleetdoctor_dns_inconclusive",
}


def validate_range(start: datetime, end: datetime, step: int, now: datetime) -> None:
    if any(t.tzinfo is None for t in (start, end)):
        raise ValueError("history requires timezone-aware times")
    duration = (end - start).total_seconds()
    if duration <= 0 or duration > 7 * 86400 or end > now or step < 5 or step > 86400:
        raise ValueError("range must be past, ordered, <=7 days with step 5..86400 seconds")
    if math.floor(duration / step) + 1 > 1500:
        raise ValueError("history limited to 1500 points per series")


class HistoryClient:
    def __init__(self, url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.url = url.rstrip("/")
        self.transport = transport
        self.slots = asyncio.Semaphore(4)

    async def query(
        self, node: str, start: datetime, end: datetime, step: int, field: str
    ) -> dict[str, Any]:
        validate_range(start, end, step, datetime.now(UTC))
        metric = HISTORY_METRICS[field]

        async def fetch() -> dict[str, Any]:
            async with self.slots:
                async with httpx.AsyncClient(
                    timeout=2, transport=self.transport, trust_env=False
                ) as client:
                    params = {
                        "query": f'{metric}{{node="{node}"}}',
                        "start": str(start.timestamp()),
                        "end": str(end.timestamp()),
                        "step": str(step),
                        "timeout": "2s",
                    }
                    async with client.stream(
                        "GET", self.url + "/api/v1/query_range", params=params
                    ) as response:
                        response.raise_for_status()
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > 2 * 1024 * 1024:
                                raise ValueError("history response exceeds 2MiB")
                        data: dict[str, Any] = json.loads(body)
                        if (
                            data.get("status") != "success"
                            or data.get("data", {}).get("resultType") != "matrix"
                        ):
                            raise ValueError("invalid Prometheus response")
                        return data["data"]  # type: ignore[no-any-return]

        return await asyncio.wait_for(fetch(), timeout=3)
