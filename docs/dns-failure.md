# DNS failure runbook

Configure `FLEETDOCTOR_DNS_HOSTNAME` as a lowercase absolute ASCII name with a trailing dot and at least two labels. Configure `FLEETDOCTOR_NETWORK_TARGET` as the exact numeric direct-IP discriminator. When DNS monitoring is enabled, `FLEETDOCTOR_COLLECTOR_URL` must use a private numeric address; loopback is accepted only with the explicit local-proof flag `FLEETDOCTOR_ALLOW_LOOPBACK_DNS_INGEST=1`.

The agent reads a stable, bounded `/etc/resolv.conf` snapshot and performs an A query with a 1.2-second total lifetime. Direct nonlocal nameservers use dnspython with application caching and search expansion disabled. Only known systemd-resolved stubs use `resolvectl --cache=no --synthesize=no --zone=no --protocol=dns`. Unsupported flags, unknown local caches, service/tool errors, malformed output, permissions, and resolver races are unavailable rather than invented failures. An upstream recursive resolver may itself cache; the contract bypasses node/application caches.

A DNS incident opens after three fresh measured query failures only when the exact same sample has a 3-sent/3-received/zero-loss direct-IP probe below the frozen DNS RTT limit and includes a valid earlier known-good local DNS/IP observation. A query failure with degraded, mismatched, stale, or unavailable IP evidence is inconclusive. Recovery requires three fresh successful query and matching healthy-IP samples. Resolver equality is intentionally not required for recovery.

The parent agent retains at most 721 serialized baseline candidates for the inclusive one-hour horizon, no more than 3072 bytes each. It sends only the minimum-IP-RTT candidate, newest sequence on a tie. Boot, session, hostname, or direct-IP target changes clear the history; resolver changes do not. Agent restart loses it conservatively. Active persisted incidents remain active and inconclusive until fresh matching recovery.

Use `deploy/dns_resource.py` only as root inside a proven disposable Linux namespace. It owns only `/etc/resolv.conf` and `/run/fleetdoctor/dns`, arms a live watchdog before publishing the exclusive lease, records permitted partial-write state before mutation, and restores exact bytes/type/metadata. A normal `start` leaves the leased fault active until explicit `cleanup` or deadline. Foreign resolver or lease state is refused and remains actionable. Never point it at the Windows, WSL, Docker-host, or an unowned resolver.

Local proof commands:

```text
uv run pytest -q tests/test_dns.py tests/test_dns_helper.py tests/test_dns_harness.py
uv run python scripts/dns_helper_integration.py --output <new-external-path>/dns-native.json
```

The native controller uses unique Docker names and exact cleanup. The measured AWS five-run batch, healthy-hour false-positive baseline, overhead calibration, hosted CI, rendered-dashboard readability, and owner acceptance are separate gates.
