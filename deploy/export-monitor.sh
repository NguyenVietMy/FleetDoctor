#!/bin/bash
set -euo pipefail
cd /opt/fleetdoctor/current
cleanup() { docker compose start prometheus grafana; }
trap cleanup EXIT
docker compose stop prometheus grafana
# Copy consistent Prometheus/Grafana stores; PostgreSQL is separately exported with pg_dump.
# Export through stopped containers, retaining Compose's named volume association.
work=$(mktemp -d)
trap 'rm -rf "$work"; cleanup' EXIT
docker cp "$(docker compose ps -aq prometheus)":/prometheus "$work/prometheus"
docker cp "$(docker compose ps -aq grafana)":/var/lib/grafana "$work/grafana"
tar -czf /tmp/fleetdoctor-stores.tgz -C "$work" .
chmod 0600 /tmp/fleetdoctor-stores.tgz
chown ec2-user:ec2-user /tmp/fleetdoctor-stores.tgz
