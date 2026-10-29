#!/bin/bash
set -euo pipefail
agent_env=${1:?private agent env path required}
ingest_token=${2:?private token path required}
trap 'rm -f -- "$agent_env" "$ingest_token"' EXIT
cd /opt/fleetdoctor/current
sha256sum --check --strict wheel.sha256
if ! command -v ping >/dev/null || ! command -v ip >/dev/null || ! command -v tc >/dev/null || ! command -v sysctl >/dev/null; then
    if command -v dnf >/dev/null; then
        dnf install -y iputils iproute procps-ng
    elif command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y --no-install-recommends iputils-ping iproute2 procps
    else
        echo "cannot install required iputils/iproute/procps tools on this platform" >&2
        exit 1
    fi
fi
command -v ping >/dev/null
command -v ip >/dev/null
command -v tc >/dev/null
command -v sysctl >/dev/null
python3.11 -m venv /opt/fleetdoctor/venv
/opt/fleetdoctor/venv/bin/pip install --require-hashes -r requirements.txt
/opt/fleetdoctor/venv/bin/pip install --force-reinstall --no-deps --no-build-isolation ./*.whl
install -m 0600 "$agent_env" /etc/fleetdoctor/agent.env
install -m 0600 "$ingest_token" /etc/fleetdoctor/ingest-token
rm "$agent_env" "$ingest_token"
install -m 0644 deploy/fleetdoctor-agent.service /etc/systemd/system/fleetdoctor-agent.service
install -m 0644 deploy/fleetdoctor-disk-prepare.service /etc/systemd/system/fleetdoctor-disk-prepare.service
install -m 0755 deploy/memory_resource.py /usr/local/sbin/fleetdoctor-memory-resource
install -m 0755 deploy/fd_resource.py /usr/local/sbin/fleetdoctor-fd-resource
install -m 0755 deploy/network_resource.py /usr/local/sbin/fleetdoctor-network-resource
install -m 0755 deploy/dns_resource.py /usr/local/sbin/fleetdoctor-dns-resource
install -m 0755 deploy/network_prepare.sh /usr/local/sbin/fleetdoctor-network-prepare
/usr/local/sbin/fleetdoctor-network-prepare fleetdoctor
systemctl daemon-reload
systemctl enable --now fleetdoctor-agent
systemctl restart fleetdoctor-agent
systemctl is-active --quiet fleetdoctor-agent
