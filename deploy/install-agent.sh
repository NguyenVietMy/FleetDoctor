#!/bin/bash
set -euo pipefail
agent_env=${1:?private agent env path required}
ingest_token=${2:?private token path required}
trap 'rm -f -- "$agent_env" "$ingest_token"' EXIT
cd /opt/fleetdoctor/current
sha256sum --check --strict wheel.sha256
python3.11 -m venv /opt/fleetdoctor/venv
/opt/fleetdoctor/venv/bin/pip install --require-hashes -r requirements.txt
/opt/fleetdoctor/venv/bin/pip install --force-reinstall --no-deps --no-build-isolation ./*.whl
install -m 0600 "$agent_env" /etc/fleetdoctor/agent.env
install -m 0600 "$ingest_token" /etc/fleetdoctor/ingest-token
rm "$agent_env" "$ingest_token"
install -m 0644 deploy/fleetdoctor-agent.service /etc/systemd/system/fleetdoctor-agent.service
install -m 0644 deploy/fleetdoctor-disk-prepare.service /etc/systemd/system/fleetdoctor-disk-prepare.service
systemctl daemon-reload
systemctl enable --now fleetdoctor-agent
systemctl restart fleetdoctor-agent
systemctl is-active --quiet fleetdoctor-agent
