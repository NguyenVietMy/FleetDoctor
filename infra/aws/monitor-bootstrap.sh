#!/bin/bash
set -euo pipefail
dnf install -y docker python3.11 python3.11-pip chrony
command -v curl
systemctl enable --now docker chronyd
usermod -aG docker ec2-user
mkdir -p /usr/local/lib/docker/cli-plugins /etc/systemd/journald.conf.d
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl --fail --location --retry 3 -o docker-compose-linux-x86_64 https://github.com/docker/compose/releases/download/v2.38.2/docker-compose-linux-x86_64
curl --fail --location --retry 3 -o checksums.txt https://github.com/docker/compose/releases/download/v2.38.2/checksums.txt
grep -E '[ *]docker-compose-linux-x86_64$' checksums.txt | sha256sum --check --strict
install -m 0755 docker-compose-linux-x86_64 /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/fleetdoctor.conf
systemctl restart systemd-journald
test -f /sys/fs/cgroup/cgroup.controllers
mkdir -p /opt/fleetdoctor
