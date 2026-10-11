#!/bin/bash
set -euo pipefail
dnf install -y python3.11 python3.11-pip chrony
systemctl enable --now chronyd
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/fleetdoctor.conf
systemctl restart systemd-journald
test -f /sys/fs/cgroup/cgroup.controllers
useradd --system --home-dir /opt/fleetdoctor --shell /sbin/nologin fleetdoctor
mkdir -p /opt/fleetdoctor /etc/fleetdoctor
