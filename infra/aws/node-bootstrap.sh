#!/bin/bash
set -euo pipefail
dnf install -y python3.11 python3.11-pip chrony iputils iproute procps-ng
systemctl enable --now chronyd
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/fleetdoctor.conf
systemctl restart systemd-journald
test -f /sys/fs/cgroup/cgroup.controllers
useradd --system --home-dir /opt/fleetdoctor --shell /sbin/nologin fleetdoctor
mkdir -p /opt/fleetdoctor /etc/fleetdoctor
gid=$(id -g fleetdoctor)
case "$gid" in *[!0-9]*|'') exit 1;; esac
printf 'net.ipv4.ping_group_range = %s %s\n' "$gid" "$gid" > /etc/sysctl.d/90-fleetdoctor-ping.conf
chown root:root /etc/sysctl.d/90-fleetdoctor-ping.conf
chmod 0644 /etc/sysctl.d/90-fleetdoctor-ping.conf
sysctl -q -p /etc/sysctl.d/90-fleetdoctor-ping.conf
read -r ping_min ping_max ping_extra < /proc/sys/net/ipv4/ping_group_range
test -z "${ping_extra:-}" && test "$ping_min" = "$gid" && test "$ping_max" = "$gid"
