#!/bin/sh
set -eu

test "$(id -u)" -eq 0 || { echo "network preparation requires root" >&2; exit 1; }
service_user=${1:-fleetdoctor}
entry=$(getent passwd "$service_user") || { echo "fleetdoctor service identity missing" >&2; exit 1; }
gid=$(printf '%s\n' "$entry" | cut -d: -f4)
case "$gid" in *[!0-9]*|'') echo "invalid fleetdoctor service GID" >&2; exit 1;; esac
test "$gid" -gt 0 || { echo "fleetdoctor service GID must be nonroot" >&2; exit 1; }
command -v ping >/dev/null
command -v ip >/dev/null
command -v tc >/dev/null
tmp=$(mktemp /etc/sysctl.d/.fleetdoctor-ping.XXXXXX)
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
printf 'net.ipv4.ping_group_range = %s %s\n' "$gid" "$gid" > "$tmp"
chown root:root "$tmp"
chmod 0644 "$tmp"
install -o root -g root -m 0644 "$tmp" /etc/sysctl.d/90-fleetdoctor-ping.conf
sysctl -q -p /etc/sysctl.d/90-fleetdoctor-ping.conf
actual=$(cat /proc/sys/net/ipv4/ping_group_range)
set -- $actual
test "$#" -eq 2 && test "$1" = "$gid" && test "$2" = "$gid" || {
  echo "ping_group_range readback mismatch" >&2
  exit 1
}
test "$(stat -c '%U:%G:%a' /etc/sysctl.d/90-fleetdoctor-ping.conf)" = "root:root:644"
