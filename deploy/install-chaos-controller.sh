#!/bin/sh
set -eu
manifest=${1:?root-owned controller manifest path required}
test "$(id -u)" -eq 0
test -f "$manifest"
test ! -L "$manifest"
test -x /usr/bin/python3.11
verify_directory() {
    test -d "$1"
    test ! -L "$1"
    test "$(stat -c %u "$1")" -eq 0
    test -z "$(find "$1" -maxdepth 0 -perm /022 -print -quit)"
}
verify_file() {
    test -f "$1"
    test ! -L "$1"
    test "$(stat -c %u "$1")" -eq 0
    test -z "$(find "$1" -maxdepth 0 -perm /022 -print -quit)"
}
verify_directory /opt/fleetdoctor/current
verify_directory /opt/fleetdoctor/current/deploy
for file in \
    chaos_controller.py config_transaction.py disk_resource.py inode_resource.py \
    fd_resource.py memory_resource.py cpu_resource.py network_resource.py \
    dns_resource.py io_resource.py fleetdoctor-chaos-controller.sh
do
    verify_file "/opt/fleetdoctor/current/deploy/$file"
done
install -d -o root -g root -m 0700 /etc/fleetdoctor /var/lib/fleetdoctor/chaos-controller
install -o root -g root -m 0755 \
    /opt/fleetdoctor/current/deploy/fleetdoctor-chaos-controller.sh \
    /usr/local/sbin/fleetdoctor-chaos-controller
install -o root -g root -m 0600 "$manifest" /etc/fleetdoctor/chaos-controller.json
/usr/bin/python3.11 -c \
    'from pathlib import Path; import sys; sys.path.insert(0,"/opt/fleetdoctor/current/deploy"); from chaos_controller import validate_source; validate_source(Path("/opt/fleetdoctor/current"), Path("/etc/fleetdoctor/chaos-controller.json"))'
