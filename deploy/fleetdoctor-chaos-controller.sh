#!/bin/sh
set -eu
exec /usr/bin/python3.11 /opt/fleetdoctor/current/deploy/chaos_controller.py "$@"
