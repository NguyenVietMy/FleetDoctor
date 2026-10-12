#!/bin/sh
set -eu
case ",$FLEETDOCTOR_FILESYSTEMS," in
  *,/var/lib/fleetdoctor/chaos/disk,*) mountpoint -q /var/lib/fleetdoctor/chaos/disk ;;
esac
