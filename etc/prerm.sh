#!/bin/sh

case "$1" in
  remove)
    # Only run when systemd is running
    [ -d /run/systemd ] || exit 0

    systemctl disable --now sshmux.service
    ;;
  upgrade|deconfigure)
    # Nothing to do
    ;;
  *)
    echo "prerm script called with unknown argument: $1"
    exit 1
    ;;
esac
