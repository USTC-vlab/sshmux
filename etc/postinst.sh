#!/bin/sh

# Only run when systemd is running
[ -d /run/systemd ] || exit 0

systemctl daemon-reload
systemctl enable sshmux.service
