#!/usr/bin/env bash
# Idempotently enable operating-system time synchronization for signed commands.

set -euo pipefail

if command -v timedatectl >/dev/null 2>&1; then
    echo "Enabling network time synchronization..."
    timedatectl set-ntp true || echo "WARNING: Could not enable NTP through timedatectl" >&2
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files systemd-timesyncd.service --no-legend 2>/dev/null \
        | grep -q '^systemd-timesyncd.service'; then
        systemctl enable --now systemd-timesyncd.service \
            || echo "WARNING: Could not enable systemd-timesyncd" >&2
    fi
    if systemctl list-unit-files systemd-time-wait-sync.service --no-legend 2>/dev/null \
        | grep -q '^systemd-time-wait-sync.service'; then
        systemctl enable systemd-time-wait-sync.service \
            || echo "WARNING: Could not enable systemd-time-wait-sync" >&2
    fi
fi
