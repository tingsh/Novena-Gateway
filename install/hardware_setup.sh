#!/usr/bin/env bash
# Idempotent CM4/Waveshare Industrial IoT carrier board setup.

set -euo pipefail

BOOT_CONFIG=""
for candidate in /boot/firmware/config.txt /boot/config.txt; do
    if [ -f "$candidate" ]; then
        BOOT_CONFIG="$candidate"
        break
    fi
done

if [ -z "$BOOT_CONFIG" ]; then
    echo "ERROR: Could not find /boot/firmware/config.txt or /boot/config.txt" >&2
    exit 1
fi

backup="${BOOT_CONFIG}.novena.$(date +%Y%m%d%H%M%S).bak"
cp "$BOOT_CONFIG" "$backup"
echo "Backed up $BOOT_CONFIG to $backup"

ensure_line() {
    local line="$1"
    if ! grep -Fxq "$line" "$BOOT_CONFIG"; then
        printf '\n%s\n' "$line" >> "$BOOT_CONFIG"
        echo "Added: $line"
    else
        echo "Present: $line"
    fi
}

ensure_line "otg_mode=1"
ensure_line "dtparam=spi=on"
ensure_line "dtoverlay=uart3"
ensure_line "dtoverlay=uart5"
ensure_line "dtoverlay=mcp2515-can0,oscillator=12000000,interrupt=25"
ensure_line "dtoverlay=i2c-rtc,pcf85063a"

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable NetworkManager >/dev/null 2>&1 || true
fi

echo "Hardware setup complete. Reboot is required for boot overlay changes."
