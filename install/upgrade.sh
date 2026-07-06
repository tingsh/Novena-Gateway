#!/usr/bin/env bash
# Novena Gateway Linux OTA Update Script
# Usage: ./upgrade.sh /path/to/firmware.tar.gz 1.2.0

set -euo pipefail

PAYLOAD_TAR="$1"
VERSION="$2"

INSTALL_DIR="/opt/novena-gateway"
NEW_RELEASE_DIR="${INSTALL_DIR}/releases/novena-gateway-${VERSION}"
CURRENT_LINK="${INSTALL_DIR}/current"
BACKUP_RELEASE=""

echo "=== Novena Gateway OTA Upgrade started (Version: ${VERSION}) ==="

# 1. Ensure target directory structure exists
mkdir -p "${INSTALL_DIR}/releases"

# Get current link target if exists for rollback
if [ -L "${CURRENT_LINK}" ]; then
    BACKUP_RELEASE=$(readlink -f "${CURRENT_LINK}")
    echo "Current active release: ${BACKUP_RELEASE}"
fi

# 2. Extract new firmware in staging directory
echo "Extracting payload..."
mkdir -p "${NEW_RELEASE_DIR}"
tar -xzf "${PAYLOAD_TAR}" -C "${NEW_RELEASE_DIR}" --strip-components=1

if [ ! -d "${NEW_RELEASE_DIR}/novena_gateway" ] || [ ! -f "${NEW_RELEASE_DIR}/requirements.txt" ]; then
    echo "ERROR: Firmware payload is missing novena_gateway/ or requirements.txt"
    exit 1
fi

# Write version file
echo "__version__ = \"${VERSION}\"" > "${NEW_RELEASE_DIR}/novena_gateway/__version__.py"

# 3. Pre-install dependencies in the new directory
echo "Installing dependencies..."
if [ -f "${NEW_RELEASE_DIR}/requirements.txt" ]; then
    if [ -d "${INSTALL_DIR}/venv" ]; then
        "${INSTALL_DIR}/venv/bin/pip" install -r "${NEW_RELEASE_DIR}/requirements.txt"
    else
        python3 -m venv "${INSTALL_DIR}/venv"
        "${INSTALL_DIR}/venv/bin/pip" install -r "${NEW_RELEASE_DIR}/requirements.txt"
    fi
fi

# 4. Atomic Symlink Swap (Blue/Green)
echo "Swapping symlink..."
ln -sfn "${NEW_RELEASE_DIR}" "${CURRENT_LINK}"

# 5. Service Restart and Health Check
echo "Restarting service..."
if systemctl list-units --full -all | grep -Fq 'novena-gateway.service'; then
    systemctl restart novena-gateway
    
    # Bounded wait for startup health check
    echo "Performing startup health check..."
    sleep 3
    if systemctl is-active --quiet novena-gateway; then
        echo "=== OTA Upgrade Successful (Version: ${VERSION}) ==="
        exit 0
    else
        echo "ERROR: New version failed to start. Rolling back..."
        if [ -n "${BACKUP_RELEASE}" ]; then
            ln -sfn "${BACKUP_RELEASE}" "${CURRENT_LINK}"
            systemctl restart novena-gateway
            echo "Rollback to version ${BACKUP_RELEASE} completed."
        fi
        exit 1
    fi
else
    echo "Systemd service 'novena-gateway' not found. Symlink swapped, but restart skipped."
    echo "=== OTA Upgrade completed without daemon restart (Local / non-systemd) ==="
    exit 0
fi
