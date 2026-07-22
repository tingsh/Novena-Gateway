#!/usr/bin/env bash
# Novena Gateway Linux OTA Update Script
# Usage: ./upgrade.sh /path/to/firmware.tar.gz 1.2.0

set -euo pipefail
umask 022

PAYLOAD_TAR="$1"
VERSION="$2"
MANIFEST_JSON="${3:?manifest required}"

INSTALL_DIR="/opt/novena-gateway"
NEW_RELEASE_DIR="${INSTALL_DIR}/releases/novena-gateway-${VERSION}"
CURRENT_LINK="${INSTALL_DIR}/current"
CONFIG_PATH="/etc/novena-gateway/config.json"
STATUS_PATH="/var/lib/novena-gateway/ota_status.json"
BACKUP_RELEASE=""
STAGING_DIR=""

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(rc|canary)\.[0-9]+)?$ ]]; then
    echo "ERROR: Invalid OTA version: ${VERSION}"
    exit 1
fi

cleanup() {
    if [ -n "${STAGING_DIR}" ] && [ -d "${STAGING_DIR}" ]; then
        rm -rf "${STAGING_DIR}"
    fi
}
trap cleanup EXIT

write_status() {
    local status="$1"
    local error="${2:-}"
    local rollback="${3:-false}"
    mkdir -p "$(dirname "${STATUS_PATH}")"
    cat > "${STATUS_PATH}" <<EOF
{"ota_status":"${status}","ota_version":"${VERSION}","ota_error":"${error}","ota_rollback_performed":${rollback}}
EOF
}

echo "=== Novena Gateway OTA Upgrade started (Version: ${VERSION}) ==="

# 1. Ensure target directory structure exists
mkdir -p "${INSTALL_DIR}/releases"
if [ -e "${NEW_RELEASE_DIR}" ]; then
    echo "ERROR: Release directory already exists: ${NEW_RELEASE_DIR}"
    write_status "failed" "Release directory already exists" "false"
    exit 1
fi
if [ ! -f "${MANIFEST_JSON}" ]; then
    echo "ERROR: Signed OTA manifest file not found"
    write_status "failed" "Signed OTA manifest file not found" "false"
    exit 1
fi

# Get current link target if exists for rollback
if [ -L "${CURRENT_LINK}" ]; then
    BACKUP_RELEASE=$(readlink -f "${CURRENT_LINK}")
    echo "Current active release: ${BACKUP_RELEASE}"
fi

# 2. Extract new firmware in staging directory
echo "Extracting payload..."
PYTHONPATH="${CURRENT_LINK}" "${INSTALL_DIR}/venv/bin/python" -c "from novena_gateway.gateway.ota_security import validate_tarball; import sys; validate_tarball(sys.argv[1])" "${PAYLOAD_TAR}"
STAGING_DIR="$(mktemp -d "${INSTALL_DIR}/releases/.ota-${VERSION}.XXXXXX")"
tar -xzf "${PAYLOAD_TAR}" -C "${STAGING_DIR}" --strip-components=1 --no-same-owner --no-same-permissions --delay-directory-restore

if [ ! -d "${STAGING_DIR}/novena_gateway" ] || [ ! -f "${STAGING_DIR}/requirements.txt" ]; then
    echo "ERROR: Firmware payload is missing novena_gateway/ or requirements.txt"
    write_status "failed" "Firmware payload missing novena_gateway or requirements.txt" "false"
    exit 1
fi
chmod -R go-w "${STAGING_DIR}"
mv "${STAGING_DIR}" "${NEW_RELEASE_DIR}"
STAGING_DIR=""

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

# 3.5 Validate candidate code against current production config before swap
echo "Validating candidate release..."
if [ -f "${CONFIG_PATH}" ]; then
    if ! (cd "${NEW_RELEASE_DIR}" && "${INSTALL_DIR}/venv/bin/python" -m novena_gateway.main --config "${CONFIG_PATH}" --validate-only); then
        echo "ERROR: Candidate release failed config validation"
        write_status "failed" "Candidate release failed config validation" "false"
        exit 1
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
    sleep 8
    if systemctl is-active --quiet novena-gateway; then
        write_status "success" "" "false"
        echo "=== OTA Upgrade Successful (Version: ${VERSION}) ==="
        exit 0
    else
        echo "ERROR: New version failed to start. Rolling back..."
        if [ -n "${BACKUP_RELEASE}" ]; then
            ln -sfn "${BACKUP_RELEASE}" "${CURRENT_LINK}"
            systemctl restart novena-gateway
            write_status "rolled_back" "New version failed service health check" "true"
            echo "Rollback to version ${BACKUP_RELEASE} completed."
        else
            write_status "failed" "New version failed service health check and no backup release was available" "false"
        fi
        exit 1
    fi
else
    echo "Systemd service 'novena-gateway' not found. Symlink swapped, but restart skipped."
    write_status "success" "systemd service not found; restart skipped" "false"
    echo "=== OTA Upgrade completed without daemon restart (Local / non-systemd) ==="
    exit 0
fi
