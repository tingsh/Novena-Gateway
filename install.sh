#!/bin/bash
# Novena Gateway - Installation Script
# Run as root on Raspberry Pi or industrial gateway hardware.
#
# Usage: sudo bash install.sh

set -e

INSTALL_DIR="/opt/novena-gateway"
CONFIG_DIR="/etc/novena-gateway"
DATA_DIR="/var/lib/novena-gateway"
LOG_DIR="/var/log/novena-gateway"
TRUST_DIR="$CONFIG_DIR/trust"
RELEASE_DIR="$INSTALL_DIR/releases/novena-gateway-initial"
CURRENT_LINK="$INSTALL_DIR/current"
SERVICE_NAME="novena-gateway"

echo "======================================"
echo "  Novena Gateway - Installer"
echo "======================================"

echo "[1/6] Creating installation directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$RELEASE_DIR"
mkdir -p "$CONFIG_DIR/certs"
mkdir -p "$TRUST_DIR"
mkdir -p "$DATA_DIR/sqlite"
mkdir -p "$DATA_DIR/update"
mkdir -p "$DATA_DIR/config_backups"
mkdir -p "$DATA_DIR/deployment_setup"
mkdir -p "$DATA_DIR/remote_control"
mkdir -p "$LOG_DIR"

echo "[2/6] Copying release files..."
cp -r novena_gateway "$RELEASE_DIR/"
cp -r install "$RELEASE_DIR/"
cp requirements.txt "$RELEASE_DIR/"
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp config.json "$CONFIG_DIR/config.json"
    echo "  -> Config template installed to $CONFIG_DIR/config.json"
else
    echo "  -> Existing config preserved at $CONFIG_DIR/config.json"
fi

if [ -f "certs/ca.crt" ]; then
    cp certs/ca.crt "$CONFIG_DIR/certs/"
    echo "  -> CA certificate installed."
fi
if [ -n "${NOVENA_OTA_PUBLIC_KEY_SRC:-}" ] && [ -f "$NOVENA_OTA_PUBLIC_KEY_SRC" ]; then
    install -m 0644 "$NOVENA_OTA_PUBLIC_KEY_SRC" "$TRUST_DIR/ota_vendor_ed25519.pub"
    echo "  -> OTA public verification key installed from NOVENA_OTA_PUBLIC_KEY_SRC."
elif [ -f "trust/ota_vendor_ed25519.pub" ]; then
    install -m 0644 "trust/ota_vendor_ed25519.pub" "$TRUST_DIR/ota_vendor_ed25519.pub"
    echo "  -> OTA public verification key installed."
fi

echo "[3/6] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$RELEASE_DIR/requirements.txt"

echo "[3.5/6] Creating unprivileged user, helper, and permissions..."
useradd -r -s /bin/false -G dialout novena || true
usermod -a -G dialout novena || true
if getent group netdev >/dev/null; then
    usermod -a -G netdev novena || true
fi
chown -R root:root "$INSTALL_DIR"
chmod -R go-w "$INSTALL_DIR"
chown -R novena:novena "$CONFIG_DIR"
chown -R novena:novena "$DATA_DIR"
chown -R novena:novena "$LOG_DIR"
chmod 0750 "$DATA_DIR"
chmod 0750 "$DATA_DIR/sqlite" "$DATA_DIR/update" "$DATA_DIR/config_backups" "$DATA_DIR/deployment_setup" "$DATA_DIR/remote_control"
chmod 0750 "$LOG_DIR"
chown -R root:root "$TRUST_DIR"
chmod 0755 "$TRUST_DIR"
if [ -f "$TRUST_DIR/ota_vendor_ed25519.pub" ]; then
    chmod 0644 "$TRUST_DIR/ota_vendor_ed25519.pub"
fi

install -m 0755 "$RELEASE_DIR/install/novena-gateway-helper" /usr/local/sbin/novena-gateway-helper
install -m 0440 "$RELEASE_DIR/install/novena-gateway-helper.sudoers" /etc/sudoers.d/novena-gateway-helper
if command -v visudo >/dev/null 2>&1; then
    visudo -cf /etc/sudoers.d/novena-gateway-helper
fi

if [ "${NOVENA_SKIP_HARDWARE_SETUP:-0}" != "1" ]; then
    echo "[3.6/6] Applying CM4/Waveshare hardware setup..."
    bash "$RELEASE_DIR/install/hardware_setup.sh" || {
        echo "  WARNING: Hardware setup did not complete. Run hardware_preflight before handoff."
    }
else
    echo "[3.6/6] Skipping hardware setup because NOVENA_SKIP_HARDWARE_SETUP=1"
fi

echo "[3.9/6] Running production configuration validation..."
if NOVENA_DEPLOYMENT_MODE="${NOVENA_DEPLOYMENT_MODE:-pilot}" "$INSTALL_DIR/venv/bin/python" -m novena_gateway.main --config "$CONFIG_DIR/config.json" --validate-only; then
    echo "  -> Configuration file is valid."
else
    echo ""
    echo "  ERROR: Configuration validation failed."
    echo "  Please inspect and edit $CONFIG_DIR/config.json before starting the service."
    echo ""
    exit 1
fi

echo "[4/6] Installing systemd service..."
cp novena-gateway.service /etc/systemd/system/
systemctl daemon-reload

echo "[5/6] Enabling service..."
systemctl enable "$SERVICE_NAME"

echo "[6/6] Starting Novena Gateway..."
systemctl start "$SERVICE_NAME"

echo ""
echo "======================================"
echo "  Installation complete!"
echo "======================================"
echo ""
echo "  Status:  sudo systemctl status $SERVICE_NAME"
echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "  Config:  $CONFIG_DIR/config.json"
echo "  Data:    $DATA_DIR"
echo "  Stop:    sudo systemctl stop $SERVICE_NAME"
echo "  Restart: sudo systemctl restart $SERVICE_NAME"
echo ""
