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
mkdir -p "$DATA_DIR/sqlite"
mkdir -p "$DATA_DIR/update"
mkdir -p "$DATA_DIR/config_backups"
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

echo "[3/6] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$RELEASE_DIR/requirements.txt"

echo "[3.5/6] Creating unprivileged user and assigning permissions..."
useradd -r -s /bin/false -G dialout novena || true
chown -R novena:novena "$INSTALL_DIR"
chown -R novena:novena "$CONFIG_DIR"
chown -R novena:novena "$DATA_DIR"
chown -R novena:novena "$LOG_DIR"

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
