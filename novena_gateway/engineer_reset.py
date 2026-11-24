"""Offline field reset. Cloud ownership remains locked until Hub revokes access."""

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


CONFIG_PATH = Path("/etc/novena-gateway/config.json")
DATA_DIR = Path("/var/lib/novena-gateway")
LOG_DIR = Path("/var/log/novena-gateway")
CONFIRMATION = "ERASE-LOCAL-CUSTOMER-DATA"


def reset_local_state(config_path: Path, data_dir: Path, log_dir: Path, serial: str) -> None:
    """Quarantine the service first, then erase all mutable Gateway state."""
    for path in (config_path.parent, config_path, data_dir, log_dir):
        if path.is_symlink():
            raise ValueError(f"Refusing symlink path: {path}")
    with config_path.open(encoding="utf-8") as source:
        current = json.load(source)
    actual_serial = current.get("gateway", {}).get("serial_number")
    if not actual_serial or actual_serial != serial:
        raise ValueError("Serial does not match the installed Gateway configuration")

    # Keep only the vendor's public OTA trust key. Other files under /etc can
    # include prior site credentials, client certificates, or config snapshots.
    ota_key = Path(current.get("ota", {}).get("public_key_path") or "")
    saved_ota_key = None
    if ota_key.is_absolute() and ota_key.is_relative_to(config_path.parent):
        if ota_key.is_symlink() or not ota_key.is_file() or ota_key.stat().st_size > 16384:
            raise ValueError("Factory OTA trust key is missing or unsafe")
        saved_ota_key = ota_key.read_bytes()

    # An intentionally unstartable configuration prevents the old site from
    # reconnecting if the machine reboots before cloud revocation/reprovisioning.
    clean = {
        "gateway": {"serial_number": serial},
        "deployment": {"mode": "local"},
        "mqtt": {"mode": "support_reset_pending", "host": "", "port": 0, "username": "", "password": ""},
        "bootstrap_mqtt": {"enabled": False},
        "connectors": [],
        "ota": current.get("ota", {}),
        "hardware": current.get("hardware", {}),
    }
    previous = config_path.stat()
    fd, temporary = tempfile.mkstemp(prefix=".gateway-reset-", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            os.fchmod(target.fileno(), stat.S_IMODE(previous.st_mode))
            os.fchown(target.fileno(), previous.st_uid, previous.st_gid)
            json.dump(clean, target, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, config_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    for path in config_path.parent.iterdir():
        if path == config_path:
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    if saved_ota_key is not None:
        ota_key.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        ota_key.write_bytes(saved_ota_key)
        ota_key.chmod(0o644)

    for path in (data_dir, log_dir):
        previous_state = path.stat() if path.exists() else None
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(mode=0o750)
        if previous_state:
            os.chown(path, previous_state.st_uid, previous_state.st_gid)
            path.chmod(stat.S_IMODE(previous_state.st_mode))


def main() -> None:
    parser = argparse.ArgumentParser(description="Erase a Gateway's local customer state")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--case-reference", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root on the physical Gateway")
    if args.confirm != CONFIRMATION:
        parser.error(f"--confirm must equal {CONFIRMATION}")
    if not args.case_reference.strip():
        parser.error("A support case reference is required")
    service = subprocess.run(
        ["systemctl", "is-active", "novena-gateway"], capture_output=True, text=True, check=False
    )
    if service.stdout.strip() not in {"inactive", "failed"}:
        parser.error("Stop novena-gateway before resetting local state")
    reset_local_state(CONFIG_PATH, DATA_DIR, LOG_DIR, args.serial.strip().upper())
    print("Local customer state erased. Gateway is quarantined and cannot start until reprovisioned.")
    print("Cloud ownership and MQTT identities must be revoked in Hub before reassignment.")


if __name__ == "__main__":
    main()
