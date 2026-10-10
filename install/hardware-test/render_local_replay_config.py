#!/usr/bin/env python3
"""Render the local hardware replay config for a Pi CM4 Novena Gateway.

This script intentionally keeps the operator command small. Runtime values that are
specific to the test bench are passed as flags; hardened trust settings are rendered
into /etc/novena-gateway/config.json from the repository template.
"""

from __future__ import annotations

import argparse
import base64
import grp
import json
import os
import pwd
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import strftime

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from novena_gateway.gateway.runtime_paths import (
    COMMAND_JOURNAL_PATH,
    COMMAND_POLICY_PATH,
    CONFIG_JOURNAL_PATH,
    DATA_DIR,
)

SERIAL = "NOV-AUDIT-FACTORY-HW"
DEFAULT_OUTPUT = Path("/etc/novena-gateway/config.json")
DEFAULT_JOURNAL = Path(CONFIG_JOURNAL_PATH)


def repo_root() -> Path:
    return REPO_ROOT


def default_template() -> Path:
    return repo_root() / "install" / "field-test-configs" / "nov-audit-factory-hw.local.json"


def validate_public_key(value: str) -> None:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - produce a clear CLI error for bad input.
        raise argparse.ArgumentTypeError(f"public key is not valid base64: {exc}") from exc
    if len(raw) != 32:
        raise argparse.ArgumentTypeError(
            f"public key must decode to 32 bytes for Ed25519, got {len(raw)} bytes"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render/install the local hardware replay Gateway config."
    )
    parser.add_argument("--mqtt-host", required=True, help="Laptop 1 IP/host reachable from the Pi.")
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=1883,
        help="MQTT port. The hardware replay flow is fixed to 1883.",
    )
    parser.add_argument("--runtime-dir", type=Path, help=f"Isolated test state subdirectory beneath {DATA_DIR}.")
    parser.add_argument("--serial", default=SERIAL, help="Factory inventory serial for this replay.")
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--mqtt-password", help="Claim code; prefer --mqtt-password-file to avoid shell history.")
    credentials.add_argument("--mqtt-password-file", type=Path, help="Mode-0600 file containing only the claim code.")
    parser.add_argument("--public-key-id", required=True, help="Hub Guided Setup signing key id.")
    parser.add_argument(
        "--public-key-b64",
        required=True,
        help="Hub Guided Setup Ed25519 public key, base64 encoded.",
    )
    parser.add_argument(
        "--modbus-host",
        required=True,
        help="Laptop 2 simulator address printed as the manual-fallback reference.",
    )
    parser.add_argument("--modbus-port", type=int, default=502, help="Modbus TCP port. Default: 502.")
    parser.add_argument("--template", type=Path, default=default_template(), help="Gateway config template.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Config path to write.")
    parser.add_argument("--no-backup", action="store_true", help="Do not back up an existing output file.")
    return parser


def require_real_value(name: str, value: str) -> None:
    if not value or value.startswith("REPLACE_") or "PASTE_" in value:
        raise SystemExit(f"{name} is empty or still looks like a placeholder.")


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak.{strftime('%Y%m%d-%H%M%S')}")
    backup.write_bytes(path.read_bytes())
    os.chmod(backup, 0o600)
    return backup


def desired_config_permissions(path: Path) -> tuple[int | None, int | None, int]:
    if path.resolve() == DEFAULT_OUTPUT:
        try:
            uid = pwd.getpwnam("novena").pw_uid
            gid = grp.getgrnam("novena").gr_gid
            return uid, gid, 0o640
        except KeyError:
            return None, None, 0o640
    return None, None, 0o600


def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        json.dump(data, tmp, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    uid, gid, mode = desired_config_permissions(path)
    os.chmod(tmp_path, mode)
    if uid is not None and gid is not None:
        os.chown(tmp_path, uid, gid)
    os.replace(tmp_path, path)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.serial or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in args.serial):
        parser.error("serial must contain only letters, digits, hyphens and underscores")
    if args.serial != SERIAL and (not args.runtime_dir or not args.runtime_dir.is_absolute()):
        parser.error("a dedicated serial requires an absolute --runtime-dir")
    if args.runtime_dir and (
        not args.runtime_dir.is_absolute() or Path(DATA_DIR) not in args.runtime_dir.resolve().parents
    ):
        parser.error(f"runtime-dir must be an absolute subdirectory beneath {DATA_DIR}")
    if args.mqtt_password_file:
        if args.mqtt_password_file.stat().st_mode & 0o077:
            parser.error("credential file must not be accessible to group or others")
        args.mqtt_password = args.mqtt_password_file.read_text().strip()

    if args.mqtt_port != 1883:
        parser.error("the local hardware replay setup uses MQTT port 1883 only")

    for name, value in {
        "--mqtt-host": args.mqtt_host,
        "--mqtt-password": args.mqtt_password,
        "--public-key-id": args.public_key_id,
        "--public-key-b64": args.public_key_b64,
        "--modbus-host": args.modbus_host,
    }.items():
        require_real_value(name, value)
    validate_public_key(args.public_key_b64)

    if not args.template.exists():
        raise SystemExit(f"Template not found: {args.template}")

    cfg = json.loads(args.template.read_text())
    cfg.setdefault("deployment", {})["mode"] = "local"
    cfg.setdefault("gateway", {})["serial_number"] = args.serial

    mqtt = cfg.setdefault("mqtt", {})
    mqtt.update(
        {
            "host": args.mqtt_host,
            "port": 1883,
            "topic": f"v1/gateway/{args.serial}/telemetry",
            "username": args.serial,
            "password": args.mqtt_password,
            "client_id": f"novena-gateway-{args.serial}",
            "allow_insecure_private_mqtt": True,
        }
    )
    mqtt.pop("tls", None)

    bootstrap = cfg.setdefault("bootstrap_mqtt", {})
    bootstrap.update(
        {
            "enabled": True,
            "username": f"bootstrap:{args.serial}",
            "password": args.mqtt_password,
        }
    )

    features = cfg.setdefault("features", {})
    remote_config = features.setdefault("remote_config", {})
    remote_config.update(
        {
            "enabled": True,
            "trusted_clock": True,
            "trusted_config_keys": {args.public_key_id: args.public_key_b64},
            "revoked_config_key_ids": [],
            "config_journal_path": str(DEFAULT_JOURNAL),
        }
    )

    rpc = features.setdefault("rpc", {})
    rpc.update(
        {
            "enabled": True,
            "trusted_clock": True,
            "diagnostic_clock_skew_seconds": 120,
            "trusted_command_keys": {args.public_key_id: args.public_key_b64},
            "revoked_command_key_ids": [],
            "command_policy_path": COMMAND_POLICY_PATH,
            "command_journal_path": COMMAND_JOURNAL_PATH,
        }
    )

    discovery = features.setdefault("discovery", {})
    discovery.update(
        {
            "enabled": True,
            "scan_on_boot": False,
            "scan_interval_seconds": 0,
            "tcp_subnet_scan": False,
            "tcp_hosts": [],
            "tcp_ports": [args.modbus_port],
            "tcp_scan_timeout_ms": 1500,
            "tcp_scan_workers": 32,
            "tcp_probe_slave_ids": [1],
            "tcp_probe_registers": [0, 1, 3000],
        }
    )

    if args.runtime_dir:
        paths = {
            ("storage", "sqlite", "data_file_path"): "sqlite/",
            ("storage", "update_path"): "updates",
            ("storage", "ota_status_path"): "ota-status.json",
            ("features", "remote_config", "backup_dir"): "config-backups",
            ("features", "remote_config", "last_known_good_path"): "last-known-good.json",
            ("features", "remote_config", "config_journal_path"): "config-journal.json",
            ("features", "rpc", "command_policy_path"): "command-policy.json",
            ("features", "rpc", "command_journal_path"): "command-journal.json",
        }
        for keys, filename in paths.items():
            destination = cfg
            for key in keys[:-1]:
                destination = destination.setdefault(key, {})
            destination[keys[-1]] = str(args.runtime_dir / filename) + ("/" if filename.endswith("/") else "")

    cfg["connectors"] = []

    backup = None if args.no_backup else backup_existing(args.output)
    atomic_write_json(args.output, cfg)

    print(f"Wrote Gateway config: {args.output}")
    if backup:
        print(f"Backed up previous config: {backup}")
    print(f"Gateway serial: {args.serial}")
    print(f"MQTT target: {args.mqtt_host}:1883")
    print(f"MQTT username: {args.serial}")
    print("MQTT password: [set]")
    print(f"Guided Setup key id: {args.public_key_id}")
    print(f"Guided Setup public key: {args.public_key_b64[:8]}...{args.public_key_b64[-8:]}")
    print(f"Manual fallback Modbus target: {args.modbus_host}:{args.modbus_port}")
    print("Local replay mode: TLS disabled only because this is private-LAN MQTT on port 1883.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
