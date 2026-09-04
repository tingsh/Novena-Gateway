#!/usr/bin/env python3
"""Render the local hardware replay config for a Pi CM4 Novena Gateway.

This script intentionally keeps the operator command small. Runtime values that are
specific to the test bench are passed as flags; hardened trust settings are rendered
into /etc/novena-gateway/config.json from the repository template.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import strftime

from novena_gateway.gateway.runtime_paths import (
    COMMAND_JOURNAL_PATH,
    COMMAND_POLICY_PATH,
    CONFIG_JOURNAL_PATH,
)

SERIAL = "NOV-AUDIT-FACTORY-HW"
DEFAULT_OUTPUT = Path("/etc/novena-gateway/config.json")
DEFAULT_JOURNAL = Path(CONFIG_JOURNAL_PATH)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


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
    parser.add_argument(
        "--mqtt-password",
        required=True,
        help="MQTT password / replay claim code. For this fixture use F157DFD4.",
    )
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
        raise SystemExit(f"{name} still looks like a placeholder: {value!r}")


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak.{strftime('%Y%m%d-%H%M%S')}")
    backup.write_bytes(path.read_bytes())
    os.chmod(backup, 0o600)
    return backup


def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", dir=str(path.parent), delete=False) as tmp:
        json.dump(data, tmp, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
    cfg.setdefault("gateway", {})["serial_number"] = SERIAL

    mqtt = cfg.setdefault("mqtt", {})
    mqtt.update(
        {
            "host": args.mqtt_host,
            "port": 1883,
            "topic": f"v1/gateway/{SERIAL}/telemetry",
            "username": SERIAL,
            "password": args.mqtt_password,
            "client_id": f"novena-gateway-{SERIAL}",
            "allow_insecure_private_mqtt": True,
        }
    )
    mqtt.pop("tls", None)

    bootstrap = cfg.setdefault("bootstrap_mqtt", {})
    bootstrap.update(
        {
            "enabled": True,
            "username": f"bootstrap:{SERIAL}",
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
            "tcp_scan_workers": 32,
        }
    )

    cfg["connectors"] = []

    backup = None if args.no_backup else backup_existing(args.output)
    atomic_write_json(args.output, cfg)

    print(f"Wrote Gateway config: {args.output}")
    if backup:
        print(f"Backed up previous config: {backup}")
    print(f"Gateway serial: {SERIAL}")
    print(f"MQTT target: {args.mqtt_host}:1883")
    print(f"MQTT username: {SERIAL}")
    print("MQTT password: [set]")
    print(f"Guided Setup key id: {args.public_key_id}")
    print(f"Guided Setup public key: {args.public_key_b64[:8]}...{args.public_key_b64[-8:]}")
    print(f"Manual fallback Modbus target: {args.modbus_host}:{args.modbus_port}")
    print("Local replay mode: TLS disabled only because this is private-LAN MQTT on port 1883.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
