"""Install a fresh cloud claim after an engineer has quarantined a physical Gateway."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


CONFIG_PATH = Path("/etc/novena-gateway/config.json")
TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "install/field-test-configs/nov-audit-factory-hw.local.json"
)
CA_CERTS_PATH = Path("/etc/ssl/certs/ca-certificates.crt")


def render_config(quarantined: dict, template: dict, bundle: dict, ca_certs: Path, host: str) -> dict:
    """Render an empty site with TLS and the current Hub public signing key."""
    if not all(isinstance(value, dict) for value in (quarantined, template, bundle)):
        raise ValueError("Gateway config, template, and provisioning bundle must be objects")
    if quarantined.get("mqtt", {}).get("mode") != "support_reset_pending":
        raise ValueError("Gateway must be locally reset before cloud commissioning")
    serial = quarantined.get("gateway", {}).get("serial_number", "")
    if not re.fullmatch(r"[A-Z0-9_-]{3,50}", serial) or bundle.get("serial") != serial:
        raise ValueError("Provisioning bundle serial does not match the reset Gateway")
    code = bundle.get("claim_code", "")
    if not isinstance(code, str) or not re.fullmatch(r"(?:[A-F0-9]{8}|[A-F0-9]{48})", code):
        raise ValueError("Provisioning bundle has no valid claim code")
    key_id = bundle.get("key_id", "")
    if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key_id):
        raise ValueError("Provisioning bundle has no valid signing key ID")
    public_key = bundle.get("key_b64", "")
    try:
        raw_key = base64.b64decode(public_key, validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Provisioning bundle has an invalid signing public key") from exc
    if len(raw_key) != 32:
        raise ValueError("Signing public key must be 32 bytes")
    if not isinstance(host, str) or len(host) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Invalid MQTT host")
    if not ca_certs.is_file():
        raise ValueError("System CA bundle is missing")

    config = json.loads(json.dumps(template))
    config["gateway"] = {"serial_number": serial}
    config["deployment"] = {"mode": "pilot"}
    config["connectors"] = []
    config["ota"] = quarantined.get("ota", {})
    config["hardware"] = quarantined.get("hardware", {})

    mqtt = config.setdefault("mqtt", {})
    mqtt.update(
        host=host,
        port=8883,
        topic=f"v1/gateway/{serial}/telemetry",
        username=serial,
        password=code,
        client_id=f"novena-gateway-{serial}",
        tls={"mode": "one-way", "ca_certs": str(ca_certs)},
    )
    mqtt.pop("allow_insecure_private_mqtt", None)
    mqtt.pop("claim_id", None)
    mqtt.pop("mode", None)

    config["bootstrap_mqtt"] = {
        "enabled": True,
        "username": f"bootstrap:{serial}",
        "password": code,
    }
    features = config.setdefault("features", {})
    remote_config = features.setdefault("remote_config", {})
    remote_config.update(
        enabled=True,
        trusted_clock=True,
        trusted_config_keys={key_id: public_key},
        revoked_config_key_ids=[],
    )
    rpc = features.setdefault("rpc", {})
    rpc.update(
        enabled=True,
        trusted_clock=True,
        trusted_command_keys={key_id: public_key},
        revoked_command_key_ids=[],
    )
    features.setdefault("network_watchdog", {})["mode"] = "diagnostic"
    features.setdefault("discovery", {})["scan_on_boot"] = False
    return config


def install_config(config_path: Path, config: dict) -> None:
    """Atomically replace only the quarantined config, keeping its owner and mode."""
    if config_path.is_symlink() or config_path.parent.is_symlink():
        raise ValueError("Gateway config path must not be a symlink")
    previous = config_path.stat()
    if not stat.S_ISREG(previous.st_mode):
        raise ValueError("Gateway config is not a regular file")
    fd, temporary = tempfile.mkstemp(prefix=".cloud-commission-", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            os.fchmod(target.fileno(), stat.S_IMODE(previous.st_mode))
            os.fchown(target.fileno(), previous.st_uid, previous.st_gid)
            json.dump(config, target, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, config_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description="Commission a reset Gateway for the Novena cloud")
    parser.add_argument("--bundle", required=True, type=Path, help="Private Hub provisioning JSON, mode 0600")
    parser.add_argument("--mqtt-host", default="mqtt.novenaplatform.com")
    parser.add_argument("--ca-certs", default=CA_CERTS_PATH, type=Path)
    parser.add_argument("--config", default=CONFIG_PATH, type=Path)
    parser.add_argument("--template", default=TEMPLATE_PATH, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root on the physical Gateway")
    service = subprocess.run(
        ["systemctl", "is-active", "novena-gateway"], capture_output=True, text=True, check=False
    )
    if service.stdout.strip() not in {"inactive", "failed"}:
        parser.error("Stop novena-gateway before commissioning")
    if args.bundle.is_symlink() or not args.bundle.is_file():
        parser.error("Provisioning bundle must be a regular file")
    if args.bundle.stat().st_mode & 0o077 or args.bundle.stat().st_size > 4096:
        parser.error("Provisioning bundle must be private (mode 0600) and at most 4 KiB")
    try:
        with args.config.open(encoding="utf-8") as source:
            quarantined = json.load(source)
        with args.template.open(encoding="utf-8") as source:
            template = json.load(source)
        with args.bundle.open(encoding="utf-8") as source:
            bundle = json.load(source)
        config = render_config(quarantined, template, bundle, args.ca_certs, args.mqtt_host)
        install_config(args.config, config)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Cloud Gateway configuration installed for {config['gateway']['serial_number']}.")
    print("Claim code and signing material were not printed. Validate before starting the service.")


if __name__ == "__main__":
    main()
