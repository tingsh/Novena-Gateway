"""Cloud commissioning must convert only a quarantined Gateway to a TLS factory claim."""

import base64
import json
from pathlib import Path
import tempfile
import unittest

from novena_gateway.cloud_commission import install_config, render_config
from novena_gateway.gateway.novena_gateway import NovenaGateway


class CloudCommissionTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        self.ca_certs = self.path / "ca.crt"
        self.ca_certs.write_text("test certificate bundle")
        self.quarantined = {
            "gateway": {"serial_number": "NOV-AUDIT-FACTORY-HW"},
            "mqtt": {"mode": "support_reset_pending"},
            "ota": {"public_key_path": "/etc/novena-gateway/trust/ota_vendor_ed25519.pub"},
            "hardware": {"can": {"interface": "can0"}},
        }
        self.template = json.loads(
            (Path(__file__).resolve().parents[1] / "install/field-test-configs/nov-audit-factory-hw.local.json").read_text()
        )
        self.bundle = {
            "serial": "NOV-AUDIT-FACTORY-HW",
            "claim_code": "A1B2C3D4",
            "key_id": "novena-trial-v2",
            "key_b64": base64.b64encode(b"k" * 32).decode(),
        }

    def test_renders_valid_tls_claim_with_no_customer_data(self):
        config = render_config(self.quarantined, self.template, self.bundle, self.ca_certs, "mqtt.novenaplatform.com")
        self.assertEqual(config["deployment"]["mode"], "pilot")
        self.assertEqual(config["mqtt"]["port"], 8883)
        self.assertEqual(config["mqtt"]["tls"]["ca_certs"], str(self.ca_certs))
        self.assertNotIn("allow_insecure_private_mqtt", config["mqtt"])
        self.assertEqual(config["bootstrap_mqtt"]["password"], "A1B2C3D4")
        self.assertEqual(config["features"]["network_watchdog"]["mode"], "diagnostic")
        self.assertEqual(config["features"]["rpc"]["trusted_command_keys"]["novena-trial-v2"], self.bundle["key_b64"])
        self.assertEqual(config["features"]["remote_config"]["trusted_config_keys"]["novena-trial-v2"], self.bundle["key_b64"])
        self.assertEqual(config["connectors"], [])
        self.assertEqual(config["ota"], self.quarantined["ota"])
        self.assertEqual(config["hardware"], self.quarantined["hardware"])
        self.assertEqual(NovenaGateway.validate_config(config), [])

        config_path = self.path / "config.json"
        config_path.write_text(json.dumps(self.quarantined))
        config_path.chmod(0o640)
        install_config(config_path, config)
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(json.loads(config_path.read_text()), config)

    def test_rejects_serial_mismatch_and_non_quarantined_state(self):
        bundle = {**self.bundle, "serial": "OTHER"}
        with self.assertRaisesRegex(ValueError, "serial"):
            render_config(self.quarantined, self.template, bundle, self.ca_certs, "mqtt.novenaplatform.com")
        with self.assertRaisesRegex(ValueError, "locally reset"):
            render_config({**self.quarantined, "mqtt": {"mode": "operational"}}, self.template, self.bundle, self.ca_certs, "mqtt.novenaplatform.com")

    def test_rejects_malformed_bundle_and_host(self):
        with self.assertRaisesRegex(ValueError, "must be objects"):
            render_config(self.quarantined, self.template, [], self.ca_certs, "mqtt.novenaplatform.com")
        with self.assertRaisesRegex(ValueError, "Invalid MQTT host"):
            render_config(self.quarantined, self.template, self.bundle, self.ca_certs, "mqtt..novenaplatform.com")
