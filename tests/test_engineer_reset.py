"""Field reset must remove old customer state and fail closed on reboot."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from novena_gateway.engineer_reset import reset_local_state
from novena_gateway.gateway.novena_gateway import NovenaGateway


class EngineerResetTests(unittest.TestCase):
    def test_reset_scrubs_credentials_config_and_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_dir = root / "etc"
            config_dir.mkdir()
            config = config_dir / "config.json"
            data = root / "data"
            logs = root / "logs"
            (data / "sqlite").mkdir(parents=True)
            logs.mkdir()
            (data / "sqlite" / "old.db").write_text("old readings")
            (logs / "old.log").write_text("old customer secret")
            (config_dir / "config.json.old").write_text("old customer credentials")
            (config_dir / "trust").mkdir()
            (config_dir / "trust" / "ota.pub").write_text("vendor public key")
            config.write_text(json.dumps({
                "gateway": {"serial_number": "NF-RESET"},
                "deployment": {"mode": "pilot"},
                "mqtt": {"host": "old-broker", "port": 8883, "username": "old", "password": "secret", "claim_id": "old"},
                "bootstrap_mqtt": {"enabled": True, "password": "sticker"},
                "connectors": [{"name": "Old customer's meter", "password": "site-secret"}],
                "ota": {"public_key_path": str(config_dir / "trust" / "ota.pub")},
                "hardware": {"can": {"interface": "can0"}},
            }))

            with self.assertRaises(ValueError):
                reset_local_state(config, data, logs, "WRONG-SERIAL")
            self.assertTrue((data / "sqlite" / "old.db").exists())

            reset_local_state(config, data, logs, "NF-RESET")
            clean = json.loads(config.read_text())
            self.assertEqual(clean["gateway"]["serial_number"], "NF-RESET")
            self.assertEqual(clean["ota"]["public_key_path"], str(config_dir / "trust" / "ota.pub"))
            self.assertEqual((config_dir / "trust" / "ota.pub").read_text(), "vendor public key")
            self.assertEqual(clean["hardware"]["can"]["interface"], "can0")
            self.assertEqual(clean["connectors"], [])
            self.assertFalse(clean["bootstrap_mqtt"]["enabled"])
            self.assertNotIn("secret", config.read_text())
            self.assertFalse((data / "sqlite" / "old.db").exists())
            self.assertFalse((logs / "old.log").exists())
            self.assertFalse((config_dir / "config.json.old").exists())
            self.assertIn("locally reset", NovenaGateway.validate_config(clean)[0])

    def test_refuses_symlink_state_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "config.json"
            config.write_text('{"gateway": {"serial_number": "NF-RESET"}}')
            real_data = root / "real"
            real_data.mkdir()
            (root / "data").symlink_to(real_data, target_is_directory=True)
            with self.assertRaises(ValueError):
                reset_local_state(config, root / "data", root / "logs", "NF-RESET")

    def test_preserves_default_ota_trust_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config_dir = root / "etc"
            trust_dir = config_dir / "trust"
            trust_dir.mkdir(parents=True)
            key = trust_dir / "ota_vendor_ed25519.pub"
            key.write_text("manufacturer public key")
            config = config_dir / "config.json"
            config.write_text('{"gateway": {"serial_number": "NF-RESET"}}')
            with patch("novena_gateway.engineer_reset.DEFAULT_OTA_PUBLIC_KEY_PATH", str(key)):
                reset_local_state(config, root / "data", root / "logs", "NF-RESET")
            self.assertEqual(key.read_text(), "manufacturer public key")
