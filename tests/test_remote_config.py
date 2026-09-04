"""Unit tests for the RemoteConfigHandler."""

import sys
import os
import json
import unittest
import tempfile
import shutil
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.remote_config_handler import RemoteConfigHandler


class MockGateway:
    def __init__(self, config=None):
        self._connectors = []
        self._config = config or {"gateway": {}, "mqtt": {}, "connectors": []}

    def _stop_connectors(self):
        self._connectors.clear()

    def _start_connectors(self):
        pass

    @staticmethod
    def validate_config(config):
        errors = []
        if "gateway" not in config:
            errors.append("gateway")
        if "mqtt" not in config:
            errors.append("mqtt")
        return errors


class FailingStartGateway(MockGateway):
    def _start_connectors(self):
        return [
            {
                "name": "Broken Modbus",
                "type": "modbus",
                "status": "error",
                "error": "failed to start connector",
            }
        ]


class TestRemoteConfigHandler(unittest.TestCase):

    def setUp(self):
        self.mock_publisher = MagicMock()
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, "config.json")
        self.backup_dir = os.path.join(self.test_dir, "backups")
        self.journal_path = os.path.join(self.test_dir, "deployment_setup", "config_journal.json")

        # Write initial config
        self.initial_config = {
            "gateway": {"serial_number": "NF-TEST"},
            "mqtt": {"host": "localhost", "port": 1883},
            "connectors": [
                {"type": "modbus", "name": "Modbus Conn", "config": {"key": "val"}}
            ]
        }
        with open(self.config_path, 'w') as f:
            json.dump(self.initial_config, f)

        self.mock_gateway = MockGateway(config=dict(self.initial_config))
        self.handler = RemoteConfigHandler(
            gateway=self.mock_gateway,
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config_path=self.config_path,
            config={
                "enabled": True,
                "backup_dir": self.backup_dir,
                "config_journal_path": self.journal_path,
            }
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_full_update_writes_config(self):
        """full_update should write new config to disk."""
        new_config = {
            "gateway": {"serial_number": "NF-NEW"},
            "mqtt": {"host": "newhost", "port": 1883},
            "connectors": []
        }
        self.handler._apply_full_update(new_config)

        # Read back from disk
        with open(self.config_path) as f:
            written = json.load(f)
        self.assertEqual(written["gateway"]["serial_number"], "NF-NEW")

    def test_full_update_creates_backup(self):
        """full_update should create a backup file."""
        new_config = {
            "gateway": {"serial_number": "NF-NEW"},
            "mqtt": {"host": "localhost"},
            "connectors": []
        }
        self.handler._apply_full_update(new_config)

        backups = os.listdir(self.backup_dir)
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].startswith("config_backup_"))

    def test_connector_update(self):
        """connector_update should replace an existing connector's config."""
        updated = {"type": "modbus", "name": "Modbus Conn", "config": {"key": "new_val"}}
        self.handler._apply_connector_update(updated)

        with open(self.config_path) as f:
            config = json.load(f)
        self.assertEqual(config["connectors"][0]["config"]["key"], "new_val")

    def test_connector_update_replaces_connector_list(self):
        """connector_update should accept Cloud-generated connector lists."""
        updated = {
            "connectors": [
                {"type": "modbus", "name": "Modbus TCP Connector", "config": {"master": {"slaves": []}}}
            ]
        }
        self.handler._apply_connector_update(updated)

        with open(self.config_path) as f:
            config = json.load(f)
        self.assertEqual(len(config["connectors"]), 1)
        self.assertEqual(config["connectors"][0]["name"], "Modbus TCP Connector")
        self.assertEqual(config["connectors"][0]["type"], "modbus")

    def test_connector_add(self):
        """connector_add should append a new connector."""
        new_conn = {"type": "opcua", "name": "OPC-UA Conn", "config": {}}
        self.handler._apply_connector_add(new_conn)

        with open(self.config_path) as f:
            config = json.load(f)
        self.assertEqual(len(config["connectors"]), 2)
        self.assertEqual(config["connectors"][1]["name"], "OPC-UA Conn")

    def test_connector_add_duplicate_raises(self):
        """Adding a duplicate connector name should raise."""
        dup = {"type": "modbus", "name": "Modbus Conn", "config": {}}
        with self.assertRaises(ValueError):
            self.handler._apply_connector_add(dup)

    def test_connector_remove(self):
        """connector_remove should delete a connector."""
        self.handler._apply_connector_remove({"name": "Modbus Conn"})

        with open(self.config_path) as f:
            config = json.load(f)
        self.assertEqual(len(config["connectors"]), 0)

    def test_connector_remove_not_found_raises(self):
        """Removing a non-existent connector should raise."""
        with self.assertRaises(ValueError):
            self.handler._apply_connector_remove({"name": "Ghost Conn"})

    def test_unsigned_config_update_is_rejected(self):
        """Remote config never falls back to an unsigned payload."""
        self.handler._on_config_update("test/topic", {
            "request_id": "req-001",
            "action": "full_update",
            "config": {
                "gateway": {"serial_number": "NF-ACK"},
                "mqtt": {"host": "localhost"},
                "connectors": []
            }
        })

        self.mock_publisher.publish_attributes.assert_called()
        payload = self.mock_publisher.publish_attributes.call_args[0][0]
        self.assertEqual(payload["attributes"]["config_update_status"], "failed")
        self.assertEqual(payload["attributes"]["config_update_request_id"], "req-001")
        self.assertEqual(payload["attributes"]["config_update_error_code"], "config_rejected")
        self.assertFalse(payload["attributes"]["rollback_performed"])
        self.assertIn("connector_results", payload["attributes"])

    def test_full_update_missing_gateway_raises(self):
        """Config without 'gateway' section should fail validation."""
        self.handler._on_config_update("test/topic", {
            "request_id": "req-002",
            "action": "full_update",
            "config": {"mqtt": {}, "connectors": []}
        })

        payload = self.mock_publisher.publish_attributes.call_args[0][0]
        self.assertEqual(payload["attributes"]["config_update_status"], "failed")

    def test_connector_start_failure_rolls_back(self):
        failing_gateway = FailingStartGateway(config=dict(self.initial_config))
        handler = RemoteConfigHandler(
            gateway=failing_gateway,
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config_path=self.config_path,
            config={
                "enabled": True,
                "backup_dir": self.backup_dir,
                "config_journal_path": self.journal_path,
            }
        )

        result = handler._apply_full_update(
            {
                "gateway": {"serial_number": "NF-BAD"},
                "mqtt": {"host": "localhost", "port": 1883},
                "connectors": [
                    {"type": "modbus", "name": "Broken Modbus", "config": {}}
                ],
            }
        )

        with open(self.config_path) as f:
            written = json.load(f)
        self.assertEqual(written["gateway"]["serial_number"], "NF-TEST")

        self.assertEqual(result["config_update_status"], "rolled_back")
        self.assertTrue(result["rollback_performed"])
        self.assertEqual(result["connector_results"][0]["status"], "error")
        self.assertEqual(
            result["rollback_connector_results"][0]["status"],
            "error",
        )

    def test_get_status_returns_last_update_result(self):
        result = self.handler._apply_full_update({
            "gateway": {"serial_number": "NF-NEW"},
            "mqtt": {"host": "localhost", "port": 1883},
            "connectors": []
        })

        status = self.handler.get_status()

        self.assertEqual(result["config_update_status"], "success")
        self.assertEqual(status["config_update_status"], "success")
        self.assertEqual(status["active_connector_count"], 0)

    def test_backup_pruning(self):
        """Only MAX_BACKUPS should be kept."""
        os.makedirs(self.backup_dir, exist_ok=True)
        # Create 12 fake backups
        for i in range(12):
            with open(os.path.join(self.backup_dir, f"config_backup_{1000+i}.json"), 'w') as f:
                f.write("{}")

        self.handler._prune_backups()
        backups = os.listdir(self.backup_dir)
        self.assertLessEqual(len(backups), 10)


if __name__ == "__main__":
    unittest.main()
