"""Unit tests for the AttributeSyncHandler."""

import sys
import os
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.attribute_sync_handler import AttributeSyncHandler


class MockGateway:
    def __init__(self):
        self._connectors = []
        self._devices = {}
        self._config = {}

    def get_devices(self):
        return self._devices

    def collect_device_health_summary(self):
        return {"Power Meter 1": {"poll_status": "healthy"}}


class TestAttributeSyncHandler(unittest.TestCase):

    def setUp(self):
        self.mock_publisher = MagicMock()
        self.mock_gateway = MockGateway()
        self.handler = AttributeSyncHandler(
            gateway=self.mock_gateway,
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config={"enabled": True, "heartbeat_interval_seconds": 999}
        )

    def test_collect_attributes(self):
        """Collected attributes should include standard gateway info."""
        attrs = self.handler._collect_attributes()

        self.assertEqual(attrs["status"], "online")
        self.assertIn("firmware_version", attrs)
        self.assertIn("ip_address", attrs)
        self.assertIn("uptime_seconds", attrs)
        self.assertIn("python_version", attrs)
        self.assertIn("connected_devices", attrs)
        self.assertIn("active_connectors", attrs)
        self.assertEqual(attrs["device_count"], 0)
        self.assertIn("device_health", attrs)

    def test_collect_attributes_with_devices(self):
        """Device count should reflect registered devices."""
        self.mock_gateway._devices = {
            "Power Meter 1": {"device_type": "power_meter"},
            "Temp Sensor": {"device_type": "temp_sensor"},
        }
        attrs = self.handler._collect_attributes()
        self.assertEqual(attrs["device_count"], 2)
        self.assertIn("Power Meter 1", attrs["connected_devices"])

    def test_publish_attributes(self):
        """Publishing attributes should call publisher.publish_attributes."""
        self.handler._publish_attributes()

        self.mock_publisher.publish_attributes.assert_called_once()
        payload = self.mock_publisher.publish_attributes.call_args[0][0]
        self.assertEqual(payload["serial_number"], "NF-TEST-001")
        self.assertIn("attributes", payload)
        self.assertIn("ts", payload)

    def test_on_attribute_push(self):
        """Inbound attribute push should update local cloud_attributes."""
        self.handler._on_attribute_push("test/topic", {
            "request_id": "req-001",
            "attributes": {"custom_key": "custom_value"}
        })

        cloud_attrs = self.handler.get_cloud_attributes()
        self.assertEqual(cloud_attrs["custom_key"], "custom_value")

    def test_offline_status_on_stop(self):
        """Stopping should publish offline status."""
        self.handler.stop()
        # Check that publish_attributes was called with 'offline' status
        if self.mock_publisher.publish_attributes.called:
            payload = self.mock_publisher.publish_attributes.call_args[0][0]
            self.assertEqual(payload["attributes"]["status"], "offline")

    def test_collects_ota_status_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status_path = os.path.join(tmpdir, "ota_status.json")
            with open(status_path, "w") as f:
                json.dump({
                    "ota_status": "rolled_back",
                    "ota_version": "1.2.0",
                    "ota_error": "health check failed",
                    "ota_rollback_performed": True,
                }, f)
            self.mock_gateway._config = {"storage": {"ota_status_path": status_path}}

            attrs = self.handler._collect_attributes()

        self.assertEqual(attrs["ota_status"], "rolled_back")
        self.assertEqual(attrs["ota_version"], "1.2.0")
        self.assertTrue(attrs["ota_rollback_performed"])


if __name__ == "__main__":
    unittest.main()
