"""Hardening tests for deployment-readiness behavior."""

import os
import sys
import tempfile
import unittest
import datetime as real_datetime
from queue import SimpleQueue
from threading import Event
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.novena_gateway import NovenaGateway
from novena_gateway.gateway.redaction import redact_secrets, redact_text
from novena_gateway.storage.sqlite.database import Database


class TestGatewayHardening(unittest.TestCase):

    def _pilot_config(self, ca_path):
        return {
            "deployment": {"mode": "pilot"},
            "gateway": {"serial_number": "NF-TEST"},
            "mqtt": {
                "host": "broker.example.com",
                "port": 8883,
                "username": "NF-TEST",
                "password": "claim",
                "tls": {"mode": "one-way", "ca_certs": ca_path},
            },
            "connectors": [],
        }

    def test_pilot_requires_tls_unless_explicit_private_override(self):
        config = {
            "deployment": {"mode": "pilot"},
            "gateway": {"serial_number": "NF-TEST"},
            "mqtt": {"host": "broker", "port": 1883, "username": "NF-TEST", "password": "claim"},
            "connectors": [],
        }

        errors = NovenaGateway.validate_config(config)

        self.assertTrue(any("mqtt.tls" in error for error in errors))

        config["mqtt"]["allow_insecure_private_mqtt"] = True
        errors = NovenaGateway.validate_config(config)
        self.assertFalse(any("mqtt.tls" in error for error in errors))

    def test_empty_connector_list_is_valid_for_plug_and_play(self):
        with tempfile.NamedTemporaryFile() as ca:
            config = self._pilot_config(ca.name)

            errors = NovenaGateway.validate_config(config)

        self.assertEqual(errors, [])

    def test_required_connector_failure_policy(self):
        gateway = object.__new__(NovenaGateway)
        gateway._config = {
            "deployment": {"mode": "pilot"},
            "connectors": [
                {"type": "modbus", "name": "Required Modbus", "config": {}},
                {"type": "mqtt", "name": "Optional MQTT", "required": False, "config": {}},
            ],
        }
        gateway._connector_start_results = [
            {"name": "Required Modbus", "status": "error", "error": "boom"},
            {"name": "Optional MQTT", "status": "error", "error": "offline"},
        ]

        failures = gateway._required_connector_failures()

        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["name"], "Required Modbus")

    def test_runtime_attributes_include_pressure_and_connector_results(self):
        gateway = object.__new__(NovenaGateway)
        gateway._config = {"deployment": {"mode": "local"}, "connectors": []}
        gateway._connector_start_results = [{"name": "Modbus", "status": "success"}]
        gateway._startup_status = "ready"
        gateway._startup_error = None
        gateway._data_queue = SimpleQueue()
        gateway._data_queue.put(("connector", object()))

        attrs = gateway.collect_runtime_attributes()

        self.assertEqual(attrs["startup_status"], "ready")
        self.assertEqual(attrs["data_queue_size"], 1)
        self.assertEqual(attrs["connector_start_results"][0]["status"], "success")

    def test_redaction_helpers_preserve_shape(self):
        config = {"mqtt": {"password": "secret", "username": "NF"}, "token": "abc"}

        redacted = redact_secrets(config)

        self.assertEqual(redacted["mqtt"]["password"], "[REDACTED]")
        self.assertEqual(redacted["mqtt"]["username"], "NF")
        self.assertEqual(redacted["token"], "[REDACTED]")
        self.assertIn("[REDACTED]", redact_text("password=secret token:abc"))

    def test_sqlite_ttl_uses_millisecond_cutoff(self):
        database = object.__new__(Database)
        database.database_stopped_event = Event()
        database.db = MagicMock()
        database.db.execute_write.return_value = object()
        database._Database__log = MagicMock()

        with patch("novena_gateway.storage.sqlite.database.datetime") as mock_datetime:
            mock_datetime.datetime.now.return_value = real_datetime.datetime(2026, 1, 8)
            mock_datetime.timedelta.side_effect = lambda days: real_datetime.timedelta(days=days)
            database.delete_data_lte(7)

        cutoff = database.db.execute_write.call_args[0][1][0]
        self.assertGreater(cutoff, 1_000_000_000_000)


if __name__ == "__main__":
    unittest.main()
