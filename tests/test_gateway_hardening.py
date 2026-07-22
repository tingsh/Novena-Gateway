"""Hardening tests for deployment-readiness behavior."""

import os
import sys
import tempfile
import unittest
import datetime as real_datetime
import json
from queue import SimpleQueue
from threading import Event
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.novena_gateway import NovenaGateway
from novena_gateway.gateway.novena_mqtt_publisher import NovenaMqttPublisher
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

    def test_activation_payload_writes_config_and_publishes_ack_before_reconnect(self):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as config_file:
            json.dump(
                {
                    "gateway": {"serial_number": "NF-ACT"},
                    "mqtt": {"username": "bootstrap:NF-ACT", "password": "claim"},
                    "connectors": [],
                },
                config_file,
            )
            config_path = config_file.name

        try:
            publisher = object.__new__(NovenaMqttPublisher)
            publisher._serial_number = "NF-ACT"
            publisher._config_path = config_path
            publisher._username = "bootstrap:NF-ACT"
            publisher._password = "claim"
            publisher._bootstrap_mode = True
            publisher.publish_attributes = MagicMock(return_value=True)
            publisher._reconnect_with_current_credentials = MagicMock()

            publisher._on_provision_message(
                "v1/gateway/NF-ACT/bootstrap/activate",
                {
                    "request_id": "activation-request",
                    "action": "activate",
                    "mqtt": {"username": "NF-ACT", "password": "operational-secret"},
                },
            )

            with open(config_path) as f:
                config = json.load(f)
            self.assertEqual(config["mqtt"]["username"], "NF-ACT")
            self.assertEqual(config["mqtt"]["password"], "operational-secret")
            self.assertEqual(config["mqtt"]["mode"], "operational")
            self.assertFalse(publisher._bootstrap_mode)
            publisher.publish_attributes.assert_called_once()
            ack, kwargs = publisher.publish_attributes.call_args
            self.assertTrue(kwargs["immediate"])
            self.assertEqual(ack[0]["attributes"]["credential_update_status"], "success")
            self.assertEqual(ack[0]["attributes"]["credential_update_action"], "activate")
            self.assertEqual(ack[0]["attributes"]["credential_update_request_id"], "activation-request")
            publisher._reconnect_with_current_credentials.assert_called_once()
        finally:
            os.unlink(config_path)

    def test_activation_payload_missing_password_reports_failed_ack(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._serial_number = "NF-ACT-MISSING"
        publisher.publish_attributes = MagicMock(return_value=True)

        publisher._on_provision_message(
            "v1/gateway/NF-ACT-MISSING/bootstrap/activate",
            {"request_id": "activation-request", "action": "activate", "mqtt": {"username": "NF-ACT-MISSING"}},
        )

        ack, kwargs = publisher.publish_attributes.call_args
        self.assertTrue(kwargs["immediate"])
        self.assertEqual(ack[0]["attributes"]["credential_update_status"], "failed")
        self.assertEqual(ack[0]["attributes"]["credential_update_error"], "missing password")

    def test_publish_helpers_use_serial_scoped_inbound_topics(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._serial_number = "NF-SCOPED"
        publisher._telemetry_topic = publisher._scoped_topic("telemetry", legacy_fallback="v1/gateway/telemetry")
        publisher.publish = MagicMock()
        publisher.publish_now = MagicMock(return_value=True)

        publisher.publish_telemetry({"kind": "telemetry"})
        publisher.publish_attributes({"kind": "attributes"})
        publisher.publish_logs({"kind": "logs"})
        publisher.publish_rpc_response({"kind": "rpc"})
        publisher.publish_attributes({"kind": "immediate"}, immediate=True)

        self.assertEqual(
            publisher.publish.call_args_list[0].args,
            ({"kind": "telemetry"}, "v1/gateway/NF-SCOPED/telemetry"),
        )
        self.assertEqual(
            publisher.publish.call_args_list[1].args,
            ({"kind": "attributes"}, "v1/gateway/NF-SCOPED/attributes"),
        )
        self.assertEqual(
            publisher.publish.call_args_list[2].args,
            ({"kind": "logs"}, "v1/gateway/NF-SCOPED/logs"),
        )
        self.assertEqual(
            publisher.publish.call_args_list[3].args,
            ({"kind": "rpc"}, "v1/gateway/NF-SCOPED/rpc/response"),
        )
        publisher.publish_now.assert_called_once_with({"kind": "immediate"}, "v1/gateway/NF-SCOPED/attributes")

    @patch("novena_gateway.gateway.novena_mqtt_publisher.mqtt.Client")
    def test_configured_telemetry_topic_cannot_override_serial_scope(self, mock_client):
        publisher = NovenaMqttPublisher(
            {
                "host": "localhost",
                "port": 1883,
                "topic": "v1/gateway/OTHER-GATEWAY/telemetry",
            },
            serial_number="NF-SERIAL-SOURCE",
        )

        self.assertEqual(publisher._telemetry_topic, "v1/gateway/NF-SERIAL-SOURCE/telemetry")

    def test_lwt_uses_serial_scoped_attributes_topic(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._serial_number = "NF-LWT"
        publisher._client = MagicMock()

        publisher._configure_lwt()

        publisher._client.will_set.assert_called_once()
        self.assertEqual(
            publisher._client.will_set.call_args.kwargs["topic"],
            "v1/gateway/NF-LWT/attributes",
        )


if __name__ == "__main__":
    unittest.main()
