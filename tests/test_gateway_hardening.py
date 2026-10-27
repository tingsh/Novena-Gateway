"""Hardening tests for deployment-readiness behavior."""

import os
import sys
import tempfile
import unittest
import datetime as real_datetime
import json
import base64
import uuid
from datetime import datetime, timedelta, timezone
from queue import SimpleQueue
from threading import Event, Lock
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.novena_gateway import NovenaGateway
from novena_gateway.gateway.novena_mqtt_publisher import NovenaMqttPublisher
from novena_gateway.gateway.deployment_setup import canonical_bytes
from novena_gateway.gateway.governed_commands import GovernedCommandGuard
from novena_gateway.gateway.redaction import redact_secrets, redact_text
from novena_gateway.storage.sqlite.database import Database


class TestGatewayHardening(unittest.TestCase):

    def test_release_removes_offline_sqlite_events(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sqlite") + os.sep
            with patch("novena_gateway.gateway.novena_mqtt_publisher.DATA_DIR", folder):
                publisher = NovenaMqttPublisher(
                    {"storage": {"data_file_path": path}}, serial_number="NF-RESET"
                )
                try:
                    publisher._storage.put(json.dumps({"topic": "old", "payload": {"value": 10}}))
                    publisher.clear_claim_buffer()
                    self.assertEqual(publisher._storage.len(), 0)
                    self.assertEqual(publisher._queue.qsize(), 0)
                finally:
                    publisher._storage.stop()

    def test_new_claim_clears_governed_control_policy_and_journal(self):
        with tempfile.TemporaryDirectory() as folder:
            policy_path = os.path.join(folder, "policy.json")
            journal_path = os.path.join(folder, "journal.json")
            guard = GovernedCommandGuard(
                serial_number="NF-RESET", gateway=MagicMock(),
                config={"command_policy_path": policy_path, "command_journal_path": journal_path},
            )
            guard.journal.write("old-command", {"device_id": "old-device", "sequence_number": 3})
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump({"old": "site policy"}, handle)
            guard._policy = {"old": "site policy"}

            guard.reset_for_new_claim()

            self.assertFalse(guard.policy_loaded)
            self.assertFalse(os.path.exists(policy_path))
            self.assertIsNone(guard.journal.get("old-command"))
            self.assertEqual(guard.journal.max_sequence("old-device"), 0)

    def test_signed_release_resets_before_ack_and_replay_is_idempotent(self):
        key = Ed25519PrivateKey.generate()
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with tempfile.TemporaryDirectory() as folder:
            config_path = os.path.join(folder, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump({"gateway": {"serial_number": "NF-RESET"}, "mqtt": {"claim_id": "old-claim"},
                           "connectors": [{"type": "modbus", "name": "Old site"}]}, handle)
            publisher = object.__new__(NovenaMqttPublisher)
            publisher._serial_number = "NF-RESET"
            publisher._config_path = config_path
            publisher._claim_id = "old-claim"
            publisher._trusted_release_keys = {"key-1": base64.b64encode(public_key).decode()}
            publisher._release_request_id = None
            publisher._release_in_progress = False
            publisher._qos = 1
            publisher._client = MagicMock()
            publisher._client.publish.return_value.rc = 0
            publisher.on_release = MagicMock()
            body = {
                "schema_version": 1, "action": "release", "request_id": str(uuid.uuid4()),
                "claim_id": "old-claim", "target": {"gateway_serial": "NF-RESET"},
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            }
            wire = {**body, "signing_key_id": "key-1", "signature": base64.b64encode(
                key.sign(canonical_bytes(body))).decode()}

            publisher._on_provision_message("v1/gateway/NF-RESET/provision", wire)
            publisher._on_provision_message("v1/gateway/NF-RESET/provision", wire)

            with open(config_path, encoding="utf-8") as handle:
                saved = json.load(handle)
            self.assertEqual(saved["connectors"], [])
            self.assertEqual(saved["mqtt"]["mode"], "release_pending")
            self.assertEqual(saved["mqtt"]["release_request_id"], body["request_id"])
            publisher.on_release.assert_called_once()
            self.assertEqual(publisher._client.publish.call_count, 2)
            publisher._client.publish.return_value.wait_for_publish.assert_not_called()

    def test_release_rejects_wrong_claim_and_tampering(self):
        key = Ed25519PrivateKey.generate()
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
        )
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._serial_number = "NF-RESET"
        publisher._claim_id = "current-claim"
        publisher._trusted_release_keys = {"key-1": base64.b64encode(public_key).decode()}
        publisher.on_release = MagicMock()
        publisher._client = MagicMock()
        body = {"schema_version": 1, "action": "release", "request_id": str(uuid.uuid4()),
                "claim_id": "old-claim", "target": {"gateway_serial": "NF-RESET"},
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
        wire = {**body, "signing_key_id": "key-1", "signature": base64.b64encode(key.sign(canonical_bytes(body))).decode()}

        publisher._on_provision_message("v1/gateway/NF-RESET/provision", wire)
        publisher._on_provision_message("v1/gateway/NF-RESET/provision", {**wire, "claim_id": "current-claim"})

        publisher.on_release.assert_not_called()
        publisher._client.publish.assert_not_called()

    def test_broker_revocation_erases_old_operational_credentials_before_reclaim(self):
        with tempfile.TemporaryDirectory() as folder:
            config_path = os.path.join(folder, "config.json")
            release_id = str(uuid.uuid4())
            config = {
                "gateway": {"serial_number": "NF-RESET"},
                "mqtt": {"username": "NF-RESET", "password": "old-site-secret", "mode": "release_pending",
                         "claim_id": "old-claim", "release_request_id": release_id},
                "bootstrap_mqtt": {"enabled": True, "username": "bootstrap:NF-RESET", "password": "factory-code"},
                "connectors": [],
            }
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(config, handle)
            with patch("novena_gateway.gateway.novena_mqtt_publisher.DATA_DIR", folder):
                publisher = NovenaMqttPublisher(
                    {**config["mqtt"], "bootstrap_mqtt": config["bootstrap_mqtt"],
                     "storage": {"data_file_path": os.path.join(folder, "sqlite") + os.sep}},
                    serial_number="NF-RESET", config_path=config_path,
                )
                publisher.on_release_revoked = MagicMock()
                publisher._reconnect_with_current_credentials = MagicMock()
                try:
                    publisher._on_connect(None, None, None, "Not authorized")
                    with open(config_path, encoding="utf-8") as handle:
                        saved = json.load(handle)
                    self.assertEqual(saved["mqtt"]["username"], "")
                    self.assertEqual(saved["mqtt"]["password"], "")
                    self.assertNotIn("claim_id", saved["mqtt"])
                    self.assertEqual(saved["mqtt"]["release_request_id"], release_id)
                    self.assertEqual(saved["bootstrap_mqtt"], config["bootstrap_mqtt"])
                    self.assertEqual(saved["connectors"], [])
                    publisher.on_release_revoked.assert_called_once_with(saved)
                    self.assertTrue(publisher._bootstrap_mode)
                    self.assertEqual(publisher._username, "bootstrap:NF-RESET")
                    self.assertEqual(publisher._password, "factory-code")
                    publisher._reconnect_with_current_credentials.assert_called_once()

                    restarted = NovenaMqttPublisher(
                        {**saved["mqtt"], "bootstrap_mqtt": saved["bootstrap_mqtt"],
                         "storage": {"data_file_path": os.path.join(folder, "sqlite") + os.sep}},
                        serial_number="NF-RESET", config_path=config_path,
                    )
                    self.assertTrue(restarted._bootstrap_mode)
                    self.assertEqual(restarted._username, "bootstrap:NF-RESET")
                    restarted._storage.stop()
                finally:
                    publisher._storage.stop()

    def test_connector_restart_drops_stale_device_references(self):
        gateway = object.__new__(NovenaGateway)
        old_connector = MagicMock()
        old_connector.get_name.return_value = "Modbus TCP Connector"
        gateway._connectors = [old_connector]
        gateway._devices = {"Cold Room": {"connector": old_connector}}

        gateway._stop_connectors()

        old_connector.close.assert_called_once_with()
        self.assertEqual(gateway._connectors, [])
        self.assertEqual(gateway._devices, {})

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
                    "connectors": [{"type": "modbus", "name": "Previous customer's meter"}],
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
            publisher._claim_id = "previous-claim"
            publisher.on_claim_changed = MagicMock()
            publisher.publish_attributes = MagicMock(return_value=True)
            publisher._reconnect_with_current_credentials = MagicMock()

            publisher._on_provision_message(
                "v1/gateway/NF-ACT/bootstrap/activate",
                {
                    "request_id": "activation-request",
                    "action": "activate",
                    "claim_id": "factory-claim",
                    "mqtt": {"username": "NF-ACT", "password": "operational-secret"},
                },
            )

            with open(config_path) as f:
                config = json.load(f)
            self.assertEqual(config["mqtt"]["username"], "NF-ACT")
            self.assertEqual(config["mqtt"]["password"], "operational-secret")
            self.assertEqual(config["mqtt"]["mode"], "operational")
            self.assertEqual(config["mqtt"]["claim_id"], "factory-claim")
            self.assertEqual(publisher._claim_id, "factory-claim")
            self.assertEqual(config["connectors"], [])
            publisher.on_claim_changed.assert_called_once_with(config)
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

    def test_replay_discards_previous_claim_events_without_publishing(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._claim_id = "factory-claim"
        publisher._stopped = False
        publisher._connected = True
        publisher._bootstrap_mode = False
        publisher._storage = MagicMock()
        publisher._storage.len.side_effect = [1, 0]
        publisher._storage.get_event_pack.return_value = [json.dumps({
            "topic": "v1/gateway/NF-ACT/logs",
            "payload": {"logs": [{"message": "old customer"}]},
            "claim_id": "cold-room-claim",
        })]
        publisher._client = MagicMock()
        publisher._qos = 1
        with patch("novena_gateway.gateway.novena_mqtt_publisher.sleep"):
            publisher._replay_loop()

        publisher._client.publish.assert_not_called()
        publisher._storage.event_pack_processing_done.assert_called_once_with()

    def test_bootstrap_connection_does_not_replay_offline_buffer(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._host = "broker"
        publisher._port = 1883
        publisher._bootstrap_mode = True
        publisher._last_error = None
        publisher._resubscribe_all = MagicMock()
        publisher._publish_bootstrap_hello = MagicMock()
        publisher._trigger_replay = MagicMock()
        publisher._on_connect(None, None, None, 0)
        publisher._publish_bootstrap_hello.assert_called_once_with()
        publisher._trigger_replay.assert_not_called()

    def test_bootstrap_hello_does_not_wait_inside_mqtt_callback(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._serial_number = "NF-ACT"
        publisher._qos = 1
        publisher._client = MagicMock()
        publisher._client.publish.return_value.rc = 0

        publisher._publish_bootstrap_hello()

        publisher._client.publish.assert_called_once()
        publisher._client.publish.return_value.wait_for_publish.assert_not_called()

    def test_new_claim_stops_old_connector_and_clears_pending_samples(self):
        gateway = object.__new__(NovenaGateway)
        gateway._field_claim_lock = Lock()
        gateway._connectors = [MagicMock()]
        gateway._devices = {"Previous device": {}}
        gateway._device_health = {"Previous device": {}}
        gateway._data_queue = SimpleQueue()
        gateway._data_queue.put(("old", object()))
        gateway._remote_config = MagicMock()
        gateway._rpc_handler = MagicMock()
        config = {"connectors": []}

        gateway._reset_field_state_for_new_claim(config)

        self.assertEqual(gateway._connectors, [])
        self.assertEqual(gateway._devices, {})
        self.assertEqual(gateway._device_health, {})
        self.assertTrue(gateway._data_queue.empty())
        self.assertIs(gateway._config, config)
        gateway._remote_config.reset_for_new_claim.assert_called_once_with(config)
        gateway._rpc_handler._governance.reset_for_new_claim.assert_called_once_with()

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

    @patch("novena_gateway.gateway.novena_mqtt_publisher.SQLiteEventStorage")
    @patch("novena_gateway.gateway.novena_mqtt_publisher.mqtt.Client")
    def test_configured_telemetry_topic_cannot_override_serial_scope(self, mock_client, _storage):
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

    def test_offline_shutdown_signals_mqtt_disconnect_before_waiting_for_loop(self):
        publisher = object.__new__(NovenaMqttPublisher)
        publisher._client = MagicMock()
        publisher._storage = MagicMock()
        publisher._storage_stop_event = Event()
        publisher._flush_queue = MagicMock()
        publisher._client.loop_stop.side_effect = lambda: self.assertTrue(publisher._client.disconnect.called)

        publisher.disconnect()

        self.assertTrue(publisher._storage_stop_event.is_set())
        publisher._storage.stop.assert_called_once()
        publisher._client.disconnect.assert_called_once()
        publisher._client.loop_stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
