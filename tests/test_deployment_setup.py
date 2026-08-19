"""Guided setup security, discovery-safety, and compatibility tests."""

from __future__ import annotations

import base64
import json
import os
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pymodbus.constants import Endian

from novena_gateway.connectors.modbus.bytes_modbus_uplink_converter import BytesModbusUplinkConverter
from novena_gateway.gateway.deployment_setup import canonical_bytes, checksum
from novena_gateway.gateway.discovery_service import DiscoveryService
from novena_gateway.gateway.governed_commands import (
    GovernedCommandGuard,
    GovernedCommandRejected,
)
from novena_gateway.gateway.remote_config_handler import RemoteConfigHandler
from novena_gateway.gateway.redaction import redact_diagnostics


class CountingGateway:
    def __init__(self, config):
        self._config = config
        self._connectors = []
        self.start_count = 0

    def _stop_connectors(self):
        self._connectors.clear()

    def _start_connectors(self):
        self.start_count += 1
        return []

    @staticmethod
    def validate_config(config):
        return [] if {"gateway", "mqtt", "connectors"} <= set(config) else ["invalid"]


class SignedConfigEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.directory.name, "config.json")
        self.initial = {
            "gateway": {"serial_number": "NF-GUIDED"},
            "mqtt": {"host": "localhost", "port": 1883},
            "connectors": [],
        }
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(self.initial, handle)
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.publisher = MagicMock()
        self.gateway = CountingGateway(dict(self.initial))
        self.handler = RemoteConfigHandler(
            gateway=self.gateway,
            publisher=self.publisher,
            serial_number="NF-GUIDED",
            config_path=self.config_path,
            config={
                "enabled": True,
                "trusted_clock": True,
                "trusted_config_keys": {"setup-key": base64.b64encode(public_key).decode()},
                "config_journal_path": os.path.join(self.directory.name, "config-journal.json"),
                "last_known_good_path": os.path.join(self.directory.name, "last-good.json"),
            },
        )

    def tearDown(self):
        self.directory.cleanup()

    def envelope(self, *, revision=1, idempotency_key="setup-1", target="NF-GUIDED"):
        config = {"connectors": []}
        body = {
            "schema_version": 1,
            "request_id": f"request-{revision}",
            "idempotency_key": idempotency_key,
            "target": {"gateway_serial": target},
            "revision": revision,
            "checksum": checksum(config),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "action": "connector_update",
            "config": config,
        }
        signature = self.private_key.sign(canonical_bytes(body))
        return {
            **body,
            "signing_key_id": "setup-key",
            "signature": base64.b64encode(signature).decode(),
        }

    def test_signed_config_is_accepted_and_applied(self):
        self.handler._on_config_update("topic", self.envelope())

        calls = self.publisher.publish_attributes.call_args_list
        self.assertEqual(calls[0].args[0]["attributes"]["config_update_status"], "accepted")
        self.assertEqual(calls[-1].args[0]["attributes"]["config_update_status"], "success")
        self.assertEqual(calls[-1].args[0]["attributes"]["config_revision"], 1)
        self.assertEqual(self.gateway.start_count, 1)

    def test_duplicate_idempotency_key_replays_result_without_reapplying(self):
        envelope = self.envelope()
        self.handler._on_config_update("topic", envelope)
        self.handler._on_config_update("topic", envelope)

        last = self.publisher.publish_attributes.call_args.args[0]["attributes"]
        self.assertTrue(last["config_replayed"])
        self.assertEqual(last["config_update_status"], "success")
        self.assertEqual(self.gateway.start_count, 1)

    def test_stale_revision_and_wrong_gateway_are_rejected(self):
        self.handler._on_config_update("topic", self.envelope(revision=2, idempotency_key="setup-2"))
        self.handler._on_config_update("topic", self.envelope(revision=1, idempotency_key="setup-stale"))
        stale = self.publisher.publish_attributes.call_args.args[0]["attributes"]
        self.assertEqual(stale["config_update_status"], "failed")
        self.assertIn("stale", stale["config_update_error"].lower())

        self.handler._on_config_update(
            "topic",
            self.envelope(revision=3, idempotency_key="wrong-target", target="NF-OTHER"),
        )
        wrong = self.publisher.publish_attributes.call_args.args[0]["attributes"]
        self.assertEqual(wrong["config_update_status"], "failed")
        self.assertIn("different Gateway", wrong["config_update_error"])

    def test_unsigned_payload_is_rejected_without_applying(self):
        self.handler._on_config_update(
            "topic",
            {
                "request_id": "legacy",
                "action": "connector_update",
                "config": {"connectors": []},
            },
        )
        last = self.publisher.publish_attributes.call_args.args[0]["attributes"]
        self.assertEqual(last["config_update_status"], "failed")
        self.assertEqual(last["config_update_error_code"], "config_rejected")
        self.assertEqual(self.gateway.start_count, 0)


class SafeDiscoveryTargetTest(unittest.TestCase):
    def setUp(self):
        self.service = DiscoveryService(
            gateway=MagicMock(),
            publisher=MagicMock(),
            serial_number="NF-GUIDED",
            config={"enabled": True, "tcp_subnet_scan": False},
        )

    def test_guided_tcp_targets_are_explicit_and_bounded(self):
        self.assertEqual(
            self.service._approved_tcp_targets(["192.168.1.50:502"]),
            [("192.168.1.50", 502)],
        )
        with self.assertRaises(ValueError):
            self.service._approved_tcp_targets(["not-an-ip"])
        with self.assertRaises(ValueError):
            self.service._approved_tcp_targets(["224.0.0.1"])
        with self.assertRaises(ValueError):
            self.service._approved_tcp_targets(["192.168.1.50:70000"])

    def test_on_demand_is_enabled_without_background_threads_by_default(self):
        self.service.start()
        self.assertIsNone(self.service._scan_thread)
        self.assertIsNone(self.service._periodic_thread)

    @patch("novena_gateway.gateway.discovery_service.os.path.exists", return_value=True)
    @patch("novena_gateway.gateway.discovery_service.subprocess.check_output")
    def test_attached_network_scan_is_private_physical_and_bounded(self, check_output, _exists):
        check_output.return_value = json.dumps(
            [
                {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "10.0.0.10", "prefixlen": 16}]},
                {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16}]},
                {"ifname": "eth1", "addr_info": [{"family": "inet", "local": "8.8.8.8", "prefixlen": 24}]},
                {"ifname": "wwan0", "addr_info": [{"family": "inet", "local": "10.20.30.40", "prefixlen": 24}]},
            ]
        )

        interfaces = self.service._enumerate_private_network_interfaces()
        targets = self.service._targets_for_network_interfaces(interfaces)

        self.assertEqual([item["name"] for item in interfaces], ["eth0"])
        self.assertEqual(len(targets), 253)
        self.assertIn(("10.0.0.20", 502), targets)
        self.assertNotIn(("10.0.0.10", 502), targets)

    def test_attached_network_scan_does_not_escape_smaller_subnet(self):
        targets = self.service._targets_for_network_interfaces(
            [{"name": "eth0", "address": "10.0.0.9", "prefixlen": 30}]
        )

        self.assertEqual(targets, [("10.0.0.10", 502)])

    def test_duplicate_terminal_scan_republishes_without_restarting(self):
        report = {"scan_id": "scan-1", "status": "complete", "discovered_devices": []}
        self.service._reports_by_scan_id["scan-1"] = report

        result = self.service.start_guided_scan({"scan_id": "scan-1", "scope": "attached_interfaces"})

        self.assertEqual(result["status"], "replayed")
        self.service._publisher.publish_attributes.assert_called_once()

    def test_cancel_must_match_active_scan(self):
        self.service._active_scan_id = "scan-1"
        with self.assertRaisesRegex(ValueError, "not active"):
            self.service.cancel_current_scan("scan-2")

    def test_duplicate_active_scan_is_idempotent_and_concurrent_scan_is_rejected(self):
        self.service._active_scan_id = "scan-1"
        self.service._scan_lock.acquire()
        try:
            duplicate = self.service.start_guided_scan({"scan_id": "scan-1"})
            self.assertEqual(duplicate["status"], "running")
            with self.assertRaisesRegex(RuntimeError, "already running"):
                self.service.start_guided_scan({"scan_id": "scan-2"})
        finally:
            self.service._scan_lock.release()

    @patch.object(DiscoveryService, "_inventory_non_modbus_interfaces", return_value=[])
    @patch.object(DiscoveryService, "_enumerate_serial_ports", return_value=[])
    @patch.object(DiscoveryService, "_targets_for_network_interfaces")
    @patch.object(DiscoveryService, "_enumerate_private_network_interfaces")
    @patch.object(DiscoveryService, "_scan_tcp_network", return_value=[])
    def test_configured_tcp_endpoint_is_skipped_without_polling(
        self, scan_tcp, enumerate_network, network_targets, _serial, _inventory
    ):
        service = DiscoveryService(
            gateway=MagicMock(
                _config={
                    "connectors": [
                        {
                            "config": {
                                "master": {
                                    "slaves": [
                                        {"type": "tcp", "host": "10.0.0.20", "port": 502}
                                    ]
                                }
                            }
                        }
                    ]
                }
            ),
            publisher=MagicMock(),
            serial_number="NF-GUIDED",
            config={"enabled": True},
        )
        enumerate_network.return_value = [{"name": "eth0", "address": "10.0.0.10", "prefixlen": 24}]
        network_targets.return_value = [("10.0.0.20", 502), ("10.0.0.21", 502)]

        report = service.scan(options={"scan_id": "scan-1", "scope": "attached_interfaces"})

        self.assertEqual(scan_tcp.call_args.kwargs["approved_targets"], [("10.0.0.21", 502)])
        self.assertEqual(report["skipped_configured"][0]["interface"], "10.0.0.20:502")
        self.assertEqual(report["status"], "complete")
        self.assertIn("completed_at", report)

    @patch.object(DiscoveryService, "_enumerate_serial_ports", return_value=[])
    @patch.object(DiscoveryService, "_scan_tcp_network", return_value=[])
    def test_guided_scan_passes_only_approved_targets(self, scan_tcp, _serial):
        self.service.scan(
            scan_type="guided",
            options={"tcp_hosts": [{"host": "192.168.1.50", "port": 502}]},
        )

        scan_tcp.assert_called_once()
        self.assertEqual(
            scan_tcp.call_args.kwargs["approved_targets"],
            [("192.168.1.50", 502)],
        )
        self.assertTrue(callable(scan_tcp.call_args.kwargs["progress_callback"]))

    def test_validation_decodes_type_scale_and_assesses_plausibility(self):
        encoded = struct.pack(">f", 230.5)
        words = [
            int.from_bytes(encoded[0:2], byteorder="big"),
            int.from_bytes(encoded[2:4], byteorder="big"),
        ]
        value = self.service._decode_validation_value(
            words,
            {
                "data_type": "float32",
                "scale": 1,
                "quality": {"min": 200, "max": 260},
            },
            {"byteOrder": "BIG", "wordOrder": "BIG"},
        )
        self.assertAlmostEqual(value, 230.5)

        warning, blocking = self.service._validation_value_assessment(
            1000,
            {"quality": {"max": 500}},
            validation_profile="site_defined",
        )
        self.assertTrue(blocking)
        self.assertIn("safety maximum", warning)

        warning, blocking = self.service._validation_value_assessment(
            9000,
            {"key": "temperature", "unit": "°C"},
            validation_profile="site_defined",
        )
        self.assertTrue(blocking)
        self.assertIn("physically plausible", warning)

    def test_site_defined_impossible_values_and_normal_warnings(self):
        cases = [
            (101, {"key": "humidity", "unit": "%"}),
            (1.2, {"key": "power_factor"}),
            (-1, {"key": "absolute_pressure", "unit": "bar"}),
        ]
        for value, datapoint in cases:
            with self.subTest(value=value, datapoint=datapoint):
                warning, blocking = self.service._validation_value_assessment(
                    value,
                    datapoint,
                    validation_profile="site_defined",
                )
                self.assertTrue(blocking)
                self.assertTrue(warning)

        warning, blocking = self.service._validation_value_assessment(
            85,
            {"key": "temperature", "unit": "°C", "normal": {"min": 20, "max": 80}},
            validation_profile="site_defined",
        )
        self.assertFalse(blocking)
        self.assertIn("normal maximum", warning)

        warning, blocking = self.service._validation_value_assessment(
            -0.5,
            {"key": "gauge_pressure", "unit": "bar"},
            validation_profile="site_defined",
        )
        self.assertFalse(blocking)
        self.assertFalse(warning)

    @patch("pymodbus.client.ModbusTcpClient")
    def test_advisory_signal_warning_preserves_raw_and_decoded_values(self, client_class):
        client = client_class.return_value
        client.connect.return_value = True
        response = MagicMock()
        response.isError.return_value = False
        response.registers = [85]
        response.bits = None
        client.read_holding_registers.return_value = response

        result = self.service.validate_modbus(
            {
                "protocol": "modbus_tcp",
                "connection": {"host": "192.168.1.50", "port": 502, "slave_id": 1},
                "validation_profile": "site_defined",
                "mapping_checksum": "map-checksum",
                "datapoints": [
                    {
                        "key": "temperature",
                        "address": 10,
                        "functionCode": 3,
                        "objectsCount": 1,
                        "data_type": "uint16",
                        "unit": "°C",
                        "normal": {"max": 80},
                    }
                ],
            }
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["warning_count"], 1)
        signal = result["signals"][0]
        self.assertEqual(signal["status"], "warning")
        self.assertEqual(signal["raw_value"], [85])
        self.assertEqual(signal["decoded_value"], 85)
        self.assertFalse(signal["blocking"])
        self.assertIn("normal maximum", signal["warning_message"])

    @patch("pymodbus.client.ModbusTcpClient")
    def test_connection_only_validation_does_not_read_registers(self, client_class):
        client = client_class.return_value
        client.connect.return_value = True

        result = self.service.validate_modbus(
            {
                "protocol": "modbus_tcp",
                "connection": {"host": "192.168.1.50", "port": 502, "slave_id": 1},
                "connection_only": True,
            }
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["mode"], "connection")
        client.read_holding_registers.assert_not_called()
        client.close.assert_called_once()

    def test_deployed_modbus_conversion_applies_multiplier_then_offset(self):
        converter = object.__new__(BytesModbusUplinkConverter)

        value = converter.decode_data(
            [100],
            {
                "functionCode": 3,
                "type": "16uint",
                "objectsCount": 1,
                "multiplier": 0.1,
                "offset": -5,
            },
            Endian.BIG,
            Endian.BIG,
        )

        self.assertEqual(value, 5)


class SignedDeploymentDiagnosticTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.guard = GovernedCommandGuard(
            serial_number="NF-GUIDED",
            gateway=MagicMock(),
            config={
                "trusted_clock": True,
                "trusted_command_keys": {
                    "setup-key": base64.b64encode(public_key).decode()
                },
                "command_journal_path": os.path.join(self.directory.name, "commands.json"),
                "command_policy_path": os.path.join(self.directory.name, "policy.json"),
            },
        )

    def tearDown(self):
        self.directory.cleanup()

    def envelope(self, *, method="deployment_preflight", expires_at=None):
        now = datetime.now(timezone.utc)
        body = {
            "schema_version": 1,
            "request_id": "rpc-request",
            "command_id": "diagnostic-command",
            "idempotency_key": "diagnostic-once",
            "target": {"gateway_serial": "NF-GUIDED", "device_id": None},
            "method": method,
            "params": {},
            "risk": "diagnostic",
            "control_epoch": 0,
            "sequence_number": 1,
            "revisions": {"template": 0, "commissioning": 0, "policy": 0},
            "policy_checksum": "",
            "issued_at": now.isoformat(),
            "expires_at": (expires_at or (now + timedelta(minutes=2))).isoformat(),
        }
        return {
            **body,
            "signing_key_id": "setup-key",
            "signature": base64.b64encode(
                self.private_key.sign(canonical_bytes(body))
            ).decode(),
        }

    def test_signed_diagnostic_is_verified_without_control_policy(self):
        verified = self.guard.validate_diagnostic(self.envelope())
        self.assertEqual(verified["method"], "deployment_preflight")

    def test_tampered_diagnostic_is_rejected(self):
        envelope = self.envelope()
        envelope["target"]["gateway_serial"] = "NF-OTHER"
        with self.assertRaises(GovernedCommandRejected):
            self.guard.validate_diagnostic(envelope)

    def test_discovery_and_legacy_alias_require_a_valid_unexpired_signature(self):
        for method in ("deployment_discover", "scan_devices"):
            with self.subTest(method=method):
                verified = self.guard.validate_diagnostic(self.envelope(method=method))
                self.assertEqual(verified["method"], method)

        unsigned = self.envelope(method="deployment_discover")
        unsigned.pop("signature")
        with self.assertRaises(GovernedCommandRejected):
            self.guard.validate_diagnostic(unsigned)

        expired = self.envelope(
            method="deployment_discover",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        with self.assertRaisesRegex(GovernedCommandRejected, "expired"):
            self.guard.validate_diagnostic(expired)

    def test_diagnostic_evidence_redacts_nested_inline_credentials(self):
        redacted = redact_diagnostics(
            {
                "connector_results": [
                    {"error": "connection failed password=secret-value"}
                ]
            }
        )
        self.assertNotIn("secret-value", str(redacted))
        self.assertIn("[REDACTED]", str(redacted))


if __name__ == "__main__":
    unittest.main()
