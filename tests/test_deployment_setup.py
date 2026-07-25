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

    def test_legacy_payload_remains_supported(self):
        self.handler._on_config_update(
            "topic",
            {
                "request_id": "legacy",
                "action": "connector_update",
                "config": {"connectors": []},
            },
        )
        last = self.publisher.publish_attributes.call_args.args[0]["attributes"]
        self.assertEqual(last["config_update_status"], "success")


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

    def test_validation_decodes_type_scale_and_plausibility(self):
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

        with self.assertRaisesRegex(ValueError, "expected range"):
            self.service._decode_validation_value(
                [1000],
                {"data_type": "uint16", "quality": {"max": 500}},
                {},
            )


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

    def envelope(self):
        now = datetime.now(timezone.utc)
        body = {
            "schema_version": 1,
            "request_id": "rpc-request",
            "command_id": "diagnostic-command",
            "idempotency_key": "diagnostic-once",
            "target": {"gateway_serial": "NF-GUIDED", "device_id": None},
            "method": "deployment_preflight",
            "params": {},
            "risk": "diagnostic",
            "control_epoch": 0,
            "sequence_number": 1,
            "revisions": {"template": 0, "commissioning": 0, "policy": 0},
            "policy_checksum": "",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=2)).isoformat(),
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
