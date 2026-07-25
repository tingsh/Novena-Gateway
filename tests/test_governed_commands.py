import base64
import copy
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from novena_gateway.gateway.governed_commands import (
    GovernedCommandGuard,
    GovernedCommandRejected,
    canonical_bytes,
    checksum,
)


class FakeGateway:
    def __init__(self):
        self._devices = {
            "VFD 1": {
                "device_id": "device-1",
                "authority_mode": "remote",
                "connector": object(),
            }
        }

    def get_devices(self):
        return self._devices

    def collect_runtime_attributes(self):
        return {"authority_mode": "remote", "pump_ready": True, "pump_ready_observed_at": 9999999999}


class GovernedCommandGuardTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.private_key = Ed25519PrivateKey.generate()
        public_raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.config = {
            "trusted_clock": True,
            "trusted_command_keys": {"key-1": base64.b64encode(public_raw).decode()},
            "command_policy_path": os.path.join(self.tempdir.name, "policy.json"),
            "command_journal_path": os.path.join(self.tempdir.name, "journal.json"),
        }
        self.guard = GovernedCommandGuard(
            serial_number="GW-001",
            gateway=FakeGateway(),
            config=self.config,
        )
        self.policy_payload = {
            "schema_version": 1,
            "gateway_serial": "GW-001",
            "revision": 4,
            "control_epoch": 7,
            "controls": {
                "device-1:speed": {
                    "device_id": "device-1",
                    "command_key": "speed",
                    "mapping": {"functionCode": 6, "address": 100, "type": "16uint"},
                    "data_type": "uint16",
                    "unit": "RPM",
                    "limits": {"min": 0, "max": 1500},
                    "prerequisites": [
                        {
                            "source": "runtime",
                            "key": "pump_ready",
                            "equals": True,
                            "max_age_seconds": 30,
                        }
                    ],
                    "revisions": {"template": 3, "commissioning": 2, "policy": 4},
                    "policy_checksum": "policy-v4",
                }
            },
        }
        self.guard.install_policy("policy", self._signed_policy(self.policy_payload))

    def _signature(self, payload):
        return base64.b64encode(self.private_key.sign(canonical_bytes(payload))).decode()

    def _signed_policy(self, payload):
        return {
            "payload": payload,
            "checksum": checksum(payload),
            "signing_key_id": "key-1",
            "signature": self._signature(payload),
        }

    def _command(self, **overrides):
        now = datetime.now(timezone.utc)
        body = {
            "schema_version": 1,
            "command_id": "command-1",
            "idempotency_key": "idempotency-1",
            "target": {"gateway_serial": "GW-001", "device_id": "device-1"},
            "method": "write_device",
            "params": {
                "device_id": "device-1",
                "device_name": "VFD 1",
                "command_key": "speed",
                "functionCode": 6,
                "address": 100,
                "type": "16uint",
                "value": 1200,
                "expected_value": 1200,
                "unit": "RPM",
            },
            "risk": "high",
            "control_epoch": 7,
            "sequence_number": 1,
            "revisions": {"template": 3, "commissioning": 2, "policy": 4},
            "policy_checksum": "policy-v4",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=30)).isoformat(),
        }
        body.update(overrides)
        return {**body, "signing_key_id": "key-1", "signature": self._signature(body)}

    def test_valid_command_passes_exact_edge_policy(self):
        control, replay = self.guard.validate(self._command())
        self.assertIsNone(replay)
        self.assertEqual(control["limits"]["max"], 1500)

    def test_tampering_and_stale_epoch_are_rejected(self):
        tampered = self._command()
        tampered["params"]["expected_value"] = 1600
        with self.assertRaises(GovernedCommandRejected):
            self.guard.validate(tampered)
        with self.assertRaisesRegex(GovernedCommandRejected, "epoch"):
            self.guard.validate(self._command(control_epoch=6))

    def test_duplicate_terminal_result_is_replayed(self):
        command = self._command()
        self.guard.mark_executing(command)
        self.guard.mark_terminal(
            command,
            status="success",
            result={"device_accepted": True},
            stage="field_protocol_accepted",
        )
        _, replay = self.guard.validate(command)
        self.assertEqual(replay["status"], "success")

    def test_restart_never_repeats_uncertain_executing_command(self):
        command = self._command()
        self.guard.mark_executing(command)
        restarted = GovernedCommandGuard(
            serial_number="GW-001",
            gateway=FakeGateway(),
            config=self.config,
        )
        with self.assertRaisesRegex(GovernedCommandRejected, "uncertain"):
            restarted.validate(command)

    def test_wrong_mapping_and_expired_command_are_rejected(self):
        wrong = self._command()
        wrong["params"]["address"] = 0
        body = {key: value for key, value in wrong.items() if key not in {"signature", "signing_key_id"}}
        wrong["signature"] = self._signature(body)
        with self.assertRaisesRegex(GovernedCommandRejected, "address"):
            self.guard.validate(wrong)

        expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired = self._command(
            issued_at=(expired_at - timedelta(seconds=30)).isoformat(),
            expires_at=expired_at.isoformat(),
        )
        with self.assertRaisesRegex(GovernedCommandRejected, "expired"):
            self.guard.validate(expired)

    def test_policy_tampering_is_rejected(self):
        wire = self._signed_policy(copy.deepcopy(self.policy_payload))
        wire["payload"]["control_epoch"] = 99
        with self.assertRaises(GovernedCommandRejected):
            self.guard.install_policy("policy", wire)
