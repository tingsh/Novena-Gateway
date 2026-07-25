import json
import unittest
from pathlib import Path

from novena_gateway.gateway.remote_control_protocol import (
    CAPABILITY_GOVERNED_COMMANDS,
    CAPABILITY_IDEMPOTENT_REPLAY,
    CAPABILITY_LIFECYCLE_STAGES,
    CAPABILITY_LOCAL_WRITEBACK,
    REMOTE_CONTROL_PROTOCOL_VERSION,
    remote_control_capabilities,
)


class RemoteControlContractTest(unittest.TestCase):
    def test_gateway_fixture_is_the_exact_hub_produced_contract_payload(self):
        gateway_root = Path(__file__).resolve().parents[1]
        gateway_fixture = json.loads(
            (gateway_root / "tests/fixtures/governed_command_v1.json").read_text()
        )
        hub_fixture_path = (
            gateway_root.parent
            / "remote-control-hub"
            / "tests/fixtures/governed_command_v1.json"
        )
        self.assertTrue(hub_fixture_path.exists(), "Cross-repository Hub contract fixture is required")
        hub_fixture = json.loads(hub_fixture_path.read_text())
        self.assertEqual(gateway_fixture, hub_fixture)
        self.assertEqual(gateway_fixture["schema_version"], REMOTE_CONTROL_PROTOCOL_VERSION)
        self.assertTrue(gateway_fixture["request_id"])
        self.assertTrue(gateway_fixture["command_id"])
        self.assertTrue(gateway_fixture["idempotency_key"])
        self.assertEqual(
            gateway_fixture["target"]["device_id"],
            gateway_fixture["params"]["device_id"],
        )
        self.assertTrue(gateway_fixture["params"]["command_key"])

    def test_capability_names_are_canonical_and_writeback_is_explicit(self):
        monitoring = remote_control_capabilities(local_writeback_enabled=False)
        controlled = remote_control_capabilities(local_writeback_enabled=True)
        self.assertEqual(
            set(monitoring),
            {
                CAPABILITY_GOVERNED_COMMANDS,
                CAPABILITY_LIFECYCLE_STAGES,
                CAPABILITY_IDEMPOTENT_REPLAY,
            },
        )
        self.assertEqual(set(controlled), set(monitoring) | {CAPABILITY_LOCAL_WRITEBACK})
