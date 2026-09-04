"""Runtime path hardening tests for systemd-installed Gateway services."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from novena_gateway.gateway import runtime_paths
from novena_gateway.gateway.deployment_setup import ConfigEnvelopeGuard
from novena_gateway.gateway.governed_commands import GovernedCommandGuard
from novena_gateway.gateway.novena_gateway import NovenaGateway
from novena_gateway.gateway.novena_mqtt_publisher import NovenaMqttPublisher


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH_FIELDS = (
    ("storage", "sqlite", "data_file_path"),
    ("storage", "update_path"),
    ("storage", "ota_status_path"),
    ("features", "remote_config", "backup_dir"),
    ("features", "remote_config", "last_known_good_path"),
    ("features", "remote_config", "config_journal_path"),
    ("features", "rpc", "command_policy_path"),
    ("features", "rpc", "command_journal_path"),
)


def get_nested(config: dict, path: tuple[str, ...]):
    current = config
    for part in path:
        current = current[part]
    return current


def assert_var_lib_path(testcase: unittest.TestCase, value: str):
    testcase.assertTrue(os.path.isabs(value), value)
    normalized = os.path.abspath(value)
    testcase.assertFalse(
        normalized == "/opt/novena-gateway" or normalized.startswith("/opt/novena-gateway/"),
        normalized,
    )
    testcase.assertTrue(
        normalized == runtime_paths.DATA_DIR or normalized.startswith(f"{runtime_paths.DATA_DIR}/"),
        normalized,
    )


class RuntimePathDefaultsTest(unittest.TestCase):
    @patch("novena_gateway.gateway.novena_mqtt_publisher.mqtt.Client")
    @patch("novena_gateway.gateway.novena_mqtt_publisher.SQLiteEventStorage")
    def test_mqtt_offline_storage_defaults_to_var_lib(self, storage_class, _client_class):
        NovenaMqttPublisher({"host": "localhost", "port": 1883}, serial_number="NF-PATHS")

        storage_config = storage_class.call_args.args[0]
        self.assertEqual(storage_config["data_file_path"], runtime_paths.SQLITE_DATA_FILE_PATH)
        assert_var_lib_path(self, storage_config["data_file_path"])

    @patch("novena_gateway.gateway.deployment_setup.ConfigReplayJournal")
    def test_deployment_setup_journal_default_uses_var_lib(self, journal_class):
        ConfigEnvelopeGuard(serial_number="NF-PATHS", config={})

        journal_class.assert_called_once_with(runtime_paths.CONFIG_JOURNAL_PATH)
        assert_var_lib_path(self, runtime_paths.CONFIG_JOURNAL_PATH)

    @patch("novena_gateway.gateway.governed_commands.DurableCommandJournal")
    def test_remote_control_defaults_use_var_lib(self, journal_class):
        guard = GovernedCommandGuard(serial_number="NF-PATHS", gateway=MagicMock(), config={})

        journal_class.assert_called_once_with(runtime_paths.COMMAND_JOURNAL_PATH)
        self.assertEqual(guard._policy_path, runtime_paths.COMMAND_POLICY_PATH)
        assert_var_lib_path(self, runtime_paths.COMMAND_JOURNAL_PATH)
        assert_var_lib_path(self, runtime_paths.COMMAND_POLICY_PATH)

    def test_validate_config_rejects_relative_and_opt_runtime_state_paths(self):
        config = {
            "deployment": {"mode": "local"},
            "gateway": {"serial_number": "NF-PATHS"},
            "mqtt": {"host": "localhost", "port": 1883, "allow_insecure_private_mqtt": True},
            "connectors": [],
            "storage": {
                "sqlite": {"data_file_path": "storage/sqlite/"},
                "update_path": "/opt/novena-gateway/storage/update",
                "ota_status_path": "/tmp/novena-gateway/ota_status.json",
            },
            "features": {
                "remote_config": {
                    "backup_dir": "storage/config_backups",
                    "last_known_good_path": "/opt/novena-gateway/last_known_good_config.json",
                    "config_journal_path": runtime_paths.CONFIG_JOURNAL_PATH,
                },
                "rpc": {
                    "command_policy_path": "storage/remote_control/policy.json",
                    "command_journal_path": "/opt/novena-gateway/storage/remote_control/command_journal.json",
                },
            },
        }

        errors = NovenaGateway.validate_config(config)

        self.assertTrue(any("storage.sqlite.data_file_path" in error for error in errors))
        self.assertTrue(any("storage.update_path" in error for error in errors))
        self.assertTrue(any("storage.ota_status_path" in error for error in errors))
        self.assertTrue(any("features.remote_config.backup_dir" in error for error in errors))
        self.assertTrue(any("features.remote_config.last_known_good_path" in error for error in errors))
        self.assertTrue(any("features.rpc.command_policy_path" in error for error in errors))
        self.assertTrue(any("features.rpc.command_journal_path" in error for error in errors))


class RuntimePathConfigTest(unittest.TestCase):
    def test_shipped_configs_use_var_lib_for_runtime_state(self):
        config_paths = [
            REPO_ROOT / "config.json",
            REPO_ROOT / "config_local.json",
            REPO_ROOT / "install/field-test-configs/nov-audit-factory-hw.local.json",
            REPO_ROOT / "install/field-test-configs/nov-audit-cold-hw.local.json",
            REPO_ROOT / "install/field-test-configs/nov-audit-facility-hw.local.json",
        ]

        for config_path in config_paths:
            with self.subTest(config_path=str(config_path)):
                config = json.loads(config_path.read_text())
                for field in RUNTIME_PATH_FIELDS:
                    assert_var_lib_path(self, get_nested(config, field))

    def test_local_replay_renderer_writes_explicit_safe_runtime_paths(self):
        script_path = REPO_ROOT / "install/hardware-test/render_local_replay_config.py"
        spec = importlib.util.spec_from_file_location("render_local_replay_config", script_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "config.json"
            public_key_b64 = base64.b64encode(b"0" * 32).decode()
            argv = [
                str(script_path),
                "--mqtt-host",
                "192.168.0.101",
                "--mqtt-password",
                "claim-code",
                "--public-key-id",
                "setup-key",
                "--public-key-b64",
                public_key_b64,
                "--modbus-host",
                "10.0.0.20",
                "--output",
                str(output_path),
                "--no-backup",
            ]
            with patch.object(sys, "argv", argv):
                self.assertEqual(module.main(), 0)

            config = json.loads(output_path.read_text())
            for field in RUNTIME_PATH_FIELDS:
                assert_var_lib_path(self, get_nested(config, field))


if __name__ == "__main__":
    unittest.main()
