"""Unit tests for the RpcHandler."""

import base64
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.rpc_handler import RpcHandler
from novena_gateway.gateway.ota_security import canonical_manifest_bytes


class MockConnector:
    """Mock connector that simulates server_side_rpc_handler."""

    def __init__(self):
        self.last_rpc_content = None

    def server_side_rpc_handler(self, content):
        self.last_rpc_content = content
        return {"success": True, "value": 42}

    def get_name(self):
        return "Modbus TCP Connector"

    def get_type(self):
        return "modbus"


class ErrorConnector(MockConnector):
    def server_side_rpc_handler(self, content):
        self.last_rpc_content = content
        return {"error": "Modbus timeout"}


class MockGateway:
    def __init__(self):
        self._mock_connector = MockConnector()
        self._connectors = [self._mock_connector]
        self._devices = {
            "Power Meter 1": {
                "device_type": "power_meter",
                "connector": self._mock_connector,
                "device_id": "device-001",
            }
        }
        self._config = {"connectors": []}
        self._device_health = {}
        self._remote_config = MagicMock()
        self._remote_config.get_status.return_value = {"config_update_status": "success"}

    def get_devices(self):
        return self._devices

    def _stop_connectors(self):
        self._connectors.clear()

    def _start_connectors(self):
        pass

    def record_device_success(self, device_name, response_ms=None):
        self._device_health[device_name] = {"poll_status": "healthy", "last_error": None}

    def record_device_failure(self, device_name, error, error_type=None, response_ms=None):
        self._device_health[device_name] = {"poll_status": "degraded", "last_error": str(error)}

    def get_device_health(self, device_name=None):
        if device_name:
            return self._device_health.get(device_name, {})
        return self._device_health

    def collect_runtime_attributes(self):
        return {"startup_status": "ready"}


class FakeHelper:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def diagnostics(self):
        return {"privilege_helper_available": self.ok}

    def reboot(self, delay):
        self.calls.append(("reboot", delay))
        return {"ok": self.ok, "stderr": "" if self.ok else "helper missing"}

    def run(self, action, *args, **kwargs):
        self.calls.append((action, args, kwargs))
        return {"ok": self.ok, "stderr": "" if self.ok else "helper missing"}


class TestRpcHandler(unittest.TestCase):

    def setUp(self):
        self.mock_publisher = MagicMock()
        self.mock_gateway = MockGateway()

        # Create a temp config file
        self.config_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump({"gateway": {"serial_number": "NF-TEST"}, "mqtt": {"password": "secret"}, "connectors": []},
                  self.config_file)
        self.config_file.close()

        self.handler = RpcHandler(
            gateway=self.mock_gateway,
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config_path=self.config_file.name,
            config={"enabled": True}
        )
        self.update_dir = tempfile.mkdtemp()
        self.ota_private_key = Ed25519PrivateKey.generate()
        public_key = self.ota_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=False)
        self.public_key_file.write(base64.b64encode(public_key).decode("ascii"))
        self.public_key_file.close()
        self.mock_gateway._config["storage"] = {"update_path": self.update_dir}
        self.mock_gateway._config["ota"] = {"public_key_path": self.public_key_file.name}

    def tearDown(self):
        os.unlink(self.config_file.name)
        os.unlink(self.public_key_file.name)
        import shutil
        shutil.rmtree(self.update_dir)

    def _tar_bytes(self, unsafe_name=None):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as tar:
            root = "novena-gateway-1.2.0"
            for dirname in (root, f"{root}/novena_gateway"):
                info = tarfile.TarInfo(dirname)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            req = b"cryptography\n"
            info = tarfile.TarInfo(f"{root}/requirements.txt")
            info.size = len(req)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(req))
            init = b""
            info = tarfile.TarInfo(f"{root}/novena_gateway/__init__.py")
            info.size = len(init)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(init))
            if unsafe_name:
                data = b"unsafe"
                info = tarfile.TarInfo(unsafe_name)
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
        return content.getvalue()

    def _signed_ota_params(self, firmware_bytes, **overrides):
        import hashlib

        now = datetime.now(timezone.utc).replace(microsecond=0)
        manifest = {
            "schema_version": 1,
            "product": "novena-gateway",
            "version": "1.2.0",
            "artifact_url": "https://novena-hub/firmware/1.2.0.tar.gz",
            "artifact_sha256": hashlib.sha256(firmware_bytes).hexdigest(),
            "size_bytes": len(firmware_bytes),
            "channel": "stable",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "minimum_gateway_version": "0.1.0",
            "maximum_gateway_version": "",
            "key_id": "novena-ota-v1",
        }
        manifest.update(overrides)
        signature = base64.b64encode(self.ota_private_key.sign(canonical_manifest_bytes(manifest))).decode("ascii")
        return {"manifest": manifest, "signature": signature}

    def test_ping(self):
        """Ping RPC should return pong."""
        result = self.handler._cmd_ping({})
        self.assertTrue(result["pong"])
        self.assertIn("ts", result)
        self.assertIn("uptime_seconds", result)

    def test_get_config(self):
        """get_config should return the config file content."""
        result = self.handler._cmd_get_config({})
        self.assertIn("config", result)
        self.assertEqual(result["config"]["gateway"]["serial_number"], "NF-TEST")
        self.assertEqual(result["config"]["mqtt"]["password"], "[REDACTED]")

    def test_get_status(self):
        """get_status should return gateway status summary."""
        result = self.handler._cmd_get_status({})
        self.assertEqual(result["serial_number"], "NF-TEST-001")
        self.assertIn("uptime_seconds", result)
        self.assertEqual(result["device_count"], 1)
        self.assertIn("Power Meter 1", result["devices"])

    def test_get_devices(self):
        """get_devices should return device dict."""
        result = self.handler._cmd_get_devices({})
        self.assertIn("Power Meter 1", result["devices"])

    def test_set_log_level(self):
        """set_log_level should change the log level."""
        result = self.handler._cmd_set_log_level({"level": "DEBUG"})
        self.assertEqual(result["level"], "DEBUG")

    def test_restart_all(self):
        """restart_all should call stop and start connectors."""
        result = self.handler._cmd_restart_all({})
        self.assertIn("connectors_restarted", result)
        self.assertIn("connector_results", result)

    def test_reboot_uses_privileged_helper(self):
        self.handler._helper = FakeHelper(ok=True)

        result = self.handler._cmd_reboot({"delay_seconds": 1})

        self.assertTrue(result["reboot_scheduled"])
        self.assertEqual(self.handler._helper.calls[0], ("reboot", 1))

    def test_privilege_preflight_reports_helper(self):
        self.handler._helper = FakeHelper(ok=True)

        result = self.handler._cmd_privilege_preflight({})

        self.assertTrue(result["privilege_helper_available"])

    def test_on_rpc_request_dispatches(self):
        """Inbound RPC request should dispatch and publish response."""
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-001",
            "method": "ping",
            "params": {}
        })

        self.assertEqual(self.mock_publisher.publish_rpc_response.call_count, 2)
        receipt = self.mock_publisher.publish_rpc_response.call_args_list[0][0][0]
        self.assertEqual(receipt["status"], "received")
        self.assertEqual(receipt["stage"], "gateway_received")
        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["request_id"], "req-001")
        self.assertEqual(payload["method"], "ping")
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["result"]["pong"])

    def test_unknown_method_returns_error(self):
        """Unknown RPC method should return an error response."""
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-002",
            "method": "nonexistent_method",
            "params": {}
        })

        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["status"], "error")
        self.assertIn("Unknown RPC method", payload["error"])


    # ─── Device control tests ──────────────────────────────────────

    def test_write_device_calls_connector(self):
        """write_device should route to the connector's server_side_rpc_handler."""
        result = self.handler._cmd_write_device({
            "device_id": "device-001",
            "device_name": "Power Meter 1",
            "functionCode": 6,
            "address": 100,
            "value": 1500,
            "type": "16uint",
        })

        self.assertEqual(result["device_name"], "Power Meter 1")
        self.assertEqual(result["operation"], "write")
        self.assertEqual(result["functionCode"], 6)
        self.assertEqual(result["address"], 100)
        self.assertEqual(result["value"], 1500)
        self.assertTrue(result["gateway_received"])
        self.assertTrue(result["connector_executed"])
        self.assertTrue(result["device_accepted"])
        self.assertIsNone(result["error"])

        # Verify the connector received the right content
        content = self.mock_gateway._mock_connector.last_rpc_content
        self.assertIsNotNone(content)
        self.assertEqual(content["device"], "Power Meter 1")
        self.assertEqual(content["data"]["method"], "set")
        self.assertEqual(content["data"]["params"]["functionCode"], 6)
        self.assertEqual(content["data"]["params"]["address"], 100)
        self.assertEqual(content["data"]["params"]["value"], 1500)

    def test_read_device_calls_connector(self):
        """read_device should route to the connector's server_side_rpc_handler."""
        result = self.handler._cmd_read_device({
            "device_name": "Power Meter 1",
            "functionCode": 3,
            "address": 3060,
            "objectsCount": 2,
            "type": "32float",
        })

        self.assertEqual(result["device_name"], "Power Meter 1")
        self.assertEqual(result["operation"], "read")
        self.assertEqual(result["functionCode"], 3)
        self.assertEqual(result["address"], 3060)
        self.assertEqual(result["objectsCount"], 2)
        self.assertTrue(result["device_accepted"])
        self.assertEqual(result["read_value"], 42)

        content = self.mock_gateway._mock_connector.last_rpc_content
        self.assertEqual(content["data"]["method"], "get")
        self.assertEqual(content["data"]["params"]["functionCode"], 3)

    def test_write_device_invalid_function_code(self):
        """write_device should reject read function codes."""
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_write_device({
                "device_id": "device-001",
                "device_name": "Power Meter 1",
                "functionCode": 3,
                "address": 100,
                "value": 42,
            })
        self.assertIn("Invalid write functionCode", str(ctx.exception))

    def test_read_device_invalid_function_code(self):
        """read_device should reject write function codes."""
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_read_device({
                "device_name": "Power Meter 1",
                "functionCode": 6,
                "address": 100,
            })
        self.assertIn("Invalid read functionCode", str(ctx.exception))

    def test_write_device_missing_device(self):
        """write_device should error for unknown device."""
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_write_device({
                "device_id": "ghost-device",
                "device_name": "Ghost Device",
                "functionCode": 6,
                "address": 100,
                "value": 42,
            })
        self.assertIn("not uniquely mapped", str(ctx.exception))

    def test_write_device_missing_params(self):
        """write_device should error when required params are missing."""
        with self.assertRaises(ValueError):
            self.handler._cmd_write_device({"device_id": "device-001", "device_name": "Power Meter 1"})

    def test_read_device_missing_params(self):
        """read_device should error when required params are missing."""
        with self.assertRaises(ValueError):
            self.handler._cmd_read_device({"device_name": "Power Meter 1"})

    def test_write_device_rejects_malformed_address(self):
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_write_device({
                "device_id": "device-001",
                "device_name": "Power Meter 1",
                "functionCode": 6,
                "address": "abc",
                "value": 42,
            })
        self.assertIn("address", str(ctx.exception))

    def test_read_device_rejects_bad_objects_count(self):
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_read_device({
                "device_name": "Power Meter 1",
                "functionCode": 3,
                "address": 100,
                "objectsCount": 0,
            })
        self.assertIn("objectsCount", str(ctx.exception))

    def test_connector_error_normalizes_command_failure(self):
        error_connector = ErrorConnector()
        self.mock_gateway._devices["Power Meter 1"]["connector"] = error_connector

        result = self.handler._cmd_write_device({
            "device_id": "device-001",
            "device_name": "Power Meter 1",
            "functionCode": 6,
            "address": 100,
            "value": 1500,
        })

        self.assertFalse(result["device_accepted"])
        self.assertEqual(result["error"], "Modbus timeout")
        self.assertEqual(self.mock_gateway._device_health["Power Meter 1"]["poll_status"], "degraded")

    def test_get_device_health(self):
        self.mock_gateway.record_device_failure("Power Meter 1", "timeout")

        result = self.handler._cmd_get_device_health({"device_name": "Power Meter 1"})

        self.assertEqual(result["device_health"]["last_error"], "timeout")

    def test_get_config_status(self):
        result = self.handler._cmd_get_config_status({})

        self.assertEqual(result["config_update_status"], "success")

    def test_write_device_via_rpc_dispatch_is_default_denied(self):
        """A fresh Gateway must remain monitoring-only even for a valid write shape."""
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-write-001",
            "method": "write_device",
            "schema_version": 1,
            "command_id": "command-001",
            "params": {
                "device_id": "device-001",
                "device_name": "Power Meter 1",
                "functionCode": 6,
                "address": 100,
                "value": 1500,
            }
        })

        for _ in range(100):
            if self.mock_publisher.publish_rpc_response.call_count >= 2:
                break
            time.sleep(0.001)
        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["request_id"], "req-write-001")
        self.assertEqual(payload["method"], "write_device")
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["stage"], "rejected")
        self.assertIn("disabled", payload["error"])
        self.assertIsNone(self.mock_gateway._mock_connector.last_rpc_content)

    def test_locally_enabled_write_still_requires_signed_retained_policy(self):
        self.handler._local_writeback_enabled = True
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-write-002",
            "method": "write_device",
            "schema_version": 1,
            "command_id": "command-002",
            "idempotency_key": "idempotency-002",
            "target": {
                "gateway_serial": "NF-TEST-001",
                "device_id": "device-001",
            },
            "params": {
                "device_id": "device-001",
                "device_name": "Power Meter 1",
                "command_key": "power_setpoint",
                "functionCode": 6,
                "address": 100,
                "value": 1500,
            },
        })

        for _ in range(100):
            if self.mock_publisher.publish_rpc_response.call_count >= 2:
                break
            time.sleep(0.001)
        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["status"], "error")
        self.assertIn("Trusted clock", payload["error"])

    def test_ota_reports_initiation_not_verified_execution(self):
        self.handler._local_writeback_enabled = True
        self.handler._governance.validate = MagicMock(return_value=({}, None))
        self.handler._governance.enforce_prerequisites = MagicMock()
        self.handler._governance.mark_executing = MagicMock()
        self.handler._governance.mark_terminal = MagicMock()
        self.handler._commands["update_firmware"] = lambda _params: {
            "status": "accepted",
            "message": "Upgrade initiated",
        }
        self.handler._on_rpc_request(
            "test/topic",
            {
                "schema_version": 1,
                "request_id": "req-ota-stage",
                "command_id": "command-ota-stage",
                "idempotency_key": "idempotency-ota-stage",
                "target": {
                    "gateway_serial": "NF-TEST-001",
                    "device_id": "device-001",
                },
                "method": "update_firmware",
                "params": {},
            },
        )

        for _ in range(100):
            if self.mock_publisher.publish_rpc_response.call_count >= 3:
                break
            time.sleep(0.001)
        stages = [
            call.args[0]["stage"]
            for call in self.mock_publisher.publish_rpc_response.call_args_list
        ]
        self.assertEqual(stages, ["gateway_received", "executing", "ota_initiated"])
        terminal = self.handler._governance.mark_terminal.call_args.kwargs
        self.assertEqual(terminal["stage"], "ota_initiated")

    def test_write_rejects_mutable_name_mismatch(self):
        with self.assertRaises(ValueError) as raised:
            self.handler._cmd_write_device({
                "device_id": "device-001",
                "device_name": "Renamed Device",
                "functionCode": 6,
                "address": 100,
                "value": 1500,
            })
        self.assertIn("does not match", str(raised.exception))

    def test_read_device_via_rpc_dispatch(self):
        """read_device should work through the full RPC dispatch path."""
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-read-001",
            "method": "read_device",
            "params": {
                "device_name": "Power Meter 1",
                "functionCode": 3,
                "address": 3060,
                "objectsCount": 2,
            }
        })

        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["request_id"], "req-read-001")
        self.assertEqual(payload["method"], "read_device")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["result"]["operation"], "read")

    def test_guided_discovery_starts_asynchronously_and_can_be_cancelled(self):
        discovery = MagicMock()
        self.mock_gateway._discovery_service = discovery

        started = self.handler._cmd_deployment_discover(
            {"tcp_hosts": ["192.168.1.50:502"]}
        )
        cancelled = self.handler._cmd_deployment_discover({"cancel": True})

        discovery.start_guided_scan.assert_called_once_with(
            {"tcp_hosts": ["192.168.1.50:502"]}
        )
        discovery.cancel_current_scan.assert_called_once()
        self.assertEqual(started["status"], "running")
        self.assertEqual(cancelled["status"], "cancelled")

    def test_update_firmware(self):
        """update_firmware should verify a signed manifest before running the upgrade."""
        from unittest.mock import patch

        firmware_bytes = self._tar_bytes()
        mock_response = MagicMock()
        mock_response.__enter__.return_value.read.return_value = firmware_bytes
        
        self.handler._helper = FakeHelper(ok=True)
        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
             
            result = self.handler._cmd_update_firmware(self._signed_ota_params(firmware_bytes))
            
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["version"], "1.2.0")
            mock_urlopen.assert_called_once()
            self.assertEqual(self.handler._helper.calls[0][0], "run-upgrade")
            self.assertEqual(self.handler._helper.calls[0][1][1], "1.2.0")

    def test_update_firmware_rejects_missing_signed_manifest(self):
        with self.assertRaises(ValueError):
            self.handler._cmd_update_firmware({
                "version": "1.2.0",
                "url": "https://novena-hub/firmware/1.2.0.tar.gz",
            })

    def test_update_firmware_rejects_bad_signature(self):
        firmware_bytes = self._tar_bytes()
        params = self._signed_ota_params(firmware_bytes)
        params["signature"] = base64.b64encode(b"bad signature").decode("ascii")
        with self.assertRaises(ValueError):
            self.handler._cmd_update_firmware(params)

    def test_update_firmware_rejects_caller_insecure_override(self):
        firmware_bytes = self._tar_bytes()
        params = self._signed_ota_params(firmware_bytes)
        params["allow_insecure"] = True
        with self.assertRaises(ValueError):
            self.handler._cmd_update_firmware(params)

    def test_update_firmware_rejects_invalid_manifest_version(self):
        firmware_bytes = self._tar_bytes()
        params = self._signed_ota_params(firmware_bytes, version="../../bad")
        with self.assertRaises(ValueError):
            self.handler._cmd_update_firmware(params)

    def test_update_firmware_rejects_unsafe_archive(self):
        from unittest.mock import patch

        firmware_bytes = self._tar_bytes(unsafe_name="../escape.txt")
        mock_response = MagicMock()
        mock_response.__enter__.return_value.read.return_value = firmware_bytes
        with patch('urllib.request.urlopen', return_value=mock_response):
            with self.assertRaises(ValueError):
                self.handler._cmd_update_firmware(self._signed_ota_params(firmware_bytes))


if __name__ == "__main__":
    unittest.main()
