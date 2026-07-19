"""Unit tests for the RpcHandler."""

import sys
import os
import json
import unittest
import tempfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.rpc_handler import RpcHandler


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
        self.mock_gateway._config["storage"] = {"update_path": self.update_dir}

    def tearDown(self):
        os.unlink(self.config_file.name)
        import shutil
        shutil.rmtree(self.update_dir)

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

        self.mock_publisher.publish_rpc_response.assert_called_once()
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
                "device_name": "Ghost Device",
                "functionCode": 6,
                "address": 100,
                "value": 42,
            })
        self.assertIn("not found", str(ctx.exception))

    def test_write_device_missing_params(self):
        """write_device should error when required params are missing."""
        with self.assertRaises(ValueError):
            self.handler._cmd_write_device({"device_name": "Power Meter 1"})

    def test_read_device_missing_params(self):
        """read_device should error when required params are missing."""
        with self.assertRaises(ValueError):
            self.handler._cmd_read_device({"device_name": "Power Meter 1"})

    def test_write_device_rejects_malformed_address(self):
        with self.assertRaises(ValueError) as ctx:
            self.handler._cmd_write_device({
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

    def test_write_device_via_rpc_dispatch(self):
        """write_device should work through the full RPC dispatch path."""
        self.handler._on_rpc_request("test/topic", {
            "request_id": "req-write-001",
            "method": "write_device",
            "params": {
                "device_name": "Power Meter 1",
                "functionCode": 6,
                "address": 100,
                "value": 1500,
            }
        })

        payload = self.mock_publisher.publish_rpc_response.call_args[0][0]
        self.assertEqual(payload["request_id"], "req-write-001")
        self.assertEqual(payload["method"], "write_device")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["result"]["operation"], "write")

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

    def test_update_firmware(self):
        """update_firmware should download the firmware and run the upgrade script."""
        # We can mock the urllib request to return successfully
        import hashlib
        from unittest.mock import patch

        firmware_bytes = b"Mock zip/tar content"
        mock_response = MagicMock()
        mock_response.__enter__.return_value.read.return_value = firmware_bytes
        
        self.handler._helper = FakeHelper(ok=True)
        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
             
            result = self.handler._cmd_update_firmware({
                "version": "1.2.0",
                "url": "https://novena-hub/firmware/1.2.0.tar.gz",
                "token": "test_token",
                "sha256": hashlib.sha256(firmware_bytes).hexdigest(),
            })
            
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["version"], "1.2.0")
            mock_urlopen.assert_called_once()
            self.assertEqual(self.handler._helper.calls[0][0], "run-upgrade")

    def test_update_firmware_rejects_missing_checksum(self):
        with self.assertRaises(ValueError):
            self.handler._cmd_update_firmware({
                "version": "1.2.0",
                "url": "https://novena-hub/firmware/1.2.0.tar.gz",
            })


if __name__ == "__main__":
    unittest.main()
