"""
Novena Gateway RPC Handler

Subscribes to `v1/gateway/{serial_number}/rpc/request` for inbound RPC
commands from Novena Hub. Dispatches commands and publishes results
to `v1/gateway/{serial_number}/rpc/response`.

Supported Commands:
- ping                  → respond with pong + timestamp
- get_config            → return current config.json content
- set_log_level         → change log level at runtime
- restart_connector     → restart a specific connector by name
- restart_all           → restart all connectors
- reboot                → reboot the host system
- get_status            → return gateway status summary
- get_devices           → return list of connected devices
- write_device          → write to a physical device (e.g. Modbus register write)
- read_device           → on-demand read from a physical device
- scan_devices          → trigger device discovery scan

Inbound RPC Request (cloud → edge):
{
    "request_id": "uuid-string",
    "method": "ping" | "get_config" | "set_log_level" | ...,
    "params": { ... }
}

Outbound RPC Response (edge → cloud):
{
    "serial_number": "NF-EDGE-001",
    "request_id": "uuid-string",
    "method": "ping",
    "ts": 1714000000000,
    "status": "success" | "error",
    "result": { ... } | null,
    "error": "..." | null
}
"""

import json
import logging
import os
import subprocess
import hashlib
from time import time, monotonic
from typing import Optional
from urllib.parse import urlparse
from novena_gateway.gateway.hardware_preflight import run_preflight
from novena_gateway.gateway.privileged_helper import PrivilegedCommandRunner
from novena_gateway.gateway.redaction import redact_secrets

log = logging.getLogger("novena_gateway.rpc_handler")


class RpcHandler:
    """Handles inbound RPC commands from Novena Hub."""

    def __init__(self, gateway, publisher, serial_number: str,
                 config_path: str, config: Optional[dict] = None):
        self._gateway = gateway
        self._publisher = publisher
        self._serial_number = serial_number
        self._config_path = config_path
        self._handler_config = config or {}

        self._enabled = self._handler_config.get("enabled", True)
        self._inbound_topic = f"v1/gateway/{self._serial_number}/rpc/request"
        self._start_time = monotonic()
        self._helper = PrivilegedCommandRunner(self._handler_config.get("helper_path"))

        # Command dispatch table
        self._commands = {
            "ping": self._cmd_ping,
            "get_config": self._cmd_get_config,
            "get_config_status": self._cmd_get_config_status,
            "set_log_level": self._cmd_set_log_level,
            "restart_connector": self._cmd_restart_connector,
            "restart_all": self._cmd_restart_all,
            "reboot": self._cmd_reboot,
            "get_status": self._cmd_get_status,
            "get_devices": self._cmd_get_devices,
            "write_device": self._cmd_write_device,
            "read_device": self._cmd_read_device,
            "get_device_health": self._cmd_get_device_health,
            "register_preflight": self._cmd_register_preflight,
            "scan_devices": self._cmd_scan_devices,
            "update_firmware": self._cmd_update_firmware,
            "network_preflight": self._cmd_network_preflight,
            "hardware_preflight": self._cmd_hardware_preflight,
            "privilege_preflight": self._cmd_privilege_preflight,
        }

    def start(self):
        """Subscribe to the RPC request topic."""
        if not self._enabled:
            log.info("RPC handler is disabled.")
            return

        self._publisher.subscribe(self._inbound_topic, self._on_rpc_request)
        log.info("RPC handler started, listening on: %s", self._inbound_topic)

    def stop(self):
        """No persistent resources to clean up."""
        pass

    def _on_rpc_request(self, topic: str, payload: dict):
        """Handle an inbound RPC request."""
        request_id = payload.get("request_id", "unknown")
        method = payload.get("method", "")
        params = payload.get("params", {})

        log.info("RPC request received: method=%s, request_id=%s", method, request_id)

        handler = self._commands.get(method)
        if not handler:
            self._send_response(request_id, method, status="error",
                                error=f"Unknown RPC method: {method}")
            return

        import threading

        def execute():
            try:
                result = handler(params)
                status = "success"
                error = None
                if method in ("read_device", "write_device", "register_preflight") and isinstance(result, dict):
                    if result.get("error") or result.get("device_accepted") is False:
                        status = "error"
                        error = result.get("error") or "Device command was not accepted"
                self._send_response(request_id, method, status=status, result=result, error=error)
            except Exception as e:
                log.exception("RPC command '%s' failed: %s", method, e)
                self._send_response(request_id, method, status="error", error=str(e))

        thread = threading.Thread(target=execute, name=f"RPC-{method}-{request_id[:8]}")
        thread.daemon = True
        thread.start()

    def _send_response(self, request_id: str, method: str, status: str,
                       result=None, error=None):
        """Publish an RPC response to the cloud."""
        payload = {
            "serial_number": self._serial_number,
            "request_id": request_id,
            "method": method,
            "ts": int(time() * 1000),
            "status": status,
            "result": result,
            "error": error,
        }
        self._publisher.publish_rpc_response(redact_secrets(payload))
        log.debug("RPC response sent: method=%s, status=%s", method, status)

    # ─── Command implementations ──────────────────────────────────────

    def _cmd_ping(self, params: dict) -> dict:
        """Simple connectivity check."""
        return {
            "pong": True,
            "ts": int(time() * 1000),
            "uptime_seconds": int(monotonic() - self._start_time),
        }

    def _cmd_get_config(self, params: dict) -> dict:
        """Return the current config.json content."""
        with open(self._config_path, 'r') as f:
            config = json.load(f)
        return {"config": redact_secrets(config)}

    def _cmd_get_config_status(self, params: dict) -> dict:
        """Return the last remote config apply/rollback result."""
        remote_config = getattr(self._gateway, "_remote_config", None)
        if remote_config and hasattr(remote_config, "get_status"):
            return remote_config.get_status()
        return {"config_update_status": "unavailable"}

    def _cmd_set_log_level(self, params: dict) -> dict:
        """
        Change log level at runtime.
        params: {"logger": "novena_gateway.gateway" (optional), "level": "DEBUG"}
        """
        level_name = params.get("level", "INFO").upper()
        logger_name = params.get("logger")

        level = logging.getLevelName(level_name)
        if isinstance(level, str):
            raise ValueError(f"Invalid log level: {level_name}")

        if logger_name:
            target_logger = logging.getLogger(logger_name)
            target_logger.setLevel(level)
            log.info("Set log level for '%s' to %s", logger_name, level_name)
        else:
            # Set root logger level
            logging.getLogger().setLevel(level)
            log.info("Set root log level to %s", level_name)

        return {"logger": logger_name or "root", "level": level_name}

    def _cmd_restart_connector(self, params: dict) -> dict:
        """
        Restart a specific connector by name.
        params: {"name": "Modbus TCP Connector"}
        """
        name = params.get("name")
        if not name:
            raise ValueError("Missing 'name' parameter")

        # Find the connector
        target = None
        for conn in self._gateway._connectors:
            try:
                if conn.get_name() == name:
                    target = conn
                    break
            except Exception:
                pass

        if not target:
            raise ValueError(f"Connector '{name}' not found")

        # Stop it
        try:
            target.close()
            log.info("Stopped connector: %s", name)
        except Exception as e:
            log.warning("Error stopping connector %s: %s", name, e)

        # Remove from list
        self._gateway._connectors.remove(target)

        # Find its config and restart
        connector_config = None
        for conn_cfg in self._gateway._config.get("connectors", []):
            if conn_cfg.get("name") == name:
                connector_config = conn_cfg
                break

        if connector_config:
            from novena_gateway.gateway.constants import DEFAULT_CONNECTORS
            from novena_gateway.tb_utility.tb_loader import TBModuleLoader

            ctype = connector_config["type"]
            cname = connector_config.get("name", ctype)
            ccfg = connector_config.get("config", {})
            ccfg["name"] = cname

            class_name = DEFAULT_CONNECTORS.get(ctype)
            if class_name:
                connector_class = TBModuleLoader.import_module(ctype, class_name)
                if not isinstance(connector_class, list):
                    new_conn = connector_class(self._gateway, ccfg, ctype)
                    new_conn.open()
                    self._gateway._connectors.append(new_conn)
                    log.info("Restarted connector: %s", cname)

        return {"connector": name, "restarted": True}

    def _cmd_restart_all(self, params: dict) -> dict:
        """Restart all connectors."""
        self._gateway._stop_connectors()
        results = self._gateway._start_connectors()
        if hasattr(self._gateway, "_connector_start_results"):
            self._gateway._connector_start_results = results or []
        count = len(self._gateway._connectors)
        return {"connectors_restarted": count, "connector_results": results or []}

    def _cmd_reboot(self, params: dict) -> dict:
        """
        Reboot the host system.
        This is a privileged operation — only works if running as root/systemd.
        """
        delay = params.get("delay_seconds", 5)
        log.warning("REBOOT requested! Rebooting in %d seconds...", delay)

        result = self._helper.reboot(delay)
        if not result.get("ok"):
            raise RuntimeError(result.get("stderr") or "privileged reboot helper failed")

        return {"reboot_scheduled": True, "delay_seconds": delay, "privilege": result}

    def _cmd_get_status(self, params: dict) -> dict:
        """Return a summary of the gateway's current status."""
        uptime = int(monotonic() - self._start_time)
        devices = self._gateway.get_devices()
        connectors = []
        for conn in self._gateway._connectors:
            try:
                connectors.append({
                    "name": conn.get_name(),
                    "type": conn.get_type(),
                    "connected": conn.is_connected() if hasattr(conn, 'is_connected') else None,
                })
            except Exception:
                pass

        return {
            "serial_number": self._serial_number,
            "uptime_seconds": uptime,
            "mqtt_connected": self._publisher.is_connected(),
            "device_count": len(devices),
            "devices": list(devices.keys()),
            "connectors": connectors,
            "runtime": self._gateway.collect_runtime_attributes() if hasattr(self._gateway, "collect_runtime_attributes") else {},
        }

    def _cmd_get_devices(self, params: dict) -> dict:
        """Return detailed device information."""
        return {"devices": self._gateway.get_devices()}

    def _cmd_get_device_health(self, params: dict) -> dict:
        """Return per-device health diagnostics."""
        device_name = params.get("device_name")
        if hasattr(self._gateway, "get_device_health"):
            return {"device_health": self._gateway.get_device_health(device_name)}
        return {"device_health": {}}

    # ─── Device control commands ──────────────────────────────────────

    def _find_connector_for_device(self, device_name: str):
        """
        Find the connector instance that owns the given device.
        Returns (connector, device_info) or raises ValueError.
        """
        devices = self._gateway.get_devices()
        device_info = devices.get(device_name)
        if not device_info:
            raise ValueError(f"Device '{device_name}' not found in gateway registry")

        connector = device_info.get("connector")
        if not connector:
            raise ValueError(f"Device '{device_name}' has no connector reference")

        return connector, device_info

    def _build_connector_rpc_content(self, device_name: str, method: str, params: dict) -> dict:
        """
        Build the content dict expected by connector.server_side_rpc_handler().
        The format matches what RPCRequest (Modbus) / OpcUaRpcRequest (OPC-UA) parsers expect.
        """
        return {
            "device": device_name,
            "data": {
                "id": params.get("rpc_id", 1),
                "method": method,
                "params": params,
            },
            "timeout": params.get("timeout", 5.0),
        }

    def _validate_int_param(self, params: dict, name: str, *, minimum: int = 0, maximum: int = None) -> int:
        if name not in params:
            raise ValueError(f"Missing '{name}' parameter")
        try:
            value = int(params[name])
        except (TypeError, ValueError):
            raise ValueError(f"Invalid '{name}' parameter: must be an integer")
        if value < minimum:
            raise ValueError(f"Invalid '{name}' parameter: must be >= {minimum}")
        if maximum is not None and value > maximum:
            raise ValueError(f"Invalid '{name}' parameter: must be <= {maximum}")
        return value

    def _validate_timeout(self, params: dict) -> float:
        try:
            timeout = float(params.get("timeout", 5.0))
        except (TypeError, ValueError):
            raise ValueError("Invalid 'timeout' parameter: must be a number")
        if timeout < 0.1 or timeout > 60:
            raise ValueError("Invalid 'timeout' parameter: must be between 0.1 and 60 seconds")
        return timeout

    def _find_response_error(self, response):
        if response is None:
            return "empty response from connector"
        if isinstance(response, dict):
            if response.get("success") is False:
                return response.get("message") or "connector reported unsuccessful execution"
            error = response.get("error")
            if error:
                return str(error)
            for value in response.values():
                nested = self._find_response_error(value)
                if nested:
                    return nested
        if isinstance(response, list):
            for item in response:
                nested = self._find_response_error(item)
                if nested:
                    return nested
        return None

    def _extract_response_value(self, response):
        if isinstance(response, dict):
            if "value" in response:
                return response["value"]
            if "result" in response:
                return response["result"]
        return response

    def _build_command_result(self, *, operation: str, device_name: str, function_code: int,
                              address: int, raw_response, value=None, read_value=None,
                              objects_count=None) -> dict:
        error = self._find_response_error(raw_response)
        result = {
            "operation": operation,
            "device_name": device_name,
            "functionCode": function_code,
            "address": address,
            "gateway_received": True,
            "connector_executed": raw_response is not None,
            "device_accepted": error is None,
            "raw_response": raw_response,
            "error": error,
        }
        if value is not None:
            result["value"] = value
        if read_value is not None:
            result["read_value"] = read_value
        if objects_count is not None:
            result["objectsCount"] = objects_count
        return result

    def _cmd_write_device(self, params: dict) -> dict:
        """
        Write to a physical device via its connector.

        params: {
            "device_name": "VFD Motor 1",
            "functionCode": 6,       // Modbus: 5=coil, 6=register, 15=multi-coil, 16=multi-register
            "address": 2,
            "value": 1500,
            "type": "16uint",         // optional: data type for encoding
            "objectsCount": 1,       // optional: number of registers
            "timeout": 5.0           // optional: seconds
        }
        """
        device_name = params.get("device_name")
        if not device_name:
            raise ValueError("Missing 'device_name' parameter")

        function_code = params.get("functionCode")
        if function_code is None:
            raise ValueError("Missing 'functionCode' parameter")
        function_code = int(function_code)
        if function_code not in (5, 6, 15, 16):
            raise ValueError(f"Invalid write functionCode: {function_code}. Must be 5, 6, 15, or 16")

        address = self._validate_int_param(params, "address", minimum=0)
        timeout = self._validate_timeout(params)
        if "value" not in params:
            raise ValueError("Missing 'value' parameter")
        if params["value"] is None:
            raise ValueError("Invalid 'value' parameter: value cannot be null")

        connector, _ = self._find_connector_for_device(device_name)

        # Build the RPC content in the format the connector expects
        rpc_params = {
            "functionCode": function_code,
            "address": address,
            "value": params["value"],
            "timeout": timeout,
        }
        if "type" in params:
            rpc_params["type"] = params["type"]
        if "objectsCount" in params:
            rpc_params["objectsCount"] = self._validate_int_param(params, "objectsCount", minimum=1, maximum=125)

        content = self._build_connector_rpc_content(device_name, "set", rpc_params)

        log.info("Writing to device '%s': FC=%d, addr=%d, value=%s",
                 device_name, function_code, address, params["value"])

        response = connector.server_side_rpc_handler(content)

        result = self._build_command_result(
            operation="write",
            device_name=device_name,
            function_code=function_code,
            address=address,
            value=params["value"],
            raw_response=response,
            objects_count=rpc_params.get("objectsCount"),
        )
        self._record_command_health(device_name, result)
        return result

    def _cmd_scan_devices(self, params: dict) -> dict:
        """
        Trigger a device discovery scan.

        params: {
            "scan_type": "manual",     // optional: "manual" or "boot"
            "slave_range": [1, 32]     // optional: override default slave range
        }
        """
        discovery = getattr(self._gateway, "_discovery_service", None)
        if not discovery:
            raise ValueError("Discovery service is not available on this gateway")

        scan_type = params.get("scan_type", "manual")
        report = discovery.scan(scan_type=scan_type)

        return {
            "devices_found": len(report.get("discovered_devices", [])),
            "interfaces_scanned": len(report.get("interfaces", [])),
            "scan_ts": report.get("scan_ts"),
        }

    def _cmd_read_device(self, params: dict) -> dict:
        """
        On-demand read from a physical device via its connector.

        params: {
            "device_name": "Power Meter 1",
            "functionCode": 3,       // Modbus: 1=coils, 2=discrete, 3=holding, 4=input
            "address": 3060,
            "objectsCount": 2,       // number of registers to read
            "type": "32float",       // optional: data type for decoding
            "timeout": 5.0           // optional: seconds
        }
        """
        device_name = params.get("device_name")
        if not device_name:
            raise ValueError("Missing 'device_name' parameter")

        function_code = params.get("functionCode")
        if function_code is None:
            raise ValueError("Missing 'functionCode' parameter")
        function_code = int(function_code)
        if function_code not in (1, 2, 3, 4):
            raise ValueError(f"Invalid read functionCode: {function_code}. Must be 1, 2, 3, or 4")

        address = self._validate_int_param(params, "address", minimum=0)
        objects_count = self._validate_int_param(params, "objectsCount", minimum=1, maximum=125) if "objectsCount" in params else 1
        timeout = self._validate_timeout(params)

        connector, _ = self._find_connector_for_device(device_name)

        # Build the RPC content in the format the connector expects
        rpc_params = {
            "functionCode": function_code,
            "address": address,
            "objectsCount": objects_count,
            "timeout": timeout,
        }
        if "type" in params:
            rpc_params["type"] = params["type"]

        content = self._build_connector_rpc_content(device_name, "get", rpc_params)

        log.info("Reading from device '%s': FC=%d, addr=%d, count=%d",
                 device_name, function_code, address, rpc_params["objectsCount"])

        response = connector.server_side_rpc_handler(content)

        result = self._build_command_result(
            operation="read",
            device_name=device_name,
            function_code=function_code,
            address=address,
            read_value=self._extract_response_value(response),
            raw_response=response,
            objects_count=objects_count,
        )
        self._record_command_health(device_name, result)
        return result

    def _cmd_register_preflight(self, params: dict) -> dict:
        """Read a register on demand without storing it as telemetry."""
        return self._cmd_read_device(params)

    def _record_command_health(self, device_name: str, result: dict):
        if not hasattr(self._gateway, "record_device_success"):
            return
        if result.get("device_accepted"):
            self._gateway.record_device_success(device_name)
        else:
            self._gateway.record_device_failure(device_name, result.get("error") or "command failed")

    def _cmd_update_firmware(self, params: dict) -> dict:
        """
        Download a firmware update and run the upgrade script.
        params: {
            "version": "1.2.0",
            "url": "http://...",
            "token": "..."
        }
        """
        version = params.get("version")
        url = params.get("url")
        token = params.get("token")
        expected_sha256 = params.get("sha256")

        if not version or not url:
            raise ValueError("Missing 'version' or 'url' parameter")
        if not expected_sha256:
            raise ValueError("Missing 'sha256' parameter")

        parsed = urlparse(url)
        allow_insecure = params.get("allow_insecure", False)
        if parsed.scheme != "https" and not (allow_insecure or parsed.hostname in ("localhost", "127.0.0.1")):
            raise ValueError("Firmware URL must use HTTPS")

        log.warning("OTA Firmware Update requested! Version: %s, URL: %s", version, url)

        self._publish_ota_status("accepted", version=version, error=None, rollback=False)

        # Determine paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))

        # Create staging directory
        storage_cfg = getattr(self._gateway, "_config", {}).get("storage", {})
        update_dir = storage_cfg.get("update_path") or os.path.join(base_dir, "storage", "update")
        os.makedirs(update_dir, exist_ok=True)

        dest_tar = os.path.join(update_dir, f"firmware_{version}.tar.gz")
        log.info("Downloading firmware to %s...", dest_tar)
        self._publish_ota_status("downloading", version=version, error=None, rollback=False)

        # Download payload securely in the background using urllib
        import urllib.request
        req = urllib.request.Request(url)
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        with urllib.request.urlopen(req, timeout=60) as response, open(dest_tar, 'wb') as out_file:
            out_file.write(response.read())

        actual_sha256 = self._sha256_file(dest_tar)
        if actual_sha256.lower() != expected_sha256.lower():
            try:
                os.remove(dest_tar)
            except OSError:
                pass
            self._publish_ota_status("failed", version=version, error="Firmware checksum mismatch", rollback=False)
            raise ValueError("Firmware checksum mismatch")

        self._publish_ota_status("verified", version=version, error=None, rollback=False)
        log.info("Download and checksum verification completed. Launching upgrade script...")

        # OS-specific upgrade script execution
        if os.name == "nt":
            upgrade_script = os.path.join(base_dir, "install", "upgrade.bat")
            log.info("Executing Windows mock upgrade: %s", upgrade_script)
            subprocess.Popen(
                ["cmd.exe", "/c", upgrade_script, dest_tar, version],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=base_dir
            )
        else:
            upgrade_script = os.path.join(base_dir, "install", "upgrade.sh")
            # Make sure it is executable
            os.chmod(upgrade_script, 0o755)
            log.info("Executing Linux atomic upgrade: %s", upgrade_script)
            self._publish_ota_status("restarting", version=version, error=None, rollback=False)
            helper_result = self._helper.run("run-upgrade", upgrade_script, dest_tar, version, timeout=10)
            if not helper_result.get("ok"):
                self._publish_ota_status("failed", version=version, error=helper_result.get("stderr"), rollback=False)
                raise RuntimeError(helper_result.get("stderr") or "privileged OTA helper failed")

        return {
            "status": "accepted",
            "message": "Firmware verified. Upgrade process initiated.",
            "version": version
        }

    def _cmd_hardware_preflight(self, params: dict) -> dict:
        """Return CM4/Waveshare hardware readiness diagnostics."""
        return run_preflight(getattr(self._gateway, "_config", {}))

    def _cmd_privilege_preflight(self, params: dict) -> dict:
        """Return scoped privileged helper diagnostics."""
        return self._helper.diagnostics()

    def _cmd_network_preflight(self, params: dict) -> dict:
        """Return network facts useful for customer-site troubleshooting."""
        import shutil
        import socket

        def run_text(cmd):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return {"ok": res.returncode == 0, "output": (res.stdout or res.stderr).strip()[:1000]}
            except Exception as e:
                return {"ok": False, "output": str(e)}

        mqtt_host = getattr(self._publisher, "_host", "")
        mqtt_port = getattr(self._publisher, "_port", None)
        mqtt_reachable = False
        mqtt_error = ""
        if mqtt_host and mqtt_port:
            try:
                with socket.create_connection((mqtt_host, mqtt_port), timeout=5):
                    mqtt_reachable = True
            except Exception as e:
                mqtt_error = str(e)

        connectivity = None
        health = getattr(self._gateway, "_connectivity_health", None)
        if health and hasattr(health, "run_check"):
            connectivity = health.run_check()

        return redact_secrets({
            "connectivity": connectivity,
            "ip_route": run_text(["ip", "route"]),
            "dns": run_text(["getent", "hosts", mqtt_host]) if mqtt_host else {"ok": False, "output": "missing mqtt host"},
            "mqtt": {"host": mqtt_host, "port": mqtt_port, "reachable": mqtt_reachable, "error": mqtt_error},
            "nmcli_available": shutil.which("nmcli") is not None,
            "mmcli_available": shutil.which("mmcli") is not None,
            "wifi": run_text(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"]) if shutil.which("nmcli") else None,
            "modem": run_text(["mmcli", "-L"]) if shutil.which("mmcli") else None,
            "privilege": self._helper.diagnostics(),
        })

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _publish_ota_status(self, status: str, version: str = None, error: str = None, rollback: bool = False):
        payload = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": {
                "ota_status": status,
                "ota_version": version,
                "ota_error": error,
                "ota_rollback_performed": rollback,
            },
        }
        try:
            self._publisher.publish_attributes(payload)
        except Exception:
            pass
