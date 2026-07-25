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

import contextlib
import json
import logging
import os
import subprocess
import hashlib
from time import time, monotonic
from typing import Optional
from novena_gateway.gateway.hardware_preflight import run_preflight
from novena_gateway.gateway.governed_commands import (
    GovernedCommandGuard,
    GovernedCommandRejected,
)
from novena_gateway.gateway.ota_security import (
    DEFAULT_OTA_PUBLIC_KEY_PATH,
    OtaSecurityError,
    resolve_child_path,
    safe_release_dir,
    validate_tarball,
    verify_manifest,
)
from novena_gateway.gateway.privileged_helper import PrivilegedCommandRunner
from novena_gateway.gateway.redaction import redact_diagnostics, redact_secrets
from novena_gateway.gateway.remote_control_protocol import REMOTE_CONTROL_PROTOCOL_VERSION

log = logging.getLogger("novena_gateway.rpc_handler")

STATE_CHANGING_COMMANDS = {
    "set_log_level",
    "restart_connector",
    "restart_all",
    "reboot",
    "write_device",
    "update_firmware",
}
SIGNED_DEPLOYMENT_DIAGNOSTICS = {
    "deployment_preflight",
    "deployment_discover",
    "deployment_validate",
}


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
        self._local_writeback_enabled = bool(
            self._handler_config.get("local_writeback_enabled", False)
        )
        self._inbound_topic = f"v1/gateway/{self._serial_number}/rpc/request"
        self._start_time = monotonic()
        self._helper = PrivilegedCommandRunner(self._handler_config.get("helper_path"))
        self._governance = GovernedCommandGuard(
            serial_number=serial_number,
            gateway=gateway,
            config=self._handler_config,
        )

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
            "deployment_preflight": self._cmd_deployment_preflight,
            "deployment_discover": self._cmd_deployment_discover,
            "deployment_validate": self._cmd_deployment_validate,
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
        self._publisher.subscribe(
            f"v1/gateway/{self._serial_number}/control/policy",
            self._on_control_policy,
        )
        reconciliation = self._governance.journal.reconciliation_events()
        if reconciliation:
            self._publisher.publish_attributes(
                {
                    "serial_number": self._serial_number,
                    "ts": int(time() * 1000),
                    "attributes": {
                        "remote_control_reconciliation": reconciliation[-500:],
                        **self._governance.readiness(),
                    },
                },
                immediate=True,
            )
        log.info("RPC handler started, listening on: %s", self._inbound_topic)

    def stop(self):
        """No persistent resources to clean up."""
        pass

    def _on_control_policy(self, topic, payload):
        try:
            self._governance.install_policy(topic, payload)
            log.info(
                "Installed governed-control policy revision %s at epoch %s",
                self._governance.policy_revision,
                self._governance.control_epoch,
            )
            self._publisher.publish_attributes(
                {
                    "serial_number": self._serial_number,
                    "ts": int(time() * 1000),
                    "attributes": {
                        **self._governance.readiness(),
                        "remote_control_policy_ack_revision": self._governance.policy_revision,
                        "remote_control_policy_ack_epoch": self._governance.control_epoch,
                    },
                },
                immediate=True,
            )
        except GovernedCommandRejected as exc:
            log.warning("Rejected governed-control policy: %s", exc)

    def _on_rpc_request(self, topic: str, payload: dict):
        """Handle an inbound RPC request."""
        if not isinstance(payload, dict):
            log.warning("Rejected malformed RPC payload: expected an object")
            return
        request_id = payload.get("request_id")
        method = payload.get("method", "")
        params = payload.get("params", {})

        log.info("RPC request received: method=%s, request_id=%s", method, request_id)

        if not isinstance(request_id, str) or not request_id.strip():
            log.warning("Rejected RPC payload without request_id")
            return

        handler = self._commands.get(method)
        if not handler:
            self._send_response(request_id, method, status="error",
                                error=f"Unknown RPC method: {method}", stage="rejected")
            return
        if not isinstance(params, dict):
            self._send_response(
                request_id,
                method,
                status="error",
                error="RPC params must be an object",
                stage="rejected",
            )
            return
        if method in SIGNED_DEPLOYMENT_DIAGNOSTICS:
            try:
                self._governance.validate_diagnostic(payload)
            except GovernedCommandRejected as exc:
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error=str(exc),
                    stage="rejected",
                )
                return
        if method in STATE_CHANGING_COMMANDS:
            if not self._local_writeback_enabled:
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error="Local write-back is disabled on this Gateway",
                    stage="rejected",
                )
                return
            if payload.get("schema_version") != REMOTE_CONTROL_PROTOCOL_VERSION:
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error="Unsupported or missing governed-command schema version",
                    stage="rejected",
                )
                return
            if not payload.get("command_id"):
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error="Governed state-changing commands require command_id",
                    stage="rejected",
                )
                return
            target = payload.get("target")
            if (
                not payload.get("idempotency_key")
                or not isinstance(target, dict)
                or target.get("gateway_serial") != self._serial_number
            ):
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error="Governed commands require canonical command and Gateway identity",
                    stage="rejected",
                )
                return
            if method == "write_device" and (
                not params.get("device_id")
                or not params.get("command_key")
                or str(target.get("device_id")) != str(params.get("device_id"))
            ):
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error="Governed device writes require one canonical device_id and command_key",
                    stage="rejected",
                )
                return
            try:
                governed_control, replay = self._governance.validate(payload)
            except GovernedCommandRejected as exc:
                self._send_response(
                    request_id,
                    method,
                    status="error",
                    error=str(exc),
                    stage="rejected",
                )
                return
            if replay:
                self._send_response(
                    request_id,
                    method,
                    status=replay["status"],
                    result=replay.get("result"),
                    error=replay.get("error"),
                    stage=replay.get("stage") or "replayed_terminal_result",
                )
                return
        else:
            governed_control = None

        self._send_response(request_id, method, status="received", stage="gateway_received")

        import threading

        def execute():
            lock = (
                self._governance.device_lock(payload["target"]["device_id"])
                if method in STATE_CHANGING_COMMANDS
                else contextlib.nullcontext()
            )
            try:
                with lock:
                    if method in STATE_CHANGING_COMMANDS:
                        self._governance.enforce_prerequisites(governed_control, params)
                        self._governance.mark_executing(payload)
                        self._send_response(
                            request_id,
                            method,
                            status="processing",
                            stage="executing",
                        )
                    result = handler(params)
                    status = "success"
                    error = None
                    if method in ("read_device", "write_device", "register_preflight") and isinstance(result, dict):
                        if result.get("error") or result.get("device_accepted") is False:
                            status = "error"
                            error = result.get("error") or "Device command was not accepted"
                    if method == "write_device" and status == "success":
                        readback = governed_control.get("readback") or {}
                        if readback.get("required"):
                            read_result = self._cmd_read_device(
                                {
                                    "device_name": params["device_name"],
                                    "functionCode": int(readback.get("functionCode", 3)),
                                    "address": int(readback.get("address", params["address"])),
                                    "objectsCount": int(readback.get("objectsCount", 1)),
                                    "type": readback.get("type", params.get("type")),
                                }
                            )
                            actual = read_result.get("read_value")
                            tolerance = float(readback.get("tolerance", 0))
                            expected = float(params["expected_value"])
                            if actual is None or abs(float(actual) - expected) > tolerance:
                                status = "error"
                                error = "Post-write verification mismatch"
                                result["verification"] = {
                                    "status": "mismatch",
                                    "expected": expected,
                                    "actual": actual,
                                    "tolerance": tolerance,
                                    "critical": governed_control.get("risk") == "critical",
                                }
                            else:
                                result["verification"] = {
                                    "status": "verified",
                                    "expected": expected,
                                    "actual": actual,
                                    "tolerance": tolerance,
                                }
                    stage = "failed"
                    if status == "success" and method == "write_device":
                        verification = result.get("verification", {}) if isinstance(result, dict) else {}
                        stage = (
                            "field_execution_verified"
                            if verification.get("status") == "verified"
                            else "field_protocol_accepted"
                        )
                    elif status == "success" and method == "update_firmware":
                        stage = "ota_initiated"
                    elif status == "success" and method in STATE_CHANGING_COMMANDS:
                        stage = "gateway_action_completed"
                    elif status == "success":
                        stage = "diagnostic_completed"
                    if method in STATE_CHANGING_COMMANDS:
                        self._governance.mark_terminal(
                            payload,
                            status=status,
                            result=result,
                            error=error,
                            stage=stage,
                        )
                    self._send_response(
                        request_id,
                        method,
                        status=status,
                        result=result,
                        error=error,
                        stage=stage,
                    )
            except Exception as e:
                log.exception("RPC command '%s' failed: %s", method, e)
                if method in STATE_CHANGING_COMMANDS:
                    self._governance.mark_terminal(
                        payload,
                        status="error",
                        error=str(e),
                        stage="failed",
                    )
                self._send_response(request_id, method, status="error", error=str(e), stage="failed")

        thread = threading.Thread(target=execute, name=f"RPC-{method}-{request_id[:8]}")
        thread.daemon = True
        thread.start()

    def _send_response(self, request_id: str, method: str, status: str,
                       result=None, error=None, stage=None):
        """Publish an RPC response to the cloud."""
        payload = {
            "serial_number": self._serial_number,
            "request_id": request_id,
            "method": method,
            "ts": int(time() * 1000),
            "status": status,
            "stage": stage or status,
            "result": result,
            "error": error,
        }
        self._publisher.publish_rpc_response(redact_diagnostics(payload))
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

    def _resolve_canonical_device(self, device_id: str):
        """Resolve an immutable commissioned identifier to the live connector entry."""
        matches = [
            (name, info)
            for name, info in self._gateway.get_devices().items()
            if str(info.get("device_id") or "") == str(device_id)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"Canonical device_id '{device_id}' is not uniquely mapped in the gateway registry"
            )
        device_name, device_info = matches[0]
        connector = device_info.get("connector")
        if not connector:
            raise ValueError(f"Device '{device_id}' has no connector reference")
        return device_name, connector, device_info

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
        device_id = params.get("device_id")
        if not device_id:
            raise ValueError("Missing 'device_id' parameter")
        device_name, connector, _ = self._resolve_canonical_device(device_id)
        requested_name = params.get("device_name")
        if requested_name and requested_name != device_name:
            raise ValueError("device_name does not match canonical device_id")

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

    def _cmd_deployment_preflight(self, params: dict) -> dict:
        """Return setup-specific readiness without changing appliance state."""
        hardware = self._cmd_hardware_preflight({})
        network = self._cmd_network_preflight({})
        remote_config = getattr(self._gateway, "_remote_config", None)
        capabilities = list(getattr(remote_config, "capabilities", []))
        checks = [
            {
                "key": "secure_config",
                "label": "Secure configuration",
                "status": "pass" if "guided_setup_v1" in capabilities else "fail",
                "message": (
                    "Secure guided setup is ready."
                    if "guided_setup_v1" in capabilities
                    else "This Gateway needs a trusted clock and Novena configuration key."
                ),
                "action": "Install the approved Novena public key and synchronize the Gateway clock.",
                "blocking": True,
            },
            {
                "key": "clock",
                "label": "Clock health",
                "status": "pass" if (hardware.get("clock") or {}).get("ok") else "fail",
                "message": (
                    "Gateway clock is synchronized."
                    if (hardware.get("clock") or {}).get("ok")
                    else "The Gateway clock is not synchronized."
                ),
                "action": "Check internet time access and restart time synchronization.",
                "blocking": True,
            },
            {
                "key": "disk",
                "label": "Disk space",
                "status": "pass" if (hardware.get("disk") or {}).get("ok") else "fail",
                "message": (
                    f"{(hardware.get('disk') or {}).get('free_mb')} MB of free storage is available."
                    if (hardware.get("disk") or {}).get("ok")
                    else "The Gateway does not have enough free storage for reliable operation."
                ),
                "action": "Remove old support files or replace the storage before continuing.",
                "blocking": True,
            },
            {
                "key": "interfaces",
                "label": "Equipment interfaces",
                "status": (
                    "pass"
                    if hardware.get("serial_ports") or hardware.get("ip_available")
                    else "warning"
                ),
                "message": (
                    "Equipment interfaces were detected."
                    if hardware.get("serial_ports") or hardware.get("ip_available")
                    else "No usable equipment interface was detected."
                ),
                "action": "Reconnect the Ethernet or RS485 interface, then retry.",
                "blocking": False,
            },
            {
                "key": "hardware",
                "label": "Gateway hardware",
                "status": "pass" if hardware.get("ok", hardware.get("status") == "ok") else "warning",
                "message": "Gateway hardware checks completed.",
                "action": "Open technical details to review the hardware warnings.",
                "blocking": False,
            },
            {
                "key": "network",
                "label": "Network health",
                "status": "pass" if (network.get("mqtt") or {}).get("reachable") else "warning",
                "message": (
                    "The Gateway can reach the Novena service."
                    if (network.get("mqtt") or {}).get("reachable")
                    else "The Gateway could not confirm broker reachability."
                ),
                "action": "Check the site internet connection, DNS, and broker firewall access.",
                "blocking": False,
            },
        ]
        blocked = any(check["blocking"] and check["status"] == "fail" for check in checks)
        return redact_secrets(
            {
                "status": "blocked" if blocked else "ready",
                "message": "Gateway readiness checks completed.",
                "checks": checks,
                "capabilities": capabilities,
                "technical_evidence": {
                    "internet_reachable": bool((network.get("mqtt") or {}).get("reachable")),
                    "dns_ok": bool((network.get("dns") or {}).get("ok")),
                    "broker_tcp_ok": bool((network.get("mqtt") or {}).get("reachable")),
                    "tls_ok": True,
                    "clock_synchronized": bool((hardware.get("clock") or {}).get("ok")),
                    "disk_free_mb": (hardware.get("disk") or {}).get("free_mb"),
                    "serial_interfaces": hardware.get("serial_ports") or [],
                    "details": {"hardware": hardware, "network": network},
                },
                "retryable": True,
            }
        )

    def _cmd_deployment_discover(self, params: dict) -> dict:
        """Run a rate-bounded scan against customer-approved targets."""
        discovery = getattr(self._gateway, "_discovery_service", None)
        if not discovery:
            raise RuntimeError("Equipment discovery is not available on this Gateway")
        if params.get("cancel"):
            discovery.cancel_current_scan()
            return {
                "status": "cancelled",
                "message": "The equipment scan was cancelled.",
                "retryable": True,
            }
        discovery.start_guided_scan(params)
        return {
            "status": "running",
            "message": "Equipment discovery started. Results will appear as each target is checked.",
            "retryable": True,
        }

    def _cmd_deployment_validate(self, params: dict) -> dict:
        """Read selected datapoints without saving config or emitting telemetry."""
        discovery = getattr(self._gateway, "_discovery_service", None)
        if not discovery:
            raise RuntimeError("Equipment validation is not available on this Gateway")
        return redact_secrets(discovery.validate_modbus(params))

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
        Download a signed firmware update and run the upgrade script.
        params: {
            "manifest": {...},
            "signature": "base64-ed25519-signature"
        }
        """
        if params.get("allow_insecure"):
            raise ValueError("Caller-controlled OTA HTTPS bypass is not allowed")

        manifest = params.get("manifest")
        signature = params.get("signature")
        if not manifest or not signature:
            raise ValueError("Missing signed OTA manifest or signature")

        ota_cfg = getattr(self._gateway, "_config", {}).get("ota", {})
        public_key_path = ota_cfg.get(
            "public_key_path",
            self._handler_config.get("ota_public_key_path", DEFAULT_OTA_PUBLIC_KEY_PATH),
        )
        trusted_key_ids = ota_cfg.get("trusted_key_ids") or self._handler_config.get("ota_trusted_key_ids")
        try:
            trusted_manifest = verify_manifest(
                manifest,
                signature,
                public_key_path=public_key_path,
                trusted_key_ids=trusted_key_ids,
            )
        except OtaSecurityError as e:
            self._publish_ota_status("failed", version=None, error=str(e), rollback=False)
            raise ValueError(str(e))

        version = trusted_manifest["version"]
        url = trusted_manifest["artifact_url"]
        expected_sha256 = trusted_manifest["artifact_sha256"]
        expected_size = trusted_manifest["size_bytes"]

        log.warning("OTA Firmware Update requested! Version: %s, URL: %s", version, url)

        self._publish_ota_status("accepted", version=version, error=None, rollback=False)

        # Determine paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_dir, "..", ".."))

        # Create staging directory
        storage_cfg = getattr(self._gateway, "_config", {}).get("storage", {})
        update_dir = storage_cfg.get("update_path") or os.path.join(base_dir, "storage", "update")
        os.makedirs(update_dir, exist_ok=True)

        install_dir = storage_cfg.get("install_path") or "/opt/novena-gateway"
        safe_release_dir(install_dir, version)
        dest_tar = resolve_child_path(update_dir, f"firmware_{version}.tar.gz")
        manifest_path = resolve_child_path(update_dir, f"manifest_{version}.json")
        log.info("Downloading firmware to %s...", dest_tar)
        self._publish_ota_status("downloading", version=version, error=None, rollback=False)

        # Download payload securely in the background using urllib. The trusted
        # checksum and URL come only from the verified manifest.
        import urllib.request
        req = urllib.request.Request(url)

        with urllib.request.urlopen(req, timeout=60) as response, open(dest_tar, 'wb') as out_file:
            out_file.write(response.read())

        actual_size = os.path.getsize(dest_tar)
        if actual_size != expected_size:
            try:
                os.remove(dest_tar)
            except OSError:
                pass
            self._publish_ota_status("failed", version=version, error="Firmware size mismatch", rollback=False)
            raise ValueError("Firmware size mismatch")

        actual_sha256 = self._sha256_file(dest_tar)
        if actual_sha256.lower() != expected_sha256.lower():
            try:
                os.remove(dest_tar)
            except OSError:
                pass
            self._publish_ota_status("failed", version=version, error="Firmware checksum mismatch", rollback=False)
            raise ValueError("Firmware checksum mismatch")

        try:
            validate_tarball(dest_tar)
        except OtaSecurityError as e:
            try:
                os.remove(dest_tar)
            except OSError:
                pass
            self._publish_ota_status("failed", version=version, error=str(e), rollback=False)
            raise ValueError(str(e))

        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            json.dump(trusted_manifest, manifest_file, sort_keys=True, separators=(",", ":"))

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
            log.info("Executing Linux atomic upgrade through scoped helper")
            self._publish_ota_status("restarting", version=version, error=None, rollback=False)
            helper_result = self._helper.run("run-upgrade", dest_tar, version, manifest_path, timeout=10)
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
