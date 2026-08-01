"""
Novena Gateway Discovery Service

Scans physical interfaces for connected Modbus devices and reports
findings to Novena Hub via MQTT attributes.

Supports:
- Modbus RTU scanning (serial ports, configurable slave range + baud rates)
- Modbus TCP scanning (local subnet, port 502)
- Device identification via FC43 MEI and vendor-specific registers
"""

import glob
import ipaddress
import logging
import math
import subprocess
import socket
import struct
import threading
from time import time, sleep
from typing import Optional

log = logging.getLogger("novena_gateway.discovery")

# Known vendor identification registers
VENDOR_ID_REGISTERS = {
    "eastron": {
        "address": 64515, "count": 1, "fc": 3,
        "models": {0x0089: "SDM630", 0x0001: "SDM120", 0x0070: "SDM72D"},
    },
    "abb": {"address": 1, "count": 1, "fc": 3},
    "schneider": {"address": 29, "count": 1, "fc": 3},
}


class DiscoveryService:
    """
    Scans physical interfaces for connected Modbus devices
    and reports findings to Novena Hub via MQTT attributes.
    """

    def __init__(self, gateway, publisher, serial_number: str, config: Optional[dict] = None):
        self._gateway = gateway
        self._publisher = publisher
        self._serial_number = serial_number
        self._config = config or {}

        self._enabled = self._config.get("enabled", False)
        self._scan_on_boot = self._config.get("scan_on_boot", True)
        self._scan_interval_seconds = self._config.get("scan_interval_seconds", 3600)
        self._rtu_slave_range = self._config.get("rtu_slave_range", [1, 32])
        self._rtu_baud_rates = self._config.get("rtu_baud_rates", [9600, 19200])
        # Broad subnet scanning is opt-in and never enabled by a Hub request.
        self._tcp_subnet_scan = self._config.get("tcp_subnet_scan", False)
        self._tcp_scan_timeout_ms = self._config.get("tcp_scan_timeout_ms", 500)
        self._tcp_hosts = self._config.get("tcp_hosts", [])
        self._tcp_ports = self._config.get("tcp_ports", [502])

        self._scan_thread = None
        self._periodic_thread = None
        self._stopped = False
        self._scan_cancelled = threading.Event()
        self._scan_lock = threading.Lock()
        self._guided_scan_thread = None
        self._last_report = None

    def start(self):
        """Start boot and periodic scan threads if enabled."""
        if not self._enabled:
            log.info("Discovery service is disabled.")
            return

        if self._scan_on_boot:
            self._scan_thread = threading.Thread(
                target=self._boot_scan, name="DiscoveryBootScan", daemon=True
            )
            self._scan_thread.start()

        if self._scan_interval_seconds > 0:
            self._periodic_thread = threading.Thread(
                target=self._periodic_scan_loop, name="DiscoveryPeriodicScan", daemon=True
            )
            self._periodic_thread.start()
            log.info("Discovery periodic scan scheduled every %d seconds.", self._scan_interval_seconds)

    def stop(self):
        """Cancel any pending scans."""
        self._stopped = True
        self._scan_cancelled.set()

    def cancel_current_scan(self):
        """Cancel the active scan without stopping the service permanently."""
        self._scan_cancelled.set()

    def start_guided_scan(self, options: Optional[dict] = None):
        """Start a guided scan off the MQTT callback thread so it can be cancelled."""
        if self._scan_lock.locked() or (
            self._guided_scan_thread and self._guided_scan_thread.is_alive()
        ):
            raise RuntimeError("A discovery scan is already running")

        self._scan_cancelled.clear()

        def run():
            try:
                self.scan(
                    scan_type="guided",
                    options=options or {},
                    reset_cancel=False,
                )
            except Exception as exc:
                log.exception("Guided discovery scan failed: %s", exc)

        self._guided_scan_thread = threading.Thread(
            target=run,
            name="GuidedDiscovery",
            daemon=True,
        )
        self._guided_scan_thread.start()

    def _boot_scan(self):
        """Run a scan after a delay to let MQTT connection establish."""
        sleep(10)
        if self._stopped:
            return
        log.info("Running boot discovery scan...")
        try:
            self.scan(scan_type="boot")
        except Exception as e:
            log.exception("Boot discovery scan failed: %s", e)

    def _periodic_scan_loop(self):
        """Run periodic discovery scans at configured intervals."""
        while not self._stopped:
            # Sleep in small increments to respond to shutdown/stop quickly
            sleep_time = self._scan_interval_seconds
            for _ in range(int(sleep_time)):
                if self._stopped:
                    return
                sleep(1)

            if self._stopped:
                return

            log.info("Running periodic discovery scan...")
            try:
                self.scan(scan_type="periodic")
            except Exception as e:
                log.exception("Periodic discovery scan failed: %s", e)

    def scan(
        self,
        scan_type: str = "manual",
        options: Optional[dict] = None,
        *,
        reset_cancel: bool = True,
    ) -> dict:
        """
        Execute a full discovery scan. Returns the discovery report dict.
        """
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("A discovery scan is already running")
        if reset_cancel:
            self._scan_cancelled.clear()
        options = options or {}
        log.info("Starting discovery scan (type=%s)...", scan_type)
        scan_ts = int(time() * 1000)

        interfaces = []
        discovered_devices = []
        errors = []

        try:
            requested_serial_ports = options.get("serial_ports")
            serial_ports = self._approved_serial_ports(requested_serial_ports)
            for port in serial_ports:
                if self._cancelled:
                    break
                interfaces.append({"name": port, "type": "serial", "label": self._serial_label(port)})
                try:
                    devices = self._scan_rtu_interface(port)
                    discovered_devices.extend(devices)
                    self._publish_progress(scan_ts, scan_type, interfaces, discovered_devices, errors)
                except Exception as e:
                    log.warning("Error scanning RTU port %s: %s", port, e)
                    errors.append({"interface": port, "error": str(e)})

            approved_targets = self._approved_tcp_targets(options.get("tcp_hosts"))
            if approved_targets or (scan_type != "guided" and self._tcp_subnet_scan):
                interfaces.append({"name": "ethernet", "type": "ethernet", "label": "Approved LAN targets"})
                try:
                    tcp_devices = self._scan_tcp_network(
                        approved_targets=approved_targets,
                        progress_callback=lambda partial: self._publish_progress(
                            scan_ts,
                            scan_type,
                            interfaces,
                            discovered_devices + partial,
                            errors,
                        ),
                    )
                    discovered_devices.extend(tcp_devices)
                except Exception as e:
                    log.warning("Error during TCP scan: %s", e)
                    errors.append({"interface": "tcp", "error": str(e)})

            report = {
                "scan_ts": scan_ts,
                "scan_type": scan_type,
                "status": "cancelled" if self._cancelled else "complete",
                "interfaces": interfaces,
                "discovered_devices": discovered_devices,
                "errors": errors,
            }

            self._last_report = report
            log.info(
                "Discovery scan complete: %d devices found across %d interfaces",
                len(discovered_devices), len(interfaces),
            )
            self._publish_report(report)
            return report
        finally:
            self._scan_lock.release()

    @property
    def _cancelled(self) -> bool:
        return self._stopped or self._scan_cancelled.is_set()

    def _approved_serial_ports(self, requested_ports) -> list[str]:
        available = self._enumerate_serial_ports()
        if requested_ports is None:
            return available
        if not isinstance(requested_ports, list):
            raise ValueError("serial_ports must be a list")
        approved = []
        for port in requested_ports[:8]:
            port = str(port)
            if port not in available:
                raise ValueError(f"Serial interface is not available: {port}")
            approved.append(port)
        return approved

    def get_last_report(self) -> Optional[dict]:
        return self._last_report

    # ─── Serial/RTU scanning ──────────────────────────────────────────

    def _enumerate_serial_ports(self) -> list:
        """Find serial ports on the system."""
        patterns = ["/dev/ttyUSB*", "/dev/ttyAMA*", "/dev/ttyACM*", "/dev/ttyS*"]
        ports = []
        for pattern in patterns:
            ports.extend(glob.glob(pattern))
        # Filter out common non-RS485 ports
        ports = [p for p in ports if "ttyS0" not in p]  # ttyS0 is usually console
        log.debug("Enumerated serial ports: %s", ports)
        return sorted(ports)

    def _scan_rtu_interface(self, port: str) -> list:
        """Scan a serial port for Modbus RTU slaves."""
        try:
            from pymodbus.client import ModbusSerialClient
        except ImportError:
            log.warning("pymodbus not available, skipping RTU scan for %s", port)
            return []

        devices = []
        slave_min, slave_max = self._rtu_slave_range

        for baud_rate in self._rtu_baud_rates:
            if self._cancelled:
                break
            try:
                client = ModbusSerialClient(
                    port=port, baudrate=baud_rate,
                    timeout=0.3, stopbits=1, bytesize=8, parity="N",
                )
                if not client.connect():
                    continue

                for slave_id in range(slave_min, slave_max + 1):
                    if self._cancelled:
                        break
                    try:
                        result = client.read_holding_registers(0, 1, slave=slave_id)
                        if result and not result.isError():
                            ident = self._identify_device_rtu(client, slave_id)
                            device = {
                                "interface": port,
                                "connection": "modbus_rtu",
                                "slave_id": slave_id,
                                "baud_rate": baud_rate,
                                "signature": ident.get("signature", "Unknown Modbus Device"),
                                "identification": ident if ident.get("vendor") else None,
                                "registers_found": self._count_registers(client, slave_id),
                            }
                            devices.append(device)
                            log.info("Found RTU device: %s at %s slave %d @ %d baud",
                                     device["signature"], port, slave_id, baud_rate)
                    except Exception:
                        pass

                client.close()
            except Exception as e:
                log.debug("RTU scan error on %s @ %d: %s", port, baud_rate, e)

        return devices

    # ─── TCP scanning ─────────────────────────────────────────────────

    def _scan_tcp_network(self, approved_targets=None, progress_callback=None) -> list:
        """Scan configured or explicitly approved Modbus TCP targets."""
        try:
            from pymodbus.client import ModbusTcpClient
        except ImportError:
            log.warning("pymodbus not available, skipping TCP scan")
            return []

        devices = []
        timeout_s = self._tcp_scan_timeout_ms / 1000.0

        targets = list(approved_targets or self._configured_tcp_targets())
        if approved_targets is None and self._tcp_subnet_scan:
            targets.extend(self._subnet_tcp_targets())

        seen_targets = set()
        for ip, port in targets:
            if self._cancelled:
                break
            key = (ip, int(port))
            if key in seen_targets:
                continue
            seen_targets.add(key)
            device = self._probe_tcp_target(ModbusTcpClient, ip, int(port), timeout_s)
            if device:
                devices.append(device)
            if progress_callback:
                progress_callback(list(devices))

        return devices

    def _approved_tcp_targets(self, requested_hosts) -> list[tuple[str, int]]:
        if requested_hosts is None:
            return []
        if not isinstance(requested_hosts, list):
            raise ValueError("tcp_hosts must be a list")
        if len(requested_hosts) > 64:
            raise ValueError("A guided scan is limited to 64 approved targets")
        targets = []
        for item in requested_hosts:
            if isinstance(item, dict):
                host = item.get("host") or item.get("ip")
                port = item.get("port", 502)
            else:
                value = str(item)
                host, separator, raw_port = value.rpartition(":")
                if not separator:
                    host, port = value, 502
                else:
                    port = raw_port
            try:
                parsed = ipaddress.ip_address(str(host))
                parsed_port = int(port)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid approved Modbus TCP target: {item}") from exc
            if parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved:
                raise ValueError(f"Unsafe Modbus TCP target: {host}")
            if not 1 <= parsed_port <= 65535:
                raise ValueError(f"Invalid Modbus TCP port: {parsed_port}")
            targets.append((str(parsed), parsed_port))
        return targets

    def _configured_tcp_targets(self) -> list[tuple[str, int]]:
        targets = []
        for host in self._tcp_hosts:
            if not host:
                continue
            if isinstance(host, dict):
                ip = host.get("host") or host.get("ip")
                port = int(host.get("port", 502))
                if ip:
                    targets.append((ip, port))
                continue
            host_str = str(host)
            if ":" in host_str:
                ip, port = host_str.rsplit(":", 1)
                targets.append((ip, int(port) if port.isdigit() else 502))
            else:
                for port in self._tcp_ports:
                    targets.append((host_str, int(port)))
        return targets

    def _subnet_tcp_targets(self) -> list[tuple[str, int]]:
        targets = []
        local_ips = self._get_local_ips()
        if not local_ips:
            log.warning("Could not determine local IPs for TCP scan")
            return targets

        for local_ip in local_ips:
            subnet_base = ".".join(local_ip.split(".")[:3])
            log.info("Scanning TCP subnet %s.0/24 for Modbus devices...", subnet_base)
            for host_part in range(1, 255):
                ip = f"{subnet_base}.{host_part}"
                if ip == local_ip:
                    continue
                for port in self._tcp_ports:
                    targets.append((ip, int(port)))
        return targets

    def _probe_tcp_target(self, client_class, ip: str, port: int, timeout_s: float) -> Optional[dict]:
        try:
            sock = socket.create_connection((ip, port), timeout=timeout_s)
            sock.close()
            client = client_class(ip, port=port, timeout=1)
            if client.connect():
                result = client.read_holding_registers(0, 1, slave=1)
                if result and not result.isError():
                    ident = self._identify_device_tcp(client, 1)
                    device = {
                        "interface": f"{ip}:{port}",
                        "connection": "modbus_tcp",
                        "slave_id": 1,
                        "signature": ident.get("signature", "Unknown Modbus Device"),
                        "identification": ident if ident.get("vendor") else None,
                        "registers_found": self._count_registers(client, 1),
                    }
                    log.info("Found TCP device: %s at %s:%s", device["signature"], ip, port)
                    client.close()
                    return device
            client.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            log.debug("TCP discovery probe failed for %s:%s: %s", ip, port, e)
        return None

    # ─── Device identification ────────────────────────────────────────

    def _identify_device_rtu(self, client, slave_id: int) -> dict:
        """Attempt to identify a Modbus RTU device."""
        return self._identify_device(client, slave_id)

    def _identify_device_tcp(self, client, slave_id: int) -> dict:
        """Attempt to identify a Modbus TCP device."""
        return self._identify_device(client, slave_id)

    def _identify_device(self, client, slave_id: int) -> dict:
        """
        Attempt to identify a Modbus device via multiple methods:
        1. Modbus Device Identification (FC 43, MEI type 14)
        2. Vendor-specific ID registers
        3. Register count probing
        """
        # Method 1: FC43 MEI device identification
        try:
            from pymodbus.mei_message import ReadDeviceInformationRequest
            request = ReadDeviceInformationRequest(read_code=0x01, slave=slave_id)
            response = client.execute(request)
            if response and not response.isError() and hasattr(response, "information"):
                info = response.information
                vendor = info.get(0x00, b"").decode(errors="ignore").strip()
                model = info.get(0x01, b"").decode(errors="ignore").strip()
                if vendor or model:
                    return {
                        "vendor": vendor or "Unknown",
                        "model": model or "Unknown",
                        "signature": f"{vendor} {model}".strip(),
                    }
        except Exception:
            pass

        # Method 2: Vendor-specific ID registers
        for vendor_name, reg_info in VENDOR_ID_REGISTERS.items():
            try:
                result = client.read_holding_registers(
                    reg_info["address"], reg_info["count"], slave=slave_id
                )
                if result and not result.isError():
                    raw_val = result.registers[0]
                    models = reg_info.get("models", {})
                    model = models.get(raw_val, None)
                    if model:
                        return {
                            "vendor": vendor_name.capitalize(),
                            "model": model,
                            "signature": f"{vendor_name.capitalize()} {model}",
                            "raw_id": hex(raw_val),
                        }
            except Exception:
                pass

        return {"vendor": None, "model": None, "signature": "Unknown Modbus Device"}

    def _count_registers(self, client, slave_id: int) -> int:
        """Probe how many holding registers are readable (rough estimate)."""
        counts = [10, 50, 100, 200, 500]
        last_good = 0
        for count in counts:
            try:
                result = client.read_holding_registers(0, count, slave=slave_id)
                if result and not result.isError():
                    last_good = count
                else:
                    break
            except Exception:
                break
        return last_good

    def validate_modbus(self, params: dict) -> dict:
        """Perform non-destructive reads against a proposed Modbus setup."""
        protocol = params.get("protocol")
        connection = params.get("connection") or {}
        datapoints = params.get("datapoints") or []
        connection_only = bool(params.get("connection_only"))
        validation_profile = str(params.get("validation_profile") or "fixed")
        mapping_checksum = str(params.get("mapping_checksum") or "")
        if protocol not in {"modbus_tcp", "modbus_rtu"}:
            raise ValueError("Only Modbus TCP and Modbus RTU validation are supported")
        if not connection_only and (not isinstance(datapoints, list) or not datapoints):
            raise ValueError("At least one datapoint is required for validation")
        if len(datapoints) > 20:
            raise ValueError("Validation is limited to 20 datapoints")

        slave_id = int(connection.get("slave_id", 1))
        if not 1 <= slave_id <= 247:
            raise ValueError("Slave ID must be between 1 and 247")

        if protocol == "modbus_tcp":
            targets = self._approved_tcp_targets(
                [{"host": connection.get("host"), "port": connection.get("port", 502)}]
            )
            host, port = targets[0]
            from pymodbus.client import ModbusTcpClient

            client = ModbusTcpClient(host, port=port, timeout=min(float(connection.get("timeout", 3)), 10))
        else:
            port = str(connection.get("serial_port") or "")
            if port not in self._enumerate_serial_ports():
                raise ValueError("The selected serial interface is not available")
            from pymodbus.client import ModbusSerialClient

            client = ModbusSerialClient(
                port=port,
                baudrate=int(connection.get("baudrate", 9600)),
                parity=str(connection.get("parity", "N")).upper(),
                stopbits=int(connection.get("stopbits", 1)),
                bytesize=8,
                timeout=min(float(connection.get("timeout", 3)), 10),
            )

        results = []
        try:
            if not client.connect():
                raise ConnectionError("The Gateway could not connect to this equipment")
            if connection_only:
                return {
                    "status": "success",
                    "mode": "connection",
                    "message": "The Gateway reached the equipment connection endpoint.",
                    "signals": [],
                    "retryable": True,
                }
            for datapoint in datapoints:
                address = int(datapoint.get("address", 0))
                count = int(datapoint.get("objectsCount", 1))
                function_code = int(datapoint.get("functionCode", 3))
                if not 0 <= address <= 65535 or not 1 <= count <= 4:
                    raise ValueError("Datapoint address or register count is outside the safe validation range")
                if function_code == 4:
                    response = client.read_input_registers(address, count, slave=slave_id)
                elif function_code == 3:
                    response = client.read_holding_registers(address, count, slave=slave_id)
                elif function_code == 2:
                    response = client.read_discrete_inputs(address, count, slave=slave_id)
                elif function_code == 1:
                    response = client.read_coils(address, count, slave=slave_id)
                else:
                    raise ValueError("Validation supports read-only Modbus function codes 1, 2, 3, and 4")
                if not response or response.isError():
                    results.append(
                        {
                            "key": datapoint.get("key", f"register_{address}"),
                            "status": "failed",
                            "address": address,
                            "error_message": "The equipment did not return a readable value",
                            "reason": "The equipment did not return a readable value",
                            "blocking": True,
                        }
                    )
                    continue
                value = getattr(response, "registers", None) or getattr(response, "bits", None) or []
                try:
                    decoded = self._decode_validation_value(
                        value[:count],
                        datapoint,
                        connection,
                        bits=function_code in {1, 2},
                    )
                except (TypeError, ValueError, struct.error) as exc:
                    results.append(
                        {
                            "key": datapoint.get("key", f"register_{address}"),
                            "status": "failed",
                            "address": address,
                            "error_message": str(exc),
                            "reason": str(exc),
                            "blocking": True,
                        }
                    )
                    continue
                try:
                    warning_message, blocking = self._validation_value_assessment(
                        decoded,
                        datapoint,
                        validation_profile=validation_profile,
                    )
                except (TypeError, ValueError) as exc:
                    results.append(
                        {
                            "key": datapoint.get("key", f"register_{address}"),
                            "status": "failed",
                            "address": address,
                            "sample": list(value[:count]),
                            "raw_value": list(value[:count]),
                            "value": decoded,
                            "decoded_value": decoded,
                            "error_message": f"Validation limits are invalid: {exc}",
                            "reason": f"Validation limits are invalid: {exc}",
                            "blocking": True,
                        }
                    )
                    continue
                signal_status = "failed" if blocking else ("warning" if warning_message else "success")
                results.append(
                    {
                        "key": datapoint.get("key", f"register_{address}"),
                        "status": signal_status,
                        "address": address,
                        "sample": list(value[:count]),
                        "raw_value": list(value[:count]),
                        "value": decoded,
                        "decoded_value": decoded,
                        "unit": str(datapoint.get("unit") or ""),
                        "warning_message": warning_message or "",
                        "reason": warning_message if blocking else "",
                        "blocking": blocking,
                    }
                )
        finally:
            client.close()

        readable = [item for item in results if item["status"] in {"success", "warning"}]
        warnings = [item for item in results if item["status"] == "warning"]
        return {
            "status": "success" if len(readable) == len(results) else ("partial" if readable else "failed"),
            "mode": "datapoints",
            "mapping_checksum": mapping_checksum,
            "message": (
                f"All {len(results)} selected signals were read; {len(warnings)} need review."
                if len(readable) == len(results) and warnings
                else f"{len(readable)} of {len(results)} selected signals were read successfully."
                if readable
                else "The Gateway connected, but could not read the selected signals."
            ),
            "warning_count": len(warnings),
            "signals": results,
            "retryable": True,
        }

    @staticmethod
    def _decode_validation_value(values, datapoint, connection, *, bits=False):
        if not values:
            raise ValueError("The equipment returned no value")
        if bits:
            decoded = bool(values[0])
        else:
            data_type = str(datapoint.get("data_type") or "uint16").lower()
            formats = {
                "uint16": (1, ">H"),
                "int16": (1, ">h"),
                "uint32": (2, ">I"),
                "int32": (2, ">i"),
                "float32": (2, ">f"),
                "uint64": (4, ">Q"),
                "int64": (4, ">q"),
                "float64": (4, ">d"),
            }
            required, fmt = formats.get(data_type, (None, None))
            if required is None:
                raise ValueError(f"Unsupported validation data type: {data_type}")
            if len(values) < required:
                raise ValueError(f"{data_type} needs {required} Modbus registers")
            words = [int(value) & 0xFFFF for value in values[:required]]
            if str(connection.get("wordOrder", "BIG")).upper() == "LITTLE" and required > 1:
                words.reverse()
            raw = bytearray()
            for word in words:
                encoded = word.to_bytes(2, byteorder="big")
                if str(connection.get("byteOrder", "BIG")).upper() == "LITTLE":
                    encoded = encoded[::-1]
                raw.extend(encoded)
            decoded = struct.unpack(fmt, bytes(raw))[0]
            decoded = decoded * float(datapoint.get("scale", 1)) + float(
                datapoint.get("offset", 0)
            )
            if isinstance(decoded, float) and not math.isfinite(decoded):
                raise ValueError("Decoded value is not finite; check data type and byte order")

        return decoded

    @staticmethod
    def _validation_value_assessment(decoded, datapoint, *, validation_profile="fixed"):
        """Return an explainable warning and whether it must block confirmation."""
        value = float(decoded)
        quality = datapoint.get("quality") or {}
        safety_min = quality.get("min", datapoint.get("min"))
        safety_max = quality.get("max", datapoint.get("max"))
        unit = str(datapoint.get("unit") or "").strip().lower()

        if safety_min is not None and value < float(safety_min):
            return f"Decoded value {decoded} is below the configured safety minimum {safety_min}.", True
        if safety_max is not None and value > float(safety_max):
            return f"Decoded value {decoded} is above the configured safety maximum {safety_max}.", True

        if validation_profile != "site_defined":
            if unit in {"°c", "degc", "celsius"} and not -100 <= value <= 500:
                return "Decoded value is outside the expected temperature range.", True
            if unit in {"%", "%rh", "percent"} and not 0 <= value <= 100:
                return "Decoded value is outside the expected percentage range.", True
            return "", False

        semantic = " ".join(
            [str(datapoint.get("key") or ""), str(datapoint.get("label") or "")]
        ).lower().replace("_", " ")
        hard_range = None
        range_label = ""
        if (
            unit in {"%", "%rh", "percent", "pct"}
            or "humidity" in semantic
            or "percent" in semantic
            or "percentage" in semantic
        ):
            hard_range, range_label = (0, 100), "percentage or humidity"
        elif "power factor" in semantic or "pf" in semantic.split():
            hard_range, range_label = (-1, 1), "power factor"
        elif unit in {"°c", "degc", "celsius"}:
            hard_range, range_label = (-273.15, 2000), "Celsius temperature"
        elif unit in {"°f", "degf", "fahrenheit"}:
            hard_range, range_label = (-459.67, 3632), "Fahrenheit temperature"
        elif unit in {"k", "kelvin"} and "temp" in semantic:
            hard_range, range_label = (0, 2273.15), "Kelvin temperature"
        elif value < 0 and "pressure" in semantic and ("absolute" in semantic or "abs pressure" in semantic):
            return "Absolute pressure cannot be negative; check the address, data type, and scaling.", True

        if hard_range and not hard_range[0] <= value <= hard_range[1]:
            return (
                f"Decoded value {decoded} is outside the physically plausible {range_label} range "
                f"({hard_range[0]} to {hard_range[1]}).",
                True,
            )

        normal = datapoint.get("normal") or {}
        normal_min = normal.get("min")
        normal_max = normal.get("max")
        if normal_min is not None and value < float(normal_min):
            return f"Decoded value {decoded} is below the configured normal minimum {normal_min}.", False
        if normal_max is not None and value > float(normal_max):
            return f"Decoded value {decoded} is above the configured normal maximum {normal_max}.", False
        return "", False

    # ─── Helpers ──────────────────────────────────────────────────────

    def _get_local_ip(self) -> Optional[str]:
        """Get the local IP address of the default interface."""
        ips = self._get_local_ips()
        if ips:
            return ips[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def _get_local_ips(self) -> list[str]:
        """Get non-loopback IPv4 addresses from all active local interfaces."""
        ips = []
        try:
            output = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show", "scope", "global"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[3].split("/", 1)[0]
                    if ip and not ip.startswith("127.") and ip not in ips:
                        ips.append(ip)
        except Exception:
            pass

        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127."):
                    ips.append(ip)
            except Exception:
                pass
        return ips

    @staticmethod
    def _serial_label(port: str) -> str:
        """Generate a human-readable label for a serial port."""
        if "ttyUSB" in port:
            idx = port.replace("/dev/ttyUSB", "")
            return f"RS485-{int(idx) + 1}" if idx.isdigit() else f"USB-Serial"
        elif "ttyAMA" in port:
            return "Built-in UART"
        elif "ttyACM" in port:
            return "USB-ACM"
        return port.split("/")[-1]

    def _publish_report(self, report: dict):
        """Publish the discovery report as a gateway attribute."""
        payload = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": {
                "status": "online",
                "discovery_report": report,
            },
        }
        self._publisher.publish_attributes(payload)
        log.info("Published discovery report to Cloud (%d devices)", len(report.get("discovered_devices", [])))

    def _publish_progress(self, scan_ts, scan_type, interfaces, devices, errors):
        self._publish_report(
            {
                "scan_ts": scan_ts,
                "scan_type": scan_type,
                "status": "running",
                "interfaces": list(interfaces),
                "discovered_devices": list(devices),
                "errors": list(errors),
            }
        )
