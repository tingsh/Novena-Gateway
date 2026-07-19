"""
Novena Gateway — Core Orchestrator

Replaces TBGatewayService. Loads config, starts connectors, receives
ConvertedData from them, formats payloads, and publishes via MQTT to
the Novena Hub platform.
"""

import json
import logging
import os
import signal
import sys
from queue import SimpleQueue
from threading import Event, Thread
from time import monotonic, sleep, time

import sdnotify

from novena_gateway.gateway.attribute_sync_handler import AttributeSyncHandler
from novena_gateway.gateway.connectivity_health_handler import ConnectivityHealthHandler
from novena_gateway.gateway.constants import DEFAULT_CONNECTORS
from novena_gateway.gateway.discovery_service import DiscoveryService
from novena_gateway.gateway.entities.converted_data import ConvertedData
from novena_gateway.gateway.novena_mqtt_publisher import NovenaMqttPublisher
from novena_gateway.gateway.payload_formatter import PayloadFormatter
from novena_gateway.gateway.remote_config_handler import RemoteConfigHandler
from novena_gateway.gateway.remote_log_handler import RemoteLogHandler
from novena_gateway.gateway.rpc_handler import RpcHandler
from novena_gateway.gateway.network_watchdog_handler import NetworkWatchdogHandler
from novena_gateway.tb_utility.tb_loader import TBModuleLoader
from novena_gateway.gateway.hardware_preflight import run_preflight

log = logging.getLogger("novena_gateway.gateway")


class NovenaGateway:
    """
    Core gateway process. Implements the interface expected by TB-style connectors
    so they can be used without modification.
    """

    def __init__(self, config_path: str):
        self._config_path = config_path
        self._config = self._load_config(config_path)

        # Gateway identity
        self._serial_number = self._config["gateway"]["serial_number"]

        # Internal state
        self._devices = {}          # device_name -> device_info
        self._device_health = {}    # device_name -> runtime health details
        self._connectors = []       # list of running connector instances
        self._connector_start_results = []
        self._startup_status = "initializing"
        self._startup_error = None
        self._stopped = False
        self.stop_event = Event()

        # MQTT publisher
        mqtt_config = dict(self._config["mqtt"])
        if "bootstrap_mqtt" in self._config:
            mqtt_config["bootstrap_mqtt"] = self._config["bootstrap_mqtt"]
        if "storage" in self._config:
            mqtt_config["storage"] = self._config["storage"]
        self._mqtt_publisher = NovenaMqttPublisher(mqtt_config, serial_number=self._serial_number, config_path=config_path)

        # Payload formatter
        self._formatter = PayloadFormatter(self._serial_number)

        # Data queue — connectors put ConvertedData here via send_to_storage
        self._data_queue = SimpleQueue()

        # Report strategy service placeholder (some connectors check for it)
        self._report_strategy_service = None

        # ─── Cloud feature handlers ───────────────────────────────────
        feature_cfg = self._config.get("features", {})

        # Network watchdog handler
        self._network_watchdog = NetworkWatchdogHandler(
            gateway=self,
            config=feature_cfg.get("network_watchdog", {}),
        )

        self._connectivity_health = ConnectivityHealthHandler(
            gateway=self,
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            mqtt_config=self._config.get("mqtt", {}),
            config=feature_cfg.get("connectivity_health", {}),
        )

        # Remote logging handler
        self._remote_log_handler = RemoteLogHandler(
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            config=feature_cfg.get("remote_logging", {}),
        )

        # Attribute sync handler
        self._attribute_sync = AttributeSyncHandler(
            gateway=self,
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            config=feature_cfg.get("attribute_sync", {}),
        )

        # Remote config handler
        self._remote_config = RemoteConfigHandler(
            gateway=self,
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            config_path=config_path,
            config=feature_cfg.get("remote_config", {}),
        )

        # RPC handler
        self._rpc_handler = RpcHandler(
            gateway=self,
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            config_path=config_path,
            config=feature_cfg.get("rpc", {}),
        )

        # Discovery service
        self._discovery_service = DiscoveryService(
            gateway=self,
            publisher=self._mqtt_publisher,
            serial_number=self._serial_number,
            config=feature_cfg.get("discovery", {}),
        )

        log.info("Novena Gateway initialized — serial_number=%s", self._serial_number)

    # ─── Configuration ────────────────────────────────────────────────

    @staticmethod
    def _load_config(config_path: str) -> dict:
        with open(config_path, 'r') as f:
            config = json.load(f)
        log.info("Configuration loaded from %s", config_path)
        NovenaGateway._validate_config(config, config_path)
        return config

    @staticmethod
    def validate_config(config: dict) -> list:
        """Validate config dictionary structure. Returns a list of error strings (empty if valid)."""
        errors = []

        # Required top-level keys
        deployment_mode = NovenaGateway.deployment_mode(config)
        if "gateway" not in config or "serial_number" not in config.get("gateway", {}):
            errors.append("gateway.serial_number")
        if "mqtt" not in config:
            errors.append("mqtt (entire section)")
        else:
            mqtt_cfg = config["mqtt"]
            if "host" not in mqtt_cfg:
                errors.append("mqtt.host")
            if "port" not in mqtt_cfg:
                errors.append("mqtt.port")
            else:
                try:
                    int(mqtt_cfg.get("port"))
                except (TypeError, ValueError):
                    errors.append("mqtt.port (must be an integer)")
            if deployment_mode in ("pilot", "production"):
                allow_insecure = bool(mqtt_cfg.get("allow_insecure_private_mqtt"))
                if not mqtt_cfg.get("tls") and not allow_insecure:
                    errors.append("mqtt.tls — required in pilot/production unless mqtt.allow_insecure_private_mqtt is true")
                try:
                    mqtt_port = int(mqtt_cfg.get("port", 1883))
                    if allow_insecure and mqtt_port != 1883:
                        errors.append("mqtt.allow_insecure_private_mqtt — only valid for plaintext/private MQTT on port 1883")
                except (TypeError, ValueError):
                    pass
        if "connectors" not in config or not isinstance(config.get("connectors"), list):
            errors.append("connectors (must be a list)")
        else:
            for index, connector in enumerate(config.get("connectors", [])):
                if not isinstance(connector, dict):
                    errors.append(f"connectors[{index}] (must be an object)")
                    continue
                if "type" not in connector:
                    errors.append(f"connectors[{index}].type")
                if "config" in connector and not isinstance(connector.get("config"), dict):
                    errors.append(f"connectors[{index}].config (must be an object)")

        if deployment_mode in ("pilot", "production"):
            serial = config.get("gateway", {}).get("serial_number", "")
            mqtt_cfg = config.get("mqtt", {})
            placeholder_fields = {
                "gateway.serial_number": serial,
                "mqtt.host": mqtt_cfg.get("host", ""),
                "mqtt.username": mqtt_cfg.get("username", ""),
                "mqtt.password": mqtt_cfg.get("password", ""),
            }
            for field, value in placeholder_fields.items():
                if not value or str(value).startswith("REPLACE_WITH_"):
                    errors.append(f"{field} — factory burn value required in {deployment_mode} mode")

        # TLS cross-validation
        tls_cfg = config.get("mqtt", {}).get("tls")
        if tls_cfg:
            mode = tls_cfg.get("mode", "one-way")
            ca_certs = tls_cfg.get("ca_certs")
            if not ca_certs:
                errors.append("mqtt.tls.ca_certs (required when tls is enabled)")
            elif not os.path.isfile(ca_certs):
                errors.append(f"mqtt.tls.ca_certs — file not found: {ca_certs}")
            if mode == "mutual":
                for key in ("certfile", "keyfile"):
                    val = tls_cfg.get(key)
                    if not val:
                        errors.append(f"mqtt.tls.{key} (required for mutual TLS mode)")
                    elif not os.path.isfile(val):
                        errors.append(f"mqtt.tls.{key} — file not found: {val}")

        return errors

    @staticmethod
    def deployment_mode(config: dict = None) -> str:
        config = config or {}
        configured = config.get("deployment", {}).get("mode")
        return (configured or os.environ.get("NOVENA_DEPLOYMENT_MODE", "local")).lower()

    @staticmethod
    def _validate_config(config: dict, config_path: str):
        """Validate required config keys on startup. Exits with a clear message on failure."""
        errors = NovenaGateway.validate_config(config)

        if errors:
            print("\n" + "=" * 60)
            print("  CONFIG ERROR — Novena Gateway cannot start")
            print("=" * 60)
            for err in errors:
                print(f"  x Missing or invalid: {err}")
            print(f"\n  Edit {config_path} to fix these issues.\n")
            sys.exit(1)

    def get_config_path(self) -> str:
        return os.path.dirname(self._config_path)

    def run_hardware_preflight(self) -> dict:
        return run_preflight(self._config)

    # ─── Device registry (called by connectors) ──────────────────────

    def get_devices(self) -> dict:
        return self._devices

    def add_device(self, device_name, content, device_type='default'):
        self._devices[device_name] = {
            "device_type": device_type,
            "connector": content.get("connector"),
        }
        self._ensure_device_health(device_name)
        log.info("Device registered: %s (type=%s)", device_name, device_type)
        return True

    def del_device(self, device_name):
        if device_name in self._devices:
            del self._devices[device_name]
            log.info("Device unregistered: %s", device_name)

    def _ensure_device_health(self, device_name: str) -> dict:
        if device_name not in self._device_health:
            self._device_health[device_name] = {
                "device_name": device_name,
                "poll_status": "unknown",
                "last_successful_poll_ts": None,
                "last_failed_poll_ts": None,
                "consecutive_failures": 0,
                "last_error": None,
                "last_error_type": None,
                "last_response_ms": None,
            }
        return self._device_health[device_name]

    def record_device_success(self, device_name: str, response_ms=None):
        health = self._ensure_device_health(device_name)
        health.update({
            "poll_status": "healthy",
            "last_successful_poll_ts": int(time() * 1000),
            "consecutive_failures": 0,
            "last_error": None,
            "last_error_type": None,
            "last_response_ms": response_ms,
        })

    def record_device_failure(self, device_name: str, error, error_type: str = None, response_ms=None):
        health = self._ensure_device_health(device_name)
        health["last_failed_poll_ts"] = int(time() * 1000)
        health["consecutive_failures"] = int(health.get("consecutive_failures") or 0) + 1
        health["last_error"] = str(error)
        health["last_error_type"] = error_type or self.classify_device_error(error)
        health["last_response_ms"] = response_ms
        if health["last_error_type"] in ("invalid_function_code", "illegal_address", "decode_type_mismatch"):
            health["poll_status"] = "misconfigured"
        elif health["consecutive_failures"] >= 3:
            health["poll_status"] = "offline"
        else:
            health["poll_status"] = "degraded"

    def classify_device_error(self, error) -> str:
        text = str(error).lower()
        if "timeout" in text:
            return "timeout"
        if "connection refused" in text or "connect" in text and "failed" in text:
            return "connection_refused"
        if "function" in text and ("invalid" in text or "unknown" in text):
            return "invalid_function_code"
        if "illegal address" in text or "address" in text and "illegal" in text:
            return "illegal_address"
        if "decode" in text or "type" in text and "mismatch" in text:
            return "decode_type_mismatch"
        if "empty" in text or text in ("none", "{}"):
            return "empty_response"
        return "device_error"

    def collect_device_health_summary(self) -> dict:
        return {
            name: dict(health)
            for name, health in sorted(self._device_health.items())
        }

    def get_device_health(self, device_name: str = None) -> dict:
        if device_name:
            return dict(self._ensure_device_health(device_name))
        return self.collect_device_health_summary()

    # ─── Data pathway (called by connectors) ─────────────────────────

    def send_to_storage(self, connector_name, connector_id, converted_data: ConvertedData):
        """Main data ingress point. Connectors call this to submit polled data."""
        self._data_queue.put((connector_name, converted_data))
        return True

    def send_rpc_reply(self, device=None, req_id=None, content=None, **kwargs):
        """RPC replies — logged locally since we have no TB server to send to."""
        log.debug("RPC reply for device=%s req_id=%s: %s", device, req_id, content)

    def send_attributes(self, device_name, attributes):
        """Attribute updates — format and publish."""
        log.debug("Attribute update for device=%s: %s", device_name, attributes)

    def is_rpc_in_progress(self, rpc_id):
        return False

    def register_rpc_request_timeout(self, *args, **kwargs):
        pass

    def rpc_with_reply_processing(self, *args, **kwargs):
        pass

    def get_report_strategy_service(self):
        return self._report_strategy_service

    # ─── Connector lifecycle ──────────────────────────────────────────

    def _start_connectors(self):
        """Instantiate and start all connectors defined in config."""
        connectors_config = self._config.get("connectors", [])
        results = []

        for connector_cfg in connectors_config:
            connector_type = connector_cfg["type"]
            connector_name = connector_cfg.get("name", connector_type)
            connector_config = connector_cfg.get("config", {})
            connector_config["name"] = connector_name

            class_name = DEFAULT_CONNECTORS.get(connector_type)
            if not class_name:
                log.error("Unknown connector type: %s. Skipping.", connector_type)
                results.append({
                    "name": connector_name,
                    "type": connector_type,
                    "status": "error",
                    "error": f"Unknown connector type: {connector_type}",
                })
                continue

            try:
                connector_class = TBModuleLoader.import_module(connector_type, class_name)
                if isinstance(connector_class, list):
                    log.error("Failed to load connector %s: %s", connector_type, connector_class)
                    results.append({
                        "name": connector_name,
                        "type": connector_type,
                        "status": "error",
                        "error": str(connector_class),
                    })
                    continue

                connector = connector_class(self, connector_config, connector_type)
                connector.open()
                self._connectors.append(connector)
                results.append({
                    "name": connector_name,
                    "type": connector_type,
                    "status": "success",
                    "error": None,
                })
                log.info("Started connector: %s (%s)", connector_name, connector_type)
            except Exception as e:
                log.exception("Failed to start connector %s: %s", connector_name, e)
                results.append({
                    "name": connector_name,
                    "type": connector_type,
                    "status": "error",
                    "error": str(e),
                })
        return results

    def _required_connectors_enabled(self) -> bool:
        deployment = self._config.get("deployment", {})
        if "required_connectors_enabled" in deployment:
            return bool(deployment["required_connectors_enabled"])
        return self.deployment_mode(self._config) in ("pilot", "production")

    def _is_connector_required(self, result: dict) -> bool:
        if not self._required_connectors_enabled():
            return False
        for connector in self._config.get("connectors", []):
            name = connector.get("name", connector.get("type"))
            if name == result.get("name"):
                return connector.get("required", True) is not False
        return True

    def _required_connector_failures(self) -> list:
        return [
            result for result in self._connector_start_results
            if result.get("status") != "success" and self._is_connector_required(result)
        ]

    def collect_runtime_attributes(self) -> dict:
        failures = self._required_connector_failures()
        try:
            data_queue_size = self._data_queue.qsize()
        except Exception:
            data_queue_size = None
        return {
            "startup_status": self._startup_status,
            "startup_error": self._startup_error,
            "connector_start_results": self._connector_start_results,
            "required_connector_failures": failures,
            "required_connector_failure_count": len(failures),
            "data_queue_size": data_queue_size,
        }

    def _stop_connectors(self):
        """Stop all running connectors."""
        for connector in self._connectors:
            try:
                connector.close()
                log.info("Stopped connector: %s", connector.get_name())
            except Exception as e:
                log.error("Error stopping connector %s: %s", connector.get_name(), e)
        self._connectors.clear()

    # ─── Data processing loop ─────────────────────────────────────────

    def _data_processing_loop(self):
        """
        Background thread that reads ConvertedData from the queue,
        formats it into Novena Hub payloads, and publishes via MQTT.
        """
        while not self._stopped:
            try:
                connector_name, converted_data = self._data_queue.get(timeout=0.5)
            except Exception:
                continue

            try:
                payloads = self._formatter.format(converted_data)
                for payload in payloads:
                    self._mqtt_publisher.publish(payload)
                    log.debug("Published payload from %s: device=%s",
                              connector_name, converted_data.device_name)
            except Exception as e:
                log.exception("Error processing data from %s: %s", connector_name, e)

    # ─── Main run / shutdown ──────────────────────────────────────────

    def run(self):
        """Start the gateway: connect MQTT, start connectors, process data."""
        log.info("=" * 60)
        log.info("  Novena Gateway starting...")
        log.info("  Serial Number: %s", self._serial_number)
        log.info("  MQTT Broker:   %s:%d",
                 self._config["mqtt"]["host"], self._config["mqtt"]["port"])
        log.info("=" * 60)

        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Connect to MQTT broker
        self._mqtt_publisher.connect()

        # Start cloud feature handlers (after MQTT is connected)
        self._network_watchdog.start()
        self._connectivity_health.start()
        self._remote_log_handler.start()
        self._remote_log_handler.install()  # Install on root logger
        self._attribute_sync.start()
        self._remote_config.start()
        self._rpc_handler.start()

        # Start discovery service
        self._discovery_service.start()

        # Start connectors
        self._connector_start_results = self._start_connectors()
        required_failures = self._required_connector_failures()
        if required_failures:
            self._startup_status = "failed"
            self._startup_error = "; ".join(
                f"{item.get('name')}: {item.get('error') or item.get('status')}"
                for item in required_failures
            )
            log.error("Required connector startup failed: %s", self._startup_error)
            try:
                self._attribute_sync._publish_attributes(status="failed")
            except Exception:
                pass
            self.stop()
            sys.exit(1)
        if any(result.get("status") != "success" for result in self._connector_start_results):
            self._startup_status = "degraded"
        else:
            self._startup_status = "ready"

        # Start data processing thread
        data_thread = Thread(target=self._data_processing_loop,
                             name="DataProcessor", daemon=True)
        data_thread.start()

        log.info("Gateway is running. Press Ctrl+C to stop.")

        # Notify systemd that startup is complete
        self._sd_notifier = sdnotify.SystemdNotifier()
        self._sd_notifier.notify("READY=1")
        log.info("Notified systemd: READY=1")

        # Main thread waits for stop signal, pinging watchdog every 60s
        last_watchdog = monotonic()
        try:
            while not self._stopped:
                self.stop_event.wait(timeout=1.0)
                if monotonic() - last_watchdog >= 60:
                    self._sd_notifier.notify("WATCHDOG=1")
                    last_watchdog = monotonic()
        except KeyboardInterrupt:
            pass

        self.stop()

    def stop(self):
        """Gracefully shut down the gateway."""
        if self._stopped:
            return
        self._stopped = True
        self.stop_event.set()

        log.info("Shutting down Novena Gateway...")

        # Stop cloud feature handlers first
        self._discovery_service.stop()
        self._rpc_handler.stop()
        self._remote_config.stop()
        self._attribute_sync.stop()
        self._connectivity_health.stop()
        self._network_watchdog.stop()
        self._remote_log_handler.uninstall()
        self._remote_log_handler.stop()

        self._stop_connectors()
        self._mqtt_publisher.disconnect()
        log.info("Novena Gateway stopped.")

    def _signal_handler(self, signum, frame):
        log.info("Received signal %d, shutting down...", signum)
        self.stop()

    @property
    def stopped(self):
        return self._stopped
