"""
Novena Gateway Attribute Sync Handler

Publishes gateway attributes (firmware, IP, uptime, connected devices) to
Novena Hub on startup and at periodic intervals. Also subscribes to
inbound attribute push messages from the cloud.

Outbound Attribute Payload Schema (edge → cloud):
{
    "serial_number": "NF-EDGE-001",
    "ts": 1714000000000,
    "attributes": {
        "firmware_version": "0.1.0",
        "ip_address": "192.168.1.50",
        "uptime_seconds": 3600,
        "python_version": "3.9.18",
        "connected_devices": ["Power Meter 1", "Temp Sensor 2"],
        "active_connectors": ["Modbus TCP Connector"],
        "status": "online"
    }
}

Inbound Attribute Payload Schema (cloud → edge):
{
    "request_id": "abc-123",
    "attributes": {
        "some_key": "some_value"
    }
}
"""

import logging
import json
import os
import platform
import socket
import sys
import threading
from time import time, sleep, monotonic
from typing import Optional

from novena_gateway.__version__ import __version__
from novena_gateway.gateway.redaction import redact_secrets

log = logging.getLogger("novena_gateway.attribute_sync")


class AttributeSyncHandler:
    """Manages bidirectional gateway attribute synchronization."""

    DEFAULT_HEARTBEAT_INTERVAL = 60  # seconds

    def __init__(self, gateway, publisher, serial_number: str, config: Optional[dict] = None):
        self._gateway = gateway
        self._publisher = publisher
        self._serial_number = serial_number
        self._config = config or {}

        self._enabled = self._config.get("enabled", True)
        self._heartbeat_interval = self._config.get(
            "heartbeat_interval_seconds", self.DEFAULT_HEARTBEAT_INTERVAL
        )

        self._stopped = False
        self._heartbeat_thread = None
        self._start_time = monotonic()

        # Inbound topic
        self._inbound_topic = f"v1/gateway/{self._serial_number}/attributes/request"

        # Local attribute store (attributes pushed from cloud)
        self._cloud_attributes = {}
        self._attributes_lock = threading.Lock()

    def start(self):
        """Start attribute sync: publish initial attributes and begin heartbeat."""
        if not self._enabled:
            log.info("Attribute sync is disabled.")
            return

        # Subscribe to inbound attribute pushes
        self._publisher.subscribe(self._inbound_topic, self._on_attribute_push)
        log.info("Subscribed to inbound attributes on: %s", self._inbound_topic)

        # Publish initial attributes
        self._publish_attributes()

        # Start heartbeat thread
        self._stopped = False
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="AttrHeartbeat", daemon=True
        )
        self._heartbeat_thread.start()
        log.info("Attribute sync started (heartbeat every %ds)", self._heartbeat_interval)

    def stop(self):
        """Stop heartbeat and publish offline status."""
        self._stopped = True
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=3)

        # Publish offline status
        try:
            self._publish_attributes(status="offline")
        except Exception:
            pass

    def get_cloud_attributes(self) -> dict:
        """Return attributes that were pushed from the cloud."""
        with self._attributes_lock:
            return dict(self._cloud_attributes)

    def _collect_attributes(self, status: str = "online") -> dict:
        """Collect current gateway attributes."""
        uptime = int(monotonic() - self._start_time)

        # Gather connected device names
        connected_devices = list(self._gateway.get_devices().keys())

        # Gather active connector names
        active_connectors = []
        for conn in self._gateway._connectors:
            try:
                active_connectors.append(conn.get_name())
            except Exception:
                pass

        # Get local IP
        ip_address = "unknown"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        attrs = {
            "firmware_version": __version__,
            "ip_address": ip_address,
            "uptime_seconds": uptime,
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "connected_devices": connected_devices,
            "active_connectors": active_connectors,
            "device_count": len(connected_devices),
            "status": status,
            "remote_control_protocol_version": 1,
            "remote_control_local_writeback_enabled": bool(
                getattr(self._gateway, "_config", {})
                .get("features", {})
                .get("rpc", {})
                .get("local_writeback_enabled", False)
            ),
            "remote_control_policy_loaded": False,
        }

        # Merge network watchdog fields if available
        if hasattr(self._gateway, "_network_watchdog") and self._gateway._network_watchdog:
            try:
                watchdog_attrs = self._gateway._network_watchdog.collect_watchdog_attributes()
                attrs.update(watchdog_attrs)
            except Exception as e:
                log.warning("Failed to collect network watchdog attributes: %s", e)

        if hasattr(self._gateway, "_connectivity_health") and self._gateway._connectivity_health:
            try:
                attrs.update(self._gateway._connectivity_health.collect_connectivity_attributes())
            except Exception as e:
                log.warning("Failed to collect connectivity health attributes: %s", e)

        if hasattr(self._gateway, "_mqtt_publisher") and self._gateway._mqtt_publisher:
            try:
                attrs.update(self._gateway._mqtt_publisher.collect_buffer_attributes())
            except Exception as e:
                log.warning("Failed to collect MQTT buffer attributes: %s", e)

        if hasattr(self._gateway, "collect_device_health_summary"):
            try:
                attrs["device_health"] = self._gateway.collect_device_health_summary()
            except Exception as e:
                log.warning("Failed to collect device health attributes: %s", e)

        if hasattr(self._gateway, "collect_runtime_attributes"):
            try:
                attrs.update(self._gateway.collect_runtime_attributes())
            except Exception as e:
                log.warning("Failed to collect runtime attributes: %s", e)

        try:
            ota_status = self._collect_ota_status()
            if ota_status:
                attrs.update(ota_status)
        except Exception as e:
            log.warning("Failed to collect OTA status attributes: %s", e)

        return redact_secrets(attrs)

    def _collect_ota_status(self) -> dict:
        config = getattr(self._gateway, "_config", {})
        storage_cfg = config.get("storage", {})
        status_path = storage_cfg.get("ota_status_path")
        if not status_path:
            update_path = storage_cfg.get("update_path", "storage/update")
            status_path = os.path.join(update_path, "ota_status.json")
        if not os.path.exists(status_path):
            return {}
        with open(status_path, "r") as f:
            payload = json.load(f)
        return {
            "ota_status": payload.get("ota_status"),
            "ota_version": payload.get("ota_version"),
            "ota_error": payload.get("ota_error"),
            "ota_rollback_performed": payload.get("ota_rollback_performed", False),
        }

    def _publish_attributes(self, status: str = "online"):
        """Publish current gateway attributes to the cloud."""
        attributes = self._collect_attributes(status=status)
        payload = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": attributes,
        }
        self._publisher.publish_attributes(payload)
        log.debug("Published gateway attributes: %s", attributes)

    def _heartbeat_loop(self):
        """Periodically publish attributes as heartbeat."""
        while not self._stopped:
            sleep(self._heartbeat_interval)
            if self._stopped:
                break
            try:
                self._publish_attributes()
            except Exception as e:
                log.error("Failed to publish heartbeat attributes: %s", e)

    def _on_attribute_push(self, topic: str, payload: dict):
        """Handle inbound attribute push from the cloud."""
        request_id = payload.get("request_id", "unknown")
        attributes = payload.get("attributes", {})

        log.info("Received attribute push (request_id=%s): %s", request_id, attributes)

        with self._attributes_lock:
            self._cloud_attributes.update(attributes)

        # Acknowledge by publishing current attributes back
        self._publish_attributes()
