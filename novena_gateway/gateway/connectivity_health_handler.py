"""
Connectivity health diagnostics for customer-site troubleshooting.

This handler answers a practical edge question: can this gateway reach the
Novena broker, not just "does it have an IP address?"  The resulting attributes
are intentionally plain so Novena Hub can show actionable messages to support
staff and non-technical operators.
"""

import logging
import socket
import ssl
import subprocess
import threading
from time import sleep, time
from typing import Optional

log = logging.getLogger("novena_gateway.connectivity_health")


class ConnectivityHealthHandler:
    """Periodically checks route, DNS, TCP, TLS, and MQTT connection health."""

    DEFAULT_INTERVAL_SECONDS = 120

    def __init__(self, gateway, publisher, serial_number: str, mqtt_config: dict, config: Optional[dict] = None):
        self._gateway = gateway
        self._publisher = publisher
        self._serial_number = serial_number
        self._mqtt_config = mqtt_config or {}
        self._config = config or {}

        self._enabled = self._config.get("enabled", True)
        self._interval_seconds = self._config.get(
            "interval_seconds", self.DEFAULT_INTERVAL_SECONDS
        )
        self._timeout_seconds = self._config.get("timeout_seconds", 5)

        self._stopped = False
        self._thread = None
        self._lock = threading.Lock()
        self._last_health = self._empty_health()

    def start(self):
        if not self._enabled:
            log.info("Connectivity health handler is disabled.")
            return

        self._stopped = False
        self.run_check()
        self._publish_health()
        self._thread = threading.Thread(
            target=self._health_loop, name="ConnectivityHealth", daemon=True
        )
        self._thread.start()
        log.info("Connectivity health handler started (interval=%ds)", self._interval_seconds)

    def stop(self):
        self._stopped = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def collect_connectivity_attributes(self) -> dict:
        with self._lock:
            return dict(self._last_health)

    def run_check(self) -> dict:
        host = self._mqtt_config.get("host", "")
        port = int(self._mqtt_config.get("port", 8883 if self._mqtt_config.get("tls") else 1883))
        tls_config = self._mqtt_config.get("tls")

        route = self._check_default_route()
        dns = self._check_dns(host, port)
        tcp = self._check_tcp(dns.get("address") or host, port) if dns["ok"] else {
            "ok": False,
            "error": "dns_failed",
        }
        tls = self._check_tls(host, port, tls_config) if tls_config and tcp["ok"] else {
            "ok": True if not tls_config else False,
            "error": None if not tls_config else tcp.get("error"),
        }

        mqtt_connected = bool(self._publisher.is_connected()) if self._publisher else False
        mqtt_last_error = None
        if self._publisher and hasattr(self._publisher, "get_connection_diagnostics"):
            mqtt_last_error = self._publisher.get_connection_diagnostics().get("mqtt_last_error")

        health = {
            "connectivity_checked_ts": int(time() * 1000),
            "internet_reachable": bool(route["ok"] and (tcp["ok"] or mqtt_connected)),
            "default_route_ok": route["ok"],
            "default_route_error": route.get("error"),
            "dns_ok": dns["ok"],
            "dns_error": dns.get("error"),
            "broker_host": host,
            "broker_port": port,
            "broker_tcp_ok": tcp["ok"],
            "broker_tcp_error": tcp.get("error"),
            "tls_ok": tls["ok"],
            "tls_error": tls.get("error"),
            "mqtt_connected": mqtt_connected,
            "mqtt_last_error": mqtt_last_error,
        }

        with self._lock:
            self._last_health = health
        return dict(health)

    def _empty_health(self) -> dict:
        host = self._mqtt_config.get("host", "")
        port = int(self._mqtt_config.get("port", 8883 if self._mqtt_config.get("tls") else 1883))
        return {
            "connectivity_checked_ts": None,
            "internet_reachable": False,
            "default_route_ok": None,
            "default_route_error": None,
            "dns_ok": None,
            "dns_error": None,
            "broker_host": host,
            "broker_port": port,
            "broker_tcp_ok": None,
            "broker_tcp_error": None,
            "tls_ok": None,
            "tls_error": None,
            "mqtt_connected": False,
            "mqtt_last_error": None,
        }

    def _health_loop(self):
        while not self._stopped:
            for _ in range(int(self._interval_seconds)):
                if self._stopped:
                    return
                sleep(1)
            try:
                self.run_check()
                self._publish_health()
            except Exception as e:
                log.warning("Connectivity health check failed: %s", e)

    def _publish_health(self):
        payload = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": self.collect_connectivity_attributes(),
        }
        self._publisher.publish_attributes(payload)

    def _check_default_route(self) -> dict:
        try:
            res = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
            )
            output = (res.stdout or res.stderr or "").strip()
            return {"ok": res.returncode == 0 and bool(output), "error": None if output else "missing_default_route"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _check_dns(self, host: str, port: int) -> dict:
        if not host:
            return {"ok": False, "error": "missing_host", "address": None}
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            address = records[0][4][0] if records else None
            return {"ok": bool(address), "error": None, "address": address}
        except Exception as e:
            return {"ok": False, "error": str(e), "address": None}

    def _check_tcp(self, host: str, port: int) -> dict:
        try:
            with socket.create_connection((host, port), timeout=self._timeout_seconds):
                return {"ok": True, "error": None}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _check_tls(self, host: str, port: int, tls_config: dict) -> dict:
        try:
            context = ssl.create_default_context()
            ca_certs = tls_config.get("ca_certs")
            if ca_certs:
                context.load_verify_locations(cafile=ca_certs)
            with socket.create_connection((host, port), timeout=self._timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return {"ok": True, "error": None}
        except Exception as e:
            return {"ok": False, "error": str(e)}
