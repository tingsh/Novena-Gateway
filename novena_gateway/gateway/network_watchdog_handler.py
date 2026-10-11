"""Role-aware, conservative network uplink monitoring for the Gateway."""

import logging
import re
import subprocess
import threading
import time
from typing import Optional

from novena_gateway.gateway.privileged_helper import PrivilegedCommandRunner

log = logging.getLogger("novena_gateway.network_watchdog")
_UUID = re.compile(r"^[0-9a-fA-F-]{36}$")


class NetworkWatchdogHandler:
    """Monitor eligible uplinks without touching private equipment networks."""

    def __init__(self, gateway, config: Optional[dict] = None):
        self._gateway = gateway
        self._config = config or {}
        self._enabled = self._config.get("enabled", True)
        self._requested_mode = self._config.get("mode", "auto")
        self._helper = PrivilegedCommandRunner(self._config.get("helper_path"))
        self._watchdog_mode = self._resolve_mode()
        self._targets = self._config.get("health_targets", [self._config.get("ping_target", "8.8.8.8")])
        self._ping_interval = self._config.get("ping_interval_seconds", 15)
        self._ping_timeout = self._config.get("ping_timeout_seconds", 3)
        self._eth_iface = self._config.get("eth_interface", "eth0")
        self._wifi_iface = self._config.get("wifi_interface", "wlan0")
        self._fourg_iface = self._config.get("fourg_interface", "wwan0")
        self._interfaces = [i for i in (self._eth_iface, self._wifi_iface, self._fourg_iface) if i]
        self._roles = self._config.get("interface_roles", {})
        self.active_interface = ""
        self.failover_count = 0
        self.ethernet_status = "unknown"
        self.wifi_status = "unknown"
        self.fourg_status = "unknown"
        self.signal_strength = None
        self.interface_diagnostics = {}
        self._original_metrics = {}
        self._stopped = False
        self._watchdog_thread = None
        self._status_lock = threading.Lock()
        self._consecutive_preferred_successes = 0

    def _resolve_mode(self) -> str:
        if self._requested_mode == "diagnostic":
            return "diagnostic"
        if self._requested_mode == "active" and self._helper.available():
            return "active"
        if self._requested_mode == "active":
            return "diagnostic"
        return "active" if self._helper.available() else "diagnostic"

    def start(self):
        if not self._enabled:
            log.info("Network watchdog is disabled.")
            return
        self._stopped = False
        self._watchdog_mode = self._resolve_mode()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, name="NetWatchdog", daemon=True)
        self._watchdog_thread.start()
        log.info("Network watchdog started in %s mode", self._watchdog_mode)

    def stop(self):
        self._stopped = True
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=30)
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            log.warning("Watchdog still running; deferring metric restoration")
            return
        self._restore_metrics()
        log.info("Network watchdog stopped")

    def _watchdog_loop(self):
        while not self._stopped:
            try:
                self._check_network()
            except Exception:
                log.exception("Error checking network status")
            for _ in range(self._ping_interval):
                if self._stopped:
                    break
                time.sleep(1)

    @staticmethod
    def _default_routes() -> dict:
        """Read kernel IPv4 defaults, including backup routes with higher metrics."""
        routes = {}
        try:
            with open("/proc/net/route", encoding="ascii") as route_file:
                next(route_file)
                for line in route_file:
                    fields = line.split()
                    if len(fields) < 8 or fields[1] != "00000000" or fields[7] != "00000000":
                        continue
                    if not (int(fields[3], 16) & 1):
                        continue
                    metric = int(fields[6])
                    routes[fields[0]] = min(metric, routes.get(fields[0], metric))
        except (OSError, ValueError, StopIteration) as exc:
            log.warning("Cannot inspect default routes: %s", exc)
        return routes

    def _role(self, interface: str, routes: dict) -> tuple[str, str]:
        configured = self._roles.get(interface)
        if configured:
            return configured, "configured"
        if interface in routes:
            return "uplink", "default_route"
        return "field", "no_default_route"

    def _ping_interface(self, interface: str) -> bool:
        for target in self._targets:
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(self._ping_timeout), "-I", interface, target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=self._ping_timeout + 1,
                )
                if result.returncode == 0:
                    return True
            except (OSError, subprocess.TimeoutExpired):
                pass
        return False

    def _is_interface_physically_up(self, interface: str) -> bool:
        try:
            with open(f"/sys/class/net/{interface}/operstate", encoding="ascii") as state_file:
                return state_file.read().strip() == "up"
        except OSError:
            return False

    @staticmethod
    def _nm_profile(interface: str) -> Optional[tuple[str, int]]:
        """Resolve the active UUID, never assume an interface is a profile name."""
        try:
            uuid_result = subprocess.run(
                ["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", interface],
                capture_output=True, text=True, timeout=3,
            )
            uuid = uuid_result.stdout.strip()
            if uuid_result.returncode or not _UUID.fullmatch(uuid):
                return None
            metric_result = subprocess.run(
                ["nmcli", "-g", "ipv4.route-metric", "connection", "show", "uuid", uuid],
                capture_output=True, text=True, timeout=3,
            )
            if metric_result.returncode:
                return None
            return uuid, int(metric_result.stdout.strip())
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None

    def _set_interface_metric(self, interface: str, metric: int) -> bool:
        if self._watchdog_mode != "active":
            return True
        profile = self._nm_profile(interface)
        if not profile:
            log.warning("No active NetworkManager profile for uplink %s; route unchanged", interface)
            return False
        uuid, original = profile
        result = self._helper.set_route_metric(interface, uuid, metric)
        if not result.get("ok"):
            log.warning("Metric change for %s (%s) failed: %s", interface, uuid, result.get("stderr"))
            return False
        self._original_metrics.setdefault(interface, (uuid, original))
        return True

    def _restore_metrics(self):
        if self._watchdog_mode != "active":
            return
        for interface, (uuid, metric) in list(self._original_metrics.items()):
            profile = self._nm_profile(interface)
            if not profile or profile[0] != uuid:
                log.warning("Profile changed on %s; skipping metric restoration", interface)
                continue
            result = self._helper.set_route_metric(interface, uuid, metric)
            if result.get("ok"):
                del self._original_metrics[interface]
            else:
                log.warning("Could not restore metric on %s: %s", interface, result.get("stderr"))

    def _check_network(self):
        routes = self._default_routes()
        diagnostics = {}
        for interface in self._interfaces:
            role, reason = self._role(interface, routes)
            physical = self._is_interface_physically_up(interface)
            eligible = role == "uplink" and interface in routes
            probe_ok = self._ping_interface(interface) if eligible and physical else None
            diagnostics[interface] = {
                "role": role, "role_reason": reason, "physical_up": physical,
                "default_route": interface in routes, "probe_ok": probe_ok,
                "status": (
                    "field" if role == "field" else
                    "no_default_route" if not eligible else
                    "down" if not physical else
                    "up" if probe_ok else "probe_failed"
                ),
            }
        healthy = [i for i in self._interfaces if diagnostics[i]["probe_ok"]]
        preferred = healthy[0] if healthy else ""
        with self._status_lock:
            current = self.active_interface
        initial = not current
        if initial:
            routed_uplinks = [i for i in self._interfaces if i in routes and diagnostics[i]["role"] == "uplink"]
            current = min(routed_uplinks, key=routes.get) if routed_uplinks else ""
        # A primary must recover for three checks before preempting a healthy backup.
        candidate = current
        if current not in healthy:
            candidate = preferred
            self._consecutive_preferred_successes = 0
        elif preferred and preferred != current:
            self._consecutive_preferred_successes += 1
            if self._consecutive_preferred_successes >= 3:
                candidate = preferred
        else:
            self._consecutive_preferred_successes = 0

        changed = bool(initial and current)
        if candidate and candidate != current:
            # The selected uplink already owns the best default route: no mutation needed.
            selected_metric = routes.get(candidate)
            other_metrics = [routes[i] for i in self._interfaces if i != candidate and i in routes and diagnostics[i]["role"] == "uplink"]
            needs_metric = bool(other_metrics and selected_metric >= min(other_metrics))
            success = not needs_metric or (
                self._watchdog_mode == "active"
                and min(other_metrics) > 0
                and self._set_interface_metric(candidate, min(other_metrics) - 1)
            )
            if success:
                with self._status_lock:
                    self.active_interface = candidate
                    if current and needs_metric:
                        self.failover_count += 1
                changed = True
            else:
                diagnostics[candidate]["action_error"] = "metric_change_failed"
                if initial and current:
                    with self._status_lock:
                        self.active_interface = current
        elif not candidate and current:
            with self._status_lock:
                self.active_interface = ""
            changed = True
        elif initial and current:
            with self._status_lock:
                self.active_interface = current

        # Restore only uplinks no longer selected, never a field interface.
        for interface in list(self._original_metrics):
            if interface != self.active_interface:
                if diagnostics.get(interface, {}).get("role") != "uplink":
                    continue
                uuid, metric = self._original_metrics[interface]
                profile = self._nm_profile(interface)
                if profile and profile[0] == uuid:
                    result = self._helper.set_route_metric(interface, uuid, metric)
                    if result.get("ok"):
                        del self._original_metrics[interface]
        signal = self._get_signal_strength()
        with self._status_lock:
            self.interface_diagnostics = diagnostics
            self.ethernet_status = diagnostics.get(self._eth_iface, {}).get("status", "disconnected")
            self.wifi_status = diagnostics.get(self._wifi_iface, {}).get("status", "disconnected")
            self.fourg_status = diagnostics.get(self._fourg_iface, {}).get("status", "disconnected")
            self.signal_strength = signal
        if changed:
            self._notify_attribute_sync()

    def _get_signal_strength(self) -> Optional[int]:
        try:
            res = subprocess.run(["mmcli", "-m", "any", "--simple-status"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "signal quality" in line:
                        pct = int(line.split(":", 1)[1].strip().strip("'\"%").strip())
                        return int((pct / 2) - 100)
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
            pass
        try:
            res = subprocess.run(["nmcli", "-t", "-f", "active,signal", "device", "wifi"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith("yes:"):
                        return int((int(line.split(":", 1)[1]) / 2) - 100)
        except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
            pass
        return None

    def _notify_attribute_sync(self):
        try:
            if getattr(self._gateway, "_attribute_sync", None):
                self._gateway._attribute_sync._publish_attributes()
        except Exception as exc:
            log.warning("Failed to trigger proactive attribute publish: %s", exc)

    def collect_watchdog_attributes(self) -> dict:
        with self._status_lock:
            return {
                "active_interface": self.active_interface,
                "failover_count": self.failover_count,
                "ethernet_status": self.ethernet_status,
                "wifi_status": self.wifi_status,
                "fourg_status": self.fourg_status,
                "signal_strength": self.signal_strength,
                "watchdog_mode": self._watchdog_mode,
                "privilege_helper_available": self._helper.available(),
                "interface_diagnostics": dict(self.interface_diagnostics),
            }
