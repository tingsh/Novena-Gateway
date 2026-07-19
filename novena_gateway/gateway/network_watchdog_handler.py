import logging
import subprocess
import threading
import time
from typing import Optional
from novena_gateway.gateway.privileged_helper import PrivilegedCommandRunner

log = logging.getLogger("novena_gateway.network_watchdog")


class NetworkWatchdogHandler:
    """
    Actively monitors gateway internet connectivity using a 3-tier Multi-WAN hierarchy.
    Manages dynamic route metric manipulation via nmcli when a zombie link is detected,
    and handles graceful fallback to primary Ethernet when connectivity heals.
    """

    def __init__(self, gateway, config: Optional[dict] = None):
        self._gateway = gateway
        self._config = config or {}

        self._enabled = self._config.get("enabled", True)
        self._requested_mode = self._config.get("mode", "auto")
        self._helper = PrivilegedCommandRunner(self._config.get("helper_path"))
        self._watchdog_mode = self._resolve_mode()
        self._ping_target = self._config.get("ping_target", "8.8.8.8")
        self._ping_interval = self._config.get("ping_interval_seconds", 15)
        self._ping_timeout = self._config.get("ping_timeout_seconds", 3)

        # Interface definitions
        self._eth_iface = self._config.get("eth_interface", "eth0")
        self._wifi_iface = self._config.get("wifi_interface", "wlan0")
        self._fourg_iface = self._config.get("fourg_interface", "wwan0")

        # Default route metrics
        self._eth_metric = self._config.get("eth_metric", 100)
        self._wifi_metric = self._config.get("wifi_metric", 600)
        self._fourg_metric = self._config.get("fourg_metric", 700)

        # Watchdog status state
        self.active_interface = self._eth_iface
        self.failover_count = 0
        self.ethernet_status = "unknown"
        self.wifi_status = "unknown"
        self.fourg_status = "unknown"
        self.signal_strength = None

        self._stopped = False
        self._watchdog_thread = None
        self._status_lock = threading.Lock()

        # Track consecutive failures or successes for healing
        self._consecutive_eth_successes = 0

    def _resolve_mode(self) -> str:
        if self._requested_mode == "diagnostic":
            return "diagnostic"
        if self._requested_mode == "active" and self._helper.available():
            return "active"
        if self._requested_mode == "active":
            return "diagnostic"
        return "active" if self._helper.available() else "diagnostic"

    def start(self):
        """Start the watchdog thread."""
        if not self._enabled:
            log.info("Network watchdog is disabled.")
            return

        self._stopped = False
        self._watchdog_mode = self._resolve_mode()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, name="NetWatchdog", daemon=True
        )
        self._watchdog_thread.start()
        log.info("Network watchdog daemon started.")

    def stop(self):
        """Stop the watchdog thread and restore default metrics."""
        self._stopped = True
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=3)
        if self._watchdog_mode == "active":
            self._restore_default_metrics()
        log.info("Network watchdog daemon stopped.")

    def _watchdog_loop(self):
        """Periodically run network interface checks."""
        while not self._stopped:
            try:
                self._check_network()
            except Exception as e:
                log.exception("Error checking network status: %s", e)

            # Sleep in small increments to allow responsive shutdown
            for _ in range(self._ping_interval):
                if self._stopped:
                    break
                time.sleep(1)

    def _check_network(self):
        """Perform ping checks, run state machine, and handle metric changes."""
        # 1. Update interface statuses
        eth_ok = self._ping_interface(self._eth_iface)
        wifi_ok = self._ping_interface(self._wifi_iface)
        fourg_ok = self._ping_interface(self._fourg_iface)

        self.signal_strength = self._get_signal_strength()

        with self._status_lock:
            # Check physical state vs ping state to identify zombie
            self.ethernet_status = "up" if eth_ok else ("zombie" if self._is_interface_physically_up(self._eth_iface) else "down")
            self.wifi_status = "up" if wifi_ok else ("down" if self._is_interface_physically_up(self._wifi_iface) else "disconnected")
            self.fourg_status = "up" if fourg_ok else ("down" if self._is_interface_physically_up(self._fourg_iface) else "disconnected")

            previous_interface = self.active_interface

            # State machine for failover and recovery
            if self.active_interface == self._eth_iface:
                if not eth_ok:
                    log.warning("Ethernet connection failed (Status: %s). Initiating failover.", self.ethernet_status)
                    self._consecutive_eth_successes = 0
                    self._execute_failover(wifi_ok, fourg_ok)
            else:
                # We are in failover mode on wifi or 4g. Test ethernet for recovery.
                if eth_ok:
                    self._consecutive_eth_successes += 1
                    if self._consecutive_eth_successes >= 3:
                        log.info("Ethernet connectivity has stabilized. Failing back to primary Ethernet.")
                        self._restore_default_metrics()
                        self.active_interface = self._eth_iface
                        self.failover_count += 1
                else:
                    self._consecutive_eth_successes = 0

                    # If current interface fails, check if we need to switch between backup interfaces
                    if self.active_interface == self._wifi_iface and not wifi_ok:
                        log.warning("Secondary Wi-Fi failed. Checking tertiary 4G.")
                        self._execute_failover(False, fourg_ok)
                    elif self.active_interface == self._fourg_iface and not fourg_ok and wifi_ok:
                        log.warning("Tertiary 4G failed, but Wi-Fi is back. Switching to Wi-Fi.")
                        self._execute_failover(wifi_ok, False)

            # If state changed, trigger attribute sync immediately
            if previous_interface != self.active_interface or self.failover_count == 0:
                self._notify_attribute_sync()

    def _execute_failover(self, wifi_ok: bool, fourg_ok: bool):
        """Adjust route metrics to prioritize backup WAN."""
        if wifi_ok:
            log.info("Failing over to Secondary Wi-Fi (%s)", self._wifi_iface)
            self._set_interface_metric(self._wifi_iface, 50)  # Metric 50 beats Ethernet metric 100
            self._set_interface_metric(self._fourg_iface, self._fourg_metric)
            self.active_interface = self._wifi_iface
            self.failover_count += 1
        elif fourg_ok:
            log.info("Failing over to Fallback 4G/LTE (%s)", self._fourg_iface)
            self._set_interface_metric(self._fourg_iface, 50)  # Metric 50 beats Ethernet metric 100
            self._set_interface_metric(self._wifi_iface, self._wifi_metric)
            self.active_interface = self._fourg_iface
            self.failover_count += 1
        else:
            log.error("All internet interfaces are offline! Keeping default metrics.")
            self._restore_default_metrics()
            self.active_interface = self._eth_iface

    def _restore_default_metrics(self):
        """Restore default route metrics for all WAN connections."""
        log.info("Restoring default route metrics (Eth=%d, WiFi=%d, 4G=%d)",
                 self._eth_metric, self._wifi_metric, self._fourg_metric)
        self._set_interface_metric(self._eth_iface, self._eth_metric)
        self._set_interface_metric(self._wifi_iface, self._wifi_metric)
        self._set_interface_metric(self._fourg_iface, self._fourg_metric)

    def _ping_interface(self, interface: str) -> bool:
        """Run an interface-bound ping connectivity test."""
        if not interface:
            return False
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(self._ping_timeout), "-I", interface, self._ping_target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self._ping_timeout + 1
            )
            return res.returncode == 0
        except Exception:
            return False

    def _is_interface_physically_up(self, interface: str) -> bool:
        """Check if interface operstate is up."""
        try:
            with open(f"/sys/class/net/{interface}/operstate", "r") as f:
                state = f.read().strip()
                return state != "down"
        except Exception:
            return False

    def _set_interface_metric(self, interface: str, metric: int):
        """Issue nmcli connection modification and reload interface."""
        if not interface:
            return
        log.info("Setting route metric for %s to %d", interface, metric)
        if self._watchdog_mode != "active":
            log.info("Network watchdog is in diagnostic mode; not changing route metric.")
            return
        try:
            result = self._helper.set_route_metric(interface, metric)
            if not result.get("ok"):
                raise RuntimeError(result.get("stderr") or "privileged helper failed")
        except Exception as e:
            log.warning("Failed to modify route metric for %s to %d: %s", interface, metric, e)

    def _get_signal_strength(self) -> Optional[int]:
        """Try mmcli and nmcli to fetch active signal strength."""
        try:
            res = subprocess.run(["mmcli", "-m", "any", "--simple-status"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "signal quality" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            val = parts[1].strip().strip("'\"").replace("%", "")
                            pct = int(val)
                            return int((pct / 2) - 100)
        except Exception:
            pass

        try:
            res = subprocess.run(["nmcli", "-t", "-f", "active,signal", "device", "wifi"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith("yes:"):
                        val = line.split(":")[1]
                        pct = int(val)
                        return int((pct / 2) - 100)
        except Exception:
            pass

        return -70  # default fallback

    def _notify_attribute_sync(self):
        """Proactively trigger attribute synchronizer heartbeat publish."""
        try:
            if hasattr(self._gateway, "_attribute_sync") and self._gateway._attribute_sync:
                self._gateway._attribute_sync._publish_attributes()
        except Exception as e:
            log.warning("Failed to trigger proactive attribute publish: %s", e)

    def collect_watchdog_attributes(self) -> dict:
        """Returns current watchdog status values for MQTT attribute serialization."""
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
            }
