"""Interface to the scoped Novena Gateway privileged helper."""

import os
import shutil
import subprocess
from typing import Optional


DEFAULT_HELPER_PATH = "/usr/local/sbin/novena-gateway-helper"


class PrivilegedCommandRunner:
    """Runs privileged appliance operations through a narrow helper command."""

    def __init__(self, helper_path: Optional[str] = None):
        self._helper_path = helper_path or os.environ.get(
            "NOVENA_GATEWAY_HELPER", DEFAULT_HELPER_PATH
        )

    @property
    def helper_path(self) -> str:
        return self._helper_path

    def available(self) -> bool:
        return os.path.exists(self._helper_path) or shutil.which(self._helper_path) is not None

    def diagnostics(self) -> dict:
        return {
            "privilege_helper_path": self._helper_path,
            "privilege_helper_available": self.available(),
        }

    def run(self, action: str, *args, timeout: int = 30) -> dict:
        if not self.available():
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": f"privileged helper not installed: {self._helper_path}",
                "privilege_available": False,
            }

        cmd = ["sudo", "-n", self._helper_path, action, *[str(arg) for arg in args]]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "ok": res.returncode == 0,
                "returncode": res.returncode,
                "stdout": (res.stdout or "").strip()[:2000],
                "stderr": (res.stderr or "").strip()[:2000],
                "privilege_available": True,
            }
        except Exception as e:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": str(e),
                "privilege_available": True,
            }

    def reboot(self, delay_seconds: int) -> dict:
        return self.run("reboot", int(delay_seconds), timeout=5)

    def restart_service(self, service_name: str = "novena-gateway") -> dict:
        return self.run("restart-service", service_name, timeout=10)

    def set_route_metric(self, interface: str, metric: int) -> dict:
        return self.run("set-route-metric", interface, int(metric), timeout=20)

    def configure_can(self, interface: str = "can0", bitrate: int = 500000) -> dict:
        return self.run("configure-can", interface, int(bitrate), timeout=20)
