"""Hardware readiness checks for Raspberry Pi CM4 Waveshare deployments."""

import glob
import json
import os
import shutil
import subprocess
from typing import Optional

from novena_gateway.gateway.privileged_helper import PrivilegedCommandRunner


BOOT_CONFIG_CANDIDATES = (
    "/boot/firmware/config.txt",
    "/boot/config.txt",
)


class HardwarePreflight:
    """Collects read-only appliance checks for customer-site deployment."""

    def __init__(self, config: Optional[dict] = None, helper: Optional[PrivilegedCommandRunner] = None):
        self._config = config or {}
        self._helper = helper or PrivilegedCommandRunner()

    def run(self) -> dict:
        hardware_cfg = self._config.get("hardware", {})
        can_cfg = hardware_cfg.get("can", {})
        rs485_cfg = hardware_cfg.get("rs485", {})
        rtc_cfg = hardware_cfg.get("rtc", {})

        boot_config = self._read_boot_config()
        checks = {
            "boot_config": boot_config,
            "usb_host_overlay": self._contains_any(boot_config.get("content", ""), ["otg_mode=1", "dr_mode=host"]),
            "spi_enabled": self._contains_any(boot_config.get("content", ""), ["dtparam=spi=on"]),
            "can_overlay": self._contains_any(boot_config.get("content", ""), ["mcp2515", "mcp251xfd"]),
            "rtc_overlay": self._contains_any(boot_config.get("content", ""), ["i2c-rtc", "pcf85063", "ds3231"]) if rtc_cfg.get("enabled", True) else True,
            "rs485_uart_overlays": self._rs485_uart_checks(boot_config.get("content", ""), rs485_cfg),
            "serial_ports": sorted(glob.glob("/dev/ttyAMA*") + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")),
            "can_interfaces": sorted(glob.glob("/sys/class/net/can*")),
            "can0_present": os.path.exists("/sys/class/net/can0"),
            "can_bitrate_configured": bool(can_cfg.get("bitrate", 500000)),
            "nmcli_available": shutil.which("nmcli") is not None,
            "mmcli_available": shutil.which("mmcli") is not None,
            "ip_available": shutil.which("ip") is not None,
            "privilege": self._helper.diagnostics(),
            "disk": self._disk_check(),
            "clock": self._clock_check(),
            "user_groups": self._user_groups(),
        }
        checks["ok"] = self._overall_ok(checks)
        checks["warnings"] = self._warnings(checks)
        return checks

    def _read_boot_config(self) -> dict:
        for candidate in BOOT_CONFIG_CANDIDATES:
            if os.path.exists(candidate):
                try:
                    with open(candidate, "r") as f:
                        return {"path": candidate, "exists": True, "content": f.read()}
                except Exception as e:
                    return {"path": candidate, "exists": True, "content": "", "error": str(e)}
        return {"path": None, "exists": False, "content": ""}

    @staticmethod
    def _contains_any(content: str, needles: list) -> bool:
        return any(needle in content for needle in needles)

    def _rs485_uart_checks(self, content: str, rs485_cfg: dict) -> dict:
        uarts = rs485_cfg.get("uarts", ["uart3", "uart5"])
        return {uart: f"dtoverlay={uart}" in content or uart in content for uart in uarts}

    def _disk_check(self) -> dict:
        path = self._config.get("storage", {}).get("sqlite", {}).get("data_file_path", "/var/lib/novena-gateway/sqlite/")
        target = path if os.path.exists(path) else os.path.dirname(path) or "/"
        try:
            usage = shutil.disk_usage(target)
            free_mb = int(usage.free / (1024 * 1024))
            return {"path": target, "free_mb": free_mb, "ok": free_mb >= 512}
        except Exception as e:
            return {"path": target, "free_mb": None, "ok": False, "error": str(e)}

    def _clock_check(self) -> dict:
        try:
            res = subprocess.run(["timedatectl", "show", "-p", "SystemClockSynchronized", "--value"],
                                 capture_output=True, text=True, timeout=3)
            value = (res.stdout or "").strip()
            return {"ok": res.returncode == 0 and value.lower() == "yes", "synchronized": value}
        except Exception as e:
            return {"ok": False, "synchronized": None, "error": str(e)}

    def _user_groups(self) -> dict:
        try:
            res = subprocess.run(["id", "-nG"], capture_output=True, text=True, timeout=3)
            groups = (res.stdout or "").strip().split()
            return {"groups": groups, "dialout": "dialout" in groups}
        except Exception as e:
            return {"groups": [], "dialout": False, "error": str(e)}

    def _overall_ok(self, checks: dict) -> bool:
        core = [
            checks["boot_config"]["exists"],
            checks["usb_host_overlay"],
            checks["spi_enabled"],
            checks["can_overlay"],
            all(checks["rs485_uart_overlays"].values()),
            checks["ip_available"],
            checks["disk"]["ok"],
        ]
        return all(core)

    def _warnings(self, checks: dict) -> list:
        warnings = []
        if not checks["boot_config"]["exists"]:
            warnings.append("boot config not found")
        for key in ("usb_host_overlay", "spi_enabled", "can_overlay", "rtc_overlay"):
            if checks.get(key) is False:
                warnings.append(f"{key} missing")
        for uart, ok in checks["rs485_uart_overlays"].items():
            if not ok:
                warnings.append(f"RS485 UART overlay missing: {uart}")
        if not checks["can0_present"]:
            warnings.append("can0 interface not present")
        if not checks["nmcli_available"]:
            warnings.append("nmcli not installed; network watchdog will run diagnostics only")
        if not checks["mmcli_available"]:
            warnings.append("mmcli not installed; 4G modem signal diagnostics unavailable")
        if not checks["privilege"]["privilege_helper_available"]:
            warnings.append("privileged helper not installed")
        if not checks["user_groups"].get("dialout"):
            warnings.append("current user is not in dialout group")
        return warnings


def run_preflight(config: Optional[dict] = None) -> dict:
    return HardwarePreflight(config).run()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Novena Gateway hardware preflight")
    parser.add_argument("--config", help="Path to config.json")
    args = parser.parse_args()

    config = {}
    if args.config:
        with open(args.config, "r") as f:
            config = json.load(f)
    print(json.dumps(run_preflight(config), indent=2))


if __name__ == "__main__":
    main()
