"""Regression coverage for Gateway field networks and uplink failover."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from novena_gateway.gateway.network_watchdog_handler import NetworkWatchdogHandler

UUID = "11111111-2222-3333-4444-555555555555"


class TestNetworkWatchdogHandler(unittest.TestCase):
    def setUp(self):
        self.gateway = MagicMock()
        self.handler = NetworkWatchdogHandler(self.gateway, {
            "eth_interface": "eth0", "wifi_interface": "wlan0", "fourg_interface": "wwan0",
            "health_targets": ["8.8.8.8", "1.1.1.1"],
        })
        self.handler._watchdog_mode = "active"
        self.handler._helper = MagicMock()
        self.handler._helper.set_route_metric.return_value = {"ok": True}
        self.route = patch.object(self.handler, "_default_routes", return_value={"wlan0": 600})
        self.physical = patch.object(self.handler, "_is_interface_physically_up", return_value=True)
        self.ping = patch.object(self.handler, "_ping_interface", return_value=True)
        self.signal = patch.object(self.handler, "_get_signal_strength", return_value=-60)
        for mock_patch in (self.route, self.physical, self.ping, self.signal):
            mock_patch.start()
            self.addCleanup(mock_patch.stop)

    def test_field_ethernet_is_never_probed_or_modified(self):
        self.handler._check_network()
        attrs = self.handler.collect_watchdog_attributes()
        self.assertEqual(attrs["active_interface"], "wlan0")
        self.assertEqual(attrs["ethernet_status"], "field")
        self.assertEqual(attrs["interface_diagnostics"]["eth0"]["role_reason"], "no_default_route")
        self.handler._ping_interface.assert_called_once_with("wlan0")
        self.handler._helper.set_route_metric.assert_not_called()
        self.gateway._attribute_sync._publish_attributes.assert_called_once()

    def test_explicit_field_role_wins_even_with_default_route(self):
        self.handler._roles = {"eth0": "field"}
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600}
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "wlan0")
        self.assertEqual(self.handler.interface_diagnostics["eth0"]["role_reason"], "configured")
        self.handler._ping_interface.assert_called_once_with("wlan0")

    def test_ethernet_uplink_and_wifi_recovery(self):
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600}
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.handler._ping_interface.side_effect = lambda iface: iface == "wlan0"
        with patch.object(self.handler, "_nm_profile", return_value=(UUID, -1)):
            self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "wlan0")
        self.assertEqual(self.handler.failover_count, 1)
        self.handler._helper.set_route_metric.assert_called_with("wlan0", UUID, 99)
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 99}
        self.handler._ping_interface.side_effect = lambda iface: True
        with patch.object(self.handler, "_nm_profile", return_value=(UUID, -1)):
            for _ in range(3):
                self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.assertEqual(self.handler.failover_count, 2)
        self.handler._helper.set_route_metric.assert_any_call("wlan0", UUID, -1)

    def test_optional_cellular_wins_when_wifi_unhealthy(self):
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600, "wwan0": 700}
        self.handler._ping_interface.side_effect = lambda iface: iface == "wwan0"
        with patch.object(self.handler, "_nm_profile", return_value=(UUID, -1)):
            self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "wwan0")
        self.handler._helper.set_route_metric.assert_called_once_with("wwan0", UUID, 99)

    def test_missing_profile_does_not_claim_failover(self):
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600}
        self.handler.active_interface = "eth0"
        self.handler._ping_interface.side_effect = lambda iface: iface == "wlan0"
        with patch.object(self.handler, "_nm_profile", return_value=None):
            self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.assertEqual(self.handler.failover_count, 0)
        self.assertEqual(self.handler.interface_diagnostics["wlan0"]["action_error"], "metric_change_failed")
        self.handler._helper.set_route_metric.assert_not_called()

    def test_failed_metric_action_does_not_claim_failover(self):
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600}
        self.handler.active_interface = "eth0"
        self.handler._ping_interface.side_effect = lambda iface: iface == "wlan0"
        self.handler._helper.set_route_metric.return_value = {"ok": False, "stderr": "rejected"}
        with patch.object(self.handler, "_nm_profile", return_value=(UUID, -1)):
            self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.assertEqual(self.handler.failover_count, 0)

    def test_diagnostic_mode_does_not_claim_route_change(self):
        self.handler._default_routes.return_value = {"eth0": 100, "wlan0": 600}
        self.handler.active_interface = "eth0"
        self.handler._watchdog_mode = "diagnostic"
        self.handler._ping_interface.side_effect = lambda iface: iface == "wlan0"
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.assertEqual(self.handler.failover_count, 0)

    @patch("subprocess.run")
    def test_multiple_health_targets(self, run):
        run.side_effect = [MagicMock(returncode=1), MagicMock(returncode=0)]
        self.assertTrue(NetworkWatchdogHandler._ping_interface(self.handler, "wlan0"))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][-1], "1.1.1.1")

    @patch("subprocess.run")
    def test_profile_resolution_uses_active_uuid(self, run):
        run.side_effect = [MagicMock(returncode=0, stdout=UUID + "\n"), MagicMock(returncode=0, stdout="-1\n")]
        self.assertEqual(self.handler._nm_profile("wlan0"), (UUID, -1))
        self.assertEqual(run.call_args.args[0][-2:], ["uuid", UUID])

    def test_notification_runs_outside_status_lock(self):
        def publish():
            self.assertTrue(self.handler._status_lock.acquire(blocking=False))
            self.handler._status_lock.release()
            self.handler.collect_watchdog_attributes()
        self.gateway._attribute_sync._publish_attributes.side_effect = publish
        self.handler._check_network()

    def test_invalid_roles_and_targets_fail_config_validation(self):
        from novena_gateway.gateway.novena_gateway import NovenaGateway

        config = {
            "gateway": {"serial_number": "NF-TEST"},
            "mqtt": {"host": "localhost", "port": 1883},
            "connectors": [],
            "features": {"network_watchdog": {
                "interface_roles": {"eth0": "field", "wlan0": "invalid"},
                "health_targets": [],
            }},
        }
        errors = NovenaGateway.validate_config(config)
        self.assertTrue(any("interface_roles" in error for error in errors))
        self.assertTrue(any("health_targets" in error for error in errors))

    def test_helper_uses_active_uuid_without_reactivating_profile(self):
        helper = Path(__file__).resolve().parents[1] / "install/novena-gateway-helper"
        with tempfile.TemporaryDirectory() as temp_dir:
            calls = Path(temp_dir) / "calls"
            nmcli = Path(temp_dir) / "nmcli"
            nmcli.write_text(
                "#!/bin/sh\n"
                f"echo \"$*\" >> '{calls}'\n"
                f"if [ \"$1\" = -g ]; then echo '{UUID}'; fi\n"
            )
            nmcli.chmod(0o755)
            env = {**os.environ, "PATH": f"{temp_dir}:{os.environ['PATH']}"}
            result = subprocess.run(
                ["bash", str(helper), "set-route-metric", "wlan0", UUID, "99"],
                capture_output=True, text=True, env=env, timeout=3,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), [
                "-g GENERAL.CON-UUID device show wlan0",
                "device modify wlan0 ipv4.route-metric 99",
            ])
            calls.write_text("")
            rejected = subprocess.run(
                ["bash", str(helper), "set-route-metric", "wlan0", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "99"],
                capture_output=True, text=True, env=env, timeout=3,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(calls.read_text().splitlines(), ["-g GENERAL.CON-UUID device show wlan0"])


if __name__ == "__main__":
    unittest.main()
