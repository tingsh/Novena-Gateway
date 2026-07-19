"""Unit tests for the NetworkWatchdogHandler."""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.network_watchdog_handler import NetworkWatchdogHandler


class MockGateway:
    def __init__(self):
        self._attribute_sync = MagicMock()


class TestNetworkWatchdogHandler(unittest.TestCase):

    def setUp(self):
        self.mock_gateway = MockGateway()
        self.config = {
            "enabled": True,
            "ping_target": "8.8.8.8",
            "ping_interval_seconds": 1,
            "ping_timeout_seconds": 1,
            "eth_interface": "eth0",
            "wifi_interface": "wlan0",
            "fourg_interface": "wwan0",
            "eth_metric": 100,
            "wifi_metric": 600,
            "fourg_metric": 700
        }
        self.handler = NetworkWatchdogHandler(self.mock_gateway, self.config)

    @patch("subprocess.run")
    def test_ping_interface_success(self, mock_run):
        """Test ping_interface returns True on success."""
        mock_run.return_value = MagicMock(returncode=0)
        
        result = self.handler._ping_interface("eth0")
        
        self.assertTrue(result)
        mock_run.assert_called_once_with(
            ["ping", "-c", "1", "-W", "1", "-I", "eth0", "8.8.8.8"],
            stdout=subprocess_devnull(),
            stderr=subprocess_devnull(),
            timeout=2
        )

    @patch("subprocess.run")
    def test_ping_interface_failure(self, mock_run):
        """Test ping_interface returns False on failure."""
        mock_run.return_value = MagicMock(returncode=1)
        
        result = self.handler._ping_interface("eth0")
        
        self.assertFalse(result)

    @patch("builtins.open")
    def test_is_interface_physically_up(self, mock_open):
        """Test physically up detection based on operstate."""
        # Setup mock file read
        mock_file = MagicMock()
        mock_file.read.return_value = "up\n"
        mock_open.return_value.__enter__.return_value = mock_file

        self.assertTrue(self.handler._is_interface_physically_up("eth0"))

        mock_file.read.return_value = "down\n"
        self.assertFalse(self.handler._is_interface_physically_up("eth0"))

    def test_set_interface_metric(self):
        """Setting interface route metric calls the privileged helper in active mode."""
        self.handler._watchdog_mode = "active"
        self.handler._helper = MagicMock()
        self.handler._helper.set_route_metric.return_value = {"ok": True}

        self.handler._set_interface_metric("wlan0", 50)

        self.handler._helper.set_route_metric.assert_called_once_with("wlan0", 50)

    def test_set_interface_metric_diagnostic_mode_does_not_mutate(self):
        self.handler._watchdog_mode = "diagnostic"
        self.handler._helper = MagicMock()

        self.handler._set_interface_metric("wlan0", 50)

        self.handler._helper.set_route_metric.assert_not_called()

    @patch("subprocess.run")
    def test_get_signal_strength_cellular(self, mock_run):
        """Test retrieving signal strength from cellular modem mmcli output."""
        mock_res = MagicMock(returncode=0, stdout="""
-------------------------
Status |   state: 'connected'
       |   signal quality: '80%'
""")
        mock_run.return_value = mock_res
        
        signal = self.handler._get_signal_strength()
        # Quality 80% -> dBm = (80 / 2) - 100 = -60
        self.assertEqual(signal, -60)

    @patch("subprocess.run")
    def test_get_signal_strength_wifi(self, mock_run):
        """Test retrieving signal strength from Wi-Fi nmcli output as fallback."""
        # 1st call for mmcli fails/errors
        # 2nd call for nmcli succeeds
        def run_side_effect(cmd, *args, **kwargs):
            if "mmcli" in cmd:
                raise FileNotFoundError()
            return MagicMock(returncode=0, stdout="yes:70\n")
        
        mock_run.side_effect = run_side_effect
        
        signal = self.handler._get_signal_strength()
        # Quality 70% -> dBm = (70 / 2) - 100 = -65
        self.assertEqual(signal, -65)

    @patch.object(NetworkWatchdogHandler, "_ping_interface")
    @patch.object(NetworkWatchdogHandler, "_is_interface_physically_up")
    @patch.object(NetworkWatchdogHandler, "_set_interface_metric")
    def test_failover_to_wifi(self, mock_set_metric, mock_phys_up, mock_ping):
        """If primary Ethernet fails but Wi-Fi succeeds, failover to Wi-Fi."""
        # eth ping fails, wifi ping succeeds, 4g ping succeeds
        mock_ping.side_effect = lambda iface: iface != "eth0"
        mock_phys_up.return_value = True  # Ethernet physically connected

        self.handler._check_network()

        self.assertEqual(self.handler.active_interface, "wlan0")
        self.assertEqual(self.handler.ethernet_status, "zombie")
        self.assertEqual(self.handler.wifi_status, "up")
        self.assertEqual(self.handler.failover_count, 1)

        # Should modify wifi metric to 50 and keep fallback 4g at 700
        mock_set_metric.assert_has_calls([
            call("wlan0", 50),
            call("wwan0", 700)
        ])

    @patch.object(NetworkWatchdogHandler, "_ping_interface")
    @patch.object(NetworkWatchdogHandler, "_is_interface_physically_up")
    @patch.object(NetworkWatchdogHandler, "_set_interface_metric")
    def test_failover_to_4g(self, mock_set_metric, mock_phys_up, mock_ping):
        """If Ethernet and Wi-Fi fail but 4G succeeds, failover to 4G."""
        # eth fails, wifi fails, 4g succeeds
        mock_ping.side_effect = lambda iface: iface == "wwan0"
        mock_phys_up.return_value = True

        self.handler._check_network()

        self.assertEqual(self.handler.active_interface, "wwan0")
        self.assertEqual(self.handler.ethernet_status, "zombie")
        self.assertEqual(self.handler.wifi_status, "down")
        self.assertEqual(self.handler.fourg_status, "up")
        self.assertEqual(self.handler.failover_count, 1)

        # Should modify 4G metric to 50 and restore wifi to 600
        mock_set_metric.assert_has_calls([
            call("wwan0", 50),
            call("wlan0", 600)
        ])

    @patch.object(NetworkWatchdogHandler, "_ping_interface")
    @patch.object(NetworkWatchdogHandler, "_is_interface_physically_up")
    @patch.object(NetworkWatchdogHandler, "_set_interface_metric")
    def test_healing_and_fallback(self, mock_set_metric, mock_phys_up, mock_ping):
        """Test that Ethernet connection recovery restores default metrics after 3 successes."""
        # Start in failover on wlan0
        self.handler.active_interface = "wlan0"
        self.handler.failover_count = 1
        
        # Pings: eth OK, wifi OK, 4g OK
        mock_ping.return_value = True
        mock_phys_up.return_value = True

        # First success
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "wlan0")
        self.assertEqual(self.handler._consecutive_eth_successes, 1)

        # Second success
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "wlan0")
        self.assertEqual(self.handler._consecutive_eth_successes, 2)

        # Third success: triggers fallback
        self.handler._check_network()
        self.assertEqual(self.handler.active_interface, "eth0")
        self.assertEqual(self.handler.failover_count, 2)

        # Verify metrics restored to default
        mock_set_metric.assert_has_calls([
            call("eth0", 100),
            call("wlan0", 600),
            call("wwan0", 700)
        ])


def subprocess_devnull():
    import subprocess
    return subprocess.DEVNULL


if __name__ == "__main__":
    unittest.main()
