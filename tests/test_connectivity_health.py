"""Unit tests for ConnectivityHealthHandler."""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.connectivity_health_handler import ConnectivityHealthHandler


class TestConnectivityHealthHandler(unittest.TestCase):

    def setUp(self):
        self.publisher = MagicMock()
        self.publisher.is_connected.return_value = True
        self.publisher.get_connection_diagnostics.return_value = {"mqtt_last_error": None}
        self.handler = ConnectivityHealthHandler(
            gateway=MagicMock(),
            publisher=self.publisher,
            serial_number="NF-TEST",
            mqtt_config={"host": "broker.local", "port": 8883, "tls": {"mode": "one-way"}},
            config={"enabled": True, "timeout_seconds": 1},
        )

    @patch("socket.create_connection")
    @patch("socket.getaddrinfo")
    @patch("subprocess.run")
    def test_healthy_broker_path(self, mock_run, mock_getaddrinfo, mock_create_connection):
        mock_run.return_value = MagicMock(returncode=0, stdout="default via 192.168.1.1\n", stderr="")
        mock_getaddrinfo.return_value = [(None, None, None, None, ("192.168.1.10", 8883))]
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_context:
            mock_context.return_value.wrap_socket.return_value.__enter__.return_value = MagicMock()
            health = self.handler.run_check()

        self.assertTrue(health["default_route_ok"])
        self.assertTrue(health["dns_ok"])
        self.assertTrue(health["broker_tcp_ok"])
        self.assertTrue(health["tls_ok"])
        self.assertTrue(health["mqtt_connected"])

    @patch("socket.getaddrinfo", side_effect=OSError("dns failed"))
    @patch("subprocess.run")
    def test_dns_failure_is_reported(self, mock_run, _mock_getaddrinfo):
        mock_run.return_value = MagicMock(returncode=0, stdout="default via 192.168.1.1\n", stderr="")

        health = self.handler.run_check()

        self.assertFalse(health["dns_ok"])
        self.assertIn("dns failed", health["dns_error"])
        self.assertFalse(health["broker_tcp_ok"])

    @patch("socket.create_connection", side_effect=TimeoutError("blocked"))
    @patch("socket.getaddrinfo")
    @patch("subprocess.run")
    def test_blocked_broker_port_is_reported(self, mock_run, mock_getaddrinfo, _mock_create_connection):
        mock_run.return_value = MagicMock(returncode=0, stdout="default via 192.168.1.1\n", stderr="")
        mock_getaddrinfo.return_value = [(None, None, None, None, ("192.168.1.10", 8883))]

        health = self.handler.run_check()

        self.assertFalse(health["broker_tcp_ok"])
        self.assertIn("blocked", health["broker_tcp_error"])


if __name__ == "__main__":
    unittest.main()
