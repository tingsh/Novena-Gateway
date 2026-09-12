"""Operating-system clock readiness tests."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import MagicMock

from novena_gateway.gateway.clock_health import SystemClockHealth


class SystemClockHealthTest(unittest.TestCase):
    def test_reports_synchronized_only_when_systemd_confirms_it(self):
        runner = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="yes\n", stderr="")
        )

        health = SystemClockHealth(cache_seconds=0, runner=runner)

        self.assertTrue(health.synchronized())
        runner.assert_called_once()

    def test_unsynchronized_or_unavailable_clock_fails_closed(self):
        unsynchronized = SystemClockHealth(
            cache_seconds=0,
            runner=MagicMock(
                return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="no\n", stderr="")
            ),
        )
        unavailable = SystemClockHealth(
            cache_seconds=0,
            runner=MagicMock(side_effect=FileNotFoundError("timedatectl")),
        )

        self.assertFalse(unsynchronized.synchronized())
        self.assertFalse(unavailable.synchronized())

    def test_result_is_cached_to_keep_heartbeat_checks_lightweight(self):
        runner = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="yes\n", stderr="")
        )
        health = SystemClockHealth(cache_seconds=60, runner=runner)

        self.assertTrue(health.synchronized())
        self.assertTrue(health.synchronized())
        runner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
