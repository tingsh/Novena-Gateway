"""Unit tests for the RemoteLogHandler."""

import sys
import os
import logging
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novena_gateway.gateway.remote_log_handler import RemoteLogHandler


class TestRemoteLogHandler(unittest.TestCase):

    def setUp(self):
        self.mock_publisher = MagicMock()
        self.handler = RemoteLogHandler(
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config={"enabled": True, "min_level": "INFO", "batch_size": 5,
                     "flush_interval_seconds": 999, "duplicate_window_seconds": 60}
        )

    @staticmethod
    def record(level, message, name="test.logger", exc_info=None):
        return logging.LogRecord(
            name=name, level=level, pathname="test.py", lineno=10,
            msg=message, args=(), exc_info=exc_info
        )

    def test_emit_buffers_log_records(self):
        """Log records should be buffered until flush."""
        record = logging.LogRecord(
            name="test.logger", level=logging.INFO,
            pathname="test.py", lineno=10,
            msg="Test message", args=(), exc_info=None
        )
        self.handler.emit(record)

        self.assertEqual(len(self.handler._buffer), 1)
        self.assertEqual(self.handler._buffer[0]["level"], "INFO")
        self.assertIn("Test message", self.handler._buffer[0]["message"])

    def test_emit_skips_below_min_level(self):
        """DEBUG records should be skipped when min_level is INFO."""
        record = logging.LogRecord(
            name="test.logger", level=logging.DEBUG,
            pathname="test.py", lineno=10,
            msg="Debug msg", args=(), exc_info=None
        )
        self.handler.emit(record)
        self.assertEqual(len(self.handler._buffer), 0)

    def test_emit_skips_own_logger(self):
        """Logs from the MQTT publisher should be skipped to prevent infinite loops."""
        record = logging.LogRecord(
            name="novena_gateway.mqtt_publisher", level=logging.INFO,
            pathname="test.py", lineno=10,
            msg="Publishing", args=(), exc_info=None
        )
        self.handler.emit(record)
        self.assertEqual(len(self.handler._buffer), 0)

    def test_flush_publishes_batch(self):
        """Flush should publish buffered logs via the publisher."""
        for i in range(3):
            record = logging.LogRecord(
                name="test", level=logging.WARNING,
                pathname="test.py", lineno=i,
                msg=f"Warning {i}", args=(), exc_info=None
            )
            self.handler.emit(record)

        self.handler._flush()

        self.mock_publisher.publish_logs.assert_called_once()
        payload = self.mock_publisher.publish_logs.call_args[0][0]
        self.assertEqual(payload["serial_number"], "NF-TEST-001")
        self.assertEqual(len(payload["logs"]), 3)
        self.assertIn("ts", payload)

    def test_flush_clears_buffer(self):
        """After flush, buffer should be empty."""
        record = logging.LogRecord(
            name="test", level=logging.ERROR,
            pathname="test.py", lineno=1,
            msg="Error", args=(), exc_info=None
        )
        self.handler.emit(record)
        self.handler._flush()

        self.assertEqual(len(self.handler._buffer), 0)

    def test_disabled_handler_does_not_buffer(self):
        """When disabled, emit should not buffer records."""
        handler = RemoteLogHandler(
            publisher=self.mock_publisher,
            serial_number="NF-TEST-001",
            config={"enabled": False}
        )
        record = logging.LogRecord(
            name="test", level=logging.ERROR,
            pathname="test.py", lineno=1,
            msg="Error", args=(), exc_info=None
        )
        handler.emit(record)
        self.assertEqual(len(handler._buffer), 0)

    @patch("novena_gateway.gateway.remote_log_handler.monotonic", side_effect=[0, 10, 20])
    def test_identical_warnings_are_forwarded_once_within_window(self, _monotonic):
        for _ in range(3):
            self.handler.emit(self.record(logging.WARNING, "Repeated library warning"))

        self.assertEqual(len(self.handler._buffer), 1)
        self.assertEqual(self.handler._buffer[0]["message"], "Repeated library warning")

    @patch("novena_gateway.gateway.remote_log_handler.monotonic", side_effect=[0, 10, 61])
    def test_expired_duplicate_window_emits_summary_and_new_occurrence(self, _monotonic):
        for _ in range(3):
            self.handler.emit(self.record(logging.WARNING, "Repeated library warning"))

        self.assertEqual(len(self.handler._buffer), 3)
        self.assertIn("Suppressed 1 identical remote warning records", self.handler._buffer[1]["message"])
        self.assertEqual(self.handler._buffer[2]["message"], "Repeated library warning")

    @patch("novena_gateway.gateway.remote_log_handler.monotonic", side_effect=[0, 10, 20])
    def test_final_flush_summarizes_suppressed_warning_count(self, _monotonic):
        self.handler.emit(self.record(logging.WARNING, "Repeated library warning"))
        self.handler.emit(self.record(logging.WARNING, "Repeated library warning"))
        self.handler._stopped = True

        self.handler._flush()

        payload = self.mock_publisher.publish_logs.call_args.args[0]
        self.assertEqual(len(payload["logs"]), 2)
        self.assertIn("Suppressed 1 identical remote warning records", payload["logs"][1]["message"])

    @patch("novena_gateway.gateway.remote_log_handler.monotonic", side_effect=[0, 1])
    def test_distinct_warnings_remain_visible(self, _monotonic):
        self.handler.emit(self.record(logging.WARNING, "Temperature probe A timeout"))
        self.handler.emit(self.record(logging.WARNING, "Temperature probe B timeout"))

        self.assertEqual(len(self.handler._buffer), 2)

    @patch("novena_gateway.gateway.remote_log_handler.monotonic", side_effect=[0, 1, 2])
    def test_identical_errors_are_bounded_but_distinct_errors_remain_visible(self, _monotonic):
        self.handler.emit(self.record(logging.ERROR, "Connector A failed"))
        self.handler.emit(self.record(logging.ERROR, "Connector A failed"))
        self.handler.emit(self.record(logging.ERROR, "Connector B failed"))

        self.assertEqual(len(self.handler._buffer), 2)

    def test_critical_records_are_never_suppressed(self):
        self.handler.emit(self.record(logging.CRITICAL, "Gateway storage corrupt"))
        self.handler.emit(self.record(logging.CRITICAL, "Gateway storage corrupt"))

        self.assertEqual(len(self.handler._buffer), 2)

    @patch("novena_gateway.gateway.remote_log_handler.monotonic")
    def test_state_activation_and_configuration_warnings_are_never_suppressed(self, _monotonic):
        for message in (
            "Gateway state changed to offline",
            "Activation failed for claimed gateway",
            "Configuration failed validation",
        ):
            self.handler.emit(self.record(logging.WARNING, message))
            self.handler.emit(self.record(logging.WARNING, message))

        self.assertEqual(len(self.handler._buffer), 6)

    def test_remote_exception_copy_is_concise_without_traceback(self):
        try:
            raise ValueError("bad register")
        except ValueError:
            exc_info = sys.exc_info()

        self.handler.emit(self.record(logging.ERROR, "Polling failed", exc_info=exc_info))

        message = self.handler._buffer[0]["message"]
        self.assertIn("ValueError: bad register", message)
        self.assertNotIn("Traceback", message)
        self.assertNotIn("test_remote_log_handler.py", message)


if __name__ == "__main__":
    unittest.main()
