"""
Novena Gateway Remote Log Handler

A Python logging.Handler that buffers log records and periodically publishes
them to Novena Hub via MQTT on the `v1/gateway/{serial}/logs` topic.

Log Payload Schema:
{
    "serial_number": "NF-EDGE-001",
    "ts": 1714000000000,
    "logs": [
        {
            "ts": 1714000000000,
            "level": "INFO",
            "logger": "novena_gateway.connectors.modbus",
            "message": "Polled 3 registers from Power Meter 1",
            "module": "modbus_connector",
            "line": 142
        },
        ...
    ]
}
"""

import logging
import threading
from collections import OrderedDict, deque
from time import monotonic, sleep, time
from typing import Optional
from novena_gateway.gateway.redaction import redact_text

log = logging.getLogger("novena_gateway.remote_log_handler")


class RemoteLogHandler(logging.Handler):
    """
    Logging handler that buffers log records and publishes batches
    to Novena Hub via MQTT.
    """

    DEFAULT_BATCH_SIZE = 20
    DEFAULT_FLUSH_INTERVAL = 5  # seconds
    DEFAULT_DUPLICATE_WINDOW = 300  # seconds
    DEFAULT_DUPLICATE_CACHE_SIZE = 512
    _DEDUPLICATE_EXEMPT_LOGGERS = (
        "novena_gateway.remote_config",
        "novena_gateway.activation",
    )
    _DEDUPLICATE_EXEMPT_TERMS = (
        "activation",
        "configuration failed",
        "config failed",
        "state changed",
        "status changed",
    )

    def __init__(self, publisher, serial_number: str, config: Optional[dict] = None):
        super().__init__()
        self._publisher = publisher
        self._serial_number = serial_number
        self._config = config or {}

        self._enabled = self._config.get("enabled", True)
        self._batch_size = self._config.get("batch_size", self.DEFAULT_BATCH_SIZE)
        self._flush_interval = self._config.get("flush_interval_seconds", self.DEFAULT_FLUSH_INTERVAL)
        self._duplicate_window = max(
            0, self._config.get("duplicate_window_seconds", self.DEFAULT_DUPLICATE_WINDOW)
        )
        self._duplicate_summary = self._config.get("duplicate_summary", True)
        self._duplicate_cache_size = max(
            1, self._config.get("duplicate_cache_size", self.DEFAULT_DUPLICATE_CACHE_SIZE)
        )
        self._min_level = logging.getLevelName(
            self._config.get("min_level", "INFO")
        )
        if isinstance(self._min_level, str):
            self._min_level = logging.INFO

        self._buffer = deque(maxlen=self._config.get("max_buffer_size", 500))
        self._duplicate_records = OrderedDict()
        self._buffer_lock = threading.Lock()
        self._stopped = False
        self._flush_thread = None

        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] - %(module)s - %(lineno)d - %(message)s'
        ))

    def start(self):
        """Start the background flush thread."""
        if not self._enabled:
            log.info("Remote logging is disabled.")
            return

        self._stopped = False
        self._flush_thread = threading.Thread(
            target=self._flush_loop, name="RemoteLogFlusher", daemon=True
        )
        self._flush_thread.start()
        log.info("Remote log handler started (flush every %ds, batch size %d)",
                 self._flush_interval, self._batch_size)

    def stop(self):
        """Stop the flush thread and send remaining logs."""
        self._stopped = True
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=3)
        # Final flush
        self._flush()

    def emit(self, record):
        """Called by the logging framework for each log record."""
        if not self._enabled:
            return

        if record.levelno < self._min_level:
            return

        # Avoid logging our own publish activity (prevent infinite loops)
        if record.name.startswith("novena_gateway.mqtt_publisher"):
            return
        if record.name == "novena_gateway.remote_log_handler":
            return

        customer_message = self._customer_message(record)
        entry = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": customer_message,
            "module": record.module,
            "line": record.lineno,
        }

        with self._buffer_lock:
            if self._should_suppress_duplicate(record, customer_message, entry):
                return
            self._buffer.append(entry)

    @staticmethod
    def _customer_message(record):
        """Build a concise remote copy while leaving local traceback formatting untouched."""
        message = record.getMessage()
        if record.exc_info and record.exc_info[1] is not None:
            exception = record.exc_info[1]
            exception_summary = f"{type(exception).__name__}: {exception}"
            if exception_summary not in message:
                message = f"{message} ({exception_summary})"
        return redact_text(message)

    def _should_suppress_duplicate(self, record, customer_message, entry):
        if self._duplicate_window <= 0 or record.levelno not in (logging.WARNING, logging.ERROR):
            return False
        if record.name.startswith(self._DEDUPLICATE_EXEMPT_LOGGERS):
            return False
        normalized_message = customer_message.casefold()
        if any(term in normalized_message for term in self._DEDUPLICATE_EXEMPT_TERMS):
            return False

        now = monotonic()
        signature = (record.levelno, record.name, customer_message)
        duplicate = self._duplicate_records.get(signature)
        if duplicate is None:
            self._remember_duplicate(signature, now, entry)
            return False

        self._duplicate_records.move_to_end(signature)
        if now - duplicate["forwarded_at"] < self._duplicate_window:
            duplicate["suppressed"] += 1
            duplicate["last_seen"] = now
            return True

        self._append_duplicate_summary(duplicate)
        self._duplicate_records[signature] = {
            "forwarded_at": now,
            "last_seen": now,
            "suppressed": 0,
            "entry": entry,
        }
        return False

    def _remember_duplicate(self, signature, now, entry):
        self._duplicate_records[signature] = {
            "forwarded_at": now,
            "last_seen": now,
            "suppressed": 0,
            "entry": entry,
        }
        self._duplicate_records.move_to_end(signature)
        while len(self._duplicate_records) > self._duplicate_cache_size:
            _, expired = self._duplicate_records.popitem(last=False)
            self._append_duplicate_summary(expired)

    def _append_duplicate_summary(self, duplicate):
        if not self._duplicate_summary or duplicate["suppressed"] <= 0:
            return
        entry = duplicate["entry"]
        duration = max(0, int(duplicate["last_seen"] - duplicate["forwarded_at"]))
        level = entry["level"].lower()
        self._buffer.append({
            **entry,
            "ts": int(time() * 1000),
            "message": (
                f"Suppressed {duplicate['suppressed']} identical remote {level} records "
                f"over {duration}s: {entry['message']}"
            ),
        })

    def _append_expired_duplicate_summaries(self, force=False):
        if not self._duplicate_summary:
            return
        now = monotonic()
        expired_signatures = []
        for signature, duplicate in self._duplicate_records.items():
            if force or now - duplicate["forwarded_at"] >= self._duplicate_window:
                self._append_duplicate_summary(duplicate)
                expired_signatures.append(signature)
        for signature in expired_signatures:
            self._duplicate_records.pop(signature, None)

    def _flush_loop(self):
        """Background thread that periodically flushes the log buffer."""
        while not self._stopped:
            sleep(self._flush_interval)
            self._flush()

    def _flush(self):
        """Publish buffered log entries as a batch."""
        with self._buffer_lock:
            self._append_expired_duplicate_summaries(force=self._stopped)
            if not self._buffer:
                return
            entries = list(self._buffer)
            self._buffer.clear()

        # Split into batches
        for i in range(0, len(entries), self._batch_size):
            batch = entries[i:i + self._batch_size]
            payload = {
                "serial_number": self._serial_number,
                "ts": int(time() * 1000),
                "logs": batch,
            }
            try:
                self._publisher.publish_logs(payload)
            except Exception as e:
                # Use print to avoid recursion
                print(f"[RemoteLogHandler] Failed to publish log batch: {e}")

    def install(self, logger_names=None):
        """
        Install this handler on the specified loggers.
        If logger_names is None, installs on the root logger.
        """
        if not self._enabled:
            return

        if logger_names is None:
            root = logging.getLogger()
            if self not in root.handlers:
                root.addHandler(self)
            log.info("Remote log handler installed on root logger")
        else:
            for name in logger_names:
                logger = logging.getLogger(name)
                if self not in logger.handlers:
                    logger.addHandler(self)
            log.info("Remote log handler installed on loggers: %s", logger_names)

    def uninstall(self):
        """Remove this handler from all loggers."""
        root = logging.getLogger()
        if self in root.handlers:
            root.removeHandler(self)
        for name in list(logging.Logger.manager.loggerDict.keys()):
            logger = logging.getLogger(name)
            if self in logger.handlers:
                logger.removeHandler(self)
