"""Live operating-system clock readiness for signed Gateway operations."""

from __future__ import annotations

import logging
import subprocess
import threading
from time import monotonic

log = logging.getLogger("novena_gateway.clock_health")


class SystemClockHealth:
    """Cache the systemd synchronization state without trusting config flags."""

    def __init__(self, *, cache_seconds: float = 5.0, runner=None):
        self._cache_seconds = max(0.0, float(cache_seconds))
        self._runner = runner or subprocess.run
        self._lock = threading.Lock()
        self._checked_at = 0.0
        self._synchronized = False

    def synchronized(self) -> bool:
        now = monotonic()
        with self._lock:
            if self._checked_at and now - self._checked_at < self._cache_seconds:
                return self._synchronized
            self._checked_at = now
            try:
                result = self._runner(
                    ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                self._synchronized = result.returncode == 0 and (result.stdout or "").strip().lower() == "yes"
            except (OSError, subprocess.SubprocessError) as exc:
                self._synchronized = False
                log.debug("Could not read system clock synchronization state: %s", exc)
            return self._synchronized
