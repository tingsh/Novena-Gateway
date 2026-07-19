"""
Novena Gateway Remote Config Handler

Subscribes to `v1/gateway/{serial_number}/config` for inbound config updates
from Novena Hub. On receiving a new config:
1. Validates the incoming JSON structure
2. Backs up the current config
3. Writes the new config to disk
4. Hot-reloads affected connectors (stop old → start new)
5. Publishes an acknowledgement attribute

Inbound Config Payload Schema (cloud → edge):
{
    "request_id": "uuid-string",
    "action": "full_update" | "connector_update" | "connector_add" | "connector_remove",
    "config": { ... }  // Full or partial config depending on action
}

Acknowledgement Attribute (edge → cloud):
{
    "serial_number": "NF-EDGE-001",
    "ts": 1714000000000,
    "attributes": {
        "config_update_status": "success" | "failed",
        "config_update_request_id": "uuid-string",
        "config_update_error": "..." | null,
        "config_version_ts": 1714000000000
    }
}
"""

import json
import logging
import os
import shutil
from time import time
from typing import Optional
from novena_gateway.gateway.redaction import redact_secrets

log = logging.getLogger("novena_gateway.remote_config")

MAX_BACKUPS = 10


class RemoteConfigHandler:
    """Handles remote configuration updates from Novena Hub."""

    def __init__(self, gateway, publisher, serial_number: str,
                 config_path: str, config: Optional[dict] = None):
        self._gateway = gateway
        self._publisher = publisher
        self._serial_number = serial_number
        self._config_path = config_path
        self._handler_config = config or {}

        self._enabled = self._handler_config.get("enabled", True)
        self._inbound_topic = f"v1/gateway/{self._serial_number}/config"
        self._backup_dir = self._handler_config.get(
            "backup_dir",
            os.path.join(os.path.dirname(self._config_path), "config_backups")
        )
        if not os.path.isabs(self._backup_dir):
            self._backup_dir = os.path.join(os.path.dirname(self._config_path), self._backup_dir)
        self._last_known_good_path = self._handler_config.get(
            "last_known_good_path",
            os.path.join(os.path.dirname(self._config_path), "last_known_good_config.json")
        )
        if not os.path.isabs(self._last_known_good_path):
            self._last_known_good_path = os.path.join(os.path.dirname(self._config_path), self._last_known_good_path)
        self._last_update_status = {
            "config_update_status": "unknown",
            "config_update_error": None,
            "rollback_performed": False,
            "connector_results": [],
            "config_version_ts": None,
        }

    def start(self):
        """Subscribe to the config update topic."""
        if not self._enabled:
            log.info("Remote config handler is disabled.")
            return

        self._ensure_last_known_good()
        self._publisher.subscribe(self._inbound_topic, self._on_config_update)
        log.info("Remote config handler started, listening on: %s", self._inbound_topic)

    def stop(self):
        """No persistent resources to clean up."""
        pass

    def _on_config_update(self, topic: str, payload: dict):
        """Handle an inbound config update message."""
        request_id = payload.get("request_id", "unknown")
        action = payload.get("action", "full_update")
        new_config = payload.get("config")

        log.info("Received config update (request_id=%s, action=%s)", request_id, action)

        try:
            if not new_config:
                raise ValueError("Config update payload is missing 'config' field")

            if action == "full_update":
                result = self._apply_full_update(new_config)
            elif action == "connector_update":
                result = self._apply_connector_update(new_config)
            elif action == "connector_add":
                result = self._apply_connector_add(new_config)
            elif action == "connector_remove":
                result = self._apply_connector_remove(new_config)
            else:
                raise ValueError(f"Unknown config action: {action}")

            self._send_ack(
                request_id,
                status=result["config_update_status"],
                error=result.get("config_update_error"),
                connector_results=result.get("connector_results", []),
                rollback_performed=result.get("rollback_performed", False),
            )
            if result["config_update_status"] == "success":
                log.info("Config update applied successfully (request_id=%s)", request_id)
            else:
                log.warning("Config update completed with status=%s (request_id=%s)",
                            result["config_update_status"], request_id)

        except Exception as e:
            log.exception("Failed to apply config update (request_id=%s): %s", request_id, e)
            self._last_update_status = {
                "config_update_status": "failed",
                "config_update_error": str(e),
                "rollback_performed": False,
                "connector_results": [],
                "config_version_ts": int(time() * 1000),
            }
            self._send_ack(request_id, status="failed", error=str(e))

    def _apply_full_update(self, new_config: dict):
        """Replace the entire config.json and hot-reload all connectors."""
        # Validate schema and required settings
        errors = self._gateway.validate_config(new_config)
        if errors:
            raise ValueError(f"Invalid config schema: {', '.join(errors)}")

        return self._apply_config_with_rollback(new_config, action="full_update")

    def _apply_connector_update(self, connector_config: dict):
        """Update connectors without replacing gateway identity or MQTT settings."""
        current_config = self._read_config()

        if "connectors" in connector_config:
            connectors = connector_config.get("connectors")
            if not isinstance(connectors, list):
                raise ValueError("Connector update 'connectors' field must be a list")
            current_config["connectors"] = connectors
            log.info("Replacing connector list with %d connector(s)", len(connectors))
        else:
            connector_name = connector_config.get("name")
            if not connector_name:
                raise ValueError("Connector update missing 'name' field")

            connectors = current_config.get("connectors", [])
            found = False
            for i, conn in enumerate(connectors):
                if conn.get("name") == connector_name:
                    connectors[i] = connector_config
                    found = True
                    break

            if not found:
                raise ValueError(f"Connector '{connector_name}' not found in current config")
            current_config["connectors"] = connectors
            log.info("Connector '%s' updated", connector_name)

        errors = self._gateway.validate_config(current_config)
        if errors:
            raise ValueError(f"Invalid config after updating connectors: {', '.join(errors)}")

        result = self._apply_config_with_rollback(current_config, action="connector_update")
        log.info("Connector update applied — %d connector(s) active", len(current_config.get("connectors", [])))
        return result

    def _apply_connector_add(self, connector_config: dict):
        """Add a new connector to the config and start it."""
        connector_name = connector_config.get("name")
        if not connector_name:
            raise ValueError("Connector add missing 'name' field")

        current_config = self._read_config()
        connectors = current_config.get("connectors", [])

        # Check for duplicates
        for conn in connectors:
            if conn.get("name") == connector_name:
                raise ValueError(f"Connector '{connector_name}' already exists")

        connectors.append(connector_config)
        current_config["connectors"] = connectors

        # Validate final config before applying
        errors = self._gateway.validate_config(current_config)
        if errors:
            raise ValueError(f"Invalid config after adding connector: {', '.join(errors)}")

        result = self._apply_config_with_rollback(current_config, action="connector_add")
        log.info("Connector '%s' added and started", connector_name)
        return result

    def _apply_connector_remove(self, connector_config: dict):
        """Remove a connector from the config and stop it."""
        connector_name = connector_config.get("name")
        if not connector_name:
            raise ValueError("Connector remove missing 'name' field")

        current_config = self._read_config()
        connectors = current_config.get("connectors", [])

        original_count = len(connectors)
        connectors = [c for c in connectors if c.get("name") != connector_name]

        if len(connectors) == original_count:
            raise ValueError(f"Connector '{connector_name}' not found")

        current_config["connectors"] = connectors

        # Validate final config before applying
        errors = self._gateway.validate_config(current_config)
        if errors:
            raise ValueError(f"Invalid config after removing connector: {', '.join(errors)}")

        result = self._apply_config_with_rollback(current_config, action="connector_remove")
        log.info("Connector '%s' removed", connector_name)
        return result

    def _apply_config_with_rollback(self, new_config: dict, action: str) -> dict:
        """Apply config and rollback to the last known good config when connectors fail."""
        self._ensure_last_known_good()
        previous_config = self._read_config()
        self._create_backup()
        self._write_config(new_config)

        self._gateway._stop_connectors()
        self._gateway._config = new_config
        connector_results = self._normalize_connector_results(
            self._gateway._start_connectors(),
            new_config,
        )
        if hasattr(self._gateway, "_connector_start_results"):
            self._gateway._connector_start_results = connector_results
        failures = [result for result in connector_results if result.get("status") != "success"]

        if failures:
            if hasattr(self._gateway, "_startup_status"):
                self._gateway._startup_status = "degraded"
            error = "; ".join(
                f"{item.get('name')}: {item.get('error') or item.get('status')}"
                for item in failures
            )
            rollback_config = self._read_last_known_good() or previous_config
            self._write_config(rollback_config)
            self._gateway._stop_connectors()
            self._gateway._config = rollback_config
            rollback_results = self._normalize_connector_results(
                self._gateway._start_connectors(),
                rollback_config,
            )
            if hasattr(self._gateway, "_connector_start_results"):
                self._gateway._connector_start_results = rollback_results
            status = {
                "config_update_status": "rolled_back",
                "config_update_error": error,
                "rollback_performed": True,
                "connector_results": connector_results,
                "rollback_connector_results": rollback_results,
                "config_version_ts": int(time() * 1000),
                "action": action,
            }
            self._last_update_status = status
            log.warning("Config update rolled back after connector failure: %s", error)
            return status

        self._write_last_known_good(new_config)
        if hasattr(self._gateway, "_startup_status"):
            self._gateway._startup_status = "ready"
            self._gateway._startup_error = None
        status = {
            "config_update_status": "success",
            "config_update_error": None,
            "rollback_performed": False,
            "connector_results": connector_results,
            "config_version_ts": int(time() * 1000),
            "action": action,
        }
        self._last_update_status = status
        return status

    def _normalize_connector_results(self, results, config: dict) -> list:
        if results is None:
            return [
                {
                    "name": connector.get("name", connector.get("type", "unknown")),
                    "type": connector.get("type", "unknown"),
                    "status": "success",
                    "error": None,
                }
                for connector in config.get("connectors", [])
            ]
        return list(results)

    def _read_config(self) -> dict:
        """Read the current config from disk."""
        with open(self._config_path, 'r') as f:
            return json.load(f)

    def _write_config(self, config: dict):
        """Write config to disk atomically."""
        tmp_path = self._config_path + ".tmp"
        with open(tmp_path, 'w') as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_path, self._config_path)
        log.debug("Config written to %s", self._config_path)

    def _ensure_last_known_good(self):
        if not os.path.exists(self._last_known_good_path) and os.path.exists(self._config_path):
            os.makedirs(os.path.dirname(self._last_known_good_path), exist_ok=True)
            shutil.copy2(self._config_path, self._last_known_good_path)

    def _write_last_known_good(self, config: dict):
        os.makedirs(os.path.dirname(self._last_known_good_path), exist_ok=True)
        tmp_path = self._last_known_good_path + ".tmp"
        with open(tmp_path, 'w') as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_path, self._last_known_good_path)

    def _read_last_known_good(self) -> Optional[dict]:
        if not os.path.exists(self._last_known_good_path):
            return None
        with open(self._last_known_good_path, 'r') as f:
            return json.load(f)

    def _create_backup(self):
        """Backup the current config file with a timestamp."""
        if not os.path.exists(self._config_path):
            return

        os.makedirs(self._backup_dir, exist_ok=True)

        ts = int(time())
        backup_name = f"config_backup_{ts}.json"
        backup_path = os.path.join(self._backup_dir, backup_name)

        shutil.copy2(self._config_path, backup_path)
        log.info("Config backed up to %s", backup_path)

        # Prune old backups
        self._prune_backups()

    def _prune_backups(self):
        """Keep only the most recent MAX_BACKUPS backup files."""
        if not os.path.exists(self._backup_dir):
            return

        backups = sorted([
            f for f in os.listdir(self._backup_dir)
            if f.startswith("config_backup_") and f.endswith(".json")
        ])

        while len(backups) > MAX_BACKUPS:
            old = backups.pop(0)
            os.remove(os.path.join(self._backup_dir, old))
            log.debug("Pruned old backup: %s", old)

    def get_status(self) -> dict:
        return {
            **self._last_update_status,
            "active_connector_count": len(getattr(self._gateway, "_connectors", [])),
            "last_known_good_path": self._last_known_good_path,
        }

    def _send_ack(self, request_id: str, status: str, error: str = None,
                  connector_results=None, rollback_performed: bool = False):
        """Publish a config update acknowledgement as a gateway attribute."""
        version_ts = int(time() * 1000)
        payload = {
            "serial_number": self._serial_number,
            "ts": version_ts,
            "attributes": {
                "config_update_status": status,
                "config_update_request_id": request_id,
                "config_update_error": error,
                "config_version_ts": version_ts,
                "rollback_performed": rollback_performed,
                "connector_results": connector_results or [],
            }
        }
        self._publisher.publish_attributes(redact_secrets(payload))
