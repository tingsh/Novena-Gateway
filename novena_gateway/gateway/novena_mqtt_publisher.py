"""
Novena Gateway MQTT Publisher

Bidirectional MQTT client for the Novena Gateway.
- Publishes telemetry, attributes, logs, and RPC responses to Novena Hub.
- Subscribes to inbound topics for remote config, RPC requests, and attribute pushes.

Features:
- Auto-reconnect with exponential backoff
- QoS 1 for reliable delivery
- Local queue buffering on disconnect
- Inbound message routing via registered callbacks
- Optional TLS support
"""

import base64
import binascii
import json
import logging
import os
import shutil
import tempfile
import threading
from datetime import datetime, timezone
from queue import Queue, Full, Empty
from time import sleep, time
from typing import Callable, Dict, List, Optional
from uuid import UUID

import paho.mqtt.client as mqtt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from novena_gateway.gateway.deployment_setup import canonical_bytes
from novena_gateway.gateway.runtime_paths import DATA_DIR, SQLITE_DATA_FILE_PATH
from novena_gateway.storage.sqlite.sqlite_event_storage import SQLiteEventStorage

log = logging.getLogger("novena_gateway.mqtt_publisher")


class NovenaMqttPublisher:
    """Bidirectional MQTT client for the Novena Gateway."""

    def __init__(self, config: dict, serial_number: str = "", config_path: str = ""):
        self._host = config.get("host", "localhost")
        self._username = config.get("username", "")
        self._password = config.get("password", "")
        self._qos = config.get("qos", 1)
        self._client_id = config.get("client_id", "novena-gateway")
        self._tls = config.get("tls", None)
        self._bootstrap = config.get("bootstrap") or config.get("bootstrap_mqtt") or {}
        self._storage_config = config.get("storage", {})
        self._max_queue_size = config.get("max_queue_size", 10000)
        self._reconnect_delay_min = config.get("reconnect_delay_min", 1)
        self._reconnect_delay_max = config.get("reconnect_delay_max", 60)
        self._serial_number = serial_number
        self._config_path = config_path
        # Stable for one Hub claim, including activation retries and password rotations.
        self._claim_id = config.get("claim_id")
        self.on_claim_changed = None
        self.on_release = None
        self.on_release_revoked = None
        self._trusted_release_keys = config.get("trusted_release_keys") or {}
        self._release_request_id = config.get("release_request_id")
        self._release_in_progress = config.get("mode") == "release_pending"
        self._operational_credentials_retired = bool(
            self._release_in_progress and self._release_request_id and not self._username and not self._password
        )
        self._telemetry_topic = self._scoped_topic(
            "telemetry",
            legacy_fallback=config.get("topic", "v1/gateway/telemetry"),
        )

        # Provisioning-mode tracking
        self._consecutive_failures = 0
        self._activation_message_shown = False
        self._bootstrap_mode = False

        # Default port: 8883 when TLS is configured, 1883 otherwise
        self._port = config.get("port", 8883 if self._tls else 1883)

        self._connected = False
        self._stopped = False
        self._queue = Queue(maxsize=self._max_queue_size)
        self._last_connection_rc = None
        self._last_disconnect_rc = None
        self._last_error = None
        self._dropped_message_count = 0

        # Inbound message routing: topic -> list of callbacks
        self._subscriptions: Dict[str, List[Callable]] = {}
        self._subscription_lock = threading.Lock()

        # Instantiate SQLiteEventStorage as local database buffer
        sqlite_config = self._storage_config.get("sqlite", self._storage_config)
        storage_config = {
            "data_file_path": SQLITE_DATA_FILE_PATH,
            "max_read_records_count": 50,
            "writing_batch_size": 50,
        }
        storage_config.update(sqlite_config or {})
        self._resolved_storage_config = storage_config
        self._storage_stop_event = threading.Event()
        self._storage = SQLiteEventStorage(storage_config, log, self._storage_stop_event)
        self._buffer_lock = threading.Lock()
        self._replay_thread = None
        self._replay_lock = threading.Lock()
        self._last_replay_status = "idle"
        self._replay_failure_count = 0

        # Create MQTT client (paho-mqtt v2.x API)
        self._client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self._client_id,
            protocol=mqtt.MQTTv311
        )

        if self._username:
            self._client.username_pw_set(self._username, self._password)
        elif self._operational_credentials_retired and self._bootstrap.get("enabled"):
            self._username = self._bootstrap.get("username", "")
            self._password = self._bootstrap.get("password", "")
            if self._username and self._password:
                self._bootstrap_mode = True
                self._client.username_pw_set(self._username, self._password)

        # ─── TLS configuration ───────────────────────────────────────
        self._configure_tls()

        # ─── Last Will and Testament (LWT) ───────────────────────────
        self._configure_lwt()

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_publish = self._on_publish
        self._client.on_message = self._on_message
        self._client.reconnect_delay_set(
            min_delay=self._reconnect_delay_min,
            max_delay=self._reconnect_delay_max
        )

        self._publish_thread = None

    def _scoped_topic(self, suffix: str, legacy_fallback: str = None) -> str:
        if self._serial_number:
            return f"v1/gateway/{self._serial_number}/{suffix}"
        return legacy_fallback or f"v1/gateway/{suffix}"

    def _configure_tls(self):
        """
        Configure TLS based on the 'tls' block in config.

        Supported modes:
          - absent / None:  No TLS (dev/local only)
          - "one-way":      Server cert verification only (standard)
          - "mutual":       mTLS — both server and client certs (enterprise)
        """
        if not self._tls:
            return

        mode = self._tls.get("mode", "one-way")
        ca_certs = self._tls.get("ca_certs")

        if not ca_certs:
            log.error("TLS enabled but 'ca_certs' path is missing from config.")
            return

        if not os.path.isfile(ca_certs):
            log.error("TLS CA certificate file not found: %s", ca_certs)
            return

        if mode == "one-way":
            self._client.tls_set(ca_certs=ca_certs)
            log.info("TLS configured in one-way mode (server verification only).")

        elif mode == "mutual":
            certfile = self._tls.get("certfile")
            keyfile = self._tls.get("keyfile")

            if not certfile or not keyfile:
                log.error("mTLS mode requires 'certfile' and 'keyfile' in tls config.")
                return

            for path, label in [(certfile, "certfile"), (keyfile, "keyfile")]:
                if not os.path.isfile(path):
                    log.error("mTLS %s not found: %s", label, path)
                    return

            self._client.tls_set(
                ca_certs=ca_certs,
                certfile=certfile,
                keyfile=keyfile,
            )
            log.info("TLS configured in mutual mode (mTLS — client cert verified).")

        else:
            log.error("Unknown TLS mode '%s'. Expected 'one-way' or 'mutual'.", mode)

    def _configure_lwt(self):
        """
        Set MQTT Last Will and Testament (LWT).
        If the gateway disconnects unexpectedly, the broker publishes this
        'offline' status message automatically on v1/gateway/{serial}/attributes.
        """
        if not self._serial_number:
            return

        lwt_payload = json.dumps({
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": {"status": "offline"}
        })
        self._client.will_set(
            topic=self._scoped_topic("attributes", legacy_fallback="v1/gateway/attributes"),
            payload=lwt_payload,
            qos=1,
            retain=False,
        )
        log.info("LWT configured — broker will publish offline status on unexpected disconnect.")

    def connect(self):
        """Connect to the MQTT broker and start the background publish loop."""
        log.info("Connecting to MQTT broker at %s:%d ...", self._host, self._port)

        # Auto-subscribe to provision topic for credential rotation
        if self._serial_number:
            provision_topic = f"v1/gateway/{self._serial_number}/provision"
            self.subscribe(provision_topic, self._on_provision_message)
            bootstrap_topic = f"v1/gateway/{self._serial_number}/bootstrap/activate"
            self.subscribe(bootstrap_topic, self._on_provision_message)

        try:
            self._client.connect(self._host, self._port, keepalive=60)
            self._client.loop_start()
        except Exception as e:
            log.error("Failed to connect to MQTT broker: %s", e)
            # loop_start will handle reconnection attempts
            self._client.loop_start()

        self._stopped = False
        self._publish_thread = threading.Thread(
            target=self._publish_loop, name="MQTT-Publisher", daemon=True
        )
        self._publish_thread.start()

    def disconnect(self):
        """Gracefully disconnect from the broker."""
        log.info("Disconnecting from MQTT broker...")
        self._stopped = True
        self._storage_stop_event.set()
        self._storage.stop()
        # Flush remaining messages
        self._flush_queue()
        # Signal the network loop to exit before joining it. A blackholed broker
        # can otherwise make loop_stop wait for the full MQTT keepalive timeout.
        self._client.disconnect()
        self._client.loop_stop()
        log.info("MQTT publisher stopped.")

    # ─── Subscription management ─────────────────────────────────────

    def subscribe(self, topic: str, callback: Callable):
        """
        Register a callback for messages on the given MQTT topic.
        The callback signature should be: callback(topic: str, payload: dict)
        Subscriptions are (re-)issued on every connect event.
        """
        with self._subscription_lock:
            if topic not in self._subscriptions:
                self._subscriptions[topic] = []
            self._subscriptions[topic].append(callback)

        # If already connected, subscribe immediately
        if self._connected:
            self._client.subscribe(topic, qos=self._qos)
            log.info("Subscribed to topic: %s", topic)

    def _resubscribe_all(self):
        """Re-subscribe to all registered topics (called on reconnect)."""
        with self._subscription_lock:
            for topic in self._subscriptions:
                self._client.subscribe(topic, qos=self._qos)
                log.info("Re-subscribed to topic: %s", topic)

    # ─── Multi-topic publish helpers ───────────────────────────────────

    def publish(self, payload: dict, topic: Optional[str] = None):
        """
        Queue a payload dict for publishing.
        If topic is None, publishes to the default telemetry topic.
        """
        if getattr(self, "_release_in_progress", False):
            return
        topic = topic or self._telemetry_topic
        payload = self._with_claim_id(payload, topic)
        item = (topic, payload, self._claim_id)
        
        if self._connected:
            try:
                self._queue.put_nowait(item)
            except Full:
                log.warning("MQTT publish queue is full (%d messages). Dropping oldest message.",
                            self._max_queue_size)
                try:
                    self._queue.get_nowait()  # Drop oldest
                except Empty:
                    pass
                self._dropped_message_count += 1
                self._queue.put_nowait(item)
        else:
            log.debug("Edge Gateway is offline. Buffering telemetry payload to SQLite database.")
            event_str = json.dumps({"topic": topic, "payload": payload, "claim_id": self._claim_id})
            if not self._buffer_event(event_str):
                self._dropped_message_count += 1

    def _buffer_event(self, event_str: str) -> bool:
        with self._buffer_lock:
            if self._release_in_progress:
                return True
            return self._storage.put(event_str)

    def publish_now(self, payload: dict, topic: str) -> bool:
        """Publish immediately and wait for the MQTT client to accept the message."""
        if not self._connected:
            return False
        result = self._client.publish(topic, json.dumps(self._with_claim_id(payload, topic)), qos=self._qos)
        try:
            result.wait_for_publish(timeout=5)
        except Exception as e:
            log.warning("Timed out waiting for publish on %s: %s", topic, e)
            return False
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def _with_claim_id(self, payload: dict, topic: str) -> dict:
        if self._claim_id and topic.endswith(("/telemetry", "/logs")):
            return {**payload, "claim_id": self._claim_id}
        return payload

    def publish_telemetry(self, payload: dict):
        """Publish to the telemetry topic."""
        self.publish(payload, self._telemetry_topic)

    def publish_attributes(self, payload: dict, *, immediate: bool = False):
        """Publish to the attributes topic."""
        topic = self._scoped_topic("attributes", legacy_fallback="v1/gateway/attributes")
        if immediate:
            return self.publish_now(payload, topic)
        self.publish(payload, topic)
        return True

    def publish_logs(self, payload: dict):
        """Publish to the logs topic."""
        self.publish(payload, self._scoped_topic("logs", legacy_fallback="v1/gateway/logs"))

    def publish_rpc_response(self, payload: dict):
        """Publish to the RPC response topic."""
        self.publish(payload, self._scoped_topic("rpc/response", legacy_fallback="v1/gateway/rpc/response"))

    def is_connected(self):
        return self._connected

    def get_connection_diagnostics(self) -> dict:
        return {
            "mqtt_connected": self._connected,
            "mqtt_last_connection_rc": self._last_connection_rc,
            "mqtt_last_disconnect_rc": self._last_disconnect_rc,
            "mqtt_last_error": self._last_error,
            "bootstrap_mode": self._bootstrap_mode,
        }

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        self._last_connection_rc = rc
        if rc == 0 or rc == mqtt.MQTT_ERR_SUCCESS:
            log.info("Connected to MQTT broker at %s:%d", self._host, self._port)
            self._connected = True
            self._last_error = None
            self._consecutive_failures = 0
            self._activation_message_shown = False
            # Re-subscribe to all registered topics on (re)connect
            self._resubscribe_all()
            if self._bootstrap_mode:
                self._publish_bootstrap_hello()
            # Trigger throttled replay of offline buffer
            if not self._bootstrap_mode:
                self._trigger_replay()
        else:
            log.error("MQTT connection failed with code %s", rc)
            self._connected = False
            self._last_error = f"connect_failed_rc_{rc}"
            if str(rc).lower() == "not authorized":
                self._retire_revoked_operational_credentials()
            self._consecutive_failures += 1
            self._show_activation_message_if_needed()
            self._switch_to_bootstrap_if_needed()

    def _on_disconnect(self, client, userdata, flags, rc, properties=None):
        self._connected = False
        self._last_disconnect_rc = rc
        if rc != 0 and rc != mqtt.MQTT_ERR_SUCCESS:
            log.warning("Unexpected MQTT disconnect (rc=%s). Will auto-reconnect.", rc)
            self._last_error = f"unexpected_disconnect_rc_{rc}"
            self._consecutive_failures += 1
            self._show_activation_message_if_needed()
            self._switch_to_bootstrap_if_needed()
        else:
            log.info("MQTT disconnected cleanly.")

    def _show_activation_message_if_needed(self):
        """Show a friendly activation message after repeated connection failures."""
        if self._consecutive_failures >= 3 and not self._activation_message_shown:
            self._activation_message_shown = True
            msg = (
                "\n"
                "==========================================================\n"
                "  AWAITING CLOUD ACTIVATION\n"
                "\n"
                "  Your Novena Gateway is ready to connect.\n"
                "  Enter your Serial Number and Claim Code at:\n"
                "\n"
                "    Set APP_BASE_URL to your Novena Hub URL.\n"
                "\n"
                f"  Serial Number: {self._serial_number}\n"
                "  (Claim Code is on the sticker on your gateway)\n"
                "=========================================================="
            )
            log.warning(msg)
            # Also print to stdout for users with a monitor connected
            print(msg)

    def _switch_to_bootstrap_if_needed(self):
        """Fall back to bootstrap credentials after repeated auth/connect failures."""
        if self._bootstrap_mode or self._consecutive_failures < 3:
            return
        if self._release_in_progress and self._release_request_id and not self._operational_credentials_retired:
            # Until broker revocation is observed, keep the operational session
            # available for Hub retries of a reset acknowledgement.
            return
        if not self._bootstrap.get("enabled", False):
            return
        username = self._bootstrap.get("username")
        password = self._bootstrap.get("password")
        if not username or not password:
            log.warning("Bootstrap fallback is enabled but username/password are missing.")
            return

        self._bootstrap_mode = True
        self._username = username
        self._password = password
        self._client.username_pw_set(self._username, self._password)
        log.warning("Switching MQTT client to bootstrap mode for self-serve activation.")
        self._reconnect_with_current_credentials()

    def _retire_revoked_operational_credentials(self):
        """Erase the old claim's local MQTT password only after broker denial."""
        if (
            not self._release_in_progress
            or not self._release_request_id
            or self._operational_credentials_retired
            or self._bootstrap_mode
            or not self._config_path
            or not self.on_release_revoked
        ):
            return
        try:
            with open(self._config_path, encoding="utf-8") as handle:
                config = json.load(handle)
            mqtt_config = config.get("mqtt", {})
            if mqtt_config.get("mode") != "release_pending" or mqtt_config.get("release_request_id") != self._release_request_id:
                return
            mqtt_config["username"] = ""
            mqtt_config["password"] = ""
            mqtt_config.pop("claim_id", None)
            self.on_release_revoked(config)
            directory = os.path.dirname(os.path.abspath(self._config_path))
            fd, temporary = tempfile.mkstemp(prefix=".release-credentials-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(config, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self._config_path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            self._username = ""
            self._password = ""
            self._claim_id = None
            self._operational_credentials_retired = True
            self._consecutive_failures = 2
            log.info("Revoked operational MQTT credentials erased from Gateway configuration.")
        except Exception as exc:
            log.error("Could not erase revoked operational MQTT credentials: %s", exc)

    def _publish_bootstrap_hello(self):
        payload = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "bootstrap": True,
        }
        topic = f"v1/gateway/{self._serial_number}/bootstrap/hello"
        # Called from paho's on_connect callback: waiting for publish here
        # blocks the network loop, including SUBACK and activation delivery.
        result = self._client.publish(topic, json.dumps(payload), qos=self._qos)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            log.warning("Could not publish bootstrap hello (rc=%s).", result.rc)

    def _on_publish(self, client, userdata, mid, rc=None, properties=None):
        log.debug("Message %d published successfully.", mid)

    def _on_message(self, client, userdata, msg):
        """Route inbound messages to registered callbacks."""
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode())
        except Exception as e:
            log.error("Failed to decode inbound MQTT message on %s: %s", topic, e)
            return

        log.debug("Inbound message on %s: %s", topic, payload)

        with self._subscription_lock:
            callbacks = list(self._subscriptions.get(topic, []))

        if not callbacks:
            log.warning("No handler registered for topic %s", topic)
            return

        for cb in callbacks:
            try:
                cb(topic, payload)
            except Exception as e:
                log.exception("Error in message handler for topic %s: %s", topic, e)

    def _publish_loop(self):
        """Background thread that drains the queue and publishes messages."""
        while not self._stopped:
            try:
                item = self._queue.get(timeout=0.5)
            except Empty:
                continue

            # Items are now (topic, payload) tuples
            if isinstance(item, tuple) and len(item) == 3:
                topic, payload, claim_id = item
            elif isinstance(item, tuple) and len(item) == 2:
                topic, payload = item
                claim_id = None
            else:
                # Backward compatibility: bare dict goes to telemetry topic
                topic = self._telemetry_topic
                payload = item

                claim_id = None

            if claim_id != self._claim_id:
                log.warning("Discarded queued MQTT event from a previous Gateway claim.")
                continue
            if getattr(self, "_release_in_progress", False):
                continue

            json_payload = json.dumps(payload)

            if self._connected and not self._bootstrap_mode:
                result = self._client.publish(
                    topic, json_payload, qos=self._qos
                )
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    log.warning("Publish failed (rc=%d) on %s, buffering to SQLite.", result.rc, topic)
                    event_str = json.dumps({"topic": topic, "payload": payload, "claim_id": claim_id})
                    if not self._buffer_event(event_str):
                        self._dropped_message_count += 1
            else:
                log.debug("Not connected in publish loop — buffering message to SQLite.")
                event_str = json.dumps({"topic": topic, "payload": payload, "claim_id": claim_id})
                if not self._buffer_event(event_str):
                    self._dropped_message_count += 1
                sleep(1)

    def _trigger_replay(self):
        """Spawns the background replay thread if it is not already running."""
        with self._replay_lock:
            if self._replay_thread is None or not self._replay_thread.is_alive():
                self._replay_thread = threading.Thread(
                    target=self._replay_loop, name="MQTT-Replayer", daemon=True
                )
                self._replay_thread.start()

    def _replay_loop(self):
        """Replay buffered historical messages from SQLite at a throttled pace."""
        log.info("Replay loop started. Checking SQLite database buffer for offline events...")
        while not self._stopped and self._connected and not self._bootstrap_mode and not getattr(self, "_release_in_progress", False):
            storage_len = self._storage.len()
            if storage_len == 0:
                self._last_replay_status = "complete"
                log.info("SQLite database buffer is empty. Replay complete.")
                break
                
            pack = self._storage.get_event_pack()
            if not pack:
                sleep(0.5)
                continue
                
            log.info("Replaying batch of %d events from SQLite...", len(pack))
            
            success_count = 0
            for event_str in pack:
                if self._stopped or not self._connected or getattr(self, "_release_in_progress", False):
                    break
                try:
                    event = json.loads(event_str)
                    topic = event["topic"]
                    payload = event["payload"]

                    if event.get("claim_id") != self._claim_id:
                        log.warning("Discarded buffered MQTT event from a previous Gateway claim.")
                        success_count += 1
                        continue
                    if self._bootstrap_mode:
                        break
                    
                    result = self._client.publish(topic, json.dumps(payload), qos=self._qos)
                    sleep(0.1)  # 100ms throttle between messages
                    
                    if result.rc == mqtt.MQTT_ERR_SUCCESS:
                        success_count += 1
                except Exception as e:
                    log.error("Failed to replay buffered event: %s", e)
            
            # Only delete the batch when every event was accepted by the local
            # MQTT client. Duplicates on partial failure are safer than data loss.
            if success_count == len(pack):
                self._storage.event_pack_processing_done()
                self._last_replay_status = "success"
            else:
                self._last_replay_status = "partial_failure"
                self._replay_failure_count += 1
                log.warning(
                    "Replay partially failed (%d/%d). Preserving batch for retry.",
                    success_count, len(pack),
                )
            log.info("Replayed %d of %d events from batch.", success_count, len(pack))
            sleep(0.5)

    def _flush_queue(self):
        """Attempt to publish remaining messages before shutdown."""
        flush_count = 0
        while not self._queue.empty() and self._connected and not self._bootstrap_mode:
            try:
                item = self._queue.get_nowait()
                if isinstance(item, tuple) and len(item) == 3:
                    topic, payload, claim_id = item
                    if claim_id != self._claim_id:
                        continue
                elif isinstance(item, tuple) and len(item) == 2:
                    topic, payload = item
                else:
                    topic = self._telemetry_topic
                    payload = item
                json_payload = json.dumps(payload)
                self._client.publish(topic, json_payload, qos=self._qos)
                flush_count += 1
            except Empty:
                break
        if flush_count:
            log.info("Flushed %d messages before shutdown.", flush_count)

    def collect_buffer_attributes(self) -> dict:
        try:
            buffered_count = self._storage.len()
        except Exception:
            buffered_count = None
        return {
            "buffered_event_count": buffered_count,
            "publish_queue_size": self._queue.qsize(),
            "dropped_message_count": self._dropped_message_count,
            "last_replay_status": self._last_replay_status,
            "replay_failure_count": self._replay_failure_count,
        }

    # ─── Credential rotation (provision topic) ────────────────────────

    def _on_provision_message(self, topic: str, payload: dict):
        """Handle inbound provisioning commands (e.g. password rotation)."""
        action = payload.get("action")
        if action == "release":
            self._handle_release(payload)
        elif action in ("rotate_password", "activate"):
            mqtt_cfg = payload.get("mqtt") or {}
            new_password = payload.get("new_password") or mqtt_cfg.get("password")
            new_username = mqtt_cfg.get("username") or self._serial_number
            request_id = payload.get("request_id")
            if not new_password:
                log.error("Provision %s: missing password", action)
                self._publish_credential_ack(
                    action,
                    request_id,
                    "failed",
                    "missing password",
                    generation=payload.get("generation"),
                )
                return
            self._rotate_password(
                new_password,
                new_username,
                request_id=request_id,
                action=action,
                generation=payload.get("generation"),
                claim_id=payload.get("claim_id"),
            )
        else:
            log.warning("Unknown provision action: %s", action)

    def _verify_release(self, payload: dict) -> str:
        """Require the Hub's signing key, current claim, target, and fresh expiry."""
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("invalid release schema")
        if payload.get("action") != "release" or (payload.get("target") or {}).get("gateway_serial") != self._serial_number:
            raise ValueError("release targets a different Gateway")
        request_id = str(UUID(str(payload.get("request_id"))))
        if payload.get("claim_id") != self._claim_id or not self._claim_id:
            raise ValueError("release belongs to a different claim")
        key_id = payload.get("signing_key_id")
        encoded_key = self._trusted_release_keys.get(key_id)
        if not encoded_key:
            raise ValueError("untrusted release signing key")
        expiry = datetime.fromisoformat(str(payload.get("expires_at")).replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            raise ValueError("expired release request")
        body = {k: v for k, v in payload.items() if k not in {"signing_key_id", "signature"}}
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded_key, validate=True))
        key.verify(base64.b64decode(payload.get("signature") or "", validate=True), canonical_bytes(body))
        return request_id

    def _handle_release(self, payload: dict):
        try:
            request_id = self._verify_release(payload)
            if self._release_request_id != request_id:
                if not self.on_release or not self._config_path:
                    raise RuntimeError("Gateway release reset is unavailable")
                with open(self._config_path, encoding="utf-8") as handle:
                    config = json.load(handle)
                config["connectors"] = []
                config["mqtt"]["mode"] = "release_pending"
                directory = os.path.dirname(os.path.abspath(self._config_path))
                fd, temporary = tempfile.mkstemp(prefix=".release-config-", dir=directory)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        json.dump(config, handle, indent=2)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, self._config_path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                self._release_in_progress = True
                self.on_release(config)
                config["mqtt"]["release_request_id"] = request_id
                fd, temporary = tempfile.mkstemp(prefix=".release-config-", dir=directory)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        json.dump(config, handle, indent=2)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, self._config_path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                self._release_request_id = request_id
            self._publish_release_ack(request_id)
        except (ValueError, TypeError, KeyError, InvalidSignature, OSError, RuntimeError, binascii.Error) as exc:
            log.warning("Rejected or could not complete Gateway release: %s", exc)

    def clear_claim_buffer(self):
        """Erase offline data and pending sends after all site connectors have stopped."""
        self._release_in_progress = True
        self._queue = Queue(maxsize=self._max_queue_size)
        if self._replay_thread and self._replay_thread.is_alive():
            self._replay_thread.join(timeout=5)
            if self._replay_thread.is_alive():
                raise RuntimeError("offline replay did not stop")
        with self._buffer_lock:
            storage_dir = os.path.realpath(self._resolved_storage_config["data_file_path"])
            data_root = os.path.realpath(DATA_DIR)
            if not storage_dir.startswith(data_root + os.sep):
                raise RuntimeError("unsafe SQLite storage directory")
            self._storage.stop()
            if os.path.isdir(storage_dir):
                shutil.rmtree(storage_dir)
            os.makedirs(storage_dir, mode=0o700, exist_ok=True)
            self._storage = SQLiteEventStorage(self._resolved_storage_config, log, self._storage_stop_event)

    def _publish_release_ack(self, request_id: str):
        ack = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": {
                "gateway_release_status": "reset_complete",
                "gateway_release_request_id": request_id,
                "gateway_release_claim_id": self._claim_id,
            },
        }
        # This runs on paho's network thread. Waiting for PUBACK here would
        # deadlock the loop; Hub retries if the QoS-1 receipt is lost.
        topic = self._scoped_topic("attributes")
        result = self._client.publish(topic, json.dumps(ack), qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            log.warning("Gateway release acknowledgement could not be queued (rc=%s).", result.rc)

    def _rotate_password(
        self,
        new_password: str,
        new_username: str = None,
        request_id: str = None,
        action: str = "rotate_password",
        generation=None,
        claim_id=None,
    ):
        """
        Rotate MQTT credentials:
        1. Update config.json on disk
        2. Update in-memory password
        3. Disconnect and reconnect with new credentials
        """
        log.info("MQTT password rotation initiated...")
        claim_changed = action == "activate" and bool(claim_id) and claim_id != self._claim_id

        # 1. Update config.json on disk
        if self._config_path:
            try:
                with open(self._config_path, 'r') as f:
                    config = json.load(f)
                if new_username:
                    config["mqtt"]["username"] = new_username
                config["mqtt"]["password"] = new_password
                config["mqtt"]["mode"] = "operational"
                if action == "activate" and claim_id:
                    config["mqtt"]["claim_id"] = claim_id
                    config["mqtt"].pop("release_request_id", None)
                if claim_changed:
                    config["connectors"] = []
                tmp_path = self._config_path + ".tmp"
                with open(tmp_path, 'w') as f:
                    json.dump(config, f, indent=2)
                os.replace(tmp_path, self._config_path)
                log.info("Updated config.json with new MQTT password")
            except Exception as e:
                log.error("Failed to update config.json during password rotation: %s", e)
                self._publish_credential_ack(action, request_id, "failed", str(e), generation=generation)
                return

        if claim_changed and self.on_claim_changed:
            try:
                self.on_claim_changed(config)
            except Exception as e:
                log.exception("Failed to clear previous claim field state: %s", e)
                self._publish_credential_ack(action, request_id, "failed", "field state reset failed", generation=generation)
                return

        # 2. Update in-memory password
        if new_username:
            self._username = new_username
        self._password = new_password
        if action == "activate" and claim_id:
            self._claim_id = claim_id
            self._release_request_id = None
            self._release_in_progress = False
            self._operational_credentials_retired = False
        self._bootstrap_mode = False
        if hasattr(self, "_client"):
            self._client.username_pw_set(self._username, self._password)

        self._publish_credential_ack(action, request_id, "success", generation=generation)

        # 3. Disconnect (paho will auto-reconnect with the new credentials)
        log.info("Disconnecting to apply new credentials...")
        self._reconnect_with_current_credentials()

    def _publish_credential_ack(
        self,
        action: str,
        request_id: str = None,
        status: str = "success",
        error: str = "",
        *,
        generation=None,
    ):
        attributes = {
            "credential_update_status": status,
            "credential_update_action": action,
            "credential_update_request_id": request_id,
        }
        if generation is not None:
            attributes["credential_update_generation"] = generation
        if error:
            attributes["credential_update_error"] = error
        ack = {
            "serial_number": self._serial_number,
            "ts": int(time() * 1000),
            "attributes": attributes,
        }
        try:
            if not self.publish_attributes(ack, immediate=True):
                log.warning("Credential %s acknowledgement was queued but not confirmed by MQTT.", action)
        except Exception as e:
            log.warning("Failed to publish credential %s acknowledgement: %s", action, e)

    def _reconnect_with_current_credentials(self):
        try:
            self._client.disconnect()
        except Exception as e:
            log.debug("MQTT disconnect before reconnect failed: %s", e)
        try:
            self._client.reconnect()
        except Exception as e:
            log.warning("MQTT reconnect with updated credentials failed: %s", e)
            pass
