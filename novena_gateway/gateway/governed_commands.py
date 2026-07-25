"""Independent edge validation and durable exactly-once command evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from time import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class GovernedCommandRejected(ValueError):
    pass


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def checksum(payload: dict) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


class DurableCommandJournal:
    def __init__(self, path: str):
        self._path = os.path.abspath(path)
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._state = self._load()

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                return data if isinstance(data, dict) else {"commands": {}, "sequences": {}}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {"commands": {}, "sequences": {}}

    def _persist(self):
        directory = os.path.dirname(self._path)
        fd, temp_path = tempfile.mkstemp(prefix=".command-journal-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._state, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def get(self, command_id):
        with self._lock:
            record = self._state["commands"].get(command_id)
            return dict(record) if record else None

    def max_sequence(self, device_id):
        with self._lock:
            return int(self._state["sequences"].get(device_id, 0))

    def write(self, command_id, record):
        with self._lock:
            self._state["commands"][command_id] = dict(record)
            device_id = record.get("device_id")
            sequence = int(record.get("sequence_number", 0))
            if device_id:
                self._state["sequences"][device_id] = max(
                    sequence,
                    int(self._state["sequences"].get(device_id, 0)),
                )
            self._persist()


class GovernedCommandGuard:
    def __init__(self, *, serial_number: str, gateway, config: dict):
        self._serial_number = serial_number
        self._gateway = gateway
        self._trusted_clock = bool(config.get("trusted_clock", False))
        self._max_clock_offset = float(config.get("max_clock_offset_seconds", 5))
        self._keys = {}
        for key_id, encoded in (config.get("trusted_command_keys") or {}).items():
            try:
                self._keys[key_id] = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))
            except (ValueError, TypeError):
                continue
        journal_path = config.get("command_journal_path", "storage/remote_control/command_journal.json")
        self.journal = DurableCommandJournal(journal_path)
        self._policy_path = os.path.abspath(
            config.get("command_policy_path", "storage/remote_control/policy.json")
        )
        self._policy = self._load_policy()
        self._device_locks = {}
        self._locks_guard = threading.Lock()

    @property
    def policy_loaded(self):
        return bool(self._policy)

    @property
    def policy_revision(self):
        return (self._policy or {}).get("revision", 0)

    @property
    def control_epoch(self):
        return (self._policy or {}).get("control_epoch", 0)

    def readiness(self):
        return {
            "remote_control_policy_loaded": self.policy_loaded,
            "remote_control_policy_revision": self.policy_revision,
            "remote_control_epoch": self.control_epoch,
            "remote_control_clock_ready": self._trusted_clock,
            "remote_control_journal_ready": os.path.isdir(os.path.dirname(self.journal._path)),
        }

    def _load_policy(self):
        try:
            with open(self._policy_path, "r", encoding="utf-8") as handle:
                wire = json.load(handle)
            self._verify_signed(wire)
            payload = wire["payload"]
            if payload.get("gateway_serial") != self._serial_number:
                return None
            return payload
        except (FileNotFoundError, OSError, ValueError, KeyError, InvalidSignature):
            return None

    def _verify_signed(self, wire):
        key_id = wire.get("signing_key_id")
        key = self._keys.get(key_id)
        if not key:
            raise GovernedCommandRejected("Signing key is not trusted")
        try:
            signature = base64.b64decode(wire["signature"], validate=True)
            key.verify(signature, canonical_bytes(wire["payload"]))
        except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
            raise GovernedCommandRejected("Signature verification failed") from exc

    def install_policy(self, _topic, wire):
        if not isinstance(wire, dict):
            raise GovernedCommandRejected("Policy bundle must be an object")
        self._verify_signed(wire)
        payload = wire["payload"]
        if wire.get("checksum") != checksum(payload):
            raise GovernedCommandRejected("Policy checksum mismatch")
        if payload.get("schema_version") != 1:
            raise GovernedCommandRejected("Unsupported policy schema")
        if payload.get("gateway_serial") != self._serial_number:
            raise GovernedCommandRejected("Policy targets a different Gateway")
        if self._policy and int(payload.get("control_epoch", 0)) < self.control_epoch:
            raise GovernedCommandRejected("Restored or stale policy epoch")
        os.makedirs(os.path.dirname(self._policy_path), exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=os.path.dirname(self._policy_path),
            prefix=".policy-",
            delete=False,
        ) as handle:
            json.dump(wire, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = handle.name
        os.replace(temp_path, self._policy_path)
        self._policy = payload

    def _parse_time(self, value):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (AttributeError, ValueError) as exc:
            raise GovernedCommandRejected("Command timestamp is invalid") from exc

    def validate(self, envelope):
        if not self._trusted_clock:
            raise GovernedCommandRejected("Trusted clock is not ready")
        if not self._policy:
            raise GovernedCommandRejected("No valid retained control policy is loaded")
        signature = envelope.get("signature")
        key_id = envelope.get("signing_key_id")
        body = {key: value for key, value in envelope.items() if key not in {"signature", "signing_key_id"}}
        self._verify_signed({"payload": body, "signature": signature, "signing_key_id": key_id})
        if envelope.get("schema_version") != 1:
            raise GovernedCommandRejected("Unsupported governed-command schema")
        target = envelope.get("target") or {}
        if target.get("gateway_serial") != self._serial_number:
            raise GovernedCommandRejected("Command targets a different Gateway")
        now = datetime.now(timezone.utc)
        issued_at = self._parse_time(envelope.get("issued_at"))
        expires_at = self._parse_time(envelope.get("expires_at"))
        if expires_at <= now:
            raise GovernedCommandRejected("Command has expired")
        if abs((now - issued_at).total_seconds()) > max(
            self._max_clock_offset,
            (expires_at - issued_at).total_seconds(),
        ):
            raise GovernedCommandRejected("Command timestamp is outside its trusted window")
        if int(envelope.get("control_epoch", 0)) != self.control_epoch:
            raise GovernedCommandRejected("Command control epoch is stale")

        params = envelope.get("params") or {}
        device_id = target.get("device_id")
        command_key = params.get("command_key")
        control = self._policy.get("controls", {}).get(f"{device_id}:{command_key}")
        if not control:
            raise GovernedCommandRejected("Device key is not enabled by retained policy")
        if envelope.get("revisions") != control.get("revisions"):
            raise GovernedCommandRejected("Command policy revisions are stale")
        if envelope.get("policy_checksum") != control.get("policy_checksum"):
            raise GovernedCommandRejected("Command policy checksum is stale")
        mapping = control.get("mapping") or {}
        for field in ("functionCode", "address"):
            if int(params.get(field, -1)) != int(mapping.get(field, -2)):
                raise GovernedCommandRejected(f"Connector {field} does not match retained policy")
        if mapping.get("type") and params.get("type") != mapping["type"]:
            raise GovernedCommandRejected("Connector data type does not match retained policy")
        if params.get("unit") != control.get("unit"):
            raise GovernedCommandRejected("Engineering unit does not match retained policy")

        expected = params.get("expected_value")
        limits = control.get("limits") or {}
        if limits.get("enum") is not None and expected not in limits["enum"]:
            raise GovernedCommandRejected("Value is not in retained allowed set")
        if limits.get("min") is not None and float(expected) < float(limits["min"]):
            raise GovernedCommandRejected("Value is below retained minimum")
        if limits.get("max") is not None and float(expected) > float(limits["max"]):
            raise GovernedCommandRejected("Value is above retained maximum")

        command_id = envelope.get("command_id")
        existing = self.journal.get(command_id)
        if existing:
            if existing.get("state") == "terminal":
                return control, existing
            raise GovernedCommandRejected("Prior execution outcome is uncertain; command will not repeat")
        sequence = int(envelope.get("sequence_number", 0))
        if sequence <= self.journal.max_sequence(device_id):
            raise GovernedCommandRejected("Command sequence is stale or duplicated")
        return control, None

    def device_lock(self, device_id):
        with self._locks_guard:
            return self._device_locks.setdefault(device_id, threading.Lock())

    def enforce_prerequisites(self, control, params):
        runtime = (
            self._gateway.collect_runtime_attributes()
            if hasattr(self._gateway, "collect_runtime_attributes")
            else {}
        )
        authority = str(runtime.get("authority_mode", "unknown")).lower()
        if authority in {"local", "hand", "manual"}:
            raise GovernedCommandRejected("Local/Hand authority currently blocks remote control")
        for prerequisite in control.get("prerequisites") or []:
            if not isinstance(prerequisite, dict):
                raise GovernedCommandRejected("Retained prerequisite definition is invalid")
            source = runtime
            if prerequisite.get("source") == "device":
                device_id = params.get("device_id")
                matches = [
                    info
                    for info in self._gateway.get_devices().values()
                    if str(info.get("device_id") or "") == str(device_id)
                ]
                source = matches[0] if len(matches) == 1 else {}
            key = prerequisite.get("key")
            actual = source.get(key)
            if "equals" in prerequisite and actual != prerequisite["equals"]:
                raise GovernedCommandRejected(
                    f"Supervisory prerequisite '{key}' is not satisfied"
                )
            if "in" in prerequisite and actual not in prerequisite["in"]:
                raise GovernedCommandRejected(
                    f"Supervisory prerequisite '{key}' is not satisfied"
                )
            observed_at = source.get(f"{key}_observed_at")
            if prerequisite.get("max_age_seconds") is not None:
                if observed_at is None or time() - float(observed_at) > float(
                    prerequisite["max_age_seconds"]
                ):
                    raise GovernedCommandRejected(
                        f"Supervisory prerequisite '{key}' is stale"
                    )

    def mark_executing(self, envelope):
        target = envelope["target"]
        self.journal.write(
            envelope["command_id"],
            {
                "state": "executing",
                "device_id": target["device_id"],
                "sequence_number": envelope["sequence_number"],
                "started_at": int(time() * 1000),
            },
        )

    def mark_terminal(self, envelope, *, status, result=None, error=None, stage=None):
        self.journal.write(
            envelope["command_id"],
            {
                "state": "terminal",
                "device_id": envelope["target"]["device_id"],
                "sequence_number": envelope["sequence_number"],
                "status": status,
                "result": result,
                "error": error,
                "stage": stage,
                "completed_at": int(time() * 1000),
            },
        )
