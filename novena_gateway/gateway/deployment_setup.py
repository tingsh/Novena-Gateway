"""Security and replay protection for guided deployment setup."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from novena_gateway.gateway.runtime_paths import CONFIG_JOURNAL_PATH


GUIDED_SETUP_SCHEMA_VERSION = 1
CAPABILITY_GUIDED_SETUP = "guided_setup_v1"


class DeploymentSetupRejected(ValueError):
    """A signed setup request failed an edge-enforced safety check."""


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def checksum(payload: dict) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


class ConfigReplayJournal:
    """Small atomic journal used to make config delivery idempotent."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._state = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as handle:
                state = json.load(handle)
            if isinstance(state, dict):
                state.setdefault("max_revision", 0)
                state.setdefault("requests", {})
                return state
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {"max_revision": 0, "requests": {}}

    def _persist(self):
        directory = os.path.dirname(self.path)
        fd, temporary_path = tempfile.mkstemp(prefix=".config-journal-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._state, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    @property
    def max_revision(self) -> int:
        with self._lock:
            return int(self._state.get("max_revision", 0))

    def get(self, idempotency_key: str) -> dict | None:
        with self._lock:
            value = self._state["requests"].get(idempotency_key)
            return dict(value) if value else None

    def record(self, *, idempotency_key: str, revision: int, result: dict):
        with self._lock:
            self._state["max_revision"] = max(int(revision), int(self._state.get("max_revision", 0)))
            self._state["requests"][idempotency_key] = {
                "revision": int(revision),
                "result": result,
            }
            # Bound the appliance journal while retaining the newest revisions.
            if len(self._state["requests"]) > 500:
                ordered = sorted(
                    self._state["requests"].items(),
                    key=lambda item: int(item[1].get("revision", 0)),
                    reverse=True,
                )
                self._state["requests"] = dict(ordered[:500])
            self._persist()


class ConfigEnvelopeGuard:
    """Verify signed config envelopes independently at the Gateway."""

    def __init__(self, *, serial_number: str, config: dict):
        self.serial_number = serial_number
        self.trusted_clock = bool(config.get("trusted_clock", False))
        self.keys = {}
        revoked = set(config.get("revoked_config_key_ids") or [])
        configured_keys = config.get("trusted_config_keys") or {}
        for key_id, encoded in configured_keys.items():
            if key_id in revoked:
                continue
            try:
                raw = base64.b64decode(encoded, validate=True)
                self.keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
            except (ValueError, TypeError):
                continue
        journal_path = config.get(
            "config_journal_path",
            CONFIG_JOURNAL_PATH,
        )
        self.journal = ConfigReplayJournal(journal_path)

    @property
    def ready(self) -> bool:
        return self.trusted_clock and bool(self.keys)

    def verify(self, wire: dict) -> tuple[dict, dict | None]:
        if not self.ready:
            raise DeploymentSetupRejected("Signed guided setup is not configured on this Gateway")
        if not isinstance(wire, dict):
            raise DeploymentSetupRejected("Configuration envelope must be an object")

        signature = wire.get("signature")
        key = self.keys.get(wire.get("signing_key_id"))
        body = {key: value for key, value in wire.items() if key not in {"signature", "signing_key_id"}}
        if not key or not signature:
            raise DeploymentSetupRejected("Configuration signing key is not trusted")
        try:
            key.verify(base64.b64decode(signature, validate=True), canonical_bytes(body))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise DeploymentSetupRejected("Configuration signature verification failed") from exc

        if body.get("schema_version") != GUIDED_SETUP_SCHEMA_VERSION:
            raise DeploymentSetupRejected("Unsupported guided setup schema version")
        if (body.get("target") or {}).get("gateway_serial") != self.serial_number:
            raise DeploymentSetupRejected("Configuration targets a different Gateway")
        if not body.get("request_id") or not body.get("idempotency_key"):
            raise DeploymentSetupRejected("Configuration request identity is incomplete")

        try:
            expires_at = datetime.fromisoformat(str(body["expires_at"]).replace("Z", "+00:00"))
            expires_at = expires_at.astimezone(timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            raise DeploymentSetupRejected("Configuration expiry is invalid") from exc
        if expires_at <= datetime.now(timezone.utc):
            raise DeploymentSetupRejected("Configuration request has expired")

        config_payload = body.get("config")
        if not isinstance(config_payload, dict):
            raise DeploymentSetupRejected("Configuration payload is missing")
        if body.get("checksum") != checksum(config_payload):
            raise DeploymentSetupRejected("Configuration checksum mismatch")

        idempotency_key = str(body["idempotency_key"])
        replay = self.journal.get(idempotency_key)
        if replay:
            return body, replay

        try:
            revision = int(body["revision"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DeploymentSetupRejected("Configuration revision is invalid") from exc
        if revision <= self.journal.max_revision:
            raise DeploymentSetupRejected("Configuration revision is stale")
        return body, None

    def record(self, body: dict, result: dict):
        self.journal.record(
            idempotency_key=str(body["idempotency_key"]),
            revision=int(body["revision"]),
            result=result,
        )
