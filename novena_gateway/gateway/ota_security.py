"""Signed OTA manifest and archive validation helpers."""

import base64
import json
import os
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from novena_gateway.__version__ import __version__ as gateway_version


DEFAULT_OTA_PUBLIC_KEY_PATH = "/etc/novena-gateway/trust/ota_vendor_ed25519.pub"
DEFAULT_OTA_KEY_ID = "novena-ota-v1"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-(?:rc|canary)\.\d+)?$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_MANIFEST_AGE_SECONDS = 60 * 60 * 24 * 30


class OtaSecurityError(ValueError):
    """Raised when an OTA manifest or artifact fails trust validation."""


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_public_key(path: str) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise OtaSecurityError("OTA public key must be Ed25519")
        return key
    except ValueError:
        try:
            return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw.strip(), validate=True))
        except Exception as exc:
            raise OtaSecurityError("Invalid OTA public key") from exc


def _parse_iso_datetime(value: str, field_name: str) -> datetime:
    if not value:
        raise OtaSecurityError(f"Manifest missing {field_name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OtaSecurityError(f"Manifest has invalid {field_name}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalised_version(value: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise OtaSecurityError("Manifest version is invalid")
    return value


def _version_tuple(value: str) -> tuple[int, int, int]:
    base = _normalised_version(value).split("-", 1)[0]
    return tuple(int(part) for part in base.split("."))


def _validate_compatibility(manifest: dict):
    current = _version_tuple(gateway_version)
    minimum = manifest.get("minimum_gateway_version")
    maximum = manifest.get("maximum_gateway_version")
    if minimum and current < _version_tuple(minimum):
        raise OtaSecurityError("Gateway version is below manifest minimum")
    if maximum and current > _version_tuple(maximum):
        raise OtaSecurityError("Gateway version is above manifest maximum")


def verify_manifest(
    manifest: dict,
    signature_b64: str,
    public_key_path: str = DEFAULT_OTA_PUBLIC_KEY_PATH,
    trusted_key_ids: Iterable[str] = None,
    now: datetime = None,
) -> dict:
    """Verify and validate a signed OTA manifest, returning trusted fields."""
    if not isinstance(manifest, dict):
        raise OtaSecurityError("Manifest must be a JSON object")
    if not signature_b64:
        raise OtaSecurityError("Missing manifest signature")

    key_id = manifest.get("key_id")
    trusted = set(trusted_key_ids or [DEFAULT_OTA_KEY_ID])
    if key_id not in trusted:
        raise OtaSecurityError("Manifest key id is not trusted")

    public_key = load_public_key(public_key_path)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise OtaSecurityError("Manifest signature is not valid base64") from exc
    try:
        public_key.verify(signature, canonical_manifest_bytes(manifest))
    except InvalidSignature as exc:
        raise OtaSecurityError("Manifest signature verification failed") from exc

    trusted_manifest = dict(manifest)
    version = _normalised_version(trusted_manifest.get("version"))
    artifact_url = trusted_manifest.get("artifact_url")
    artifact_sha256 = trusted_manifest.get("artifact_sha256")
    size_bytes = trusted_manifest.get("size_bytes")
    channel = trusted_manifest.get("channel")

    if not isinstance(artifact_url, str):
        raise OtaSecurityError("Manifest artifact_url is invalid")
    parsed = urlparse(artifact_url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
        raise OtaSecurityError("Manifest artifact URL must use HTTPS")
    if not isinstance(artifact_sha256, str) or not SHA256_RE.fullmatch(artifact_sha256):
        raise OtaSecurityError("Manifest artifact_sha256 is invalid")
    if not isinstance(size_bytes, int) or size_bytes <= 0:
        raise OtaSecurityError("Manifest size_bytes is invalid")
    if channel not in ("stable", "pilot", "canary"):
        raise OtaSecurityError("Manifest channel is invalid")

    issued_at = _parse_iso_datetime(trusted_manifest.get("issued_at"), "issued_at")
    expires_at = _parse_iso_datetime(trusted_manifest.get("expires_at"), "expires_at")
    current_time = now or datetime.now(timezone.utc)
    if expires_at <= current_time:
        raise OtaSecurityError("Manifest has expired")
    if issued_at > current_time:
        raise OtaSecurityError("Manifest issued_at is in the future")
    if (expires_at - issued_at).total_seconds() > MAX_MANIFEST_AGE_SECONDS:
        raise OtaSecurityError("Manifest validity window is too long")

    _validate_compatibility(trusted_manifest)

    trusted_manifest["version"] = version
    trusted_manifest["artifact_sha256"] = artifact_sha256.lower()
    return trusted_manifest


def resolve_child_path(base_dir: str, filename: str) -> str:
    base = Path(base_dir).expanduser().resolve()
    candidate = (base / filename).resolve()
    if not os.path.commonpath([str(base), str(candidate)]) == str(base):
        raise OtaSecurityError("Resolved OTA path escapes its base directory")
    return str(candidate)


def safe_release_dir(install_dir: str, version: str) -> str:
    version = _normalised_version(version)
    releases = (Path(install_dir).expanduser().resolve() / "releases").resolve()
    candidate = (releases / f"novena-gateway-{version}").resolve()
    if not os.path.commonpath([str(releases), str(candidate)]) == str(releases):
        raise OtaSecurityError("Resolved release path escapes releases directory")
    return str(candidate)


def validate_tarball(path: str):
    """Reject tar entries that can escape or mutate privileged paths unexpectedly."""
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts:
                raise OtaSecurityError(f"Unsafe archive path: {name}")
            if member.issym() or member.islnk():
                raise OtaSecurityError(f"Archive links are not allowed: {name}")
            if member.isdev() or member.isfifo():
                raise OtaSecurityError(f"Archive special files are not allowed: {name}")
            if member.mode & 0o002:
                raise OtaSecurityError(f"World-writable archive entry is not allowed: {name}")
