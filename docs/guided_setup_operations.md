# Guided Setup Gateway Operations

`guided_setup_v1` is the Gateway capability for secure Modbus equipment setup. The
Gateway advertises it only when its clock is trusted and at least one Hub signing
public key is installed.

## Required security configuration

Configure these fields under `features.rpc`:

```json
{
  "trusted_clock": true,
  "trusted_command_keys": {
    "hub-signing-key-id": "<base64 Ed25519 public key>"
  },
  "revoked_command_key_ids": []
}
```

The remote configuration handler reuses those public keys unless
`features.remote_config.trusted_config_keys` is set explicitly. Keep the private key
in Novena Hub; it must never be installed on a Gateway.

The service account must be able to write:

- `features.remote_config.config_journal_path`
- `features.remote_config.last_known_good_path`
- the configured backup directory

The journal stores the highest activated revision and recent idempotency outcomes.
That makes a repeated MQTT delivery safe and prevents an older configuration from
replacing a newer one.

## Discovery safety

Guided Modbus TCP discovery accepts only explicit unicast IP addresses and ports,
with at most 64 targets per request. It does not infer or sweep a subnet. Modbus RTU
uses explicit or locally enumerated serial interfaces and bounded common settings.
Scans are rate-limited, cancellable, and report partial progress.

## Activation and rollback

For a signed configuration, the Gateway verifies the target serial, expiry,
signature, checksum, revision, and idempotency key before activation. It then:

1. validates the complete candidate configuration;
2. saves the previous file as last-known-good;
3. atomically replaces the configuration;
4. starts each connector and reports per-connector evidence;
5. restores the last-known-good configuration if activation fails.

Legacy configuration payloads remain accepted during rollout. Do not enable or
manually claim `guided_setup_v1`; capability advertisement is derived from runtime
security readiness.
