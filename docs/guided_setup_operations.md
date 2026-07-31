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

## PLC signal validation

For a programmable PLC or generic I/O device, the Hub supplies a site-specific
mapping in a signed `deployment_validate` command. A connection-only check opens
the selected Modbus endpoint without reading registers. A datapoint check performs
only function-code 1, 2, 3, or 4 reads, with a maximum of 20 signals and four
objects per signal.

The Gateway decodes byte order, word order, data type, multiplier, and offset before
returning the typed value and sampled raw objects to the Hub. It also rejects
non-finite values and readings outside configured safety bounds. Conservative
defaults flag Celsius values outside -100 to 500 and percentage values outside
0 to 100 when the installer has not supplied bounds.

The returned mapping checksum identifies the exact signed request that was tested.
The Hub requires every signal to succeed and requires a user to confirm those
decoded readings before that mapping is eligible for connector configuration.
Changing the connection or mapping invalidates the evidence and requires another
test. This validation path never writes to field equipment.

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
