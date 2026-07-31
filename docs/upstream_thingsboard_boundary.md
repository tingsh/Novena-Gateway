# ThingsBoard Upstream Boundary

Novena Gateway is built around protocol and storage components inherited from the official ThingsBoard IoT Gateway project. Those components provide broad industrial protocol support and are intentionally kept separate from Novena-owned orchestration.

## Protected paths

- `novena_gateway/connectors/`
- `novena_gateway/extensions/`
- `novena_gateway/tb_utility/`
- `novena_gateway/storage/`

General cleanup, formatting and module-splitting work must not edit these paths. Their large modules reflect upstream protocol implementations and are not evidence of Novena-specific architectural bloat.

## Novena-owned extension layer

Novena behavior belongs under `novena_gateway/gateway/`: MQTT identity, activation, remote configuration, guided deployment, governed commands, health reporting, OTA security and adapters around offline storage.

When a Novena requirement needs upstream behavior, prefer a wrapper or adapter. Modify protected code only for a separately reviewed upstream synchronization or a connector defect that cannot be isolated. Preserve license headers and document the upstream revision, reason and test evidence for every divergence.

## Recorded divergences

- 2026-07-30: `bytes_modbus_uplink_converter.py` applies an optional numeric `offset` after the existing divider/multiplier conversion. Guided PLC mapping validates `decoded * multiplier + offset`, so the deployed connector must use identical edge-side arithmetic before semantic telemetry is published. This cannot be isolated in the Novena orchestration layer because it only receives already-converted values. Covered by focused converter and guided-validation tests.
