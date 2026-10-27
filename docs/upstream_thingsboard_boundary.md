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

- 2026-10-26: `modbus_connector.py` closes a TCP master after its first `ModbusIOException` instead of continuing to poll on a socket that can still report connected after field-cable loss. The previous CM4 cold-room replay showed pymodbus 3.8.6 waiting through repeated 3-retry no-response cycles and closing only at 15:26:21, despite direct Modbus reads working after cable reconnection. The connector owns the poll task and shared master, so the stale socket cannot be reset reliably in Novena-owned orchestration. A focused async regression requires immediate close and device unregistration; the full 181-test Gateway suite passed. The dependency is pinned to pymodbus 3.9.2, whose transaction callback checks completed/cancelled futures and request identity before delivering a late response; the converter uses the library's moved bit-packing functions, and the Modbus TCP integration test uses Gateway's own patched datastore context. In a physical CM4 replay the field link returned at 16:04:01 SGT and the customer saw all four fresh readings at 16:04:14, about 13 seconds later. No `InvalidStateError` appeared in that replay. A later separate temporary port-502 reachability loss while the Ethernet carrier stayed up remains a field/simulator investigation.
- 2026-10-22: `modbus_connector.py` coalesces overlapping timer callbacks for slaves sharing one master client (one TCP endpoint or serial port), while allowing independent masters to poll concurrently. The inherited scheduler (repository baseline `307607a`; original ThingsBoard upstream SHA is not recorded) created a separate TCP poll task every period even if the previous read was still awaiting a response. A local CM4 cold-room soak showed 3-retry Modbus timeouts followed by a mismatched holding-register response in a coil converter. Three focused asynchronous regressions reproduce same-slave and shared-master overlap and preserve independent-master concurrency. This scheduler defect is inside the protected connector and cannot be corrected reliably after requests reach Novena-owned orchestration. The full 180-test Gateway suite passed; timed CM4 validation and remaining pilot gates are tracked in the Round 2 audit.
- 2026-08-31: `bytes_modbus_uplink_converter.py` replaces pymodbus 3.8's deprecated `BinaryPayloadDecoder` with the supported `ModbusClientMixin.convert_from_registers` API. Register words are normalized before conversion so existing byte-order and word-order behavior remains unchanged; small compatibility helpers retain the upstream 8-bit, 16-bit float, string, bytes, bit/coil and wide-range contracts that the supported API does not express directly. The defect cannot be isolated in the Novena orchestration layer because warnings are emitted while the protected connector converts every polled value. Covered by exhaustive type/endian/conversion tests, the complete Gateway suite and a real Gateway-to-Hub software replay.
- 2026-07-30: `bytes_modbus_uplink_converter.py` applies an optional numeric `offset` after the existing divider/multiplier conversion. Guided PLC mapping validates `decoded * multiplier + offset`, so the deployed connector must use identical edge-side arithmetic before semantic telemetry is published. This cannot be isolated in the Novena orchestration layer because it only receives already-converted values. Covered by focused converter and guided-validation tests.
