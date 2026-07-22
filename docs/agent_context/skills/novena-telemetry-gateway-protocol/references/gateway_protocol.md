# Gateway Protocol Reference

## Topics
Gateway publishes:

- v1/gateway/{serial}/telemetry
- v1/gateway/{serial}/attributes
- v1/gateway/{serial}/logs
- v1/gateway/{serial}/rpc/response

Gateway subscribes:

- v1/gateway/{serial}/config
- v1/gateway/{serial}/rpc/request
- v1/gateway/{serial}/attributes/request
- v1/gateway/{serial}/provision

## Payload Identity
- Hub derives gateway identity from the authenticated client/topic namespace.
- Payload serial_number remains diagnostic metadata; if present, it must match the topic serial.
- Hub config generator writes deviceId into device/connector config.
- Modbus byte uplink config reads deviceId into gateway config objects.
- Modbus byte uplink converter passes that into ConvertedData(..., device_id=...).
- Payload formatter emits top-level device_id for telemetry and attributes when present.
- Hub uses that device_id before falling back to exact device name.

## Important Files
- novena_gateway/gateway/payload_formatter.py
- novena_gateway/gateway/entities/converted_data.py
- novena_gateway/connectors/modbus/entities/bytes_uplink_converter_config.py
- novena_gateway/connectors/modbus/bytes_modbus_uplink_converter.py
- novena_gateway/gateway/novena_mqtt_publisher.py
- novena_gateway/gateway/remote_config_handler.py
- novena_gateway/gateway/rpc_handler.py
- novena_gateway/gateway/attribute_sync_handler.py
- tests/test_payload_formatter.py

## Compatibility Rules
- Do not remove device_name; it is still useful for display and backward compatibility.
- Do not move units into telemetry values; Hub derives display units from template/register metadata.
- Keep serial number on payloads for diagnostics and backwards-compatible observability.
- Keep RPC responses auditable by preserving request IDs.
