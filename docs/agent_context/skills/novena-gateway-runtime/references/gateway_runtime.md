# Novena Gateway Runtime Reference

## Codebase Map
- novena_gateway/main.py: gateway entrypoint.
- novena_gateway/gateway/novena_gateway.py: core gateway runtime.
- novena_gateway/gateway/novena_mqtt_publisher.py: MQTT publishing, attributes, logs, RPC responses.
- novena_gateway/gateway/connectivity_health_handler.py: DNS/TCP/TLS/MQTT broker reachability diagnostics.
- novena_gateway/gateway/remote_config_handler.py: Cloud-pushed connector config.
- novena_gateway/gateway/rpc_handler.py: inbound RPC commands.
- novena_gateway/gateway/attribute_sync_handler.py: attribute requests.
- novena_gateway/gateway/payload_formatter.py: Converts ConvertedData into Novena Hub payloads.
- novena_gateway/connectors/modbus/: Modbus connector and byte converters.
- novena_gateway/storage/: memory, file, and SQLite storage.
- config.json and config_local.json: gateway identity/connectivity config.
- install.sh, install/upgrade.sh, novena-gateway.service: install and service assets.

## Runtime Principles
- Gateway publishes telemetry to Hub over MQTT.
- Gateway subscribes to serial-specific config, RPC, and attribute request topics.
- Cloud-generated configs should include enough device identity for unambiguous matching.
- Remote config apply should preserve last known good config and rollback on connector start failure.
- Device commands should report customer-facing acceptance separately from gateway transport success.
- Preserve offline resilience and avoid changes that drop buffered events during reconnects.
- Runtime state belongs outside source in production: `/etc/novena-gateway`, `/var/lib/novena-gateway`, and `/var/log/novena-gateway`.
- Keep local testing aligned with Raspberry Pi CM4 deployment expectations.

## Testing Notes
- Gateway tests currently live in tests/.
- If pytest is unavailable, many tests can run through python3 -m unittest.
- WSL may not have all Gateway dependencies installed; missing packages should be called out instead of hidden.
- Lightweight syntax check: python3 -m py_compile <files>.
