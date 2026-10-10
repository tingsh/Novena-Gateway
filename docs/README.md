# Novena Gateway Documentation Authority

- `../README.md` — developer entry point and verification commands.
- `../ARCHITECTURE.md` — current runtime architecture, configuration and MQTT behavior.
- `upstream_thingsboard_boundary.md` — protected upstream-derived code and extension policy.
- `customer_deployment_readiness.md` — customer appliance release gates.
- `guided_setup_operations.md` — guided commissioning behavior and operator recovery.
- `governed_remote_control_edge.md` — edge write-back security and incident handling.
- `.agents/skills/novena-gateway-runtime` and `.agents/skills/novena-telemetry-gateway-protocol` — mandatory agent context for runtime or protocol changes.

Runtime databases, WAL files, OTA payloads, logs and release archives are generated state, not documentation or source assets.

Local credential replay helpers: `install/hardware-test/render_local_replay_config.py`
accepts `--serial`, `--runtime-dir` and `--mqtt-password-file` for isolated identities.
Use `install/hardware-test/probe_mqtt_auth.py --config <private-saved-config> --expect rejected`
after release; it requires an explicit authentication rejection, not a network failure.
The coordinated Ubuntu broker procedure is in the Hub's `docs/local_mqtt_dynamic_security.md`.
