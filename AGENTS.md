# Novena Gateway Engineering Guidance

Novena Gateway is the Novena-owned edge runtime built around protocol components inherited from the official ThingsBoard IoT Gateway project.

## Current guidance

Use `README.md`, `ARCHITECTURE.md`, `docs/README.md` and the repo-local skills under `.agents/skills/` as current sources of truth.

Runtime state belongs outside source control. Production paths are `/etc/novena-gateway`, `/var/lib/novena-gateway` and `/var/log/novena-gateway`.

## Protected upstream boundary

Do not modify these ThingsBoard-derived paths unless a task explicitly requests an upstream synchronization or connector fix:

- `novena_gateway/connectors/`
- `novena_gateway/extensions/`
- `novena_gateway/tb_utility/`
- `novena_gateway/storage/`

Extend them through Novena-owned adapters in `novena_gateway/gateway/`. Preserve upstream license headers and record any intentional divergence in `docs/upstream_thingsboard_boundary.md`.

## Validation

Prefer focused unit tests and compilation first, followed by the complete Gateway suite. Preserve MQTT topics, payload identity, RPC request IDs, offline buffering and Raspberry Pi CM4 compatibility.
