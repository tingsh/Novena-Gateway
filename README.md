# Novena Gateway

Novena Gateway is the Raspberry Pi CM4-class edge runtime for Novena Platform. It connects industrial equipment through ThingsBoard-derived protocol connectors, applies Novena commissioning and security policy, buffers telemetry during outages and communicates with Novena Hub over serial-scoped MQTT topics.

## Start here

- [Architecture and runtime guide](ARCHITECTURE.md)
- [Documentation authority index](docs/README.md)
- [Protected upstream boundary](docs/upstream_thingsboard_boundary.md)
- [Customer deployment readiness](docs/customer_deployment_readiness.md)

## Local verification

`requirements.txt` is the authoritative appliance dependency manifest used by `install.sh` and OTA upgrades.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q novena_gateway tests
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m novena_gateway.main --config config_local.json --validate-only
```

Production configuration is burned per appliance and stores mutable state under `/var/lib/novena-gateway`. Local database, WAL, OTA download and log files are deliberately excluded from Git.

## Upstream connector policy

The protocol connector, extension, utility and storage implementation trees are inherited from ThingsBoard IoT Gateway and are protected from general Novena refactoring. Novena-specific behavior belongs under `novena_gateway/gateway/` and integrates through adapters.
