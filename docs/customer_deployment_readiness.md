# Novena Gateway Customer Deployment Readiness

This checklist prepares a Raspberry Pi CM4 on the Waveshare Industrial IoT carrier board for a customer pilot.

## Factory Provisioning

1. Burn a customer-specific `/etc/novena-gateway/config.json`.
2. Set `deployment.mode` to `pilot` or `production`.
3. Use TLS MQTT on port `8883` with `/etc/novena-gateway/certs/ca.crt`.
4. Do not commit claim codes, MQTT passwords, tokens, or private keys.
5. Keep `connectors: []` for plug-and-play onboarding when Hub will push the field-device config.

## Hardware Setup

Run the installer as root:

```bash
sudo bash install.sh
```

The installer runs `install/hardware_setup.sh` unless `NOVENA_SKIP_HARDWARE_SETUP=1` is set. It backs up the boot config, enables USB host mode, SPI/CAN, RS485 UART overlays, and RTC overlay. Reboot the device after hardware setup.

Run read-only preflight:

```bash
/opt/novena-gateway/venv/bin/python -m novena_gateway.main --config /etc/novena-gateway/config.json --preflight
```

## Customer-Site Gate

Before handoff, confirm:

- `sudo systemctl status novena-gateway` is active.
- Hub shows gateway status `online` with `startup_status` of `ready` or an understood `degraded`.
- `hardware_preflight` RPC reports USB, RS485 UART overlays, CAN overlay, RTC overlay, helper availability, and disk space.
- `privilege_preflight` RPC reports the scoped helper is installed.
- MQTT connects over TLS.
- Remote config can create connectors and rollback failed connector updates.
- Offline buffering replays after broker or network outage.
- OTA reports accepted, downloading, verified, restarting, then success or rollback.

## Support Commands

```bash
sudo journalctl -u novena-gateway -f
sudo /usr/local/sbin/novena-gateway-helper configure-can can0 500000
sudo /usr/local/sbin/novena-gateway-helper restart-service novena-gateway
ip link show can0
id novena
```

## Burn-In

Run a 24-48 hour burn-in before customer handoff:

- Power-cycle the gateway.
- Disconnect/reconnect broker and WAN.
- Push remote config from Hub.
- Poll real Modbus TCP and RTU equipment.
- Trigger a test OTA with a known-good payload.
- Verify no unexpected telemetry loss beyond configured storage limits.
