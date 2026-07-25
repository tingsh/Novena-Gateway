# Governed Remote Control at the Edge

The Gateway starts with `local_writeback_enabled=false`, `trusted_clock=false`, no trusted command keys and no retained policy. Leave those defaults for monitoring-only deployments.

For commissioned control, an installer must enable the physical/site-authorized write-back setting, establish trusted time, provision active and next Ed25519 public keys, configure durable policy/journal paths, and verify storage health. Private signing keys never belong on the Gateway.

The Gateway independently validates signature, target serial/device ID, schema, expiry, epoch, sequence, template/commissioning/policy revisions, policy checksum, exact connector mapping, type, units, range/enum, local authority and supervisory prerequisites. It writes `executing` durably before the connector call. A restart with that state is an uncertain outcome and must never repeat the command.

Key compromise: add the affected ID to `revoked_command_key_ids`, deploy the revocation, emergency-disable control, increment the Hub epoch, install the replacement public key/policy and require acknowledgement before reactivation.

Back up policy, journal and reconciliation spool evidence. A restored policy whose epoch is below the journal epoch anchor is rejected. Journal/storage health failures block write readiness. Logs and outbound errors must use existing secret/payload redaction.

Physical acceptance remains mandatory: VFD limits, pump/relay prerequisites, cold-chain readback, connector restart, reboot/config/OTA, duplicate delivery, broker loss at each stage, restart during execution, emergency disable/re-enable, local authority, clock drift, key rotation/revocation and restored stale Hub data.
