"""Canonical Hub ↔ Gateway governed remote-control protocol contract."""

REMOTE_CONTROL_PROTOCOL_VERSION = 1

CAPABILITY_GOVERNED_COMMANDS = "governed_commands_v1"
CAPABILITY_LOCAL_WRITEBACK = "local_writeback_v1"
CAPABILITY_LIFECYCLE_STAGES = "lifecycle_stages_v1"
CAPABILITY_IDEMPOTENT_REPLAY = "idempotent_replay_v1"

BASE_CAPABILITIES = (
    CAPABILITY_GOVERNED_COMMANDS,
    CAPABILITY_LIFECYCLE_STAGES,
    CAPABILITY_IDEMPOTENT_REPLAY,
)


def remote_control_capabilities(*, local_writeback_enabled):
    capabilities = list(BASE_CAPABILITIES)
    if local_writeback_enabled:
        capabilities.append(CAPABILITY_LOCAL_WRITEBACK)
    return capabilities
