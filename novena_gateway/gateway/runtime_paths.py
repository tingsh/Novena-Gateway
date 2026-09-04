"""Canonical Novena Gateway runtime state paths."""

DATA_DIR = "/var/lib/novena-gateway"

SQLITE_DATA_FILE_PATH = f"{DATA_DIR}/sqlite/"
UPDATE_PATH = f"{DATA_DIR}/update"
OTA_STATUS_PATH = f"{DATA_DIR}/ota_status.json"

CONFIG_BACKUP_DIR = f"{DATA_DIR}/config_backups"
LAST_KNOWN_GOOD_CONFIG_PATH = f"{DATA_DIR}/last_known_good_config.json"
CONFIG_JOURNAL_PATH = f"{DATA_DIR}/deployment_setup/config_journal.json"

COMMAND_POLICY_PATH = f"{DATA_DIR}/remote_control/policy.json"
COMMAND_JOURNAL_PATH = f"{DATA_DIR}/remote_control/command_journal.json"
