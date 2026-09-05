# VSO Vault Backup Fallback

This local Home Assistant add-on is an independent fallback for the
`hassio.vault_backups` network-storage backup agent. It does not use the HA
backup-agent credential or the Supervisor backup API for the transfer.

## Behavior

- Reads completed compressed archives from `/backup`.
- Mounts a configured SMB host and share directly over SMB.
- Copies the newest archive to a configured subpath only when `/trigger` is
  called by the VSO failure automation.
- Uses a temporary file, size verification, and SHA-256 verification before
  publishing the destination file.
- Skips a file whose name and SHA-256 are already recorded in `/data/manifest.json`.
- Retains the newest 12 successfully copied Vault archives.
- Stores only secret key names in options; values are read from
  `/config/secrets.yaml` and never logged.

## VSO integration

The add-on exposes:

```text
GET /status
GET /trigger
```

`/trigger` requires the `X-VSO-Token` header. The token is read from the HA
secret named by `api_token_secret` and is never logged. `/status` is read-only.

VSO should call `/trigger` only after an automatic backup reports
`failed_agent_ids` containing `hassio.vault_backups`. A separate recovery
automation should call `/trigger` after the mounted share returns online. The
fallback intentionally does not poll and repeatedly retry an unavailable Vault.

The calling HA automation still owns Maintenance Mode. It should enable its
maintenance guard before calling `/trigger`, then clear the guard after the
response or timeout.

## Installation

Place this directory in a local Home Assistant add-on repository, build it from
the Add-on Store, and configure the storage options and secret keys for your
own environment:

```yaml
vso_vault_backup_username: YOUR_USERNAME
vso_vault_backup_password: YOUR_PASSWORD
vso_vault_backup_api_token: A_LONG_RANDOM_TOKEN
```

The current session cannot install or rebuild local add-ons. The add-on also
needs `SYS_ADMIN` to mount SMB directly and should be reviewed before enabling
in production. Its control API listens on port `8124`.
