# Backups and Disaster Recovery

The payments backend persists critical state under `./data` via a bind mount:

- `registry.json` (orchestrator registry)
- `balances.json` (ledger balances)
- `workloads.json` (workload records)
- `audit/` (audit logs; may include large files)

If the underlying disk is lost (instance termination, disk corruption), these files are lost unless you have backups.

## Recommended baseline

1. **Do not rely on the root disk alone.**
   - Best: mount `./data` on a **separate EBS volume** (or EFS) and reattach it if the instance is replaced.
2. **Take regular snapshots.**
   - Use AWS Backup or DLM, or run manual snapshots via AWS CLI.

## Option A: EBS snapshots (simple + reliable)

From a machine with AWS credentials:

```bash
./scripts/aws-create-snapshot.sh --volume-id vol-xxxxxxxxxxxxxxxxx --region us-east-2
# or:
# ./scripts/aws-create-snapshot.sh --instance-id i-xxxxxxxxxxxxxxxxx --region us-east-2
```

Notes:
- Snapshots are incremental and can be restored into a new volume.
- If you keep state on the root volume, also ensure the root volume is not deleted on termination.

### Prevent root-volume deletion on termination (if applicable)

If your `data/` lives on the instance root disk, consider disabling `DeleteOnTermination` so an accidental termination doesn’t also delete the data volume:

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-xxxxxxxxxxxxxxxxx \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"DeleteOnTermination":false}}]'
```

## Option B: Quick “essential files” rsync backup

If you only need registry/ledger/workloads and audit logs (and want to skip large audit DB files), pull them with rsync:

```bash
rsync -azP -e "ssh -i /path/to/key.pem" \
  ubuntu@<host>:/home/ubuntu/payments/backend/data/ ./backups/payments-data/
```

Then store `./backups/payments-data/` somewhere durable (S3, another disk, etc.).

## Option C: One-command backup + clean deploy (SSH)

If you use this repo’s `ops/deploy_payments_backend_ssh.py`, you can:

- pull a local snapshot of `data/` + `docker-compose.yml`
- optionally reset the remote `data/` directory to a clean state
- deploy a pinned `PAYMENTS_IMAGE`

Example (essential backup; excludes very large audit DB/log artifacts by default):

```bash
python3 ops/deploy_payments_backend_ssh.py \
  --inventory ops/inventory.json \
  --target prod \
  --ssh-key /path/to/key.pem \
  --backup-out ./backups/payments-backend \
  --backup-mode essential \
  --image ghcr.io/its-define/payments-backend:latest \
  --expect-openapi-path /health
```

Clean-state reset (destructive; archives the old `data/` under `backups/<timestamp>/data` on the host):

```bash
python3 ops/deploy_payments_backend_ssh.py \
  --inventory ops/inventory.json \
  --target prod \
  --ssh-key /path/to/key.pem \
  --backup-out ./backups/payments-backend \
  --backup-mode full \
  --reset-data --yes-really-reset-data \
  --image ghcr.io/its-define/payments-backend:latest
```

Notes:
- `--backup-mode full` can be large if `data/audit/payments-audit.log` is multi-GB.
- `--backup-include-env` pulls `.env` too (contains secrets; keep private).

## Restore (high level)

1. Restore `./data` from snapshot/backup onto the target host.
2. Start the stack with the restored `./data` bind mount:

```bash
docker compose up -d
```
