#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _ssh_cmd(user: str, host: str, ssh_key: str | None) -> list[str]:
    base = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if ssh_key:
        base += ["-i", ssh_key]
    base += [f"{user}@{host}"]
    return base


def _rsync_cmd(ssh_key: str | None) -> list[str]:
    ssh = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if ssh_key:
        ssh += ["-i", ssh_key]
    return ["rsync", "-azP", "-e", " ".join(shlex.quote(x) for x in ssh)]


def _remote_bash(script: str) -> str:
    # run under bash -lc so PATH and docker compose aliases behave similarly to interactive sessions
    return f"bash -lc {shlex.quote(script)}"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    user: str
    remote_path: str


def _load_target(inventory_path: Path, target: str) -> Target:
    inv = _read_json(inventory_path)
    if not isinstance(inv, dict) or target not in inv:
        raise SystemExit(f"target {target!r} not found in inventory: {inventory_path}")
    entry = inv[target]
    if not isinstance(entry, dict):
        raise SystemExit(f"invalid inventory entry for {target!r}")
    host = str(entry.get("host") or "").strip()
    user = str(entry.get("user") or "ubuntu").strip()
    remote_path = str(entry.get("remote_path") or "").strip()
    if not host or not remote_path:
        raise SystemExit(f"inventory entry {target!r} must include host and remote_path")
    return Target(name=target, host=host, user=user, remote_path=remote_path)


def _ensure_remote_dir(target: Target, ssh_key: str | None) -> None:
    _run(_ssh_cmd(target.user, target.host, ssh_key) + [_remote_bash(f"mkdir -p {shlex.quote(target.remote_path)}")])


def _backup_remote_state(target: Target, ssh_key: str | None, out_dir: Path) -> Path:
    ts = _utc_ts()
    dest = (out_dir / target.name / ts).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    # Capture current container logs for later reconciliation.
    _run(
        _ssh_cmd(target.user, target.host, ssh_key)
        + [
            _remote_bash(
                f"cd {shlex.quote(target.remote_path)} && "
                f"(docker logs --timestamps payments-backend 2>&1 || true) > data/audit/payments-backend.container.log"
            )
        ]
    )

    rsync = _rsync_cmd(ssh_key)
    # Pull state (may include large files; see --backup-mode).
    _run(rsync + [f"{target.user}@{target.host}:{target.remote_path}/data/", str(dest / "data")])
    _run(rsync + [f"{target.user}@{target.host}:{target.remote_path}/docker-compose.yml", str(dest / "docker-compose.yml")])

    (dest / "README.txt").write_text(
        "\n".join(
            [
                "Payments backend backup snapshot",
                f"- target: {target.name}",
                f"- host: {target.host}",
                f"- remote_path: {target.remote_path}",
                f"- timestamp_utc: {ts}",
                "",
                "Contents:",
                "- data/ (registry.json, balances.json, workloads.json, audit/...)",
                "- docker-compose.yml",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return dest


def _reset_remote_state(target: Target, ssh_key: str | None) -> None:
    ts = _utc_ts()
    script = "\n".join(
        [
            f"set -euo pipefail",
            f"cd {shlex.quote(target.remote_path)}",
            f"mkdir -p backups/{ts}",
            # Stop container first (so no writes while moving).
            f"docker compose down || true",
            # Archive existing state.
            f"if [ -d data ]; then mv data backups/{ts}/data; fi",
            f"mkdir -p data/audit",
            # Fresh empty state; app will initialize missing files at runtime.
            f"echo 'OK: reset data/'",
        ]
    )
    _run(_ssh_cmd(target.user, target.host, ssh_key) + [_remote_bash(script)])


def _remote_set_env_var(target: Target, ssh_key: str | None, key: str, value: str) -> None:
    # Append or replace KEY=... in .env without printing secrets.
    script = "\n".join(
        [
            "set -euo pipefail",
            f"cd {shlex.quote(target.remote_path)}",
            "touch .env",
            f"if grep -q '^{key}=' .env; then",
            f"  sed -i.bak 's|^{key}=.*|{key}={value}|' .env",
            "else",
            f"  echo '{key}={value}' >> .env",
            "fi",
        ]
    )
    _run(_ssh_cmd(target.user, target.host, ssh_key) + [_remote_bash(script)])


def _deploy(target: Target, ssh_key: str | None, image: str | None) -> None:
    if image:
        _remote_set_env_var(target, ssh_key, "PAYMENTS_IMAGE", image)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"cd {shlex.quote(target.remote_path)}",
            "docker compose pull payments-backend",
            "docker compose up -d payments-backend",
            "docker ps --filter name=payments-backend --format '{{.Names}} {{.Status}}'",
        ]
    )
    _run(_ssh_cmd(target.user, target.host, ssh_key) + [_remote_bash(script)])


def _wait_health(target: Target, ssh_key: str | None, expect_path: str, timeout_s: int) -> None:
    # Run curl on the host so we don't require port access from the deploy machine.
    start = datetime.now(timezone.utc)
    script = "\n".join(
        [
            "set -euo pipefail",
            f"URL='http://127.0.0.1:8081{expect_path}'",
            f"DEADLINE=$(( $(date +%s) + {timeout_s} ))",
            "while true; do",
            "  if curl -fsS \"$URL\" >/dev/null; then",
            "    echo \"OK: $URL\"",
            "    exit 0",
            "  fi",
            "  if [ \"$(date +%s)\" -ge \"$DEADLINE\" ]; then",
            "    echo \"ERROR: timeout waiting for $URL\" >&2",
            "    exit 2",
            "  fi",
            "  sleep 2",
            "done",
        ]
    )
    try:
        _run(_ssh_cmd(target.user, target.host, ssh_key) + [_remote_bash(script)])
    except subprocess.CalledProcessError as exc:
        elapsed = datetime.now(timezone.utc) - start
        raise SystemExit(f"health check failed after {elapsed.total_seconds():.1f}s: {exc}") from exc


def main() -> int:
    ap = argparse.ArgumentParser(description="Deploy payments-backend to an SSH target (with optional backup/reset).")
    ap.add_argument("--inventory", required=True, help="Path to inventory.json")
    ap.add_argument("--target", required=True, help="Target key in inventory.json (e.g. prod)")
    ap.add_argument("--ssh-key", default="", help="SSH key path (optional); prefer passing explicitly, not committing.")
    ap.add_argument("--image", default="", help="PAYMENTS_IMAGE to set on the host (tag or digest).")
    ap.add_argument("--expect-openapi-path", default="/health", help="HTTP path to check on localhost:8081")
    ap.add_argument("--timeout-seconds", type=int, default=120, help="Health check timeout")
    ap.add_argument("--backup-out", default="", help="Local dir to rsync backups into (creates <target>/<ts>/...)")
    ap.add_argument(
        "--backup-mode",
        default="essential",
        choices=["essential", "full"],
        help="Backup size mode: essential excludes large audit DB/log artifacts; full pulls the entire data/ dir.",
    )
    ap.add_argument("--backup-include-env", action="store_true", help="Also rsync .env into the backup (contains secrets; keep private).")
    ap.add_argument("--reset-data", action="store_true", help="Move remote data/ aside and start clean")
    ap.add_argument("--yes-really-reset-data", action="store_true", help="Required to run --reset-data")
    args = ap.parse_args()

    inventory_path = Path(args.inventory).expanduser().resolve()
    target = _load_target(inventory_path, args.target)
    ssh_key = args.ssh_key.strip() or None
    image = args.image.strip() or None

    _ensure_remote_dir(target, ssh_key)

    if args.backup_out:
        backup_dir = Path(args.backup_out).expanduser().resolve()
        snapshot = _backup_remote_state(target, ssh_key, backup_dir)
        if args.backup_mode == "essential":
            # Remove bulky, non-ledger artifacts that can be regenerated.
            # Keep ledger-events.log + registry.log.
            for pattern in [
                "data/audit/docker.db",
                "data/audit/docker.db-shm",
                "data/audit/docker.db-wal",
                "data/audit/payments-audit.log",
            ]:
                p = snapshot / pattern
                if p.exists():
                    p.unlink()
        if args.backup_include_env:
            _run(_rsync_cmd(ssh_key) + [f"{target.user}@{target.host}:{target.remote_path}/.env", str(snapshot / ".env")])
        print("backup_ok:", snapshot)

    if args.reset_data:
        if not args.yes_really_reset_data:
            raise SystemExit("--reset-data requires --yes-really-reset-data")
        _reset_remote_state(target, ssh_key)

    _deploy(target, ssh_key, image)
    _wait_health(target, ssh_key, args.expect_openapi_path, args.timeout_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
