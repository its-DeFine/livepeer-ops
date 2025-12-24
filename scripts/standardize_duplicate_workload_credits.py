#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from payments.ledger import Ledger


def _parse_decimal(value: object) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _median(values: list[Decimal]) -> Decimal:
    if not values:
        return Decimal("0")
    values = sorted(values)
    n = len(values)
    mid = n // 2
    if n % 2 == 1:
        return values[mid]
    return (values[mid - 1] + values[mid]) / Decimal("2")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class OrchNonUnique:
    duplicate_workloads: int = 0
    duplicate_eth: Decimal = Decimal("0")


def _iter_workloads(workloads_json: Any) -> Iterable[tuple[str, Dict[str, Any]]]:
    if not isinstance(workloads_json, dict):
        return []
    items: list[tuple[str, Dict[str, Any]]] = []
    for workload_id, record in workloads_json.items():
        if isinstance(workload_id, str) and isinstance(record, dict):
            items.append((workload_id, record))
    return items


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Standardize per-orchestrator credits for workloads whose artifact_hash appears multiple times "
            "(to correct the sweep duplicate-hash bug) by writing ledger adjustment events."
        )
    )
    ap.add_argument("--data-dir", required=True, help="Directory containing workloads.json + balances.json + audit/ledger-events.log")
    ap.add_argument(
        "--standard-non-unique-eth",
        default="",
        help="If set, use this standard non-unique amount; otherwise compute the median among eligible orchestrators.",
    )
    ap.add_argument(
        "--exclude-orchestrator",
        action="append",
        default=[],
        help="Orchestrator IDs to exclude from median computation and standardization (repeatable).",
    )
    ap.add_argument(
        "--participation-only",
        action="append",
        default=[],
        help="Orchestrator IDs that should not receive standardized non-unique (set to 0; incentive TBD).",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Write ledger adjustment events + update balances.json (default is dry-run).",
    )
    ap.add_argument(
        "--reason",
        default="reconcile_workload_non_unique_standardize",
        help="Ledger reason string to use for adjustment events.",
    )
    ap.add_argument(
        "--note",
        default="",
        help="Optional freeform note to embed in adjustment metadata.",
    )
    args = ap.parse_args()

    data_dir = Path(args.data_dir).expanduser().resolve()
    balances_path = data_dir / "balances.json"
    journal_path = data_dir / "audit" / "ledger-events.log"
    workloads_path = data_dir / "workloads.json"

    if not balances_path.exists():
        raise SystemExit(f"missing {balances_path}")
    if not workloads_path.exists():
        raise SystemExit(f"missing {workloads_path}")

    workloads_json = _load_json(workloads_path)

    # Build artifact_hash -> workloads (verified/paid + credited only).
    by_hash: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for workload_id, record in _iter_workloads(workloads_json):
        status = str(record.get("status") or "").strip().lower()
        if status not in {"verified", "paid"}:
            continue
        if not record.get("credited"):
            continue
        artifact_hash = record.get("artifact_hash")
        if not isinstance(artifact_hash, str) or not artifact_hash.strip():
            continue
        by_hash[artifact_hash.strip().lower()].append((workload_id, record))

    duplicate_hashes = {h for h, items in by_hash.items() if len(items) > 1}

    # Sum current non-unique per orchestrator.
    per_orch: dict[str, OrchNonUnique] = defaultdict(OrchNonUnique)
    for artifact_hash in duplicate_hashes:
        for workload_id, record in by_hash.get(artifact_hash, []):
            orch_id = str(record.get("orchestrator_id") or "").strip()
            if not orch_id:
                continue
            amount = _parse_decimal(record.get("payout_amount_eth")) or Decimal("0")
            per_orch[orch_id].duplicate_workloads += 1
            per_orch[orch_id].duplicate_eth += amount

    excluded = {str(x).strip() for x in args.exclude_orchestrator if str(x).strip()}
    participation_only = {str(x).strip() for x in args.participation_only if str(x).strip()}

    eligible_for_standard = [
        (orch_id, summary)
        for orch_id, summary in per_orch.items()
        if orch_id not in excluded and orch_id not in participation_only
    ]
    candidate_values = [summary.duplicate_eth for _, summary in eligible_for_standard if summary.duplicate_eth > 0]
    computed_standard = _median(candidate_values).quantize(Decimal("0.00000001"))

    override = str(args.standard_non_unique_eth or "").strip()
    if override:
        parsed = _parse_decimal(override)
        if parsed is None:
            raise SystemExit("--standard-non-unique-eth must be a decimal string")
        standard = parsed.quantize(Decimal("0.00000001"))
    else:
        standard = computed_standard

    print("duplicate-hash workloads:", sum(s.duplicate_workloads for s in per_orch.values()))
    print("orchestrators with duplicate-hash workloads:", len(per_orch))
    print("computed_standard_non_unique_eth (median):", str(computed_standard))
    print("effective_standard_non_unique_eth:", str(standard))
    print("participation_only:", ", ".join(sorted(participation_only)) if participation_only else "(none)")
    print("excluded:", ", ".join(sorted(excluded)) if excluded else "(none)")
    print("apply:", bool(args.apply))

    if standard <= 0:
        print("Nothing to do: standard non-unique ETH is 0")
        return 0

    total_delta = Decimal("0")
    adjustments: list[tuple[str, Decimal, OrchNonUnique, Decimal]] = []
    for orch_id, summary in sorted(per_orch.items(), key=lambda item: item[0]):
        target = Decimal("0") if orch_id in participation_only else standard
        delta = (target - summary.duplicate_eth).quantize(Decimal("0.00000001"))
        if delta == 0:
            continue
        adjustments.append((orch_id, delta, summary, target))
        total_delta += delta

    print("adjustments:", len(adjustments))
    print("total_delta_eth:", str(total_delta))

    if not args.apply:
        for orch_id, delta, summary, target in adjustments[:50]:
            print(
                f"{orch_id}: current_non_unique_eth={summary.duplicate_eth} target_non_unique_eth={target} delta={delta} dup_workloads={summary.duplicate_workloads}"
            )
        return 0

    ledger = Ledger(
        balances_path,
        journal_path=journal_path if journal_path.exists() else None,
        default_metadata=None,
    )

    for orch_id, delta, summary, target in adjustments:
        ledger.credit(
            orch_id,
            delta,
            reason=str(args.reason),
            metadata={
                "reconcile_kind": "standardize_non_unique_workloads",
                "computed_at": _utcnow_iso(),
                "standard_non_unique_eth": str(standard),
                "target_non_unique_eth": str(target),
                "current_non_unique_eth": str(summary.duplicate_eth),
                "duplicate_workloads": int(summary.duplicate_workloads),
                "duplicate_hashes": int(len(duplicate_hashes)),
                "note": str(args.note or "").strip() or None,
            },
        )

    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

