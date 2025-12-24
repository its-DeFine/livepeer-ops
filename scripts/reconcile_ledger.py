#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Optional


WEI_PER_ETH = Decimal(10) ** 18
VIDEO_EXTENSIONS = (".webm", ".mkv", ".mp4", ".mov")


def _parse_decimal(value: object) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _read_json_lines(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


@dataclass
class OrchSummary:
    credit_pos: Decimal = Decimal("0")
    credit_neg: Decimal = Decimal("0")
    credit_workload: Decimal = Decimal("0")
    credit_workload_records: Decimal = Decimal("0")
    credit_workload_other: Decimal = Decimal("0")
    credit_session: Decimal = Decimal("0")
    credit_adjustment: Decimal = Decimal("0")
    credit_other: Decimal = Decimal("0")
    credit_workload_events: int = 0
    credit_session_events: int = 0
    credit_adjustment_events: int = 0
    credit_other_events: int = 0
    credited_workload_ids: set[str] = field(default_factory=set)
    duplicate_workload_credits: int = 0
    payout_eth: Decimal = Decimal("0")
    other_delta: Decimal = Decimal("0")
    total_delta: Decimal = Decimal("0")
    last_balance: Optional[Decimal] = None
    last_event_ts: Optional[str] = None
    payout_txs: list[str] = field(default_factory=list)
    test_delta: Decimal = Decimal("0")
    test_run_ids: dict[str, Decimal] = field(default_factory=dict)


def _is_payout_event(entry: dict[str, Any]) -> bool:
    reason = entry.get("reason")
    if isinstance(reason, str) and reason == "payout":
        return True
    metadata = entry.get("metadata")
    if isinstance(metadata, dict) and metadata.get("tx_hash") and reason == "payout":
        return True
    return False


def _entry_is_test(entry: dict[str, Any]) -> bool:
    metadata = entry.get("metadata")
    if not isinstance(metadata, dict):
        return False
    if metadata.get("test") is True:
        return True
    return bool(metadata.get("test_run_id"))


def _entry_test_run_id(entry: dict[str, Any]) -> Optional[str]:
    metadata = entry.get("metadata")
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("test_run_id")
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    return candidate or None


def _entry_delta(entry: dict[str, Any]) -> Optional[Decimal]:
    delta = _parse_decimal(entry.get("delta"))
    if delta is not None:
        return delta
    event = entry.get("event")
    if event == "credit":
        amount = _parse_decimal(entry.get("amount"))
        return amount
    return None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _has_workload_artifact(record: dict[str, Any]) -> bool:
    uri = record.get("artifact_uri")
    if isinstance(uri, str) and uri.strip():
        lowered = uri.strip().lower()
        if lowered.endswith(VIDEO_EXTENSIONS):
            return True
        # Accept non-extension URIs if a hash is present.
    if record.get("artifact_hash"):
        return True
    return False


def _render_md_table(rows: list[tuple[str, str, str, str]]) -> str:
    header = "| orchestrator_id | credits_eth | payouts_eth | balance_eth |\n|---|---:|---:|---:|\n"
    body = "".join(f"| {a} | {b} | {c} | {d} |\n" for a, b, c, d in rows)
    return header + body


def _render_md_breakdown_table(rows: list[tuple[str, str, str, str, str, str, str, str]]) -> str:
    header = (
        "| orchestrator_id | balance_eth | workload_eth | accrued_eth | session_eth | adjustment_eth | other_credit_eth | payout_eth |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|\n"
    )
    body = "".join(f"| {a} | {b} | {c} | {d} | {e} | {f} | {g} | {h} |\n" for a, b, c, d, e, f, g, h in rows)
    return header + body


def _render_md_hash_dupe_table(rows: list[tuple[str, int, str, str]]) -> str:
    header = "| artifact_hash | workloads | orchestrator_ids | workload_ids |\n|---|---:|---|---|\n"
    body = "".join(f"| {a} | {b} | {c} | {d} |\n" for a, b, c, d in rows)
    return header + body


def _render_md_unique_hash_workloads_table(
    rows: list[tuple[str, str, str, str, str, str, str]]
) -> str:
    header = (
        "| artifact_hash | orchestrator_id | workload_id | payout_amount_eth | artifact_uri | plan_id | run_id |\n"
        "|---|---|---|---:|---|---|---|\n"
    )
    body = "".join(f"| {a} | {b} | {c} | {d} | {e} | {f} | {g} |\n" for a, b, c, d, e, f, g in rows)
    return header + body


def main() -> int:
    ap = argparse.ArgumentParser(description="Reconcile balances.json against audit/ledger-events.log")
    ap.add_argument("--data-dir", required=True, help="Directory containing balances.json and audit/ledger-events.log")
    ap.add_argument("--label", default="", help="Optional label to embed in the report title (ex: stage, prod)")
    ap.add_argument("--out", default="", help="Write markdown report to this path (optional)")
    ap.add_argument(
        "--write-reconciled-balances",
        default="",
        help="Optional path to write reconstructed balances.json (based on journal last balances)",
    )
    ap.add_argument(
        "--write-mismatches-json",
        default="",
        help="Optional path to write mismatches as JSON (balances_json vs reconstructed)",
    )
    ap.add_argument(
        "--write-workload-hash-index-json",
        default="",
        help="Optional path to write a JSON index of artifact_hash → workloads (verified/paid only)",
    )
    ap.add_argument(
        "--write-workload-hash-unique-md",
        default="",
        help="Optional path to write a markdown table of verified/paid workloads with unique artifact_hash",
    )
    ap.add_argument(
        "--write-workload-hash-dupes-md",
        default="",
        help="Optional path to write a markdown table of duplicate artifact_hash values (verified/paid only)",
    )
    ap.add_argument("--top", type=int, default=25, help="Top N balances to include (default 25)")
    args = ap.parse_args()

    data_dir = Path(args.data_dir).expanduser().resolve()
    balances_path = data_dir / "balances.json"
    journal_path = data_dir / "audit" / "ledger-events.log"
    workloads_path = data_dir / "workloads.json"

    if not balances_path.exists():
        raise SystemExit(f"missing {balances_path}")
    if not journal_path.exists():
        raise SystemExit(f"missing {journal_path}")

    balances_json = _load_json(balances_path)
    balances: dict[str, Decimal] = {}
    if isinstance(balances_json, dict):
        for k, v in balances_json.items():
            dec = _parse_decimal(v)
            if dec is not None:
                balances[str(k)] = dec

    summaries: dict[str, OrchSummary] = defaultdict(OrchSummary)
    total_events = 0
    total_test_events = 0
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    total_delta = Decimal("0")
    total_credit_workload = Decimal("0")
    total_credit_workload_records = Decimal("0")
    total_credit_workload_other = Decimal("0")
    total_credit_accrued = Decimal("0")
    total_credit_session = Decimal("0")
    total_credit_adjustment = Decimal("0")
    total_credit_other = Decimal("0")
    total_payouts = Decimal("0")
    total_test_delta = Decimal("0")
    test_run_ids: dict[str, dict[str, Any]] = defaultdict(lambda: {"events": 0, "delta": Decimal("0")})
    credit_reason_totals: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    credit_reason_events: dict[str, int] = defaultdict(int)

    for entry in _read_json_lines(journal_path):
        total_events += 1
        orch_id = entry.get("orchestrator_id")
        if not isinstance(orch_id, str) or not orch_id:
            continue

        ts = entry.get("timestamp")
        if isinstance(ts, str):
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            summaries[orch_id].last_event_ts = ts

        event = entry.get("event")
        reason = entry.get("reason")
        reason_norm = str(reason).strip().lower() if isinstance(reason, str) else ""
        delta = _entry_delta(entry)
        balance = _parse_decimal(entry.get("balance"))

        if balance is not None:
            summaries[orch_id].last_balance = balance

        if delta is not None:
            summaries[orch_id].total_delta += delta
            total_delta += delta

            if _entry_is_test(entry):
                summaries[orch_id].test_delta += delta
                total_test_delta += delta
                total_test_events += 1
                run_id = _entry_test_run_id(entry) or "unknown"
                summaries[orch_id].test_run_ids[run_id] = summaries[orch_id].test_run_ids.get(run_id, Decimal("0")) + delta
                test_run_ids[run_id]["events"] += 1
                test_run_ids[run_id]["delta"] += delta

            if isinstance(event, str) and event == "credit":
                if delta >= 0:
                    summaries[orch_id].credit_pos += delta
                else:
                    summaries[orch_id].credit_neg += (-delta)

                reason_key = reason_norm or "(none)"
                credit_reason_totals[reason_key] += delta
                credit_reason_events[reason_key] += 1

                metadata = entry.get("metadata")
                if isinstance(metadata, dict):
                    workload_id = metadata.get("workload_id")
                else:
                    workload_id = None

                if reason_norm.startswith("workload"):
                    summaries[orch_id].credit_workload += delta
                    summaries[orch_id].credit_workload_events += 1
                    total_credit_workload += delta
                    if reason_norm == "workload":
                        summaries[orch_id].credit_workload_records += delta
                        total_credit_workload_records += delta
                    else:
                        summaries[orch_id].credit_workload_other += delta
                        total_credit_workload_other += delta
                    if isinstance(workload_id, str) and workload_id:
                        if workload_id in summaries[orch_id].credited_workload_ids:
                            summaries[orch_id].duplicate_workload_credits += 1
                        else:
                            summaries[orch_id].credited_workload_ids.add(workload_id)
                elif reason_norm == "session_time":
                    summaries[orch_id].credit_session += delta
                    summaries[orch_id].credit_session_events += 1
                    total_credit_session += delta
                elif reason_norm == "adjustment":
                    summaries[orch_id].credit_adjustment += delta
                    summaries[orch_id].credit_adjustment_events += 1
                    total_credit_adjustment += delta
                else:
                    summaries[orch_id].credit_other += delta
                    summaries[orch_id].credit_other_events += 1
                    total_credit_other += delta
            elif _is_payout_event(entry) and delta < 0:
                summaries[orch_id].payout_eth += (-delta)
                total_payouts += (-delta)
            else:
                summaries[orch_id].other_delta += delta

        if _is_payout_event(entry) and delta is not None and delta < 0:
            md = entry.get("metadata")
            if isinstance(md, dict):
                tx_hash = md.get("tx_hash")
                if isinstance(tx_hash, str) and tx_hash:
                    summaries[orch_id].payout_txs.append(tx_hash)

    # Compute reconstructed balances: credits - payouts, but prefer last_balance observed in journal if present.
    reconstructed: dict[str, Decimal] = {}
    for orch_id, summary in summaries.items():
        if summary.last_balance is not None:
            reconstructed[orch_id] = summary.last_balance
        else:
            reconstructed[orch_id] = summary.total_delta

    # Compare with balances.json
    all_ids = sorted(set(balances.keys()) | set(reconstructed.keys()))
    mismatches: list[tuple[str, Decimal, Decimal, Decimal]] = []
    for orch_id in all_ids:
        b_file = balances.get(orch_id, Decimal("0"))
        b_calc = reconstructed.get(orch_id, Decimal("0"))
        if b_file != b_calc:
            mismatches.append((orch_id, b_file, b_calc, b_calc - b_file))

    top_rows: list[tuple[str, str, str, str]] = []
    breakdown_rows: list[tuple[str, str, str, str, str, str, str, str]] = []
    by_balance = sorted(reconstructed.items(), key=lambda kv: kv[1], reverse=True)
    for orch_id, bal in by_balance[: max(int(args.top), 1)]:
        s = summaries.get(orch_id, OrchSummary())
        credits = str(s.credit_pos)
        payouts = str(s.payout_eth)
        top_rows.append((orch_id, credits, payouts, str(bal)))
        accrued = s.credit_session + s.credit_adjustment + s.credit_other
        breakdown_rows.append(
            (
                orch_id,
                str(bal),
                str(s.credit_workload),
                str(accrued),
                str(s.credit_session),
                str(s.credit_adjustment),
                str(s.credit_other),
                str(s.payout_eth),
            )
        )

    total_credit_accrued = total_credit_session + total_credit_adjustment + total_credit_other

    lines: list[str] = []
    label = str(args.label or "").strip()
    title = "Payments Ledger Reconciliation"
    if label:
        title += f" ({label})"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- Generated at: {datetime.utcnow().isoformat()}Z")
    lines.append(f"- Data dir: `{data_dir}`")
    lines.append(f"- Journal: `{journal_path}`")
    lines.append(f"- balances.json: `{balances_path}`")
    lines.append(f"- Total journal events parsed: `{total_events}`")
    if first_ts or last_ts:
        lines.append(f"- Journal window: `{first_ts or ''}` → `{last_ts or ''}`")
    lines.append(f"- Total delta (journal): `{total_delta}`")
    lines.append(
        f"- Total credits (workloads): `{total_credit_workload}` (records `{total_credit_workload_records}`, other `{total_credit_workload_other}`)"
    )
    lines.append(f"- Total credits (accrued): `{total_credit_accrued}` (session `{total_credit_session}`, adjustment `{total_credit_adjustment}`, other `{total_credit_other}`)")
    lines.append(f"- Total payouts (journal): `{total_payouts}`")
    lines.append(f"- Test events: `{total_test_events}` (delta `{total_test_delta}`)")
    lines.append("")
    lines.append("## Top Balances")
    lines.append(_render_md_table(top_rows))
    lines.append("")
    lines.append("## Balance Breakdown (top balances)")
    lines.append(_render_md_breakdown_table(breakdown_rows))

    if credit_reason_totals:
        lines.append("")
        lines.append("## Credit Reasons (top 25)")
        lines.append("| reason | credits_eth | events |\n|---|---:|---:|")
        top_reasons = sorted(credit_reason_totals.items(), key=lambda kv: kv[1], reverse=True)
        for reason_key, amount in top_reasons[:25]:
            lines.append(f"| {reason_key} | {amount} | {credit_reason_events.get(reason_key, 0)} |")
    lines.append("")
    lines.append("## Mismatches (balances.json vs journal)")
    lines.append(f"- Count: `{len(mismatches)}`")
    if mismatches:
        lines.append("")
        lines.append("| orchestrator_id | balances_json | journal_reconstructed | delta |\n|---|---:|---:|---:|")
        for orch_id, b_file, b_calc, diff in mismatches[:200]:
            lines.append(f"| {orch_id} | {b_file} | {b_calc} | {diff} |")
        lines.append("")
        if len(mismatches) > 200:
            lines.append(f"- (Truncated to 200; total mismatches={len(mismatches)})")
    else:
        lines.append("- None")

    if test_run_ids:
        lines.append("")
        lines.append("## Test Runs")
        lines.append("| test_run_id | events | delta |\n|---|---:|---:|")
        for run_id, stats in sorted(test_run_ids.items(), key=lambda kv: str(kv[0])):
            events = stats.get("events", 0)
            delta = stats.get("delta", Decimal("0"))
            lines.append(f"| {run_id} | {events} | {delta} |")

    workloads_json = _load_json(workloads_path) if workloads_path.exists() else None
    if isinstance(workloads_json, dict):
        total_workloads = len(workloads_json)
        by_status: dict[str, int] = defaultdict(int)
        credited_total = Decimal("0")
        credited_by_orch: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
        verified_paid_total = 0
        verified_paid_with_hash = 0
        verified_paid_missing_hash: list[tuple[str, dict[str, Any]]] = []
        artifact_hash_index: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        uncredited: list[tuple[str, dict[str, Any]]] = []
        missing_artifact: list[str] = []
        for workload_id, record in workloads_json.items():
            if not isinstance(record, dict):
                continue
            status = record.get("status") or "unknown"
            by_status[str(status)] += 1

            payout_amount = _parse_decimal(record.get("payout_amount_eth")) or Decimal("0")
            orch = record.get("orchestrator_id")
            orch_id = str(orch) if isinstance(orch, str) and orch else ""
            if record.get("credited"):
                credited_total += payout_amount
                if orch_id:
                    credited_by_orch[orch_id] += payout_amount

            if status in {"verified", "paid"}:
                verified_paid_total += 1
                artifact_hash = record.get("artifact_hash")
                if isinstance(artifact_hash, str) and artifact_hash.strip():
                    verified_paid_with_hash += 1
                    artifact_hash_index[artifact_hash.strip().lower()].append((str(workload_id), record))
                else:
                    verified_paid_missing_hash.append((str(workload_id), record))

            has_artifact = _has_workload_artifact(record)
            credited = bool(record.get("credited"))
            if status in {"verified", "paid"} and not credited:
                if has_artifact:
                    uncredited.append((str(workload_id), record))
                else:
                    missing_artifact.append(str(workload_id))

        lines.append("")
        lines.append("## Workloads")
        lines.append(f"- workloads.json: `{workloads_path}`")
        lines.append(f"- Total workloads: `{total_workloads}`")
        lines.append("- Status counts:")
        for status, count in sorted(by_status.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  - `{status}`: `{count}`")
        lines.append(f"- Verified/paid but uncredited (has artifact): `{len(uncredited)}`")
        lines.append(f"- Verified/paid but missing artifact metadata: `{len(missing_artifact)}`")

        # Compare ledger vs workloads totals for workload credits.
        ledger_workload_total = sum((s.credit_workload for s in summaries.values()), Decimal("0"))
        ledger_workload_records_total = sum((s.credit_workload_records for s in summaries.values()), Decimal("0"))
        ledger_workload_other_total = sum((s.credit_workload_other for s in summaries.values()), Decimal("0"))
        lines.append("")
        lines.append("### Workload credit consistency")
        lines.append(f"- Ledger workload credits: `{ledger_workload_total}`")
        lines.append(f"  - Ledger workload credits (records): `{ledger_workload_records_total}`")
        lines.append(f"  - Ledger workload credits (other): `{ledger_workload_other_total}`")
        lines.append(f"- workloads.json credited total: `{credited_total}`")
        lines.append(f"- Delta (ledger records - workloads): `{ledger_workload_records_total - credited_total}`")

        mismatched_orchs: list[tuple[str, Decimal, Decimal, Decimal]] = []
        for orch_id, amount in credited_by_orch.items():
            ledger_amount = summaries.get(orch_id, OrchSummary()).credit_workload_records
            diff = ledger_amount - amount
            if diff != 0:
                mismatched_orchs.append((orch_id, ledger_amount, amount, diff))
        for orch_id, summary in summaries.items():
            if orch_id in credited_by_orch:
                continue
            ledger_amount = summary.credit_workload_records
            if ledger_amount != 0:
                mismatched_orchs.append((orch_id, ledger_amount, Decimal("0"), ledger_amount))
        mismatched_orchs.sort(key=lambda item: abs(item[3]), reverse=True)
        lines.append(f"- Orchestrators with workload credit mismatches: `{len(mismatched_orchs)}`")
        if mismatched_orchs:
            lines.append("")
            lines.append("| orchestrator_id | ledger_workload_eth | workloads_credited_eth | delta |\n|---|---:|---:|---:|")
            for orch_id, ledger_amt, workload_amt, diff in mismatched_orchs[:50]:
                lines.append(f"| {orch_id} | {ledger_amt} | {workload_amt} | {diff} |")

        # Hash uniqueness report.
        unique_hashes = 0
        unique_hash_workloads: list[tuple[str, str, dict[str, Any]]] = []
        duplicate_hashes: list[tuple[str, list[tuple[str, dict[str, Any]]]]] = []
        for artifact_hash, items in artifact_hash_index.items():
            if len(items) == 1:
                unique_hashes += 1
                workload_id, record = items[0]
                unique_hash_workloads.append((artifact_hash, str(workload_id), record))
            elif len(items) > 1:
                duplicate_hashes.append((artifact_hash, items))
        duplicate_hashes.sort(key=lambda item: len(item[1]), reverse=True)

        lines.append("")
        lines.append("### Artifact hash uniqueness (verified/paid workloads)")
        lines.append(f"- Verified/paid workloads: `{verified_paid_total}`")
        lines.append(f"- With artifact_hash: `{verified_paid_with_hash}`")
        lines.append(f"- Missing artifact_hash: `{len(verified_paid_missing_hash)}`")
        lines.append(f"- Unique artifact_hash values: `{unique_hashes}`")
        lines.append(f"- Duplicate artifact_hash values: `{len(duplicate_hashes)}`")

        if duplicate_hashes:
            rows: list[tuple[str, int, str, str]] = []
            for artifact_hash, items in duplicate_hashes[:50]:
                orch_ids = sorted({str(rec.get("orchestrator_id") or "") for _, rec in items if isinstance(rec, dict)})
                workload_ids = [wid for wid, _ in items]
                rows.append(
                    (
                        artifact_hash,
                        len(items),
                        ", ".join([oid for oid in orch_ids if oid]),
                        ", ".join(workload_ids[:10]) + ("…" if len(workload_ids) > 10 else ""),
                    )
                )
            lines.append("")
            lines.append("#### Duplicate artifact_hash values (top 50)")
            lines.append(_render_md_hash_dupe_table(rows))

        if args.write_workload_hash_unique_md:
            out_path = Path(args.write_workload_hash_unique_md).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            md_rows: list[tuple[str, str, str, str, str, str, str]] = []
            for artifact_hash, workload_id, record in sorted(unique_hash_workloads, key=lambda row: row[0]):
                md_rows.append(
                    (
                        artifact_hash,
                        str(record.get("orchestrator_id") or ""),
                        workload_id,
                        str(record.get("payout_amount_eth") or ""),
                        str(record.get("artifact_uri") or ""),
                        str(record.get("plan_id") or ""),
                        str(record.get("run_id") or ""),
                    )
                )
            out_path.write_text(_render_md_unique_hash_workloads_table(md_rows), encoding="utf-8")

        if args.write_workload_hash_dupes_md:
            out_path = Path(args.write_workload_hash_dupes_md).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            md_rows = []
            for artifact_hash, items in duplicate_hashes:
                orch_ids = sorted(
                    {str(rec.get("orchestrator_id") or "") for _, rec in items if isinstance(rec, dict)}
                )
                orch_list = ", ".join([oid for oid in orch_ids if oid])
                workload_ids = [wid for wid, _ in items]
                md_rows.append((artifact_hash, len(items), orch_list, ", ".join(workload_ids)))
            out_path.write_text(_render_md_hash_dupe_table(md_rows), encoding="utf-8")

        if verified_paid_missing_hash:
            verified_paid_missing_hash.sort(
                key=lambda item: _parse_decimal(item[1].get("payout_amount_eth")) or Decimal("0"),
                reverse=True,
            )
            lines.append("")
            lines.append("#### Verified/paid workloads missing artifact_hash (top 50 by payout_amount_eth)")
            lines.append("| workload_id | orchestrator_id | status | payout_amount_eth | artifact_uri |\n|---|---|---|---:|---|")
            for workload_id, record in verified_paid_missing_hash[:50]:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            workload_id,
                            str(record.get("orchestrator_id") or ""),
                            str(record.get("status") or ""),
                            str(record.get("payout_amount_eth") or ""),
                            str(record.get("artifact_uri") or ""),
                        ]
                    )
                    + " |"
                )

        if uncredited:
            uncredited.sort(
                key=lambda item: _parse_decimal(item[1].get("payout_amount_eth")) or Decimal("0"),
                reverse=True,
            )
            lines.append("")
            lines.append("### Uncredited workloads (top 50 by payout_amount_eth)")
            lines.append("| workload_id | orchestrator_id | status | payout_amount_eth | artifact_uri | artifact_hash |\n|---|---|---|---:|---|---|")
            for workload_id, record in uncredited[:50]:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            workload_id,
                            str(record.get("orchestrator_id") or ""),
                            str(record.get("status") or ""),
                            str(record.get("payout_amount_eth") or ""),
                            str(record.get("artifact_uri") or ""),
                            str(record.get("artifact_hash") or ""),
                        ]
                    )
                    + " |"
                )

        if args.write_workload_hash_index_json:
            out_path = Path(args.write_workload_hash_index_json).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            payload = []
            for artifact_hash, items in sorted(
                artifact_hash_index.items(),
                key=lambda item: (len(item[1]), item[0]),
                reverse=True,
            ):
                workload_entries = []
                for workload_id, record in items:
                    workload_entries.append(
                        {
                            "workload_id": workload_id,
                            "orchestrator_id": record.get("orchestrator_id"),
                            "status": record.get("status"),
                            "credited": bool(record.get("credited")),
                            "payout_amount_eth": record.get("payout_amount_eth"),
                            "artifact_uri": record.get("artifact_uri"),
                            "artifact_hash": record.get("artifact_hash"),
                            "plan_id": record.get("plan_id"),
                            "run_id": record.get("run_id"),
                        }
                    )
                payload.append(
                    {
                        "artifact_hash": artifact_hash,
                        "count": len(items),
                        "workloads": workload_entries,
                    }
                )
            out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    report = "\n".join(lines).strip() + "\n"
    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
    else:
        print(report)

    if args.write_reconciled_balances:
        out_path = Path(args.write_reconciled_balances).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: str(v) for k, v in sorted(reconstructed.items(), key=lambda kv: kv[0])}
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.write_mismatches_json:
        out_path = Path(args.write_mismatches_json).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "orchestrator_id": orch_id,
                "balances_json": str(b_file),
                "reconstructed": str(b_calc),
                "delta": str(diff),
            }
            for orch_id, b_file, b_calc, diff in mismatches
        ]
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
