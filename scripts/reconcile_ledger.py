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
    total_payouts = Decimal("0")
    total_test_delta = Decimal("0")
    test_run_ids: dict[str, dict[str, Any]] = defaultdict(lambda: {"events": 0, "delta": Decimal("0")})

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
    by_balance = sorted(reconstructed.items(), key=lambda kv: kv[1], reverse=True)
    for orch_id, bal in by_balance[: max(int(args.top), 1)]:
        s = summaries.get(orch_id, OrchSummary())
        credits = str(s.credit_pos)
        payouts = str(s.payout_eth)
        top_rows.append((orch_id, credits, payouts, str(bal)))

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
    lines.append(f"- Total payouts (journal): `{total_payouts}`")
    lines.append(f"- Test events: `{total_test_events}` (delta `{total_test_delta}`)")
    lines.append("")
    lines.append("## Top Balances")
    lines.append(_render_md_table(top_rows))
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
        uncredited: list[tuple[str, dict[str, Any]]] = []
        missing_artifact: list[str] = []
        for workload_id, record in workloads_json.items():
            if not isinstance(record, dict):
                continue
            status = record.get("status") or "unknown"
            by_status[str(status)] += 1
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
