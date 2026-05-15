"""Run goldencheck on records.parquet and write a DQ report.

Replaces the prose-only "Honest limitations" section. goldencheck
profiles every column, flags nulls / type drift / outliers, and emits
a letter-grade health score. Findings + score land in
`output/dq_report.json` alongside the headline analytics.

Run this after `extract_records.py` and before `analyze.py` so any
quality regressions in upstream sources surface before reconciliation.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import goldencheck
from goldencheck import scan_file

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records.parquet"
OUT = ROOT / "output" / "dq_report.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

print(f"goldencheck {goldencheck.__version__}")
print(f"Scanning {SRC} ...")
findings, profile = scan_file(SRC)

# Per-column finding tally for the weighted health score.
findings_by_column: dict[str, dict[str, int]] = {}
for f in findings:
    bucket = findings_by_column.setdefault(f.column, {"errors": 0, "warnings": 0, "info": 0})
    name = f.severity.name.lower()
    if name in bucket:
        bucket[name] += 1

severity_counts: Counter = Counter(f.severity.name for f in findings)
grade, score = profile.health_score(findings_by_column=findings_by_column)

print(f"  rows: {profile.row_count:,}  columns: {profile.column_count}")
print(f"  findings: {len(findings)}  (errors={severity_counts.get('ERROR', 0)}, "
      f"warnings={severity_counts.get('WARNING', 0)}, info={severity_counts.get('INFO', 0)})")
print(f"  health: {grade} ({score}/100)")

print("\nPer-column health snapshot:")
for col in profile.columns:
    print(f"  {col.name:<20} type={col.inferred_type:<12} "
          f"null%={col.null_pct:5.1f}  unique%={col.unique_pct:5.1f}")

if findings:
    print("\nTop findings (first 10):")
    for f in findings[:10]:
        print(f"  [{f.severity.name}] {f.column}: {f.check} -- {f.message}")

report = {
    "goldencheck_version": goldencheck.__version__,
    "input": str(SRC.name),
    "row_count": profile.row_count,
    "column_count": profile.column_count,
    "health_grade": grade,
    "health_score": score,
    "severity_counts": dict(severity_counts),
    "columns": [
        {
            "name": c.name,
            "inferred_type": c.inferred_type,
            "null_pct": round(c.null_pct, 2),
            "unique_pct": round(c.unique_pct, 2),
            "top_values": [(str(v), int(n)) for v, n in (c.top_values or [])[:5]],
        }
        for c in profile.columns
    ],
    "findings": [
        {
            "severity": f.severity.name,
            "column": f.column,
            "check": f.check,
            "message": f.message,
            "affected_rows": f.affected_rows,
            "sample_values": f.sample_values[:5],
            "suggestion": f.suggestion,
        }
        for f in findings
    ],
}
OUT.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
print(f"\nWrote {OUT}")
