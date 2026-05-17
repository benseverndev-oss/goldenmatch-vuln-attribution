"""Summarize the Claude-baseline labels.

For each `<bucket>__claude.csv` in `output/review/`:

  - distribution of representability_type and scanner_modality
  - how often the auto-bucket (from sample_for_review.py) agrees with
    Claude's representability_type
  - rate of `OTHER` / `NONE` labels (= rows where the protocol couldn't
    confidently classify)

Output: `output/label_baseline_stats.json` + printed summary. This is
the single-rater quantitative artifact -- the κ-style multi-rater
metrics come from `compute_agreement.py` once a second rater exists.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REVIEW = ROOT / "output" / "review"
OUT = ROOT / "output" / "label_baseline_stats.json"

# Map: auto-bucket -> expected representability_type (the "obvious" mapping)
BUCKET_EXPECTATION = {
    "PACKAGE_RANGE": "PACKAGE",
    "PACKAGE_ADVISORY": "PACKAGE",
    "DISTRO": "BINARY",
    "UNREVIEWED_MIRROR": None,  # mixed; no single expectation
    "CVE_ONLY": None,           # mixed; no single expectation
    "INDEP_CONTRADICTION": "PACKAGE",
    "UNCLASSIFIED": None,
}


def analyse(path: Path) -> dict:
    rows = []
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["cve_id"].startswith("_VALID_VALUES"):
                continue
            rows.append(r)
    rt = Counter(r["representability_type"] for r in rows)
    sm = Counter(r["scanner_modality"] for r in rows)

    # Bucket-vs-rater alignment
    alignment_n = 0
    alignment_agree = 0
    disagreements = []
    for r in rows:
        expected = BUCKET_EXPECTATION.get(r["bucket"])
        if expected is None:
            continue
        alignment_n += 1
        if r["representability_type"] == expected:
            alignment_agree += 1
        else:
            disagreements.append({
                "cve_id": r["cve_id"],
                "bucket": r["bucket"],
                "expected": expected,
                "label": r["representability_type"],
                "note": r.get("notes", "")[:200],
            })

    return {
        "n_rows": len(rows),
        "representability_distribution": dict(rt),
        "scanner_modality_distribution": dict(sm),
        "bucket_alignment": {
            "n_with_expectation": alignment_n,
            "n_agree": alignment_agree,
            "rate": round(alignment_agree / alignment_n, 4) if alignment_n else None,
            "disagreements": disagreements,
        },
        "other_or_none_rate": round(
            (rt.get("OTHER", 0) + sm.get("NONE", 0)) / (2 * len(rows)), 4
        ) if rows else None,
    }


def main() -> int:
    paths = sorted(REVIEW.glob("*__claude.csv"))
    if not paths:
        print("No __claude.csv files found in output/review/.")
        return 1

    report: dict[str, dict] = {}
    total_rows = 0
    overall_rt: Counter[str] = Counter()
    overall_sm: Counter[str] = Counter()
    overall_alignment_n = 0
    overall_alignment_agree = 0

    for p in paths:
        bucket = p.name[: -len("__claude.csv")]
        a = analyse(p)
        report[bucket] = a
        total_rows += a["n_rows"]
        for k, v in a["representability_distribution"].items():
            overall_rt[k] += v
        for k, v in a["scanner_modality_distribution"].items():
            overall_sm[k] += v
        overall_alignment_n += a["bucket_alignment"]["n_with_expectation"]
        overall_alignment_agree += a["bucket_alignment"]["n_agree"]

    report["_overall"] = {
        "n_rows": total_rows,
        "representability_distribution": dict(overall_rt),
        "scanner_modality_distribution": dict(overall_sm),
        "bucket_alignment_rate": round(
            overall_alignment_agree / overall_alignment_n, 4
        ) if overall_alignment_n else None,
    }

    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print(f"\nOverall ({total_rows} rows labelled by Claude):")
    print(f"  representability_type: {dict(overall_rt)}")
    print(f"  scanner_modality:      {dict(overall_sm)}")
    print(
        f"  bucket-vs-rater alignment on the auto-bucket where there's a clear "
        f"expectation: {overall_alignment_agree}/{overall_alignment_n} "
        f"({100 * overall_alignment_agree / overall_alignment_n:.1f}%)"
    )
    print("\nPer worksheet:")
    for bucket, a in report.items():
        if bucket == "_overall":
            continue
        rt = a["representability_distribution"]
        align = a["bucket_alignment"]
        align_str = (
            f"alignment={align['n_agree']}/{align['n_with_expectation']}"
            if align["n_with_expectation"]
            else "(no expectation)"
        )
        top_rt = ", ".join(f"{k}={v}" for k, v in sorted(rt.items(), key=lambda kv: -kv[1])[:3])
        print(f"  {bucket:>30}: n={a['n_rows']:>3}  {top_rt}  {align_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
