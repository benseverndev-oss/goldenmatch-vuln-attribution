"""Deeper analysis on records_normalized.parquet.

Goes past the headline numbers in `analyze.py` to answer questions like:

  - Which sources contribute mostly singletons vs ID-aliased multi-cluster
    members? (Tells us which sources actually merge into the graph.)
  - Where is the KEV blind spot concentrated -- which vendors and product
    families dominate the 1,404 "no ecosystem" exploited vulns?
  - How does the EPSS distribution shape change once we condition on
    ecosystem coverage / KEV membership / CVE-Project presence?
  - Is the top-disagreement list still dominated by Bitnami fanout, or
    did the new ecosystems shift it?
  - How many CVE-Project records are NOT in any other source (i.e. NVD
    has them, OSS-ecosystem mirrors don't)?

Writes a single `output/analysis_deep.json` plus an optional console
summary so the workflow log is readable.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
RECORDS = ROOT / "data" / "records_normalized.parquet"
REPORT = ROOT / "output" / "report.json"
KEV_FILE = ROOT / "output" / "kev_clusters.json"
OUT = ROOT / "output" / "analysis_deep.json"


def banner(s: str) -> None:
    print()
    print("=" * 70)
    print(s)
    print("=" * 70)


banner("LOAD")
df = pl.read_parquet(RECORDS)
print(f"rows: {df.height:,}  cols: {df.columns}")
report = json.loads(REPORT.read_text(encoding="utf-8"))
kev_clusters = json.loads(KEV_FILE.read_text(encoding="utf-8"))

# ----------------------------------------------------------------------
# 1. Per-source row counts, unique IDs, and what % of rows carry aliases
# ----------------------------------------------------------------------
banner("PER-SOURCE: rows, unique_vid, aliased_rows")
per_source = (
    df.group_by("source")
    .agg(
        [
            pl.len().alias("rows"),
            pl.col("vuln_id").n_unique().alias("uniq_vid"),
            (pl.col("aliases").str.len_chars() > 0).sum().alias("with_alias"),
        ]
    )
    .sort("rows", descending=True)
)
print(per_source)

per_source_dicts: list[dict] = []
for row in per_source.iter_rows(named=True):
    rows = row["rows"]
    with_alias = row["with_alias"]
    per_source_dicts.append(
        {
            "source": row["source"],
            "rows": rows,
            "unique_vuln_ids": row["uniq_vid"],
            "with_alias_rows": with_alias,
            "alias_pct": round(100 * with_alias / max(1, rows), 2),
        }
    )

# ----------------------------------------------------------------------
# 2. Source-set frequency: which combinations of sources co-occur on a
#    canonical cluster? The 'sources' set per cluster lives in report.json
#    only at the top level (totals). To get the full set per cluster we
#    re-derive it from the parquet + alias-graph implied by the cluster
#    output. Simpler: scan rows, key by vuln_id, infer that every row
#    sharing vuln_id is in the same record-level set; canonical-level
#    set requires the union-find. For this pass we approximate at the
#    *vuln_id* level (which is a tight lower bound on canonical reach).
# ----------------------------------------------------------------------
banner("VULN-ID SOURCE COMBINATIONS (top 20)")
vid_sources: dict[str, set[str]] = defaultdict(set)
for vid, src in zip(df["vuln_id"].to_list(), df["source"].to_list()):
    if vid:
        vid_sources[vid].add(src)

combo_counts: Counter = Counter(
    tuple(sorted(s)) for s in vid_sources.values()
)
top_combos = combo_counts.most_common(20)
for combo, n in top_combos:
    print(f"  {n:>8,}  {' + '.join(combo)}")

# ----------------------------------------------------------------------
# 3. CVE Project unique contribution: how many CVEs are in cve-project
#    but in NO other source?
# ----------------------------------------------------------------------
banner("CVE PROJECT UNIQUE COVERAGE")
cveproj_only_vids = [vid for vid, srcs in vid_sources.items() if srcs == {"cve-project"}]
epss_only_vids = [vid for vid, srcs in vid_sources.items() if srcs == {"epss"}]
cve_and_epss_only = [vid for vid, srcs in vid_sources.items() if srcs == {"cve-project", "epss"}]
ghsa_unrev_only = [vid for vid, srcs in vid_sources.items() if srcs == {"ghsa-unreviewed"}]
print(f"cve-project ONLY:         {len(cveproj_only_vids):>10,}")
print(f"epss ONLY:                {len(epss_only_vids):>10,}")
print(f"cve-project + epss only:  {len(cve_and_epss_only):>10,}")
print(f"ghsa-unreviewed ONLY:     {len(ghsa_unrev_only):>10,}")

# ----------------------------------------------------------------------
# 4. KEV breakdown by vendor/product (where ecosystem is empty)
# ----------------------------------------------------------------------
banner("KEV BLIND SPOT BY VENDOR (no ecosystem coverage)")
# kev_clusters JSON has packages with "vendor:product" strings from the
# CISA KEV emit step.
kev_no_eco = [c for c in kev_clusters if not c["ecosystems"]]
vendor_counts: Counter = Counter()
for c in kev_no_eco:
    for pkg in c.get("packages", []):
        if ":" in pkg:
            vendor = pkg.split(":", 1)[0]
            vendor_counts[vendor] += 1
        else:
            vendor_counts[pkg] += 1
print(f"Total KEV-no-ecosystem clusters: {len(kev_no_eco):,}")
print("\nTop 20 vendors:")
for vendor, n in vendor_counts.most_common(20):
    print(f"  {vendor:<30} {n:>5}")

# ----------------------------------------------------------------------
# 5. KEV ransomware concentration: which vendors dominate the ransomware
#    sub-list?
# ----------------------------------------------------------------------
banner("KEV RANSOMWARE-USE BY VENDOR")
kev_ransom = [c for c in kev_clusters if c.get("kev_ransomware") == "Known"]
ransom_vendor: Counter = Counter()
for c in kev_ransom:
    for pkg in c.get("packages", []):
        if ":" in pkg:
            ransom_vendor[pkg.split(":", 1)[0]] += 1
print(f"Total ransomware-used KEV clusters: {len(kev_ransom):,}")
print("\nTop 15 vendors:")
for vendor, n in ransom_vendor.most_common(15):
    print(f"  {vendor:<30} {n:>4}")

# ----------------------------------------------------------------------
# 6. EPSS distribution conditioned on KEV
# ----------------------------------------------------------------------
banner("EPSS PERCENTILE FOR KEV-LISTED CLUSTERS")
buckets = {"p99+": 0, "p95-p99": 0, "p90-p95": 0, "p50-p90": 0, "p0-p50": 0, "no_epss": 0}
for c in kev_clusters:
    p = c.get("epss_percentile") or 0.0
    if p >= 0.99:
        buckets["p99+"] += 1
    elif p >= 0.95:
        buckets["p95-p99"] += 1
    elif p >= 0.90:
        buckets["p90-p95"] += 1
    elif p >= 0.50:
        buckets["p50-p90"] += 1
    elif p > 0:
        buckets["p0-p50"] += 1
    else:
        buckets["no_epss"] += 1
total_kev = len(kev_clusters)
for b, n in buckets.items():
    print(f"  {b:<10} {n:>5,}  ({100*n/max(1,total_kev):.1f}%)")
print(f"\n=> {100*(buckets['p95-p99']+buckets['p99+'])/max(1,total_kev):.1f}% "
      f"of KEV-listed vulns are p95+ on EPSS (model 'caught' them)")
print(f"=> {100*buckets['no_epss']/max(1,total_kev):.1f}% have NO EPSS score "
      f"(model never saw them -- pure post-hoc KEV catch)")

# ----------------------------------------------------------------------
# 7. Bitnami fanout check: is top-disagreement still dominated by Bitnami?
# ----------------------------------------------------------------------
banner("TOP-DISAGREEMENT: BITNAMI FANOUT CHECK")
top_dis = json.loads((ROOT / "output" / "top_disagreement.json").read_text(encoding="utf-8"))
bit_count = sum(1 for c in top_dis if any("BIT-" in m for m in c.get("members", [])))
print(f"Bitnami-dominated clusters in top 15: {bit_count}/{len(top_dis)}")
print("Top 5 by n_members:")
for c in top_dis[:5]:
    bit = any("BIT-" in m for m in c.get("members", []))
    print(f"  root={c['root_id']:<30} n_ids={c['n_members']:>3}  "
          f"sources={len(c['sources'])}  bitnami={bit}")

# ----------------------------------------------------------------------
# 8. Ubuntu/Debian pocket collapse: did ER fold the per-release rows?
# ----------------------------------------------------------------------
banner("UBUNTU / DEBIAN ECOSYSTEM FANOUT")
# Look at the report.json ecosystem_coverage -- Ubuntu shows multiple
# release pockets. If ER worked, the same canonical cluster should
# appear in multiple of those pockets (one cluster, many ecosystem
# tags). The headline "Ubuntu canonical clusters across all pockets"
# answers this -- we count clusters that touch ANY Ubuntu pocket
# vs sum of pocket counts.
ubuntu_pockets = {k: v for k, v in report["ecosystem_coverage"].items() if k.startswith("Ubuntu")}
sum_pockets = sum(ubuntu_pockets.values())
print(f"Ubuntu rows summed across {len(ubuntu_pockets)} pockets: {sum_pockets:,}")
print(f"  (if ER folded perfectly across pockets, the unique Ubuntu")
print(f"  cluster count would be much smaller than this sum.)")

# ----------------------------------------------------------------------
# 9. Severity coverage gap
# ----------------------------------------------------------------------
banner("SEVERITY COVERAGE")
with_sev = (df.filter(pl.col("severity") != "").select(pl.col("vuln_id").n_unique()).item())
print(f"Unique vuln_ids with any severity string: {with_sev:,} "
      f"({100*with_sev/df.select(pl.col('vuln_id').n_unique()).item():.1f}% of unique IDs)")

# ----------------------------------------------------------------------
# 10. Write JSON output
# ----------------------------------------------------------------------
deep = {
    "per_source": per_source_dicts,
    "top_vuln_id_source_combos": [
        {"combo": list(c), "count": n} for c, n in top_combos
    ],
    "cve_project_unique_to_cveproj": len(cveproj_only_vids),
    "epss_unique_to_epss": len(epss_only_vids),
    "cve_project_and_epss_only": len(cve_and_epss_only),
    "ghsa_unreviewed_only": len(ghsa_unrev_only),
    "kev_blind_spot_by_vendor": vendor_counts.most_common(50),
    "kev_ransomware_by_vendor": ransom_vendor.most_common(20),
    "kev_epss_buckets": buckets,
    "top_disagreement_bitnami_share": {
        "bitnami_in_top15": bit_count,
        "total_in_top15": len(top_dis),
    },
    "ubuntu_pocket_rows_summed": sum_pockets,
    "severity_coverage": {
        "unique_vids_with_severity": with_sev,
        "total_unique_vids": df.select(pl.col("vuln_id").n_unique()).item(),
    },
}
OUT.write_text(json.dumps(deep, indent=2, default=str), encoding="utf-8")
print(f"\nWrote {OUT}")
