"""Cross-source vulnerability reconciliation.

Builds a canonical vulnerability cluster graph from the (vuln_id, alias)
pairs across every source. Edge construction is domain-specific (OSV
schema's `aliases` field); clustering is delegated to
`goldenmatch.build_clusters`, which is the same union-find primitive
goldenmatch uses internally for entity resolution (with cluster_quality
+ confidence tagging on top).

Headline questions answered:

  1. How many unique real-world vulnerabilities are there, across all
     free public databases?
  2. What does each individual database cover as a % of that union?
  3. Which clusters have the highest ID-disagreement (the Lazarus/
     Ronin Bridge analog for vulnerabilities)?
  4. Which ecosystems are most / least covered?
  5. How many vulnerabilities are in the GitHub unreviewed mirror but
     absent from the github-reviewed set that Dependabot actually
     surfaces?
  6. What do famous reference CVEs (Log4Shell, Heartbleed, Shellshock)
     look like once reconciled?
"""
from __future__ import annotations
import json
from collections import Counter, defaultdict
from pathlib import Path

import goldenmatch as gm
import polars as pl

ROOT = Path(__file__).resolve().parent
# Prefer the goldenflow-normalized file when available; fall back to raw.
NORMALIZED = ROOT / "data" / "records_normalized.parquet"
RAW = ROOT / "data" / "records.parquet"
RECORDS = NORMALIZED if NORMALIZED.exists() else RAW
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)

print(f"Loading records from {RECORDS.name}...")
df = pl.read_parquet(RECORDS)
print(f"  rows: {df.height:,}")
print(f"  unique vuln_id: {df.select('vuln_id').n_unique():,}")
if RECORDS is NORMALIZED:
    print("  (using goldenflow-normalized IDs; case + whitespace cleaned)")
else:
    print("  (raw IDs; run normalize.py to apply goldenflow standardization)")

# ---------- Build edge list, then hand to goldenmatch ----------
print("\nBuilding (vuln_id, alias) edges across all sources...")
# goldenmatch.build_clusters wants integer node IDs + scored pairs.
# Intern every string ID to a stable int, build edges with score=1.0
# (exact ID-alias link), then let build_clusters do union-find +
# cluster_quality + confidence + auto-split.
id_to_idx: dict[str, int] = {}


def intern(s: str) -> int:
    idx = id_to_idx.get(s)
    if idx is None:
        idx = len(id_to_idx)
        id_to_idx[s] = idx
    return idx


pairs: list[tuple[int, int, float]] = []
for row in df.iter_rows(named=True):
    vid = row["vuln_id"]
    if not vid:
        continue
    vid_idx = intern(vid)
    aliases = row["aliases"]
    if not aliases:
        continue
    for a in aliases.split(";"):
        a = a.strip()
        if not a:
            continue
        pairs.append((vid_idx, intern(a), 1.0))

print(f"  unique IDs in graph: {len(id_to_idx):,}")
print(f"  alias edges:         {len(pairs):,}")

print("\nRunning goldenmatch.build_clusters (union-find + quality scoring)...")
gm_clusters = gm.build_clusters(
    pairs=pairs,
    all_ids=list(id_to_idx.values()),
    # OSV alias edges are an authoritative ID-equivalence, so keep
    # auto-split off and the weak threshold loose. We're not scoring
    # fuzzy similarity here; an edge means "these two IDs name the
    # same vulnerability".
    auto_split=False,
    weak_cluster_threshold=0.0,
    max_cluster_size=10_000,
)

# Map int cluster member ids back to strings, and pick a stable string
# "root" per cluster (smallest-CVE-first when present, else lexicographic).
idx_to_id = {idx: s for s, idx in id_to_idx.items()}


def pick_root(members: list[str]) -> str:
    cves = sorted(m for m in members if m.startswith("CVE-"))
    return cves[0] if cves else sorted(members)[0]


clusters: dict[str, set[str]] = {}
member_to_root: dict[str, str] = {}
for cid, cinfo in gm_clusters.items():
    members_str = [idx_to_id[m] for m in cinfo["members"]]
    root = pick_root(members_str)
    members_set = set(members_str)
    clusters[root] = members_set
    for m in members_set:
        member_to_root[m] = root

# Singletons: build_clusters omits unconnected nodes by default. Add
# every interned ID that didn't end up in a multi-node cluster as its
# own one-member cluster so the downstream stats stay correct.
for s in id_to_idx:
    if s not in member_to_root:
        clusters[s] = {s}
        member_to_root[s] = s

print(f"  canonical clusters:   {len(clusters):,}")
multi = {r: m for r, m in clusters.items() if len(m) >= 2}
print(f"  multi-ID clusters:    {len(multi):,}")

# ---------- Attach source / package data to each cluster ----------
print("\nAttaching per-cluster metadata...")
id_to_rows: dict[str, list[dict]] = defaultdict(list)
for row in df.iter_rows(named=True):
    id_to_rows[row["vuln_id"]].append(row)

cluster_info: dict[str, dict] = {}
for root, members in clusters.items():
    sources: set[str] = set()
    ecos: set[str] = set()
    purls: set[str] = set()
    packages: set[str] = set()
    published: list[str] = []
    modified: list[str] = []
    severities: set[str] = set()
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    kev: bool = False
    kev_ransomware: str = ""
    for m in members:
        for row in id_to_rows.get(m, []):
            src = row["source"]
            sources.add(src)
            sev = row["severity"] or ""
            if src == "epss" and sev.startswith("epss:"):
                # epss:<score>:<percentile>
                parts = sev.split(":")
                if len(parts) >= 3:
                    try:
                        s = float(parts[1])
                        p = float(parts[2])
                        if s > epss_score:
                            epss_score = s
                        if p > epss_percentile:
                            epss_percentile = p
                    except ValueError:
                        pass
                # EPSS rows don't contribute ecosystem/package signal
                continue
            if src == "cisa-kev":
                kev = True
                if sev.startswith("kev:ransomware="):
                    kev_ransomware = sev.split("=", 1)[1]
            if row["ecosystem"]:
                ecos.add(row["ecosystem"])
            if row["purl"]:
                purls.add(row["purl"])
            if row["package"]:
                packages.add(row["package"])
            if row["published"]:
                published.append(row["published"])
            if row["modified"]:
                modified.append(row["modified"])
            if sev:
                severities.add(sev)
    cluster_info[root] = {
        "root_id": root,
        "members": sorted(members),
        "n_members": len(members),
        "sources": sorted(sources),
        "n_sources": len(sources),
        "ecosystems": sorted(ecos),
        "n_ecosystems": len(ecos),
        "purls": sorted(purls),
        "n_purls": len(purls),
        "packages": sorted(packages)[:10],
        "earliest_published": min(published) if published else "",
        "latest_modified": max(modified) if modified else "",
        "severities": sorted(severities)[:5],
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "kev": kev,
        "kev_ransomware": kev_ransomware,
    }

# ---------- Headline stats ----------
print("\n" + "=" * 60)
print("HEADLINE STATS")
print("=" * 60)

total_clusters = len(cluster_info)
print(f"Unique vulnerabilities (after alias resolution): {total_clusters:,}")

print("\nCoverage per source (number of canonical clusters the source touches):")
source_coverage: Counter = Counter()
for info in cluster_info.values():
    for s in info["sources"]:
        source_coverage[s] += 1
for src, n in source_coverage.most_common():
    pct = 100 * n / total_clusters
    print(f"  {src:<20} {n:>8,}  ({pct:5.1f}%)")

# ---------- The Dependabot gap ----------
print("\n" + "=" * 60)
print("GITHUB DEPENDABOT COVERAGE vs FULL OSS VULN UNIVERSE")
print("=" * 60)

ghsa_rev = {r for r, info in cluster_info.items() if "ghsa-reviewed" in info["sources"]}
ghsa_unrev = {r for r, info in cluster_info.items() if "ghsa-unreviewed" in info["sources"]}
osv_sources = {s for s in source_coverage if s.startswith("osv-")}
osv_any = {r for r, info in cluster_info.items() if any(s in info["sources"] for s in osv_sources)}
full_oss_universe = ghsa_rev | osv_any

print(f"github-reviewed (Dependabot corpus):   {len(ghsa_rev):>8,}")
print(f"github-unreviewed (NVD mirror):        {len(ghsa_unrev):>8,}")
print(f"OSV ecosystem coverage (any):          {len(osv_any):>8,}")
print(f"Full OSS universe (union):             {len(full_oss_universe):>8,}")
print()
rev_gap_pct = 100 * (1 - len(ghsa_rev) / len(full_oss_universe))
print(f"Fraction of OSS universe MISSED by github-reviewed alone: {rev_gap_pct:.1f}%")
rev_pct = 100 * len(ghsa_rev) / len(full_oss_universe)
print(f"Dependabot reviewed-set coverage: {rev_pct:.1f}%")

# ---------- KEV (actively exploited) ----------
print("\n" + "=" * 60)
print("CISA KEV: ACTIVELY EXPLOITED VULNERABILITIES")
print("=" * 60)
kev_clusters = [info for info in cluster_info.values() if info["kev"]]
kev_with_ecosystem = [c for c in kev_clusters if c["ecosystems"]]
kev_in_ghsa_rev = [c for c in kev_clusters if "ghsa-reviewed" in c["sources"]]
kev_ransom = [c for c in kev_clusters if c["kev_ransomware"] == "Known"]
print(f"KEV-listed canonical vulns:            {len(kev_clusters):>6,}")
print(f"  ...with ecosystem coverage:          {len(kev_with_ecosystem):>6,}  "
      f"({100 * len(kev_with_ecosystem) / max(1, len(kev_clusters)):.1f}%)")
print(f"  ...in github-reviewed (Dependabot):  {len(kev_in_ghsa_rev):>6,}  "
      f"({100 * len(kev_in_ghsa_rev) / max(1, len(kev_clusters)):.1f}%)")
print(f"  ...with known ransomware use:        {len(kev_ransom):>6,}")
kev_gap = len(kev_clusters) - len(kev_with_ecosystem)
print(f"\nKEV vulns with NO ecosystem coverage:  {kev_gap:,}")
print("(actively exploited, but no package-scanner can see them)")

# ---------- EPSS distribution ----------
print("\n" + "=" * 60)
print("EPSS EXPLOIT-PREDICTION DISTRIBUTION")
print("=" * 60)
epss_buckets = {
    "p99+ (top 1%)":   [c for c in cluster_info.values() if c["epss_percentile"] >= 0.99],
    "p95-p99":         [c for c in cluster_info.values() if 0.95 <= c["epss_percentile"] < 0.99],
    "p90-p95":         [c for c in cluster_info.values() if 0.90 <= c["epss_percentile"] < 0.95],
    "p50-p90":         [c for c in cluster_info.values() if 0.50 <= c["epss_percentile"] < 0.90],
    "p0-p50":          [c for c in cluster_info.values() if 0.0 < c["epss_percentile"] < 0.50],
    "no EPSS score":   [c for c in cluster_info.values() if c["epss_percentile"] == 0.0],
}
for bucket, items in epss_buckets.items():
    n_with_eco = sum(1 for c in items if c["ecosystems"])
    print(f"  {bucket:<18} {len(items):>8,}  (with ecosystem: {n_with_eco:,})")

high_epss_no_coverage = [
    c for c in cluster_info.values()
    if c["epss_percentile"] >= 0.95 and not c["ecosystems"] and not c["kev"]
]
print(f"\nHigh-EPSS (p95+) with NO ecosystem and NOT in KEV: {len(high_epss_no_coverage):,}")
print("(model says likely-to-be-exploited, but invisible to package scanners and not yet exploited)")

# ---------- Ecosystem asymmetry ----------
print("\n" + "=" * 60)
print("ECOSYSTEM COVERAGE ASYMMETRY")
print("=" * 60)
eco_clusters: Counter = Counter()
for info in cluster_info.values():
    for e in info["ecosystems"]:
        eco_clusters[e] += 1
for eco, n in eco_clusters.most_common(15):
    print(f"  {eco:<20} {n:>8,}")

# ---------- ID-disagreement cases ----------
print("\n" + "=" * 60)
print("HIGH-DISAGREEMENT CLUSTERS (most IDs per vulnerability)")
print("=" * 60)
top_disagreement = sorted(cluster_info.values(), key=lambda c: -c["n_members"])[:15]
for c in top_disagreement:
    pkgs = c["packages"][:3]
    src = c["sources"]
    print(f"  root={c['root_id']} n_ids={c['n_members']} n_sources={c['n_sources']}")
    print(f"    ids: {c['members'][:6]}{' ...' if c['n_members'] > 6 else ''}")
    print(f"    sources: {src}")
    print(f"    packages: {pkgs}")
    print()

# ---------- Famous vulns reference lookup ----------
print("=" * 60)
print("FAMOUS VULNERABILITIES AFTER RECONCILIATION")
print("=" * 60)

famous = {
    "Log4Shell":  "CVE-2021-44228",
    "Spring4Shell": "CVE-2022-22965",
    "Heartbleed": "CVE-2014-0160",
    "Shellshock": "CVE-2014-6271",
    "ProxyShell": "CVE-2021-34473",
    "ZipSlip":   "CVE-2018-1002105",
}
for name, cve in famous.items():
    root = member_to_root.get(cve)
    if not root:
        print(f"  {name} ({cve}): NOT FOUND in any source")
        continue
    info = cluster_info[root]
    print(f"  {name} ({cve}):")
    print(f"    cluster root: {root}")
    print(f"    IDs in cluster: {info['n_members']}")
    print(f"    sources: {info['sources']}")
    print(f"    ecosystems: {info['ecosystems']}")
    print(f"    affected packages (first 5): {info['packages'][:5]}")
    print(f"    earliest published: {info['earliest_published']}")
    print()

# ---------- Save report ----------
report = {
    "goldenmatch_version": gm.__version__,
    "input_file": RECORDS.name,
    "total_rows": int(df.height),
    "unique_vuln_ids": int(df.select("vuln_id").n_unique()),
    "unique_canonical_vulns": total_clusters,
    "multi_id_canonical_clusters": len(multi),
    "source_coverage": dict(source_coverage.most_common()),
    "dependabot_gap": {
        "ghsa_reviewed_clusters": len(ghsa_rev),
        "ghsa_unreviewed_clusters": len(ghsa_unrev),
        "osv_any_clusters": len(osv_any),
        "full_oss_universe": len(full_oss_universe),
        "reviewed_coverage_pct": round(rev_pct, 2),
        "reviewed_missed_pct": round(rev_gap_pct, 2),
    },
    "ecosystem_coverage": dict(eco_clusters.most_common(20)),
    "kev": {
        "total_kev_clusters": len(kev_clusters),
        "with_ecosystem_coverage": len(kev_with_ecosystem),
        "in_ghsa_reviewed": len(kev_in_ghsa_rev),
        "known_ransomware_use": len(kev_ransom),
        "no_ecosystem_coverage": kev_gap,
    },
    "epss": {
        bucket: len(items) for bucket, items in epss_buckets.items()
    },
    "high_epss_blind_spot": len(high_epss_no_coverage),
}
(OUT / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"Wrote {OUT / 'report.json'}")

# KEV-exploited clusters in their own file for drill-down
kev_export = sorted(
    [
        {
            "root_id": c["root_id"],
            "n_members": c["n_members"],
            "sources": c["sources"],
            "ecosystems": c["ecosystems"],
            "packages": c["packages"][:5],
            "epss_score": c["epss_score"],
            "epss_percentile": c["epss_percentile"],
            "kev_ransomware": c["kev_ransomware"],
        }
        for c in kev_clusters
    ],
    key=lambda c: (-c["epss_percentile"], c["root_id"]),
)
(OUT / "kev_clusters.json").write_text(
    json.dumps(kev_export, indent=2, default=str),
    encoding="utf-8",
)
print(f"Wrote {OUT / 'kev_clusters.json'}")

# Save top disagreement clusters
(OUT / "top_disagreement.json").write_text(
    json.dumps([c for c in top_disagreement], indent=2, default=str),
    encoding="utf-8",
)
print(f"Wrote {OUT / 'top_disagreement.json'}")

# Save famous vulns
famous_clusters = []
for name, cve in famous.items():
    root = member_to_root.get(cve)
    if root:
        famous_clusters.append({"name": name, "seed_cve": cve, **cluster_info[root]})
(OUT / "famous_vulns.json").write_text(
    json.dumps(famous_clusters, indent=2, default=str),
    encoding="utf-8",
)
print(f"Wrote {OUT / 'famous_vulns.json'}")
