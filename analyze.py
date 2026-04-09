"""Cross-source vulnerability reconciliation.

Builds a canonical vulnerability cluster graph by walking the
(vuln_id, alias) pairs across every source with union-find. Each
canonical cluster gets tagged with the source databases that know
about it, the affected packages, and the ID set, so we can answer:

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

import polars as pl

ROOT = Path(__file__).resolve().parent
RECORDS = ROOT / "data" / "records.parquet"
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)

print("Loading records...")
df = pl.read_parquet(RECORDS)
print(f"  rows: {df.height:,}")
print(f"  unique vuln_id: {df.select('vuln_id').n_unique():,}")

# ---------- Union-find over (vuln_id, aliases) ----------
print("\nBuilding canonical clusters via union-find on (vuln_id, aliases)...")
parent: dict[str, str] = {}


def find(x: str) -> str:
    while parent.get(x, x) != x:
        parent[x] = parent.get(parent[x], parent[x])
        x = parent[x]
    return x


def union(a: str, b: str) -> None:
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[rb] = ra


# Iterate rows and union vuln_id with each alias
for row in df.iter_rows(named=True):
    vid = row["vuln_id"]
    if not vid:
        continue
    parent.setdefault(vid, vid)
    aliases = row["aliases"]
    if not aliases:
        continue
    for a in aliases.split(";"):
        a = a.strip()
        if not a:
            continue
        parent.setdefault(a, a)
        union(vid, a)

# Compact each id to its root
print("  compacting parents...")
for x in list(parent.keys()):
    parent[x] = find(x)

# Group members by root
clusters: dict[str, set[str]] = defaultdict(set)
for x, root in parent.items():
    clusters[root].add(x)

print(f"  unique IDs in graph:  {len(parent):,}")
print(f"  canonical clusters:   {len(clusters):,}")
multi = {r: m for r, m in clusters.items() if len(m) >= 2}
print(f"  multi-ID clusters:    {len(multi):,}")

# ---------- Attach source / package data to each cluster ----------
print("\nAttaching per-cluster metadata...")
# Build id -> rows lookup
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
    for m in members:
        for row in id_to_rows.get(m, []):
            sources.add(row["source"])
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
            if row["severity"]:
                severities.add(row["severity"])
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
    }

# ---------- Headline stats ----------
print("\n" + "=" * 60)
print("HEADLINE STATS")
print("=" * 60)

total_clusters = len(cluster_info)
print(f"Unique vulnerabilities (after alias resolution): {total_clusters:,}")

# Per-source unique-cluster coverage
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
    root = parent.get(cve)
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
}
(OUT / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(f"Wrote {OUT / 'report.json'}")

# Save top disagreement clusters
(OUT / "top_disagreement.json").write_text(
    json.dumps([c for c in top_disagreement], indent=2, default=str),
    encoding="utf-8",
)
print(f"Wrote {OUT / 'top_disagreement.json'}")

# Save famous vulns
famous_clusters = []
for name, cve in famous.items():
    root = parent.get(cve)
    if root:
        famous_clusters.append({"name": name, "seed_cve": cve, **cluster_info[root]})
(OUT / "famous_vulns.json").write_text(
    json.dumps(famous_clusters, indent=2, default=str),
    encoding="utf-8",
)
print(f"Wrote {OUT / 'famous_vulns.json'}")
