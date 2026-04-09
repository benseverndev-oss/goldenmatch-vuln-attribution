"""Count records in each fetched source by reading directly from zips.

This is the scoping pass: before writing the full extractor, we want to
confirm real row counts per ecosystem/source and sample a few records
to validate the schema shape.
"""
from __future__ import annotations
import gzip
import io
import json
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUB = ROOT / "data" / "public"
OSV = PUB / "osv"

totals: dict[str, int] = {}
alias_samples: list[dict] = []


def scan_osv(eco: str) -> int:
    zp = OSV / f"{eco.replace('.', '_')}.zip"
    n = 0
    with zipfile.ZipFile(zp) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            n += 1
            # Sample a few for alias inspection
            if len(alias_samples) < 20 and n % 500 == 0:
                with zf.open(info) as f:
                    d = json.load(f)
                if d.get("aliases"):
                    alias_samples.append({
                        "ecosystem": eco,
                        "id": d.get("id"),
                        "aliases": d.get("aliases"),
                        "affected_pkgs": [
                            a.get("package", {}).get("purl") or a.get("package", {}).get("name")
                            for a in (d.get("affected") or [])
                        ][:3],
                    })
    return n


print("OSV ecosystems:")
OSV_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io",
    "Packagist", "NuGet", "Debian", "Alpine",
]
for eco in OSV_ECOSYSTEMS:
    n = scan_osv(eco)
    totals[f"osv:{eco}"] = n
    print(f"  {eco:>12}: {n:>7,}")

osv_total = sum(v for k, v in totals.items() if k.startswith("osv:"))
print(f"  {'OSV TOTAL':>12}: {osv_total:>7,}")

# ---------- GHSA ----------
print("\nGHSA (advisory-database zip):")
ghsa_zp = PUB / "ghsa.zip"
ghsa_count = 0
ghsa_ecos: Counter = Counter()
ghsa_severity: Counter = Counter()
with zipfile.ZipFile(ghsa_zp) as zf:
    for info in zf.infolist():
        if not info.filename.endswith(".json"):
            continue
        # Only count the reviewed / unreviewed advisories directories
        if "/advisories/" not in info.filename:
            continue
        ghsa_count += 1
        if ghsa_count <= 5 or ghsa_count % 500 == 0:
            with zf.open(info) as f:
                try:
                    d = json.load(f)
                except Exception:
                    continue
            # Path tells us reviewed vs unreviewed
            if "/reviewed/" in info.filename:
                ghsa_severity["reviewed"] += 1
            elif "/unreviewed/" in info.filename:
                ghsa_severity["unreviewed"] += 1
            for aff in d.get("affected") or []:
                pkg = aff.get("package") or {}
                eco = pkg.get("ecosystem")
                if eco:
                    ghsa_ecos[eco] += 1
print(f"  advisory json files: {ghsa_count:,}")
print(f"  (sampled) reviewed/unreviewed split: {dict(ghsa_severity)}")
print(f"  (sampled) top ecosystems: {dict(ghsa_ecos.most_common(10))}")
totals["ghsa"] = ghsa_count

# ---------- PyPA ----------
print("\nPyPA advisory-database:")
pypa_zp = PUB / "pypa.zip"
pypa_count = 0
with zipfile.ZipFile(pypa_zp) as zf:
    for info in zf.infolist():
        if info.filename.endswith(".yaml") or info.filename.endswith(".yml"):
            pypa_count += 1
        if info.filename.endswith(".json") and "/vulns/" in info.filename:
            pypa_count += 1
print(f"  records: {pypa_count:,}")
totals["pypa"] = pypa_count

# ---------- RustSec ----------
print("\nRustSec advisory-db:")
rs_zp = PUB / "rustsec.zip"
rs_count = 0
with zipfile.ZipFile(rs_zp) as zf:
    for info in zf.infolist():
        if info.filename.endswith(".md") and "/crates/" in info.filename:
            rs_count += 1
        if info.filename.endswith(".toml") and "/crates/" in info.filename:
            rs_count += 1
print(f"  records: {rs_count:,}")
totals["rustsec"] = rs_count

# ---------- Go vulndb ----------
print("\nGo vulndb:")
go_zp = PUB / "go-vulndb.zip"
go_count = 0
with zipfile.ZipFile(go_zp) as zf:
    for info in zf.infolist():
        # Go vulndb stores reports in data/reports/*.yaml
        if info.filename.endswith(".yaml") and "/data/reports/" in info.filename:
            go_count += 1
print(f"  records: {go_count:,}")
totals["go-vulndb"] = go_count

# ---------- EPSS ----------
print("\nEPSS:")
epss = PUB / "epss_scores.csv.gz"
with gzip.open(epss, "rt") as f:
    epss_count = sum(1 for _ in f) - 2  # header + metadata line
print(f"  CVEs with EPSS scores: {epss_count:,}")
totals["epss"] = epss_count

# Grand total
grand = sum(totals.values())
print()
print("=" * 50)
print(f"{'TOTAL RECORDS':<40} {grand:>10,}")
print("=" * 50)

# Alias shape samples
print("\nAlias samples (show cross-database linkage):")
for s in alias_samples[:10]:
    print(f"  [{s['ecosystem']}] {s['id']} -> {s['aliases']}  pkg={s['affected_pkgs'][0] if s['affected_pkgs'] else None}")

# Save
import json as _j
(ROOT / "data" / "source_counts.json").write_text(_j.dumps({"totals": totals, "grand_total": grand}, indent=2))
print(f"\nWrote data/source_counts.json")
