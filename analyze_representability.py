"""Formalize the 'representability' concept.

A CVE is **package-representable** iff at least one of its alias-graph
records carries a `ranges` JSON (i.e. lives in one of the 8 v1 language
ecosystems: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist).

Everything else is **operational/system**: its affectedness can't be
expressed as a (package, version-range) pair in those feeds. Think
Exchange, Cisco IOS, F5 BIG-IP, Fortinet, VMware ESXi, browsers,
kernels, firmware -- the bulk of CISA KEV.

This script:

1. Extracts the set of CVEs whose alias graph touches any range-bearing
   row -> `representable_cves`.
2. Loads the KEV catalog, EPSS top-percentile slice, and total CVE set
   (any source).
3. Reports representability rate for each population, plus the slices
   readers actually want: KEV with ransomware tag, KEV by year, etc.

Outputs `output/representability.json`:

    {
      "definition": "...",
      "totals": { ... },
      "representability_rate": { ... },
      "kev_breakdown": { ... }
    }
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "representability.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


def cves_in(s: str) -> list[str]:
    out = []
    for tok in s.split(";"):
        tok = tok.strip()
        if tok.startswith("CVE-"):
            out.append(tok)
    return out


def main() -> int:
    print(f"Loading {SRC.name} ...")
    df = pl.read_parquet(
        SRC,
        columns=["vuln_id", "aliases", "source", "severity", "ranges"],
    )
    print(f"  rows: {df.height:,}")

    # ---------- Step 1: representable CVE set ----------
    range_df = df.filter(pl.col("ranges") != "")
    print(f"  range-bearing rows: {range_df.height:,}")
    repr_cves: set[str] = set()
    for vid, al in zip(range_df["vuln_id"].to_list(), range_df["aliases"].to_list()):
        if vid.startswith("CVE-"):
            repr_cves.add(vid)
        if al:
            for c in cves_in(al):
                repr_cves.add(c)
    print(f"  representable CVEs (touch any range row): {len(repr_cves):,}")

    # ---------- Step 2: KEV catalog + ransomware flag ----------
    kev_df = df.filter(pl.col("source") == "cisa-kev")
    kev_cves: set[str] = set()
    ransom_cves: set[str] = set()
    for vid, sev in zip(kev_df["vuln_id"].to_list(), kev_df["severity"].to_list()):
        if vid.startswith("CVE-"):
            kev_cves.add(vid)
            # severity format from extract: "kev:ransomware=<Known|Unknown>"
            if sev and "Known" in sev:
                ransom_cves.add(vid)
    print(f"  KEV CVEs: {len(kev_cves):,}  (ransomware-tagged: {len(ransom_cves):,})")

    # ---------- Step 3: EPSS p95 cohort ----------
    epss_df = df.filter(pl.col("source") == "epss")
    epss_p95: set[str] = set()
    epss_p99: set[str] = set()
    for vid, sev in zip(epss_df["vuln_id"].to_list(), epss_df["severity"].to_list()):
        if not sev or not sev.startswith("epss:"):
            continue
        try:
            _, _, pct = sev.split(":", 2)
            p = float(pct)
        except Exception:
            continue
        if p >= 0.95:
            epss_p95.add(vid)
        if p >= 0.99:
            epss_p99.add(vid)
    print(f"  EPSS p95+ CVEs: {len(epss_p95):,}  (p99+: {len(epss_p99):,})")

    # ---------- Step 4: total CVE universe (anything mentioning a CVE) ----------
    all_cves: set[str] = set()
    for vid, al in zip(df["vuln_id"].to_list(), df["aliases"].to_list()):
        if vid.startswith("CVE-"):
            all_cves.add(vid)
        if al:
            for c in cves_in(al):
                all_cves.add(c)
    print(f"  all CVEs anywhere in corpus: {len(all_cves):,}")

    # ---------- Compute rates ----------
    def rate(pop: set[str]) -> dict:
        n = len(pop)
        r = len(pop & repr_cves)
        return {
            "total": n,
            "representable": r,
            "non_representable": n - r,
            "representability_rate": round(r / n, 4) if n else None,
        }

    rates = {
        "all_cves": rate(all_cves),
        "kev": rate(kev_cves),
        "kev_ransomware": rate(ransom_cves),
        "epss_p95": rate(epss_p95),
        "epss_p99": rate(epss_p99),
        "kev_and_epss_p95": rate(kev_cves & epss_p95),
        "kev_not_epss_p95": rate(kev_cves - epss_p95),
        "epss_p95_not_kev": rate(epss_p95 - kev_cves),
    }

    # ---------- KEV by year (uses CVE year prefix, not dateAdded) ----------
    kev_by_year: dict[str, dict] = defaultdict(lambda: {"total": 0, "representable": 0})
    for cve in kev_cves:
        parts = cve.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            year = parts[1]
            kev_by_year[year]["total"] += 1
            if cve in repr_cves:
                kev_by_year[year]["representable"] += 1
    kev_by_year_out = {}
    for y, c in sorted(kev_by_year.items()):
        c["representability_rate"] = (
            round(c["representable"] / c["total"], 4) if c["total"] else None
        )
        kev_by_year_out[y] = c

    out = {
        "definition": (
            "A CVE is package-representable iff at least one row whose "
            "vuln_id or aliases includes that CVE carries a non-empty "
            "`ranges` field for one of the 8 v1 language ecosystems "
            "(PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist). "
            "Everything else is operational/system: not expressible in "
            "package coordinates by these feeds."
        ),
        "totals": {
            "all_cves_in_corpus": len(all_cves),
            "representable_cves": len(repr_cves),
            "kev_cves": len(kev_cves),
            "kev_ransomware_cves": len(ransom_cves),
            "epss_p95_cves": len(epss_p95),
            "epss_p99_cves": len(epss_p99),
        },
        "representability_by_population": rates,
        "kev_by_year": kev_by_year_out,
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print("\nRepresentability rates:")
    for name, r in rates.items():
        rr = r["representability_rate"]
        if rr is None:
            continue
        print(f"  {name:>20}: {r['representable']:>6,} / {r['total']:>6,}  ({rr:.2%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
