"""Actionability: representable AND has a published `fixed` event.

Representability (analyze_representability.py) tells us a CVE is at
least *expressible* in package coordinates -- some source ships a
version range for it. Actionability tightens the bar: at least one of
those range rows must include a `fixed` event, so a remediator can
say "upgrade to >= X" rather than just "you're affected, good luck".

In the operator sense:
    REPRESENTABLE = the matcher returns AFFECTED / NOT_AFFECTED instead
                    of UNKNOWN for some installed version of the package
    ACTIONABLE    = REPRESENTABLE *and* there is a concrete upgrade
                    target published

Defined formally in docs/definitions.md.

Outputs `output/actionability.json`:

    {
      "totals": {representable, actionable, gap},
      "by_population": { kev / kev_ransomware / epss_p95 / ... },
      "per_ecosystem": { PyPI / npm / ... }
    }
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "actionability.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

LANG_ECOSYSTEMS = {
    "PyPI", "npm", "Maven", "Go", "crates.io",
    "RubyGems", "NuGet", "Packagist",
}


def cves_in(s: str) -> list[str]:
    out = []
    for tok in s.split(";"):
        tok = tok.strip()
        if tok.startswith("CVE-"):
            out.append(tok)
    return out


def has_fixed_event(ranges_json: str) -> bool:
    try:
        ranges = json.loads(ranges_json)
    except Exception:
        return False
    for rng in ranges:
        if rng.get("type") == "GIT":
            continue
        for ev in rng.get("events") or []:
            if "fixed" in ev:
                return True
    return False


def main() -> int:
    print(f"Loading {SRC.name} ...")
    df = pl.read_parquet(
        SRC,
        columns=["vuln_id", "aliases", "source", "ecosystem", "severity", "ranges"],
    )
    print(f"  rows: {df.height:,}")

    # Build CVE -> {ecosystem -> {is_repr, is_actionable}} indicators.
    cve_repr: set[str] = set()
    cve_actionable: set[str] = set()
    cve_repr_by_eco: dict[str, set[str]] = defaultdict(set)
    cve_actionable_by_eco: dict[str, set[str]] = defaultdict(set)

    range_df = df.filter(pl.col("ranges") != "")
    print(f"  range-bearing rows: {range_df.height:,}")
    vids = range_df["vuln_id"].to_list()
    als = range_df["aliases"].to_list()
    ecos = range_df["ecosystem"].to_list()
    rngs = range_df["ranges"].to_list()

    for i in range(len(vids)):
        if ecos[i] not in LANG_ECOSYSTEMS:
            continue
        cves: set[str] = set()
        if vids[i].startswith("CVE-"):
            cves.add(vids[i])
        if als[i]:
            for c in cves_in(als[i]):
                cves.add(c)
        if not cves:
            continue
        actionable = has_fixed_event(rngs[i])
        for cve in cves:
            cve_repr.add(cve)
            cve_repr_by_eco[ecos[i]].add(cve)
            if actionable:
                cve_actionable.add(cve)
                cve_actionable_by_eco[ecos[i]].add(cve)

    print(f"  representable CVEs: {len(cve_repr):,}")
    print(f"  actionable CVEs:    {len(cve_actionable):,}")
    print(f"  gap (repr but not actionable): {len(cve_repr - cve_actionable):,}")

    # KEV / EPSS / ransomware cohorts
    kev_cves: set[str] = set()
    ransom_cves: set[str] = set()
    epss_pct: dict[str, float] = {}
    for r in df.iter_rows(named=True):
        s = r["source"]
        vid = r["vuln_id"]
        if s == "cisa-kev" and vid.startswith("CVE-"):
            kev_cves.add(vid)
            if r["severity"] and "Known" in r["severity"]:
                ransom_cves.add(vid)
        elif s == "epss" and vid.startswith("CVE-"):
            sev = r["severity"] or ""
            if sev.startswith("epss:"):
                try:
                    _, _, p = sev.split(":", 2)
                    epss_pct[vid] = float(p)
                except Exception:
                    pass

    epss_p95 = {c for c, p in epss_pct.items() if p >= 0.95}
    epss_p99 = {c for c, p in epss_pct.items() if p >= 0.99}

    def cohort(name: str, pop: set[str]) -> dict:
        n = len(pop)
        r = len(pop & cve_repr)
        a = len(pop & cve_actionable)
        return {
            "total": n,
            "representable": r,
            "actionable": a,
            "gap": r - a,
            "representability_rate": round(r / n, 4) if n else None,
            "actionability_rate": round(a / n, 4) if n else None,
            "actionable_given_representable": (
                round(a / r, 4) if r else None
            ),
        }

    pops = {
        "kev": kev_cves,
        "kev_ransomware": ransom_cves,
        "epss_p95": epss_p95,
        "epss_p99": epss_p99,
        "kev_minus_epss_p95": kev_cves - epss_p95,
        "epss_p95_minus_kev": epss_p95 - kev_cves,
    }
    by_population = {name: cohort(name, pop) for name, pop in pops.items()}

    per_eco = {}
    for eco in sorted(LANG_ECOSYSTEMS):
        r = len(cve_repr_by_eco.get(eco, set()))
        a = len(cve_actionable_by_eco.get(eco, set()))
        per_eco[eco] = {
            "representable": r,
            "actionable": a,
            "gap": r - a,
            "actionable_given_representable": round(a / r, 4) if r else None,
        }

    out = {
        "definition": (
            "A CVE is actionable iff it is representable (has range data "
            "in one of the 8 v1 language ecosystems) *and* at least one "
            "of those range rows ships a `fixed` event, giving a "
            "concrete upgrade target."
        ),
        "totals": {
            "representable": len(cve_repr),
            "actionable": len(cve_actionable),
            "gap_representable_not_actionable": len(cve_repr - cve_actionable),
            "actionable_given_representable": (
                round(len(cve_actionable) / len(cve_repr), 4) if cve_repr else None
            ),
        },
        "by_population": by_population,
        "per_ecosystem": per_eco,
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print(f"Overall actionable-given-representable: "
          f"{out['totals']['actionable_given_representable']:.4f}")
    print("By population (rate of actionability over total):")
    for name, c in by_population.items():
        print(
            f"  {name:>22}  repr={c['representable']:>5}  "
            f"action={c['actionable']:>5}  gap={c['gap']:>4}  "
            f"action_rate={c['actionability_rate']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
