"""De-overlap test for the fix-version "convergence" claim.

`analyze_ranges.py` reported that of 32,746 (vuln_id, ecosystem, package)
groups where two or more sources both publish `fixed` events, only 1
had a non-trivial fix-version disagreement. The timing analysis showed
why: `ghsa-reviewed -> osv-ecosystem` has a p95 lag of 0 days, i.e.
most "multi-source" rows are GHSA being mirrored verbatim into OSV's
per-ecosystem buckets. So the prior result was largely measuring
redistribution fidelity, not independent convergence.

This script redoes the same agreement test, but with sources tagged
INDEPENDENT vs MIRROR, and only counts a "real" disagreement when at
least two INDEPENDENT sources both publish a `fixed` event for the
same (CVE, ecosystem, package).

Source classification (v1):

    INDEPENDENT
      - ghsa-reviewed      (GitHub Security curation)
      - pypa               (PyPA Python advisories)
      - rustsec            (RustSec curation; no ranges in our extract)
      - go-vulndb          (Go vuln db curation; no ranges in our extract)
      - cve-project        (MITRE/NVD; no ranges in our extract)
      - cisa-kev           (CISA listing; no ranges in our extract)

    MIRROR (downstream of one of the above)
      - osv-*              (OSV.dev redistributes PyPA + RustSec + Go
                             vulndb + GHSA into per-ecosystem buckets)
      - ghsa-unreviewed    (mostly NVD passthrough)
      - epss               (CVE scores only, no ranges)

In practice, the only INDEPENDENT pair with range data in the current
corpus is `ghsa-reviewed` x `pypa`. That's a finding in itself: the
public OSS vulnerability ecosystem has very little redundant version-
range data once you de-duplicate by upstream feed.

Outputs `output/independence.json`:

    {
      "source_classification": {INDEPENDENT: [...], MIRROR: [...]},
      "control_mirror_pairs": {
        "ghsa-reviewed_vs_osv-PyPI": {n_groups, n_disagreements, ...}
      },
      "independent_pairs": {
        "ghsa-reviewed_vs_pypa": {n_groups, n_disagreements,
          n_asymmetric_coverage,  // source A has fix events, source B has only `introduced`
          examples: [...]
        }
      },
      "summary_line": "..."  // ready-to-paste README hook
    }
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "independence.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

INDEPENDENT_SOURCES = {
    "ghsa-reviewed",
    "pypa",
    "rustsec",
    "go-vulndb",
    "cve-project",
    "cisa-kev",
}
MIRROR_SOURCES_PREFIXES = ("osv-",)
MIRROR_SOURCES_EXACT = {"ghsa-unreviewed", "epss"}


def classify(source: str) -> str:
    if source in INDEPENDENT_SOURCES:
        return "INDEPENDENT"
    if source.startswith(MIRROR_SOURCES_PREFIXES) or source in MIRROR_SOURCES_EXACT:
        return "MIRROR"
    return "UNCLASSIFIED"


def extract_fixed(ranges_json: str) -> tuple[set[str], bool]:
    """Return (set_of_fixed_versions, had_any_introduced_only_interval).

    The second bool flags asymmetric-coverage cases: the source ships a
    range with `introduced` events but never reaches a `fixed`. That's
    informational asymmetry vs another source that does ship a fix.
    """
    try:
        ranges = json.loads(ranges_json)
    except Exception:
        return set(), False
    fixes: set[str] = set()
    has_introduced_only = False
    for rng in ranges:
        if rng.get("type") == "GIT":
            continue
        events = rng.get("events") or []
        local_intro = False
        local_fix = False
        for ev in events:
            if "introduced" in ev:
                local_intro = True
            elif "fixed" in ev:
                fixes.add(str(ev["fixed"]))
                local_fix = True
        if local_intro and not local_fix:
            has_introduced_only = True
    return fixes, has_introduced_only


def pair_compare(
    src_a: str, src_b: str, rows_by_key: dict
) -> dict:
    """Compare two sources on every (vuln_id, ecosystem, package) where both publish a row."""
    n_groups = 0
    n_both_have_fixes = 0
    n_agreement = 0
    n_disagreement = 0
    # Sub-classification: subset_only (one set wholly contains the other,
    # i.e. completeness asymmetry on backport branches) vs disjoint_or_partial
    # (sets neither equal nor subset -- a real version contradiction).
    n_disagreement_subset_only = 0
    n_disagreement_contradiction = 0
    n_asymmetric_a_has_fix_b_doesnt = 0
    n_asymmetric_b_has_fix_a_doesnt = 0
    examples_disagreement: list[dict] = []
    examples_asymmetric: list[dict] = []

    for key, by_src in rows_by_key.items():
        if src_a not in by_src or src_b not in by_src:
            continue
        n_groups += 1
        a_fixes, a_intro_only = by_src[src_a]
        b_fixes, b_intro_only = by_src[src_b]
        if a_fixes and b_fixes:
            n_both_have_fixes += 1
            if a_fixes == b_fixes:
                n_agreement += 1
            else:
                n_disagreement += 1
                if a_fixes < b_fixes or b_fixes < a_fixes:
                    sub_class = "subset_only"
                    n_disagreement_subset_only += 1
                else:
                    sub_class = "contradiction"
                    n_disagreement_contradiction += 1
                if len(examples_disagreement) < 25:
                    examples_disagreement.append(
                        {
                            "cve_id": key[0],
                            "ecosystem": key[1],
                            "package": key[2],
                            "sub_class": sub_class,
                            src_a: sorted(a_fixes),
                            src_b: sorted(b_fixes),
                        }
                    )
        elif a_fixes and not b_fixes and b_intro_only:
            n_asymmetric_a_has_fix_b_doesnt += 1
            if len(examples_asymmetric) < 10:
                examples_asymmetric.append(
                    {
                        "cve_id": key[0],
                        "ecosystem": key[1],
                        "package": key[2],
                        "direction": f"{src_a} has fix, {src_b} introduced-only",
                        f"{src_a}_fixes": sorted(a_fixes),
                    }
                )
        elif b_fixes and not a_fixes and a_intro_only:
            n_asymmetric_b_has_fix_a_doesnt += 1

    return {
        "n_groups_both_publish_range": n_groups,
        "n_groups_both_have_fixes": n_both_have_fixes,
        "n_agreement": n_agreement,
        "n_disagreement": n_disagreement,
        "n_disagreement_subset_only": n_disagreement_subset_only,
        "n_disagreement_contradiction": n_disagreement_contradiction,
        "agreement_rate": (
            round(n_agreement / n_both_have_fixes, 4) if n_both_have_fixes else None
        ),
        "contradiction_rate": (
            round(n_disagreement_contradiction / n_both_have_fixes, 4)
            if n_both_have_fixes
            else None
        ),
        "n_asymmetric_a_has_fix_b_doesnt": n_asymmetric_a_has_fix_b_doesnt,
        "n_asymmetric_b_has_fix_a_doesnt": n_asymmetric_b_has_fix_a_doesnt,
        "examples_disagreement": examples_disagreement,
        "examples_asymmetric": examples_asymmetric,
    }


def main() -> int:
    print(f"Loading {SRC.name} (range-bearing rows only) ...")
    df = pl.read_parquet(
        SRC, columns=["vuln_id", "aliases", "ecosystem", "package", "source", "ranges"]
    )
    df = df.filter(pl.col("ranges") != "")
    print(f"  range-bearing rows: {df.height:,}")

    # (cve_id, ecosystem, package_lower) -> {source -> (fixes_set, had_introduced_only)}
    # Sources use different vuln_id schemes (PYSEC-*, GHSA-*, GO-*, ...), so a
    # direct vuln_id join would find zero overlap between independent sources.
    # The cross-source key is the CVE alias, which appears in either `vuln_id`
    # (if the source's own ID is a CVE) or `aliases` (otherwise).
    # Package names are lowercased for the join because GHSA preserves casing
    # ("AccessControl") while PyPA lowercases ("accesscontrol").
    rows_by_key: dict[tuple[str, str, str], dict[str, tuple[set[str], bool]]] = defaultdict(dict)
    vids = df["vuln_id"].to_list()
    als = df["aliases"].to_list()
    ecos = df["ecosystem"].to_list()
    pkgs = df["package"].to_list()
    srcs = df["source"].to_list()
    rngs = df["ranges"].to_list()
    for i in range(len(vids)):
        fixes, intro_only = extract_fixed(rngs[i])
        if not fixes and not intro_only:
            continue
        cves = set()
        if vids[i].startswith("CVE-"):
            cves.add(vids[i])
        if als[i]:
            for a in als[i].split(";"):
                a = a.strip()
                if a.startswith("CVE-"):
                    cves.add(a)
        if not cves:
            continue
        pkg_lower = pkgs[i].lower()
        for cve in cves:
            key = (cve, ecos[i], pkg_lower)
            existing = rows_by_key[key].get(srcs[i])
            if existing is None:
                rows_by_key[key][srcs[i]] = (fixes, intro_only)
            else:
                f0, io0 = existing
                rows_by_key[key][srcs[i]] = (f0 | fixes, io0 or intro_only)

    print(f"  distinct (cve, eco, pkg) groups with any range: {len(rows_by_key):,}")

    # Tally source-pair coverage so we know what's even comparable.
    pair_counts: dict[frozenset, int] = defaultdict(int)
    for by_src in rows_by_key.values():
        for s1 in by_src:
            for s2 in by_src:
                if s1 < s2:
                    pair_counts[frozenset((s1, s2))] += 1

    # Pairs to actually run. INDEPENDENT x INDEPENDENT is the centerpiece.
    # MIRROR-vs-MIRROR and INDEPENDENT-vs-MIRROR are controls.
    independent_pairs = []
    mirror_controls = []
    for pair, n in sorted(pair_counts.items(), key=lambda kv: -kv[1]):
        s1, s2 = sorted(pair)
        c1, c2 = classify(s1), classify(s2)
        if c1 == "INDEPENDENT" and c2 == "INDEPENDENT":
            independent_pairs.append((s1, s2, n))
        elif "MIRROR" in (c1, c2):
            mirror_controls.append((s1, s2, n))

    # Run the comparisons.
    independent_results = {}
    for s1, s2, n in independent_pairs:
        independent_results[f"{s1}_vs_{s2}"] = pair_compare(s1, s2, rows_by_key)
        independent_results[f"{s1}_vs_{s2}"]["n_total_pair_coverage"] = n

    # Only run the top-N mirror controls so the file doesn't explode.
    mirror_results = {}
    for s1, s2, n in mirror_controls[:6]:
        mirror_results[f"{s1}_vs_{s2}"] = pair_compare(s1, s2, rows_by_key)
        mirror_results[f"{s1}_vs_{s2}"]["n_total_pair_coverage"] = n

    # Build a one-liner summary for the README.
    summary_bits = []
    for name, r in independent_results.items():
        if r["n_groups_both_have_fixes"]:
            summary_bits.append(
                f"{name}: agreement {r['n_agreement']}/{r['n_groups_both_have_fixes']} "
                f"({r['agreement_rate']:.2%})"
            )
    summary_line = "; ".join(summary_bits) if summary_bits else "no independent pair had range overlap"

    out = {
        "source_classification": {
            "INDEPENDENT": sorted(INDEPENDENT_SOURCES),
            "MIRROR_prefixes": list(MIRROR_SOURCES_PREFIXES),
            "MIRROR_exact": sorted(MIRROR_SOURCES_EXACT),
        },
        "independent_pairs": independent_results,
        "mirror_control_pairs": mirror_results,
        "summary_line": summary_line,
    }
    OUT.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print(f"\nIndependent pairs with range overlap:")
    if not independent_results:
        print("  (none)")
    for name, r in independent_results.items():
        print(
            f"  {name:>40}  total_overlap={r['n_total_pair_coverage']:>5}  "
            f"both_have_fixes={r['n_groups_both_have_fixes']:>5}  "
            f"agreement={r['n_agreement']:>5}  disagreement={r['n_disagreement']:>3}  "
            f"asym(A-fix)={r['n_asymmetric_a_has_fix_b_doesnt']:>4}  "
            f"asym(B-fix)={r['n_asymmetric_b_has_fix_a_doesnt']:>4}"
        )
    print(f"\nMirror-control pairs (top {len(mirror_results)} by overlap):")
    for name, r in mirror_results.items():
        print(
            f"  {name:>40}  total_overlap={r['n_total_pair_coverage']:>6}  "
            f"both_have_fixes={r['n_groups_both_have_fixes']:>6}  "
            f"agreement={r['n_agreement']:>6}  disagreement={r['n_disagreement']:>4}"
        )
    print(f"\nSummary: {summary_line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
