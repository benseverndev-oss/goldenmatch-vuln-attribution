"""Representability taxonomy: where do non-representable CVEs live?

Builds on `analyze_representability.py` (which gave a binary
representable / not flag). This script partitions every CVE in the
corpus into five mutually-exclusive buckets by which source-family
ships data for it, then cross-tabulates against KEV / EPSS / ransomware.

Buckets (from richest to poorest detection signal):

    PACKAGE_RANGE          version range in one of the 8 v1 language
                           ecosystems. The matcher can answer "am I
                           affected at version X" for this CVE.

    PACKAGE_ADVISORY       a curated advisory exists (ghsa-reviewed,
                           pypa, rustsec, go-vulndb, osv-{8 ecos}) but
                           no source ships a version range. The advisory
                           exists; version info doesn't.

    DISTRO                 a curated record exists in OSV's distro
                           buckets (Debian / Ubuntu / Alpine / RPM-based).
                           Fixed in an OS package manager, not a language
                           ecosystem.

    UNREVIEWED_MIRROR      only appears in ghsa-unreviewed and/or
                           osv-GIT -- both are essentially CVE-Project /
                           NVD passthroughs that GitHub & OSV ingest
                           without curation. Sometimes informative, often
                           just the CVE description re-labelled.

    CVE_ONLY               only appears in cve-project / KEV / EPSS.
                           No advisory feed (curated or unreviewed)
                           ships any record. The classic appliance /
                           firmware / browser / kernel population.

    UNCLASSIFIED           defensive bucket; should be ~0.

We then ask, for each bucket, how the population skews on:
- CISA KEV listing
- KEV-with-ransomware tag
- EPSS p95+ / p99+

And for the operationally-most-interesting bucket (CVE_ONLY), surface
the top vendor:product strings so readers can see *what* lives there.

Outputs `output/representability_taxonomy.json`.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "representability_taxonomy.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

LANG_ECOSYSTEMS = {
    "PyPI", "npm", "Maven", "Go", "crates.io",
    "RubyGems", "NuGet", "Packagist",
}
DISTRO_ECOSYSTEMS = {
    "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "Mageia",
    "openSUSE", "SUSE", "Photon OS", "Red Hat", "Wolfi", "Chainguard",
    "MinimOS",
}
# Sources that ship a curated advisory in the language-ecosystem space.
# osv-{lang-eco} also lands here because it carries the OSV redistribution
# of curated GHSA / PyPA / RustSec / Go-vulndb records.
CURATED_ADVISORY_SOURCES = {
    "ghsa-reviewed", "pypa", "rustsec", "go-vulndb",
}
# Sources that are CVE-Project / NVD passthroughs wearing a different label.
UNREVIEWED_MIRROR_SOURCES = {
    "ghsa-unreviewed",
}
# `osv-GIT` is a special OSV bucket for CVE-shaped GIT-range records that
# don't belong to any package ecosystem. Treated as unreviewed mirror.
UNREVIEWED_MIRROR_ECOSYSTEMS = {"GIT", "Linux", "OSS-Fuzz", "Bitnami", "UVI",
                               "GitHub Actions", "Kubernetes", "Android",
                               "Curl", "Hex", "Pub", "Hackage", "CRAN",
                               "Bioconductor", "GHC", "SwiftURL"}


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
        columns=["vuln_id", "aliases", "source", "ecosystem", "package", "severity", "ranges"],
    )
    print(f"  rows: {df.height:,}")

    # ---------- Pass 1: build the signal sets ----------
    has_package_range: set[str] = set()       # 8-eco with range
    has_curated_advisory: set[str] = set()    # curated-source record in 8-eco context
    has_distro_record: set[str] = set()       # osv distro bucket
    has_unreviewed_mirror: set[str] = set()   # ghsa-unreviewed / osv-GIT / etc.
    has_cve_project: set[str] = set()
    has_kev: set[str] = set()
    has_kev_ransomware: set[str] = set()
    epss_pct: dict[str, float] = {}

    vids = df["vuln_id"].to_list()
    als = df["aliases"].to_list()
    srcs = df["source"].to_list()
    ecos = df["ecosystem"].to_list()
    pkgs = df["package"].to_list()
    sevs = df["severity"].to_list()
    rngs = df["ranges"].to_list()

    cve_vendor_product: dict[str, str] = {}  # for CVE_ONLY bucket vendor reporting

    n = len(vids)
    for i in range(n):
        cves: set[str] = set()
        if vids[i].startswith("CVE-"):
            cves.add(vids[i])
        if als[i]:
            for c in cves_in(als[i]):
                cves.add(c)
        if not cves:
            continue

        s = srcs[i]
        e = ecos[i]
        has_range = bool(rngs[i])
        is_lang_eco_range = has_range and e in LANG_ECOSYSTEMS
        # Classify the source record itself.
        is_distro = s.startswith("osv-") and e in DISTRO_ECOSYSTEMS
        is_curated_lang_eco = (
            (s in CURATED_ADVISORY_SOURCES)
            or (s.startswith("osv-") and e in LANG_ECOSYSTEMS)
        )
        is_unreviewed_mirror = (
            s in UNREVIEWED_MIRROR_SOURCES
            or (s.startswith("osv-") and e in UNREVIEWED_MIRROR_ECOSYSTEMS)
        )

        for cve in cves:
            if is_lang_eco_range:
                has_package_range.add(cve)
            if is_curated_lang_eco:
                has_curated_advisory.add(cve)
            if is_distro:
                has_distro_record.add(cve)
            if is_unreviewed_mirror:
                has_unreviewed_mirror.add(cve)
            if s == "cve-project":
                has_cve_project.add(cve)
                if pkgs[i] and cve not in cve_vendor_product:
                    cve_vendor_product[cve] = pkgs[i]
            elif s == "cisa-kev":
                has_kev.add(cve)
                if sevs[i] and "Known" in sevs[i]:
                    has_kev_ransomware.add(cve)
            elif s == "epss":
                if sevs[i] and sevs[i].startswith("epss:"):
                    try:
                        _, _, pct = sevs[i].split(":", 2)
                        epss_pct[cve] = float(pct)
                    except Exception:
                        pass

    all_cves = (
        has_package_range
        | has_curated_advisory
        | has_distro_record
        | has_unreviewed_mirror
        | has_cve_project
        | has_kev
        | set(epss_pct.keys())
    )
    print(f"  unique CVEs in corpus: {len(all_cves):,}")
    print(f"  has package range: {len(has_package_range):,}")
    print(f"  has curated advisory (8-eco): {len(has_curated_advisory):,}")
    print(f"  has distro record: {len(has_distro_record):,}")
    print(f"  has unreviewed/mirror: {len(has_unreviewed_mirror):,}")
    print(f"  has cve-project record: {len(has_cve_project):,}")
    print(f"  has kev: {len(has_kev):,}")

    # ---------- Bucket each CVE (priority order: richest signal first) ----------
    def bucket(cve: str) -> str:
        if cve in has_package_range:
            return "PACKAGE_RANGE"
        if cve in has_curated_advisory:
            return "PACKAGE_ADVISORY"
        if cve in has_distro_record:
            return "DISTRO"
        if cve in has_unreviewed_mirror:
            return "UNREVIEWED_MIRROR"
        if cve in has_cve_project or cve in has_kev or cve in epss_pct:
            return "CVE_ONLY"
        return "UNCLASSIFIED"

    buckets: dict[str, set[str]] = defaultdict(set)
    for cve in all_cves:
        buckets[bucket(cve)].add(cve)

    # ---------- Cross-tab against KEV / EPSS / ransomware ----------
    def cohort(members: set[str]) -> dict:
        total = len(members)
        out: dict[str, object] = {"total_in_cohort": total}
        for b, pop in buckets.items():
            n_in = len(members & pop)
            out[b] = {
                "n": n_in,
                "share_of_cohort": round(n_in / total, 4) if total else None,
            }
        return out

    epss_p95 = {c for c, p in epss_pct.items() if p >= 0.95}
    epss_p99 = {c for c, p in epss_pct.items() if p >= 0.99}

    cohorts = {
        "all_cves": cohort(all_cves),
        "kev": cohort(has_kev),
        "kev_ransomware": cohort(has_kev_ransomware),
        "epss_p95": cohort(epss_p95),
        "epss_p99": cohort(epss_p99),
        "kev_minus_epss_p95": cohort(has_kev - epss_p95),
        "epss_p95_minus_kev": cohort(epss_p95 - has_kev),
    }

    # ---------- Top vendors in CVE_ONLY (the operational/system bucket) ----------
    cve_only_kev = buckets["CVE_ONLY"] & has_kev
    cve_only_kev_ransom = buckets["CVE_ONLY"] & has_kev_ransomware
    vendor_counter: Counter[str] = Counter()
    vendor_counter_kev: Counter[str] = Counter()
    vendor_counter_kev_ransom: Counter[str] = Counter()
    for cve in buckets["CVE_ONLY"]:
        vp = cve_vendor_product.get(cve, "")
        if vp:
            vendor = vp.split(":", 1)[0]
            vendor_counter[vendor] += 1
            if cve in cve_only_kev:
                vendor_counter_kev[vendor] += 1
            if cve in cve_only_kev_ransom:
                vendor_counter_kev_ransom[vendor] += 1

    out = {
        "bucket_definitions": {
            "PACKAGE_RANGE": "Has version-range data in one of 8 language ecosystems (the matcher can answer 'am I affected at version X' for this CVE)",
            "PACKAGE_ADVISORY": "Has a curated advisory in the 8-ecosystem space (ghsa-reviewed, pypa, rustsec, go-vulndb, osv-{8 ecos}) but no source ships a version range",
            "DISTRO": "Has a curated record only in OSV's distro buckets (Debian / Ubuntu / Alpine / RPM-based / Wolfi / Chainguard / MinimOS)",
            "UNREVIEWED_MIRROR": "Only appears in ghsa-unreviewed and/or osv-GIT/Linux/Bitnami/etc -- essentially CVE-Project passthroughs ingested without curation",
            "CVE_ONLY": "Only appears in cve-project / KEV / EPSS. No advisory feed (curated or unreviewed) ships any record. Classic appliance/firmware/browser/kernel population.",
            "UNCLASSIFIED": "Defensive bucket; should be ~0",
        },
        "bucket_sizes": {b: len(pop) for b, pop in buckets.items()},
        "bucket_shares_of_corpus": {
            b: round(len(pop) / len(all_cves), 4) for b, pop in buckets.items()
        },
        "cohort_breakdown": cohorts,
        "cve_only_top_vendors_overall": dict(vendor_counter.most_common(30)),
        "cve_only_top_vendors_in_kev": dict(vendor_counter_kev.most_common(30)),
        "cve_only_top_vendors_in_kev_ransomware": dict(
            vendor_counter_kev_ransom.most_common(30)
        ),
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print("\nBucket sizes (corpus share):")
    for b in ["PACKAGE_RANGE", "PACKAGE_ADVISORY", "DISTRO",
              "UNREVIEWED_MIRROR", "CVE_ONLY", "UNCLASSIFIED"]:
        size = len(buckets.get(b, set()))
        share = size / len(all_cves) if all_cves else 0
        print(f"  {b:>22} {size:>8,}  ({share:.2%})")
    print("\nKEV bucket distribution:")
    for b, info in cohorts["kev"].items():
        if isinstance(info, dict):
            print(f"  {b:>22} {info['n']:>5}  ({info['share_of_cohort']:.2%})")
    print("\nKEV-ransomware bucket distribution:")
    for b, info in cohorts["kev_ransomware"].items():
        if isinstance(info, dict):
            print(f"  {b:>22} {info['n']:>5}  ({info['share_of_cohort']:.2%})")
    print("\nTop 10 vendors in CVE_ONLY KEV (the operational-exploit bucket):")
    for v, c in vendor_counter_kev.most_common(10):
        print(f"  {v:>20} {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
