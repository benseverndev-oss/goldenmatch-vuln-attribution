"""Longitudinal lag analysis: how long does it take a CVE to land in each source?

For every CVE that appears anywhere in the corpus, this measures the
distance (in days) between:

    first_cve_project  -- earliest cveMetadata.datePublished from CVE Project
    first_osv_eco      -- earliest `published` in any of the 8 v1 language
                          ecosystems (PyPI/npm/Maven/Go/crates.io/RubyGems/
                          NuGet/Packagist)
    first_ghsa         -- earliest `published` in ghsa-reviewed
    first_kev          -- earliest `dateAdded` in cisa-kev

The CVE pivot is built from both the `vuln_id` column (rows where the
record's own ID is a CVE) and the `aliases` column (rows where the
record is a GHSA / PYSEC / RUSTSEC / GO advisory that lists a CVE
alias). This is the same alias-graph the cluster build uses, just
without the union-find step -- we only need the cross-source links
that a CVE is the natural join key for.

Emits `output/timing_lag.json`:

    {
      "summary": {
        "cves_with_any_record": int,
        "cves_with_cve_project_date": int,
        "pairs": {
            "cve_to_osv_eco": {median, p25, p75, p95, n},
            "cve_to_ghsa":    {...},
            "cve_to_kev":     {...},
        },
        "per_ecosystem": {<eco>: {median_days, n}, ...}
      },
      "histogram_buckets": {pair: {bucket_label: count, ...}}
    }
"""
from __future__ import annotations

import json
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "timing_lag.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

# 8 v1 target ecosystems (must match check_affected / analyze_ranges).
LANG_ECOS = {
    "PyPI", "npm", "Maven", "Go", "crates.io",
    "RubyGems", "NuGet", "Packagist",
}

# Histogram bucket edges, in days. Negative = source published BEFORE the
# CVE Project record (happens for GHSA-reviewed where the analyst predates
# CVE assignment).
BUCKET_EDGES = [-365, -30, -7, 0, 1, 7, 30, 90, 365, 1825, 10000]
BUCKET_LABELS = [
    "<= -365 (>1y early)",
    "-365 to -30",
    "-30 to -7",
    "-7 to -1",
    "0 (same day)",
    "1-7",
    "8-30",
    "31-90",
    "91-365",
    "366-1825 (1-5y late)",
    "> 1825 (>5y late)",
]


def bucket_for(days: float) -> str:
    for i, edge in enumerate(BUCKET_EDGES):
        if days < edge:
            return BUCKET_LABELS[i]
    return BUCKET_LABELS[-1]


def main() -> int:
    print(f"Loading {SRC.name} ...")
    df = pl.read_parquet(
        SRC,
        columns=["vuln_id", "aliases", "published", "source", "ecosystem"],
    )
    print(f"  rows: {df.height:,}")

    # ---------- Build (cve_id, source, ecosystem, published) long table ----------
    # Every row contributes (vuln_id, source) and one row per alias.
    # We then keep only the rows where the joined ID starts with "CVE-".
    # Doing this in polars avoids materializing 6M Python tuples.
    print("Building CVE -> source -> published long table ...")
    base = df.with_columns(pl.col("vuln_id").alias("cve_id"))
    from_vid = base.filter(pl.col("cve_id").str.starts_with("CVE-"))
    from_aliases = (
        df.filter(pl.col("aliases") != "")
        .with_columns(pl.col("aliases").str.split(";").alias("_alist"))
        .explode("_alist")
        .with_columns(pl.col("_alist").str.strip_chars().alias("cve_id"))
        .filter(pl.col("cve_id").str.starts_with("CVE-"))
        .drop("_alist")
    )
    long = pl.concat(
        [
            from_vid.select(["cve_id", "source", "ecosystem", "published"]),
            from_aliases.select(["cve_id", "source", "ecosystem", "published"]),
        ],
        how="vertical",
    )
    # Drop empty published; parse to date. Sources use a mix of ISO 8601
    # with Z (OSV/GHSA), tz-naive ISO (PyPA), and YYYY-MM-DD (KEV/EPSS),
    # which trips polars' tz inference. Day-level precision is plenty for
    # a lag analysis, so slice to the first 10 chars and parse as date.
    long = long.filter(pl.col("published") != "").with_columns(
        pl.col("published").str.slice(0, 10).str.to_date(strict=False).alias("pub_dt")
    )
    long = long.filter(pl.col("pub_dt").is_not_null())
    print(f"  long table rows: {long.height:,}")

    # ---------- Reduce to first-seen per (CVE, source-category) ----------
    is_osv_eco = (
        pl.col("source").str.starts_with("osv-")
        & pl.col("ecosystem").is_in(list(LANG_ECOS))
    )
    long = long.with_columns(
        pl.when(pl.col("source") == "cve-project")
        .then(pl.lit("cve"))
        .when(is_osv_eco)
        .then(pl.lit("osv_eco"))
        .when(pl.col("source") == "ghsa-reviewed")
        .then(pl.lit("ghsa"))
        .when(pl.col("source") == "cisa-kev")
        .then(pl.lit("kev"))
        .otherwise(pl.lit(""))
        .alias("bucket")
    ).filter(pl.col("bucket") != "")

    firsts = long.group_by(["cve_id", "bucket"]).agg(
        pl.col("pub_dt").min().alias("first")
    )
    wide = firsts.pivot(values="first", index="cve_id", on="bucket")
    # Make sure all expected columns exist even if a bucket was empty.
    for b in ("cve", "osv_eco", "ghsa", "kev"):
        if b not in wide.columns:
            wide = wide.with_columns(pl.lit(None).alias(b))
    print(f"  distinct CVEs with any record: {wide.height:,}")

    # ---------- Lag distributions ----------
    def pair_stats(left: str, right: str) -> dict:
        sub = wide.filter(pl.col(left).is_not_null() & pl.col(right).is_not_null())
        if sub.height == 0:
            return {"n": 0}
        diffs = (
            sub.select(((pl.col(right) - pl.col(left)).dt.total_days()).alias("days"))
            .to_series()
            .to_list()
        )
        diffs.sort()
        n = len(diffs)

        def q(p):
            i = max(0, min(n - 1, int(round((n - 1) * p))))
            return diffs[i]

        return {
            "n": n,
            "median_days": q(0.5),
            "p25_days": q(0.25),
            "p75_days": q(0.75),
            "p95_days": q(0.95),
            "min_days": diffs[0],
            "max_days": diffs[-1],
        }

    pairs = {
        "cve_to_osv_eco": pair_stats("cve", "osv_eco"),
        "cve_to_ghsa": pair_stats("cve", "ghsa"),
        "cve_to_kev": pair_stats("cve", "kev"),
        "ghsa_to_osv_eco": pair_stats("ghsa", "osv_eco"),
    }

    # Histograms
    histograms = {}
    for pair_name, (left, right) in [
        ("cve_to_osv_eco", ("cve", "osv_eco")),
        ("cve_to_ghsa", ("cve", "ghsa")),
        ("cve_to_kev", ("cve", "kev")),
        ("ghsa_to_osv_eco", ("ghsa", "osv_eco")),
    ]:
        sub = wide.filter(pl.col(left).is_not_null() & pl.col(right).is_not_null())
        diffs = (
            sub.select(((pl.col(right) - pl.col(left)).dt.total_days()).alias("days"))
            .to_series()
            .to_list()
        )
        bucket_counts: dict[str, int] = {lbl: 0 for lbl in BUCKET_LABELS}
        for d in diffs:
            bucket_counts[bucket_for(d)] += 1
        histograms[pair_name] = bucket_counts

    # ---------- Per-ecosystem CVE-to-osv-eco median ----------
    eco_long = long.filter(pl.col("bucket") == "osv_eco")
    eco_firsts = eco_long.group_by(["cve_id", "ecosystem"]).agg(
        pl.col("pub_dt").min().alias("first_eco")
    )
    cve_only = wide.select(["cve_id", "cve"])
    eco_join = eco_firsts.join(cve_only, on="cve_id").filter(pl.col("cve").is_not_null())
    eco_join = eco_join.with_columns(
        ((pl.col("first_eco") - pl.col("cve")).dt.total_days()).alias("days")
    )
    per_eco = {}
    for eco in sorted(LANG_ECOS):
        s = eco_join.filter(pl.col("ecosystem") == eco)["days"].to_list()
        if not s:
            continue
        s.sort()
        n = len(s)
        per_eco[eco] = {
            "n": n,
            "median_days": s[n // 2],
            "p95_days": s[max(0, min(n - 1, int(round((n - 1) * 0.95))))],
        }

    out = {
        "summary": {
            "cves_with_any_record": int(wide.height),
            "cves_with_cve_project_date": int(
                wide.filter(pl.col("cve").is_not_null()).height
            ),
            "pairs": pairs,
            "per_ecosystem": per_eco,
        },
        "histogram_buckets": histograms,
    }
    OUT.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {OUT}")
    print("Headline lags (median days, n=...):")
    for name, stats in pairs.items():
        if stats.get("n"):
            print(f"  {name:25} n={stats['n']:>7,} median={stats['median_days']:>7.1f}d  p95={stats['p95_days']:>7.1f}d")
        else:
            print(f"  {name:25} no overlap")
    print("Per-ecosystem (CVE -> first OSV ecosystem row):")
    for eco, st in per_eco.items():
        print(f"  {eco:>12} n={st['n']:>6,}  median={st['median_days']:>7.1f}d  p95={st['p95_days']:>7.1f}d")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
