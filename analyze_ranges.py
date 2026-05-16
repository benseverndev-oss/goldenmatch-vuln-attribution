"""Cross-source disagreement on `fixed` versions for the same advisory.

For every (vuln_id, ecosystem, package) the parquet ships ranges for, check
whether two or more sources publish different `fixed` events. When OSV-PyPI
says CVE-X is fixed in 2.4.1 and ghsa-reviewed says it's fixed in 2.4.2,
operators don't know which version actually closes the bug.

This is the version-range analog of the existing alias-disagreement
finding. Reads `data/records_normalized.parquet` only -- no cluster build
required, so it runs in <1 GB even on a laptop where analyze.py OOMs.

Writes `output/range_disagreement.json` (top 500 by EPSS / fix-count) plus
a `range_disagreement_summary` block.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
OUT = ROOT / "output" / "range_disagreement.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


def main() -> int:
    print(f"Loading {SRC.name} (ranges only) ...")
    df = pl.read_parquet(
        SRC, columns=["vuln_id", "ecosystem", "package", "source", "ranges"]
    )
    df = df.filter(pl.col("ranges") != "")
    print(f"  range-bearing rows: {df.height:,}")

    # (vuln_id, ecosystem, package) -> {source -> set(fixed_version)}
    # Materialize columns once instead of iter_rows -- polars row iteration
    # via Python is ~10x slower than indexed list access at this scale.
    vids = df["vuln_id"].to_list()
    ecos = df["ecosystem"].to_list()
    pkgs = df["package"].to_list()
    srcs = df["source"].to_list()
    rngs = df["ranges"].to_list()
    fixed: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    json_loads = json.loads  # local alias is measurably faster in hot loop
    for i in range(len(vids)):
        try:
            ranges = json_loads(rngs[i])
        except Exception:
            continue
        bucket: set[str] | None = None
        for rng in ranges:
            if rng.get("type") == "GIT":
                continue
            for ev in rng.get("events") or []:
                fx = ev.get("fixed")
                if fx:
                    if bucket is None:
                        bucket = fixed[(vids[i], ecos[i], pkgs[i])][srcs[i]]
                    bucket.add(str(fx))

    print(f"  groups with at least one fixed event: {len(fixed):,}")

    # True disagreement = at least one source has a fix-set different from
    # another source. Sources reporting identical fix-sets across many
    # backport branches (e.g. npm + ghsa-reviewed both listing 92 patched
    # minor versions of @solana/web3.js) is agreement, not disagreement.
    disagreements = []
    for (vid, eco, pkg), by_src in fixed.items():
        if len(by_src) < 2:
            continue
        source_fix_sets = list(by_src.values())
        first = source_fix_sets[0]
        if all(s == first for s in source_fix_sets[1:]):
            continue
        all_fixes: set[str] = set()
        for fxs in source_fix_sets:
            all_fixes.update(fxs)
        only_in_one = set()
        for src, fxs in by_src.items():
            other = set()
            for other_src, other_fxs in by_src.items():
                if other_src != src:
                    other |= other_fxs
            only_in_one |= (fxs - other)
        disagreements.append(
            {
                "vuln_id": vid,
                "ecosystem": eco,
                "package": pkg,
                "fixes_by_source": {s: sorted(v) for s, v in by_src.items()},
                "fixes_only_in_one_source": sorted(only_in_one),
                "distinct_fix_versions": sorted(all_fixes),
                "n_sources": len(by_src),
                "n_distinct_fixes": len(all_fixes),
                "n_fixes_only_in_one_source": len(only_in_one),
            }
        )

    disagreements.sort(
        key=lambda d: (
            -d["n_fixes_only_in_one_source"],
            -d["n_sources"],
            d["vuln_id"],
        )
    )

    summary = {
        "total_groups_checked": len(fixed),
        "multi_source_groups": sum(1 for v in fixed.values() if len(v) >= 2),
        "disagreement_groups": len(disagreements),
        "per_ecosystem": {},
    }
    per_eco: dict[str, int] = defaultdict(int)
    for d in disagreements:
        per_eco[d["ecosystem"]] += 1
    summary["per_ecosystem"] = dict(
        sorted(per_eco.items(), key=lambda kv: -kv[1])
    )

    OUT.write_text(
        json.dumps(
            {"summary": summary, "disagreements": disagreements[:500]},
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    print(f"\nWrote {OUT}")
    print(f"  total disagreements: {summary['disagreement_groups']:,}")
    print(f"  by ecosystem: {summary['per_ecosystem']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
