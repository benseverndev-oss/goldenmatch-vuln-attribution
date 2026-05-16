"""Answer "is my installed version actually affected?" for a given SBOM.

Reads the reconciled `data/records_normalized.parquet`, takes a list of
PURLs (either as a flat text file or extracted from a CycloneDX SBOM), and
emits a per-component verdict for every matching advisory:

    AFFECTED       installed version falls inside the advisory's range
    NOT_AFFECTED   installed version is outside every range
    UNKNOWN        range is type=GIT, the version string is unparseable,
                   or no range was published for that (vuln_id, package)
                   pair in any source we ingested

Only the 8 v1 target ecosystems are supported (PyPI, npm, Maven, Go,
crates.io, RubyGems, NuGet, Packagist). Components from other ecosystems
are surfaced in the report under `skipped_components` so users see they
were excluded by design, not silently lost.

Usage:
    python check_affected.py --purls examples/sample_purls.txt
    python check_affected.py --sbom examples/sample_sbom.json
    python check_affected.py --sbom path.json --out output/my_report.json
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import polars as pl
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

ROOT = Path(__file__).resolve().parent
DEFAULT_PARQUET = ROOT / "data" / "records_normalized.parquet"
DEFAULT_OUT = ROOT / "output" / "affected_report.json"

# PURL type -> (OSV ecosystem string used in the parquet, univers scheme).
# These are the 8 v1 target ecosystems. Anything outside this map is
# reported as `skipped_components` so users know it was out of scope.
PURL_TO_ECO_SCHEME = {
    "pypi": ("PyPI", "pypi"),
    "npm": ("npm", "npm"),
    "maven": ("Maven", "maven"),
    "golang": ("Go", "golang"),
    "cargo": ("crates.io", "cargo"),
    "gem": ("RubyGems", "gem"),
    "nuget": ("NuGet", "nuget"),
    "composer": ("Packagist", "composer"),
}


def purl_lookup_key(purl_str: str) -> tuple[str, str, str, str] | None:
    """(osv_ecosystem, package_name, version, univers_scheme) or None.

    Parquet's `package` column stores the OSV-canonical name: groupId:artifactId
    for Maven, vendor/package for Composer, full module path for Go, @scope/name
    for npm. We reassemble the same shape from the parsed PURL so the join works.
    """
    try:
        p = PackageURL.from_string(purl_str)
    except Exception:
        return None
    eco_scheme = PURL_TO_ECO_SCHEME.get(p.type)
    if eco_scheme is None:
        return None
    eco, scheme = eco_scheme
    if not p.version:
        return None
    name = p.name
    if p.type == "maven" and p.namespace:
        name = f"{p.namespace}:{p.name}"
    elif p.type == "composer" and p.namespace:
        name = f"{p.namespace}/{p.name}"
    elif p.type == "npm" and p.namespace:
        name = f"{p.namespace}/{p.name}"
    elif p.type == "golang":
        # Go modules use the full import path as the package name. PURL may
        # carry it in namespace or split it; rejoin defensively.
        name = f"{p.namespace}/{p.name}" if p.namespace else p.name
    return eco, name, p.version, scheme


def osv_range_verdict(rng: dict, installed_version: str, scheme: str) -> tuple[str, str]:
    """Return (verdict, reason) for one OSV range against an installed version.

    Verdict is "AFFECTED", "NOT_AFFECTED", or "UNKNOWN". `reason` is a short
    human-readable string for the report (e.g. ">=1.0,<2.0 contains 1.5").
    """
    rng_type = rng.get("type", "")
    if rng_type == "GIT":
        return "UNKNOWN", "GIT range (commit-based, not version-comparable)"
    if rng_type not in ("SEMVER", "ECOSYSTEM"):
        return "UNKNOWN", f"unsupported range type: {rng_type or '(missing)'}"

    cls = RANGE_CLASS_BY_SCHEMES.get(scheme)
    if cls is None:
        return "UNKNOWN", f"no univers scheme for {scheme}"
    vcls = cls.version_class

    # Parse installed version once. If it fails, every interval is UNKNOWN.
    try:
        installed = vcls(installed_version)
    except Exception as e:
        return "UNKNOWN", f"cannot parse installed version {installed_version!r}: {e}"

    events = rng.get("events") or []
    # OSV semantics: walk events in order, pair `introduced` with the next
    # `fixed` / `last_affected` to form one interval. A trailing `introduced`
    # with no terminator means "from there on, no known fix".
    intervals: list[tuple[object | None, str | None, object | None]] = []
    pending_intro: object | None = None
    pending_intro_str: str = ""
    try:
        for ev in events:
            if "introduced" in ev:
                raw = ev["introduced"]
                pending_intro = None if raw == "0" else vcls(raw)
                pending_intro_str = "" if raw == "0" else str(raw)
            elif "fixed" in ev:
                term = vcls(ev["fixed"])
                intervals.append((pending_intro, "<", term))
                pending_intro = None
                pending_intro_str = ""
            elif "last_affected" in ev:
                term = vcls(ev["last_affected"])
                intervals.append((pending_intro, "<=", term))
                pending_intro = None
                pending_intro_str = ""
            # `limit` events deliberately ignored (rarely meaningful for matching).
        if pending_intro is not None or pending_intro_str:
            intervals.append((pending_intro, None, None))
    except Exception as e:
        return "UNKNOWN", f"cannot parse range events: {e}"

    if not intervals:
        return "UNKNOWN", "no intervals in range"

    # Affected if installed sits inside ANY interval.
    for intro, term_op, term in intervals:
        if intro is not None and not (installed >= intro):
            continue
        if term is not None:
            if term_op == "<" and not (installed < term):
                continue
            if term_op == "<=" and not (installed <= term):
                continue
        intro_s = str(intro) if intro is not None else "0"
        term_s = f"{term_op}{term}" if term is not None else "(no fix)"
        return "AFFECTED", f">={intro_s},{term_s} contains {installed_version}"

    return "NOT_AFFECTED", f"{installed_version} outside all intervals"


def aggregate_verdict(verdicts: Iterable[str]) -> str:
    """AFFECTED beats UNKNOWN beats NOT_AFFECTED."""
    seen = set(verdicts)
    if "AFFECTED" in seen:
        return "AFFECTED"
    if "UNKNOWN" in seen:
        return "UNKNOWN"
    return "NOT_AFFECTED"


def load_purls_from_text(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def load_purls_from_cyclonedx(path: Path) -> list[str]:
    sbom = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for comp in sbom.get("components", []) or []:
        purl = comp.get("purl")
        if purl:
            out.append(purl)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--purls", type=Path, help="text file: one PURL per line")
    ap.add_argument("--sbom", type=Path, help="CycloneDX JSON SBOM")
    ap.add_argument("--parquet", type=Path, default=DEFAULT_PARQUET)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    if not args.purls and not args.sbom:
        ap.error("provide --purls or --sbom")
    if not args.parquet.exists():
        ap.error(f"parquet not found: {args.parquet} (run extract_records.py first)")

    purls: list[str] = []
    if args.purls:
        purls.extend(load_purls_from_text(args.purls))
    if args.sbom:
        purls.extend(load_purls_from_cyclonedx(args.sbom))
    print(f"Input PURLs: {len(purls)}")

    # Resolve each PURL to a parquet lookup key. Components outside the v1
    # ecosystem scope are tracked separately so the report is honest.
    parsed: list[tuple[str, str, str, str, str]] = []  # purl, eco, pkg, ver, scheme
    skipped: list[dict] = []
    for purl in purls:
        key = purl_lookup_key(purl)
        if key is None:
            skipped.append({"purl": purl, "reason": "out-of-scope ecosystem or unparseable PURL"})
            continue
        eco, pkg, ver, scheme = key
        parsed.append((purl, eco, pkg, ver, scheme))
    if not parsed:
        print("No in-scope PURLs to check.")
    else:
        print(f"In-scope: {len(parsed)}  Skipped: {len(skipped)}")

    # Load only the columns we need, filter to range-bearing rows.
    print(f"Loading {args.parquet.name} ...")
    df = pl.read_parquet(
        args.parquet,
        columns=["vuln_id", "aliases", "ecosystem", "package", "severity", "source", "ranges"],
    )
    df = df.filter(pl.col("ranges") != "")
    print(f"  range-bearing rows: {df.height:,}")

    # Build an (ecosystem, package) -> list-of-row-indices index for cheap lookups.
    # At ~1M range-bearing rows this fits comfortably in RAM.
    index: dict[tuple[str, str], list[int]] = defaultdict(list)
    ecos = df["ecosystem"].to_list()
    pkgs = df["package"].to_list()
    for i, (e, p) in enumerate(zip(ecos, pkgs)):
        index[(e, p)].append(i)

    vids = df["vuln_id"].to_list()
    aliases_col = df["aliases"].to_list()
    severity_col = df["severity"].to_list()
    source_col = df["source"].to_list()
    ranges_col = df["ranges"].to_list()

    results = []
    summary = {"AFFECTED": 0, "NOT_AFFECTED": 0, "UNKNOWN": 0, "NO_DATA": 0}

    for purl, eco, pkg, ver, scheme in parsed:
        row_idxs = index.get((eco, pkg), [])
        # Per-vuln aggregation: a single advisory may produce multiple rows
        # (npm scoped pkg in OSV + GHSA both ship ranges) -> deduplicate by
        # vuln_id and combine verdicts most-conservatively.
        by_vuln: dict[str, dict] = {}
        for i in row_idxs:
            raw = ranges_col[i]
            try:
                ranges = json.loads(raw)
            except Exception:
                continue
            vid = vids[i]
            for rng in ranges:
                verdict, reason = osv_range_verdict(rng, ver, scheme)
                entry = by_vuln.setdefault(
                    vid,
                    {
                        "vuln_id": vid,
                        "aliases": aliases_col[i],
                        "severity": severity_col[i],
                        "sources": set(),
                        "verdicts": [],
                        "reasons": [],
                    },
                )
                entry["sources"].add(source_col[i])
                entry["verdicts"].append(verdict)
                entry["reasons"].append(f"[{source_col[i]}] {reason}")

        vulns = []
        for vid, e in by_vuln.items():
            v = aggregate_verdict(e["verdicts"])
            vulns.append({
                "vuln_id": vid,
                "aliases": e["aliases"],
                "severity": e["severity"],
                "sources": sorted(e["sources"]),
                "verdict": v,
                "evidence": e["reasons"][:5],  # cap evidence to keep report readable
            })
        vulns.sort(key=lambda r: (r["verdict"] != "AFFECTED", r["verdict"] != "UNKNOWN", r["vuln_id"]))

        component_verdict = aggregate_verdict(v["verdict"] for v in vulns) if vulns else "NO_DATA"
        summary[component_verdict] = summary.get(component_verdict, 0) + 1

        results.append({
            "purl": purl,
            "ecosystem": eco,
            "package": pkg,
            "version": ver,
            "verdict": component_verdict,
            "vuln_count": len(vulns),
            "vulns": vulns,
        })

    report = {
        "input_purls": len(purls),
        "in_scope_components": len(parsed),
        "skipped_components": skipped,
        "component_summary": summary,
        "components": results,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {args.out}")
    print("Component verdict summary:")
    for k, v in summary.items():
        print(f"  {k:>14}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
