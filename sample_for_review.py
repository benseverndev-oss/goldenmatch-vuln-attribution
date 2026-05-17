"""Emit CSV worksheets for manual qualitative validation.

Pulls random CVE samples from each of the structural buckets so a human
reviewer can label representability_type / scanner_modality / notes
without doing any joins themselves. Output goes to `output/review/`,
one CSV per worksheet. The reviewer fills in the empty columns; the
filled CSVs are then the ground-truth dataset against which the
quantitative findings can be validated.

Worksheets emitted (default n=100 each, --n to override):

    kev_blind_spots.csv          KEV CVEs that are NOT package-representable
    kev_representable.csv        KEV CVEs that ARE package-representable
                                 (baseline / control for comparison)
    independent_contradictions.csv  (CVE, package) cases where ghsa-reviewed
                                 and pypa publish disjoint fix-version sets
    unreviewed_mirror.csv        random sample from the dominant bucket
    cve_only.csv                 random sample of CVEs absent from every
                                 advisory feed (curated or mirror)
    orphan_single_source.csv     CVEs that appear in exactly one source

Each row is pre-filled with:
    cve_id, bucket, kev, kev_ransomware, epss_percentile,
    sources (semicolon-joined), vendor_product, description (first 300
    chars from cvelistV5.zip), top_aliases

Empty columns the reviewer fills:
    manual_label                 free-text bucket assertion
    representability_type        PACKAGE / BINARY / RUNTIME_CONFIG /
                                 SERVICE / APPLIANCE / CLOUD / OTHER
    scanner_modality             SBOM / HOST / NETWORK / RUNTIME / CSPM
    notes                        free-text

Random sampling uses a fixed seed (default 0) so two runs from the
same parquet produce identical worksheets -- avoids spurious git
churn when re-generating.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import zipfile
from collections import defaultdict
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records_normalized.parquet"
CVELIST_ZIP = ROOT / "data" / "public" / "cvelistV5.zip"
INDEPENDENCE_JSON = ROOT / "output" / "independence.json"
OUT_DIR = ROOT / "output" / "review"

LANG_ECOSYSTEMS = {
    "PyPI", "npm", "Maven", "Go", "crates.io",
    "RubyGems", "NuGet", "Packagist",
}
DISTRO_ECOSYSTEMS = {
    "Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "Mageia",
    "openSUSE", "SUSE", "Photon OS", "Red Hat", "Wolfi", "Chainguard",
    "MinimOS",
}
UNREVIEWED_MIRROR_ECOSYSTEMS = {"GIT", "Linux", "OSS-Fuzz", "Bitnami", "UVI",
                               "GitHub Actions", "Kubernetes", "Android",
                               "Curl", "Hex", "Pub", "Hackage", "CRAN",
                               "Bioconductor", "GHC", "SwiftURL"}
CURATED_ADVISORY_SOURCES = {"ghsa-reviewed", "pypa", "rustsec", "go-vulndb"}
UNREVIEWED_MIRROR_SOURCES = {"ghsa-unreviewed"}

REVIEW_COLUMNS = [
    "cve_id", "bucket", "kev", "kev_ransomware", "epss_percentile",
    "sources", "vendor_product", "description", "top_aliases",
    # blank columns for the reviewer
    "manual_label", "representability_type", "scanner_modality", "notes",
]

# Closed enums per docs/annotation-protocol.md. Update both places together.
REPRESENTABILITY_TYPES = (
    "PACKAGE", "BINARY", "RUNTIME_CONFIG", "SERVICE", "APPLIANCE",
    "CLOUD", "OTHER",
)
SCANNER_MODALITIES = (
    "SBOM", "HOST", "NETWORK", "RUNTIME", "CSPM", "NONE",
)
CATEGORY_CHEATSHEET = f"""# Annotation cheat sheet

Full rules: `docs/annotation-protocol.md`. This file is the spreadsheet-side
quick reference -- keep open next to your CSV.

## representability_type (pick one)

  PACKAGE         vuln in a language-ecosystem package (PyPI/npm/Maven/...)
  BINARY          vuln in an installed binary / distro package / OS binary
  RUNTIME_CONFIG  exists only when a specific runtime config is in place
  SERVICE         daemon vuln where network exposure is part of exploitability
  APPLIANCE       vendor appliance (Cisco / Fortinet / F5 / VMware / etc.)
  CLOUD           cloud-account / managed-service misconfiguration
  OTHER           none of the above (explain in `notes`)

If two fit, pick the one EARLIEST in this list.

## scanner_modality (pick one)

  SBOM     OSV-Scanner / Trivy / Grype / Dependabot
  HOST     host scanner / Lynis / CIS / Tenable host plug-ins
  NETWORK  nmap / Nessus / OpenVAS / Greenbone
  RUNTIME  Falco / runtime EDR / container-runtime scanner
  CSPM     Wiz / Prisma / AWS Config / Azure Defender
  NONE     no scanner class can decide it

## common pairings

  PACKAGE        -> SBOM
  BINARY         -> HOST
  RUNTIME_CONFIG -> RUNTIME (or HOST for static configs)
  SERVICE        -> NETWORK
  APPLIANCE      -> NETWORK (or out-of-band asset inventory)
  CLOUD          -> CSPM
  OTHER          -> usually NONE

Allowed values are also encoded as the first data row of every CSV
(the row starting with `_VALID_VALUES:`). Treat that row as a header
extension, not as data.
"""


def cves_in(s: str) -> list[str]:
    out = []
    for tok in s.split(";"):
        tok = tok.strip()
        if tok.startswith("CVE-"):
            out.append(tok)
    return out


def build_cve_description_index() -> tuple[zipfile.ZipFile | None, dict[str, str]]:
    """Build CVE-ID -> zip-internal-path lookup so we can lazy-fetch descriptions."""
    if not CVELIST_ZIP.exists():
        print(f"  WARN: {CVELIST_ZIP} not present; descriptions will be blank")
        return None, {}
    zf = zipfile.ZipFile(CVELIST_ZIP)
    idx: dict[str, str] = {}
    for n in zf.namelist():
        if "/cves/" in n and n.endswith(".json") and "/delta_" not in n:
            stem = Path(n).stem  # CVE-YYYY-NNNNN
            idx[stem] = n
    print(f"  built CVE -> cvelistV5 path index: {len(idx):,} entries")
    return zf, idx


def fetch_description(
    zf: zipfile.ZipFile | None, idx: dict[str, str], cve_id: str
) -> str:
    if zf is None:
        return ""
    path = idx.get(cve_id)
    if path is None:
        return ""
    try:
        with zf.open(path) as f:
            d = json.load(f)
    except Exception:
        return ""
    cna = (d.get("containers") or {}).get("cna") or {}
    descs = cna.get("descriptions") or []
    for desc in descs:
        if isinstance(desc, dict) and desc.get("lang", "en").startswith("en"):
            text = (desc.get("value") or "").strip()
            return text[:300]
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--n", type=int, default=100, help="rows per worksheet (default 100)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading {SRC.name} ...")
    df = pl.read_parquet(
        SRC,
        columns=["vuln_id", "aliases", "source", "ecosystem", "package", "severity", "ranges"],
    )
    print(f"  rows: {df.height:,}")

    # ---------- Build per-CVE indexes in one pass ----------
    cve_sources: dict[str, set[str]] = defaultdict(set)
    cve_aliases: dict[str, set[str]] = defaultdict(set)
    cve_vendor_product: dict[str, str] = {}
    has_package_range: set[str] = set()
    has_curated_advisory: set[str] = set()
    has_distro_record: set[str] = set()
    has_unreviewed_mirror: set[str] = set()
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
    n = len(vids)

    for i in range(n):
        s = srcs[i]
        e = ecos[i]
        has_range = bool(rngs[i])
        is_lang_eco_range = has_range and e in LANG_ECOSYSTEMS
        is_distro = s.startswith("osv-") and e in DISTRO_ECOSYSTEMS
        is_curated_lang_eco = (
            (s in CURATED_ADVISORY_SOURCES)
            or (s.startswith("osv-") and e in LANG_ECOSYSTEMS)
        )
        is_unreviewed_mirror = (
            s in UNREVIEWED_MIRROR_SOURCES
            or (s.startswith("osv-") and e in UNREVIEWED_MIRROR_ECOSYSTEMS)
        )

        cves: set[str] = set()
        if vids[i].startswith("CVE-"):
            cves.add(vids[i])
        if als[i]:
            for c in cves_in(als[i]):
                cves.add(c)
        if not cves:
            continue
        # Capture every non-CVE alias too (GHSA-/PYSEC-/etc) for top_aliases.
        non_cve_aliases: set[str] = set()
        if als[i]:
            for tok in als[i].split(";"):
                tok = tok.strip()
                if tok and not tok.startswith("CVE-"):
                    non_cve_aliases.add(tok)
        if vids[i] and not vids[i].startswith("CVE-"):
            non_cve_aliases.add(vids[i])

        for cve in cves:
            cve_sources[cve].add(s)
            cve_aliases[cve].update(non_cve_aliases)
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
                        _, _, p = sevs[i].split(":", 2)
                        epss_pct[cve] = float(p)
                    except Exception:
                        pass

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

    # CVE description index from cvelistV5.zip
    zf, cve_path_idx = build_cve_description_index()

    def row_for(cve: str, bucket_override: str | None = None) -> dict:
        return {
            "cve_id": cve,
            "bucket": bucket_override or bucket(cve),
            "kev": "Y" if cve in has_kev else "N",
            "kev_ransomware": "Y" if cve in has_kev_ransomware else "N",
            "epss_percentile": (
                f"{epss_pct[cve]:.4f}" if cve in epss_pct else ""
            ),
            "sources": ";".join(sorted(cve_sources.get(cve, set()))),
            "vendor_product": cve_vendor_product.get(cve, ""),
            "description": fetch_description(zf, cve_path_idx, cve),
            "top_aliases": ";".join(sorted(cve_aliases.get(cve, set()))[:5]),
            "manual_label": "",
            "representability_type": "",
            "scanner_modality": "",
            "notes": "",
        }

    hint_row = {
        "cve_id": "_VALID_VALUES:",
        "bucket": "(skip this row; treat as header extension)",
        "kev": "Y or N",
        "kev_ransomware": "Y or N",
        "epss_percentile": "0.0000-1.0000",
        "sources": "(pre-filled)",
        "vendor_product": "(pre-filled)",
        "description": "(pre-filled)",
        "top_aliases": "(pre-filled)",
        "manual_label": "(free text)",
        "representability_type": " | ".join(REPRESENTABILITY_TYPES),
        "scanner_modality": " | ".join(SCANNER_MODALITIES),
        "notes": "(free text)",
    }

    def write_worksheet(path: Path, rows: list[dict]) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=REVIEW_COLUMNS)
            w.writeheader()
            w.writerow(hint_row)
            for r in rows:
                w.writerow(r)
        print(f"  wrote {path.relative_to(ROOT)}  ({len(rows)} rows)")

    # ---------- Sample each cohort ----------
    def sample(pop: set[str]) -> list[str]:
        pop_list = sorted(pop)
        if len(pop_list) <= args.n:
            return pop_list
        return rng.sample(pop_list, args.n)

    print(f"\nGenerating worksheets (n={args.n}, seed={args.seed}) ...")

    # 1. KEV blind spots (KEV ∩ not PACKAGE_RANGE)
    write_worksheet(
        OUT_DIR / "kev_blind_spots.csv",
        [row_for(c) for c in sample(has_kev - has_package_range)],
    )

    # 2. KEV representable (baseline)
    write_worksheet(
        OUT_DIR / "kev_representable.csv",
        [row_for(c) for c in sample(has_kev & has_package_range)],
    )

    # 3. UNREVIEWED_MIRROR (the dominant bucket)
    unreviewed = {c for c in (has_unreviewed_mirror) if bucket(c) == "UNREVIEWED_MIRROR"}
    write_worksheet(
        OUT_DIR / "unreviewed_mirror.csv",
        [row_for(c) for c in sample(unreviewed)],
    )

    # 4. CVE_ONLY (no advisory feed at all)
    cve_only = {c for c in (has_cve_project | has_kev | set(epss_pct)) if bucket(c) == "CVE_ONLY"}
    write_worksheet(
        OUT_DIR / "cve_only.csv",
        [row_for(c) for c in sample(cve_only)],
    )

    # 5. Orphan: only one source mentions it
    orphans = {c for c, ss in cve_sources.items() if len(ss) == 1}
    write_worksheet(
        OUT_DIR / "orphan_single_source.csv",
        [row_for(c) for c in sample(orphans)],
    )

    # 6. Independent-pair contradictions from independence.json
    if INDEPENDENCE_JSON.exists():
        ind = json.loads(INDEPENDENCE_JSON.read_text(encoding="utf-8"))
        examples = (
            ind.get("independent_pairs", {})
            .get("ghsa-reviewed_vs_pypa", {})
            .get("examples_disagreement", [])
        )
        # Filter to the harder "contradiction" sub-class.
        examples = [e for e in examples if e.get("sub_class") == "contradiction"]
        contradictions: list[dict] = []
        for e in examples[: args.n]:
            cve = e.get("cve_id", "")
            base = row_for(cve, bucket_override="INDEP_CONTRADICTION")
            base["notes"] = (
                f"package={e.get('package','')} "
                f"ghsa-reviewed-fixes={e.get('ghsa-reviewed','')} "
                f"pypa-fixes={e.get('pypa','')}"
            )
            contradictions.append(base)
        write_worksheet(OUT_DIR / "independent_contradictions.csv", contradictions)
    else:
        print(f"  (skipping independent_contradictions.csv -- {INDEPENDENCE_JSON.name} missing)")

    if zf is not None:
        zf.close()

    cheatsheet_path = OUT_DIR / "_categories.md"
    cheatsheet_path.write_text(CATEGORY_CHEATSHEET, encoding="utf-8")
    print(f"  wrote {cheatsheet_path.relative_to(ROOT)}")

    print(f"\nDone. CSVs in {OUT_DIR.relative_to(ROOT)}.")
    print("Reviewer fills: manual_label, representability_type, scanner_modality, notes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
