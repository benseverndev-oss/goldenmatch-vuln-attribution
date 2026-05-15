"""Extract every vulnerability record into a single parquet.

Reads in place from zip archives (no extraction to disk). Projects every
source to a common row schema:

    vuln_id    : primary identifier (GHSA-/CVE-/PYSEC-/RUSTSEC-/GO-/MAL-...)
    aliases    : semicolon-joined cross-database aliases
    ecosystem  : PyPI / npm / Maven / ... / "" for cross-ecosystem records
    package    : package name
    purl       : Package URL if available (pkg:pypi/requests)
    published  : ISO timestamp (may be empty)
    modified   : ISO timestamp (may be empty)
    severity   : free-text severity (CVSS string or level name)
    source     : osv-PyPI / ghsa-reviewed / ghsa-unreviewed / pypa / rustsec / go-vulndb / epss / cisa-kev / cve-project

One row per (vuln_id, affected_package) pair -- i.e., a single advisory that
affects three packages emits three rows with the same vuln_id. This matches
how downstream ER pipelines want to reason about it.
"""
from __future__ import annotations
import csv
import gzip
import io
import json
import re
import zipfile
from pathlib import Path

import polars as pl

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parent
PUB = ROOT / "data" / "public"
OUT = ROOT / "data" / "records.parquet"

COLS: dict[str, list[str]] = {
    "vuln_id": [], "aliases": [], "ecosystem": [], "package": [],
    "purl": [], "published": [], "modified": [], "severity": [], "source": [],
}


def emit(*, vuln_id: str, aliases: list[str], ecosystem: str, package: str,
         purl: str, published: str, modified: str, severity: str, source: str) -> None:
    COLS["vuln_id"].append(vuln_id or "")
    COLS["aliases"].append(";".join(a for a in (aliases or []) if a))
    COLS["ecosystem"].append(ecosystem or "")
    COLS["package"].append(package or "")
    COLS["purl"].append(purl or "")
    COLS["published"].append(str(published) if published else "")
    COLS["modified"].append(str(modified) if modified else "")
    COLS["severity"].append(str(severity) if severity else "")
    COLS["source"].append(source)


def severity_text(d: dict) -> str:
    sev = d.get("severity") or []
    if isinstance(sev, list) and sev:
        s = sev[0]
        if isinstance(s, dict):
            return f"{s.get('type','')}:{s.get('score','')}"
    if isinstance(sev, str):
        return sev
    db = d.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"])
    return ""


def emit_osv_record(d: dict, source: str) -> None:
    vid = d.get("id") or ""
    aliases = d.get("aliases") or []
    published = d.get("published") or ""
    modified = d.get("modified") or ""
    sev = severity_text(d)
    affected = d.get("affected") or []
    if not affected:
        emit(vuln_id=vid, aliases=aliases, ecosystem="", package="",
             purl="", published=published, modified=modified,
             severity=sev, source=source)
        return
    for aff in affected:
        pkg = aff.get("package") or {}
        eco = pkg.get("ecosystem") or ""
        name = pkg.get("name") or ""
        purl = pkg.get("purl") or ""
        emit(vuln_id=vid, aliases=aliases, ecosystem=eco, package=name,
             purl=purl, published=published, modified=modified,
             severity=sev, source=source)


# ---------- 1. OSV bulk exports ----------
OSV_ECOSYSTEMS = [
    # Language / package ecosystems
    "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io",
    "Packagist", "NuGet", "Hex", "Pub", "Hackage", "CRAN",
    "Bioconductor", "GHC", "SwiftURL",
    # OS / distro
    "Debian", "Alpine", "Ubuntu", "Rocky Linux", "AlmaLinux",
    "Mageia", "openSUSE", "SUSE", "Photon OS", "Red Hat",
    "Wolfi", "Chainguard", "MinimOS",
    # Cross-cutting
    "Linux", "OSS-Fuzz", "Bitnami", "GIT", "Curl", "UVI",
    "GitHub Actions", "Kubernetes", "Android",
]
print("[1] OSV bulk exports")
for eco in OSV_ECOSYSTEMS:
    fname = eco.replace(".", "_").replace(" ", "_") + ".zip"
    zp = PUB / "osv" / fname
    if not zp.exists():
        # Optional ecosystems may have 404'd at fetch time
        continue
    src = f"osv-{eco}"
    n = 0
    with zipfile.ZipFile(zp) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            with zf.open(info) as f:
                try:
                    d = json.load(f)
                except Exception:
                    continue
            emit_osv_record(d, src)
            n += 1
    print(f"  {eco:>16}: {n:>7,}")

# ---------- 2. GHSA (split reviewed / unreviewed) ----------
print("[2] GHSA")
with zipfile.ZipFile(PUB / "ghsa.zip") as zf:
    n_rev = 0
    n_unrev = 0
    for info in zf.infolist():
        if not info.filename.endswith(".json"):
            continue
        if "/advisories/github-reviewed/" in info.filename:
            source = "ghsa-reviewed"
            n_rev += 1
        elif "/advisories/unreviewed/" in info.filename:
            source = "ghsa-unreviewed"
            n_unrev += 1
        else:
            continue
        with zf.open(info) as f:
            try:
                d = json.load(f)
            except Exception:
                continue
        emit_osv_record(d, source)
print(f"  reviewed:   {n_rev:>7,}")
print(f"  unreviewed: {n_unrev:>7,}")

# ---------- 3. PyPA advisory-database (YAML, OSV schema) ----------
print("[3] PyPA")
n = 0
if yaml is not None:
    with zipfile.ZipFile(PUB / "pypa.zip") as zf:
        for info in zf.infolist():
            if "/vulns/" not in info.filename or not info.filename.endswith(".yaml"):
                continue
            with zf.open(info) as f:
                try:
                    d = yaml.safe_load(f)
                except Exception:
                    continue
            if isinstance(d, dict):
                emit_osv_record(d, "pypa")
                n += 1
print(f"  records:    {n:>7,}")

# ---------- 4. RustSec (Markdown with TOML frontmatter) ----------
print("[4] RustSec")
n = 0
# Format: '```toml\n{toml-block}\n```' at top of markdown, or '+++' delimiters
with zipfile.ZipFile(PUB / "rustsec.zip") as zf:
    for info in zf.infolist():
        if "/crates/" not in info.filename or not info.filename.endswith(".md"):
            continue
        with zf.open(info) as f:
            try:
                text = f.read().decode("utf-8", errors="replace")
            except Exception:
                continue
        # Extract ```toml block
        m = re.search(r"```toml\n(.*?)```", text, re.DOTALL)
        if not m:
            continue
        block = m.group(1)
        # Minimal TOML field extraction (don't import a toml parser)
        def field(name: str) -> str:
            mm = re.search(rf'^{name}\s*=\s*"([^"]*)"', block, re.MULTILINE)
            return mm.group(1) if mm else ""
        vid = field("id")
        pkg = field("package")
        date = field("date")
        aliases_raw = re.search(r"aliases\s*=\s*\[([^\]]*)\]", block)
        aliases = []
        if aliases_raw:
            aliases = [a.strip().strip('"') for a in aliases_raw.group(1).split(",") if a.strip()]
        emit(
            vuln_id=vid,
            aliases=aliases,
            ecosystem="crates.io",
            package=pkg,
            purl=f"pkg:cargo/{pkg}" if pkg else "",
            published=date,
            modified=date,
            severity="",
            source="rustsec",
        )
        n += 1
print(f"  records:    {n:>7,}")

# ---------- 5. Go vulndb (YAML, Go schema) ----------
print("[5] Go vulndb")
n = 0
if yaml is not None:
    with zipfile.ZipFile(PUB / "go-vulndb.zip") as zf:
        for info in zf.infolist():
            if "/data/reports/" not in info.filename or not info.filename.endswith(".yaml"):
                continue
            with zf.open(info) as f:
                try:
                    d = yaml.safe_load(f)
                except Exception:
                    continue
            if not isinstance(d, dict):
                continue
            vid = d.get("id") or ""
            aliases = []
            cves = d.get("cves") or []
            ghsas = d.get("ghsas") or []
            aliases = list(cves) + list(ghsas)
            published = str(d.get("published") or "")
            modified = str(d.get("modified") or "")
            mods = d.get("modules") or []
            if not mods:
                emit(vuln_id=vid, aliases=aliases, ecosystem="Go", package="",
                     purl="", published=published, modified=modified,
                     severity="", source="go-vulndb")
                n += 1
                continue
            for m in mods:
                mod_path = m.get("module") or ""
                emit(vuln_id=vid, aliases=aliases, ecosystem="Go",
                     package=mod_path,
                     purl=f"pkg:golang/{mod_path}" if mod_path else "",
                     published=published, modified=modified,
                     severity="", source="go-vulndb")
                n += 1
print(f"  records:    {n:>7,}")

# ---------- 6. EPSS exploit prediction scores ----------
# Stored as gzipped CSV, schema: cve,epss,percentile.
# We emit one row per scored CVE so it joins to the alias graph and
# shows up as a source coverage line. Score lives in the severity column
# (formatted as 'epss:<score>:<percentile>') because every other source
# already overloads that field for CVSS strings / level names.
print("[6] EPSS")
n = 0
epss_path = PUB / "epss_scores.csv.gz"
if epss_path.exists():
    with gzip.open(epss_path, "rt", encoding="utf-8") as f:
        # First line is a comment: "#model_version:...,score_date:..."
        first = f.readline()
        # If first line wasn't a comment, rewind via concat
        if not first.startswith("#"):
            reader = csv.DictReader(io.StringIO(first + f.read()))
        else:
            reader = csv.DictReader(f)
        for row in reader:
            cve = (row.get("cve") or "").strip()
            if not cve:
                continue
            score = row.get("epss") or ""
            pct = row.get("percentile") or ""
            emit(
                vuln_id=cve,
                aliases=[],
                ecosystem="",
                package="",
                purl="",
                published="",
                modified="",
                severity=f"epss:{score}:{pct}",
                source="epss",
            )
            n += 1
print(f"  records:    {n:>7,}")

# ---------- 7. CISA KEV (actively exploited catalog) ----------
print("[7] CISA KEV")
n = 0
kev_path = PUB / "cisa_kev.json"
if kev_path.exists():
    with kev_path.open(encoding="utf-8") as f:
        kev = json.load(f)
    for v in kev.get("vulnerabilities", []):
        cve = v.get("cveID") or ""
        if not cve:
            continue
        vendor = v.get("vendorProject") or ""
        product = v.get("product") or ""
        package = f"{vendor}:{product}".strip(":")
        ransom = v.get("knownRansomwareCampaignUse") or ""
        emit(
            vuln_id=cve,
            aliases=[],
            ecosystem="",
            package=package,
            purl="",
            published=v.get("dateAdded") or "",
            modified=v.get("dateAdded") or "",
            severity=f"kev:ransomware={ransom or 'Unknown'}",
            source="cisa-kev",
        )
        n += 1
print(f"  records:    {n:>7,}")

# ---------- 8. CVE Project bulk (cvelistV5) ----------
# One JSON file per CVE record under cves/<year>/<thousand>/CVE-*.json.
# The schema is the official CVE JSON 5.x form (cveMetadata + containers.cna).
# We pull cveId, dates, descriptions[0].lang=en for severity hint, and any
# affected.vendor+product as package rows.
print("[8] CVE Project (cvelistV5)")
n = 0
cve_path = PUB / "cvelistV5.zip"
if cve_path.exists():
    with zipfile.ZipFile(cve_path) as zf:
        for info in zf.infolist():
            name = info.filename
            # Skip non-CVE entries (READMEs, schema, deltas).
            if "/cves/" not in name or not name.endswith(".json"):
                continue
            if "/delta_" in name:
                continue
            with zf.open(info) as f:
                try:
                    d = json.load(f)
                except Exception:
                    continue
            if not isinstance(d, dict):
                continue
            meta = d.get("cveMetadata") or {}
            if not isinstance(meta, dict):
                continue
            cve = meta.get("cveId") or ""
            if not cve:
                continue
            state = meta.get("state") or ""
            if state and state.upper() == "REJECTED":
                continue
            published = meta.get("datePublished") or ""
            modified = meta.get("dateUpdated") or ""
            containers = d.get("containers") or {}
            cna = containers.get("cna") if isinstance(containers, dict) else None
            if not isinstance(cna, dict):
                cna = {}
            metrics = cna.get("metrics") or []
            sev = ""
            for m in metrics:
                if not isinstance(m, dict):
                    continue
                for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                    if k in m and isinstance(m[k], dict):
                        score = m[k].get("baseScore")
                        vec = m[k].get("vectorString") or ""
                        if score is not None:
                            sev = f"{k}:{score}:{vec}"
                            break
                if sev:
                    break
            affected = cna.get("affected") or []
            if not affected:
                emit(
                    vuln_id=cve, aliases=[], ecosystem="", package="",
                    purl="", published=published, modified=modified,
                    severity=sev, source="cve-project",
                )
                n += 1
                continue
            for aff in affected:
                if not isinstance(aff, dict):
                    continue
                vendor = aff.get("vendor") or ""
                product = aff.get("product") or ""
                pkg = f"{vendor}:{product}".strip(":")
                emit(
                    vuln_id=cve, aliases=[], ecosystem="", package=pkg,
                    purl="", published=published, modified=modified,
                    severity=sev, source="cve-project",
                )
                n += 1
print(f"  records:    {n:>7,}")

# ---------- Write parquet ----------
# Build a polars DataFrame from columnar lists — far cheaper in memory
# than a list-of-dicts at 6M+ rows. Schema is pinned to Utf8 across the
# board so YAML datetimes / numeric severities can't fight inference.
n_rows = len(COLS["vuln_id"])
print(f"\nTotal rows emitted: {n_rows:,}")
schema = {
    "vuln_id": pl.Utf8, "aliases": pl.Utf8, "ecosystem": pl.Utf8,
    "package": pl.Utf8, "purl": pl.Utf8, "published": pl.Utf8,
    "modified": pl.Utf8, "severity": pl.Utf8, "source": pl.Utf8,
}
df = pl.DataFrame(COLS, schema=schema)
# Free the columnar lists before write so the parquet allocator has room.
COLS.clear()
df.write_parquet(OUT, compression="zstd")
print(f"Wrote {OUT.name} ({OUT.stat().st_size / 1024 / 1024:.1f} MB)")
print()
print("Schema:")
for name, dtype in zip(df.columns, df.dtypes):
    print(f"  {name}: {dtype}")
print()
print("Source distribution:")
print(df.group_by("source").len().sort("len", descending=True))
