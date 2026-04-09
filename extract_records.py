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
    source     : osv-PyPI / ghsa-reviewed / ghsa-unreviewed / pypa / rustsec / go-vulndb

One row per (vuln_id, affected_package) pair — i.e., a single advisory that
affects three packages emits three rows with the same vuln_id. This matches
how downstream ER pipelines want to reason about it.
"""
from __future__ import annotations
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

ROWS: list[dict] = []


def emit(*, vuln_id: str, aliases: list[str], ecosystem: str, package: str,
         purl: str, published: str, modified: str, severity: str, source: str) -> None:
    ROWS.append({
        "vuln_id": vuln_id or "",
        "aliases": ";".join(a for a in (aliases or []) if a),
        "ecosystem": ecosystem or "",
        "package": package or "",
        "purl": purl or "",
        "published": published or "",
        "modified": modified or "",
        "severity": severity or "",
        "source": source,
    })


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
    "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io",
    "Packagist", "NuGet", "Debian", "Alpine",
]
print("[1] OSV bulk exports")
for eco in OSV_ECOSYSTEMS:
    zp = PUB / "osv" / f"{eco.replace('.', '_')}.zip"
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
    print(f"  {eco:>12}: {n:>7,}")

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

# ---------- Write parquet ----------
# Coerce every cell to a string so YAML datetime values don't fight polars
# schema inference.
for r in ROWS:
    for k, v in list(r.items()):
        if v is None:
            r[k] = ""
        elif not isinstance(v, str):
            r[k] = str(v)

print(f"\nTotal rows emitted: {len(ROWS):,}")
schema = {
    "vuln_id": pl.Utf8, "aliases": pl.Utf8, "ecosystem": pl.Utf8,
    "package": pl.Utf8, "purl": pl.Utf8, "published": pl.Utf8,
    "modified": pl.Utf8, "severity": pl.Utf8, "source": pl.Utf8,
}
df = pl.DataFrame(ROWS, schema=schema)
df.write_parquet(OUT)
print(f"Wrote {OUT.name} ({OUT.stat().st_size / 1024 / 1024:.1f} MB)")
print()
print("Schema:")
for name, dtype in zip(df.columns, df.dtypes):
    print(f"  {name}: {dtype}")
print()
print("Source distribution:")
print(df.group_by("source").len().sort("len", descending=True))
