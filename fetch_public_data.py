"""Fetch every public vulnerability database.

Keeps everything as zip archives on disk. Readers iterate entries
directly via ``zipfile.ZipFile`` -- extracting millions of tiny JSON
files onto NTFS blows up disk usage by two orders of magnitude.

Sources:
  1. OSV.dev bulk exports (~25 ecosystems)
  2. GitHub Security Advisories (GHSA)
  3. PyPA advisory-database
  4. RustSec advisory-db
  5. Go vulnerability DB
  6. EPSS exploit prediction scores (gzipped CSV)
  7. CISA Known Exploited Vulnerabilities catalog (JSON)
  8. CVEProject/cvelistV5 bulk archive (~290k CVE JSON records)
"""
from __future__ import annotations
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUB = ROOT / "data" / "public"
PUB.mkdir(parents=True, exist_ok=True)


def download(url: str, target: Path, min_size: int = 1024, optional: bool = False) -> bool:
    """Download URL to target. Returns True on success, False if 404 and optional."""
    if target.exists() and target.stat().st_size >= min_size:
        print(f"  [skip] {target.name} ({target.stat().st_size / 1024 / 1024:.1f} MB)")
        return True
    tmp = target.with_suffix(target.suffix + ".tmp")
    print(f"  [get ] {target.name}")
    try:
        with urllib.request.urlopen(url, timeout=600) as resp:
            with tmp.open("wb") as f:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
    except urllib.error.HTTPError as e:
        if optional and e.code == 404:
            print(f"         -> 404 (skipping, not fatal)")
            tmp.unlink(missing_ok=True)
            return False
        raise
    tmp.rename(target)
    print(f"         -> {target.stat().st_size / 1024 / 1024:.1f} MB")
    return True


# ---------- 1. OSV bulk exports (zips only, no extraction) ----------
# Ecosystems served by https://osv-vulnerabilities.storage.googleapis.com/.
# Names are case-sensitive and match the bucket layout exactly. Any that
# 404 are silently skipped; OSV adds/removes ecosystems over time.
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
OSV_DIR = PUB / "osv"
OSV_DIR.mkdir(parents=True, exist_ok=True)
print(f"\n[1/8] OSV bulk exports ({len(OSV_ECOSYSTEMS)} ecosystems attempted)")


def fetch_osv(eco: str) -> tuple[str, bool]:
    # OSV bucket uses the exact ecosystem name (with spaces, capitalization)
    # URL-encoded. urlopen handles encoding for us when we pass a Request.
    safe = eco.replace(" ", "%20")
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{safe}/all.zip"
    fname = eco.replace(".", "_").replace(" ", "_") + ".zip"
    target = OSV_DIR / fname
    ok = download(url, target, min_size=1_000, optional=True)
    return eco, ok


with ThreadPoolExecutor(max_workers=8) as ex:
    for fut in as_completed([ex.submit(fetch_osv, e) for e in OSV_ECOSYSTEMS]):
        fut.result()

# ---------- 2. GitHub Security Advisories ----------
print("\n[2/8] GitHub Security Advisories (~130 MB)")
download(
    "https://github.com/github/advisory-database/archive/refs/heads/main.zip",
    PUB / "ghsa.zip",
    min_size=10_000_000,
)

# ---------- 3. PyPA advisory-database ----------
print("\n[3/8] PyPA advisory-database")
download(
    "https://github.com/pypa/advisory-database/archive/refs/heads/main.zip",
    PUB / "pypa.zip",
    min_size=100_000,
)

# ---------- 4. RustSec ----------
print("\n[4/8] RustSec advisory-db")
download(
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.zip",
    PUB / "rustsec.zip",
    min_size=100_000,
)

# ---------- 5. Go vulndb ----------
print("\n[5/8] Go vulnerability DB")
download(
    "https://github.com/golang/vulndb/archive/refs/heads/master.zip",
    PUB / "go-vulndb.zip",
    min_size=100_000,
)

# ---------- 6. EPSS ----------
print("\n[6/8] EPSS exploit prediction scores")
download(
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    PUB / "epss_scores.csv.gz",
    min_size=500_000,
)

# ---------- 7. CISA KEV ----------
print("\n[7/8] CISA Known Exploited Vulnerabilities")
download(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    PUB / "cisa_kev.json",
    min_size=100_000,
)

# ---------- 8. CVE Project bulk ----------
# CVEProject/cvelistV5 ships ~290k CVE JSON records. The main branch
# tarball is ~700 MB. Optional (set SKIP_CVELIST=1 to skip) because some
# laptops can't spare the disk / bandwidth.
import os  # noqa: E402 (kept local to the optional block)

if os.environ.get("SKIP_CVELIST") == "1":
    print("\n[8/8] CVE Project bulk -- SKIP_CVELIST=1, skipping")
else:
    print("\n[8/8] CVE Project bulk (cvelistV5, ~700 MB)")
    download(
        "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip",
        PUB / "cvelistV5.zip",
        min_size=100_000_000,
    )

print("\nAll fetched. Next: python extract_records.py")
