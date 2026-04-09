"""Fetch every public vulnerability database.

Keeps everything as zip archives on disk. Readers iterate entries
directly via ``zipfile.ZipFile`` — extracting millions of tiny JSON
files onto NTFS blows up disk usage by two orders of magnitude.

Sources:
  1. OSV.dev bulk exports (10 ecosystems, ~334 MB total)
  2. GitHub Security Advisories (GHSA) — github.com/github/advisory-database
  3. PyPA advisory-database
  4. RustSec advisory-db
  5. Go vulnerability DB
  6. EPSS exploit prediction scores (gzipped CSV)

NVD (~343k CVEs) is deferred to ``fetch_nvd.py`` because it requires
paginated API calls (~15 min with no API key).
"""
from __future__ import annotations
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUB = ROOT / "data" / "public"
PUB.mkdir(parents=True, exist_ok=True)


def download(url: str, target: Path, min_size: int = 1024) -> None:
    if target.exists() and target.stat().st_size >= min_size:
        print(f"  [skip] {target.name} ({target.stat().st_size / 1024 / 1024:.1f} MB)")
        return
    tmp = target.with_suffix(target.suffix + ".tmp")
    print(f"  [get ] {target.name}")
    with urllib.request.urlopen(url, timeout=600) as resp:
        with tmp.open("wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
    tmp.rename(target)
    print(f"         -> {target.stat().st_size / 1024 / 1024:.1f} MB")


# ---------- 1. OSV bulk exports (zips only, no extraction) ----------
OSV_ECOSYSTEMS = [
    "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io",
    "Packagist", "NuGet", "Debian", "Alpine",
]
OSV_DIR = PUB / "osv"
OSV_DIR.mkdir(parents=True, exist_ok=True)
print("\n[1/6] OSV bulk exports (10 ecosystems)")


def fetch_osv(eco: str) -> str:
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
    target = OSV_DIR / f"{eco.replace('.', '_')}.zip"
    download(url, target, min_size=1_000)
    return eco


with ThreadPoolExecutor(max_workers=5) as ex:
    for fut in as_completed([ex.submit(fetch_osv, e) for e in OSV_ECOSYSTEMS]):
        fut.result()

# ---------- 2. GitHub Security Advisories ----------
print("\n[2/6] GitHub Security Advisories (~130 MB)")
download(
    "https://github.com/github/advisory-database/archive/refs/heads/main.zip",
    PUB / "ghsa.zip",
    min_size=10_000_000,
)

# ---------- 3. PyPA advisory-database ----------
print("\n[3/6] PyPA advisory-database")
download(
    "https://github.com/pypa/advisory-database/archive/refs/heads/main.zip",
    PUB / "pypa.zip",
    min_size=100_000,
)

# ---------- 4. RustSec ----------
print("\n[4/6] RustSec advisory-db")
download(
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.zip",
    PUB / "rustsec.zip",
    min_size=100_000,
)

# ---------- 5. Go vulndb ----------
print("\n[5/6] Go vulnerability DB")
download(
    "https://github.com/golang/vulndb/archive/refs/heads/master.zip",
    PUB / "go-vulndb.zip",
    min_size=100_000,
)

# ---------- 6. EPSS ----------
print("\n[6/6] EPSS exploit prediction scores")
download(
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    PUB / "epss_scores.csv.gz",
    min_size=500_000,
)

print("\nAll fetched. Next: python extract_records.py")
