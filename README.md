# Vulnerability Reconciliation Demo

Cross-database entity resolution on public OSS vulnerability data.

This repo reconciles **6,126,895 records** across **40 sources** (33 OSV
ecosystems, GHSA reviewed + unreviewed, PyPA, RustSec, Go vulndb, EPSS,
CISA KEV, CVE Project bulk) into **847,475 canonical vulnerabilities**
by feeding the `(vuln_id, alias)` graph into the
[GoldenMatch suite](https://github.com/benzsevern/goldenmatch). The full
pipeline runs as four suite stages:

- **GoldenCheck** profiles `records.parquet` and emits a DQ health grade
- **GoldenFlow** normalizes `vuln_id` + `aliases` (strip + uppercase)
- **GoldenMatch** runs union-find clustering on the alias edges
- **GoldenPipe** orchestrates the four stages end-to-end

The full extract runs on a `large-new-64GB` GitHub Actions runner in
~5 minutes via [`.github/workflows/full-pipeline.yml`](./.github/workflows/full-pipeline.yml);
laptops can run it too with `SKIP_CVELIST=1` to skip the 556 MB CVE
Project archive.

Companion repo to the [wallet-attribution demo](https://github.com/benzsevern/goldenmatch-wallet-attribution)
that ran the same pipeline shape on blockchain data.

## Headline findings

| Metric | Value |
|---|---|
| Rows ingested | **6,126,895** |
| Unique vuln IDs (pre-ER) | 1,192,187 |
| **Canonical vulnerabilities (post-ER)** | **847,475** |
| Clusters with 2+ cross-database IDs | **358,170** (42%) |
| Full OSS vulnerability universe | 584,148 canonical clusters |
| github-reviewed coverage of that universe | **5.2%** |
| CISA KEV (actively exploited) clusters | **1,592** |
| KEV clusters with NO ecosystem coverage | **1,404** (88%) |
| KEV clusters in github-reviewed | 120 (7.5%) |
| KEV clusters with known ransomware use | 321 |
| High-EPSS (p95+) clusters invisible to package scanners | **14,093** |

Five defensible findings surface in the data:

### 1. 88% of actively-exploited vulns are invisible to package scanners

CISA's Known Exploited Vulnerabilities catalog lists **1,592 CVEs that
attackers are actively using**. After reconciliation:

| KEV slice | Count | % of KEV |
|---|---|---|
| Total KEV-listed canonical vulns | 1,592 | 100% |
| With **any** ecosystem coverage (OSV/GHSA/PyPA/RustSec/Go) | 188 | 11.8% |
| In the `github-reviewed` set Dependabot surfaces | 120 | 7.5% |
| Known to be used in ransomware campaigns | 321 | 20.2% |
| **No ecosystem coverage anywhere** | **1,404** | **88.2%** |

The bugs being exploited in the wild today are overwhelmingly system
software (Exchange, Cisco IOS, F5, Fortinet, VMware, browsers, kernels)
distributed outside managed package ecosystems. A package scanner
running against an SBOM cannot see them by construction. Drill-down:
[`output/kev_clusters.json`](./output/kev_clusters.json).

### 2. EPSS flags 14,093 high-risk vulns that no package scanner can find

EPSS (the FIRST.org exploit prediction model) scores **326,035 CVEs**.
Of those, **30,019 sit at the 95th percentile or higher** — meaning the
model believes they're highly likely to be exploited in the next 30
days. Cross-referencing with the reconciled cluster graph:

| EPSS bucket | Canonical clusters | With ecosystem |
|---|---|---|
| p99+ (top 1%) | 3,340 | (small fraction) |
| p95–p99 | 13,341 | (small fraction) |
| p90–p95 | 16,678 | |
| p50–p90 | 133,383 | |
| no EPSS score | 514,092 | |

**14,093 clusters** are p95+ EPSS, **not** in KEV (so not yet exploited
that we know of), and have **no ecosystem coverage**. These are the
model's "imminent exploitation" calls that package-level tooling
structurally can't act on.

### 3. GitHub-reviewed coverage of the OSS universe is 5.2%

After folding in EPSS, KEV, CVE Project bulk, and 20+ extra OSV
ecosystems, the full OSS vulnerability universe grew to **584,148**
canonical clusters. Only **30,394 (5.2%)** are in the `github-reviewed`
set Dependabot surfaces — down from 9.1% in the OSV-10-only run because
the denominator grew faster than the curated numerator. The other
~94.8% are passthrough mirrors from NVD / OSV.

### 4. Ecosystem coverage is dramatically asymmetric

| Ecosystem | Canonical vulns |
|---|---|
| npm | 218,646 |
| Debian (4 releases combined) | ~165,000 |
| Ubuntu (10 release pockets combined) | ~210,000 |
| MinimOS | 40,117 |
| Chainguard | 39,363 |
| Wolfi | 20,494 |
| Linux kernel | 17,698 |
| PyPI | 16,604 |
| Maven | 6,565 |
| Bitnami container images | 6,242 |
| Packagist (PHP) | 6,237 |
| Mageia | 5,911 |
| Go modules | 4,030 |
| Android | 3,163 |
| RubyGems | 2,027 |
| NuGet (.NET) | 1,711 |
| crates.io | 1,575 |

**npm has 13× more tracked vulnerabilities than PyPI and 128× more than
NuGet.** The OS-distro and container-base ecosystems (Ubuntu, Debian,
Chainguard, Wolfi, MinimOS) dominate at the volume level — but most of
those rows are rebuilds of the same upstream CVE, which is exactly the
disagreement-clustering this pipeline collapses.

### 5. Famous system-level vulns still have zero ecosystem coverage

Some household-name vulnerabilities cleanly resolve to affected packages:

| Vuln | Ecosystems | Affected packages |
|---|---|---|
| Log4Shell (CVE-2021-44228) | Maven | 5 log4j-derivative packages |
| Spring4Shell (CVE-2022-22965) | Maven | 5 Spring packages |
| ZipSlip (CVE-2018-1002105) | Go | `github.com/kubernetes/kubernetes` |

Others — **Heartbleed, Shellshock, ProxyShell** — exist as passthrough
CVE IDs with **no ecosystem and no affected packages** in any of the
free public OSS vulnerability databases. OpenSSL, bash, and Exchange
Server are system software, distributed outside managed package
ecosystems. The KEV finding above (#1) generalizes this from a few
famous examples to the full 1,404-vuln blind spot.

Full numbers: [`output/report.json`](./output/report.json).
KEV drill-down: [`output/kev_clusters.json`](./output/kev_clusters.json).
Famous-vuln reconciliation: [`output/famous_vulns.json`](./output/famous_vulns.json).
Top ID-disagreement clusters: [`output/top_disagreement.json`](./output/top_disagreement.json).

## How it works

1. **Fetch** — eight sources as zip / json / csv.gz archives
   (`fetch_public_data.py`). OSV bulk (33 ecosystems), GHSA, PyPA,
   RustSec, Go vulndb, EPSS, CISA KEV, CVE Project bulk.
2. **Extract** — every source projected to a 9-column schema
   (`extract_records.py`) and written to a single zstd parquet (~6.1 M
   rows, ~200 MB).
3. **Check** — GoldenCheck profiles the parquet and writes a DQ health
   grade + per-column nulls/types/outliers (`dq_check.py`).
4. **Normalize** — GoldenFlow strips + uppercases `vuln_id` and
   `aliases` (`normalize.py`).
5. **Resolve** — GoldenMatch's `build_clusters` runs union-find +
   cluster-quality scoring on the `(vuln_id, aliases)` edge list
   (`analyze.py`).
6. **Analyze** — KEV exploitation gap, EPSS distribution, per-source
   coverage, ecosystem asymmetry, famous-vuln lookups, top-disagreement
   clusters (also in `analyze.py`).

GoldenPipe stitches stages 1–6 into a single run with per-stage status
reporting (`run_pipeline.py`). At ~850k clusters the analysis fits in
~3 GB on a laptop; the full extract is heavier and is intended for the
GitHub Actions runner.

## Run it

### On a GitHub Actions runner (recommended)

```bash
gh workflow run full-pipeline.yml --ref main
gh run watch
gh run download <run-id> --name pipeline-outputs --dir output/
```

The [`full-pipeline.yml`](./.github/workflows/full-pipeline.yml) workflow
targets the org's `large-new-64GB` runner (16 vCPU / 64 GB RAM / 600 GB
SSD) and completes in ~5 minutes including fetch.

### On a laptop

Requires Python 3.12, ~6 GB RAM, ~3 GB free disk (or set
`SKIP_CVELIST=1` to skip the 556 MB CVE Project archive and run in
~4 GB / 1 GB).

```powershell
# 1. Install
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. One-command run via goldenpipe
.\.venv\Scripts\python.exe run_pipeline.py

# Or skip stages once their outputs exist on disk:
.\.venv\Scripts\python.exe run_pipeline.py --skip-fetch --skip-extract
```

Each stage is also independently runnable:

```powershell
.\.venv\Scripts\python.exe fetch_public_data.py   # ~1.5 GB, ~5 min
.\.venv\Scripts\python.exe extract_records.py     # ~3 min, 6 M rows
.\.venv\Scripts\python.exe dq_check.py            # goldencheck scan
.\.venv\Scripts\python.exe normalize.py           # goldenflow transforms
.\.venv\Scripts\python.exe analyze.py             # goldenmatch.build_clusters + reports
```

Outputs land in `output/`:
- `report.json` — headline reconciliation stats (KEV + EPSS sections)
- `kev_clusters.json` — every KEV-listed cluster with EPSS + ecosystem
- `dq_report.json` — GoldenCheck health grade + findings
- `normalize_manifest.json` — GoldenFlow transforms applied
- `famous_vulns.json`, `top_disagreement.json` — drill-down samples

## Scripts

| File | Purpose |
|---|---|
| `fetch_public_data.py` | Download 6 sources as zip archives (no extraction) |
| `count_sources.py` | Diagnostic row count per source, reading zips in place |
| `extract_records.py` | Project every source to common schema → `data/records.parquet` |
| `dq_check.py` | GoldenCheck profile + findings → `output/dq_report.json` |
| `normalize.py` | GoldenFlow strip + uppercase → `data/records_normalized.parquet` |
| `analyze.py` | GoldenMatch `build_clusters` + headline findings + famous-vuln lookup |
| `run_pipeline.py` | GoldenPipe orchestrator over all of the above |

## Data sources

| Source | What it covers | License |
|---|---|---|
| [OSV.dev](https://osv.dev) (33 bulk ecosystems) | Language ecosystems (PyPI, npm, Go, Maven, RubyGems, crates.io, Packagist, NuGet, Hex, Pub, Hackage, CRAN, Bioconductor, GHC, SwiftURL) + distros (Debian, Alpine, Ubuntu, Rocky/AlmaLinux, Mageia, openSUSE, SUSE, Red Hat, Wolfi, Chainguard, MinimOS) + cross-cutting (Linux, OSS-Fuzz, Bitnami, GIT, UVI, GitHub Actions, Android) | CC-BY 4.0 |
| [github/advisory-database](https://github.com/github/advisory-database) | GHSA reviewed + unreviewed | CC-BY 4.0 |
| [pypa/advisory-database](https://github.com/pypa/advisory-database) | Python Packaging Authority curated vulns | CC-BY 4.0 |
| [rustsec/advisory-db](https://github.com/rustsec/advisory-db) | Rust crate advisories | CC0 |
| [golang/vulndb](https://github.com/golang/vulndb) | Go module vulnerabilities | BSD-3-Clause |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System (326k CVE scores) | CC-BY 4.0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog (1,592 CVEs) | Public domain |
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | Authoritative CVE record bulk (~290k JSON) | CC0 |

All sources are permissively licensed and redistributable. No API keys required.

## Honest limitations

- **~~No NVD direct fetch.~~** *Fixed:* CVE Project's `cvelistV5` bulk
  repo provides the same authoritative CVE corpus without the paginated
  API. 514k rows from cvelistV5 fold into the cluster graph.
- **~~Union-find on literal IDs.~~** *Fixed in the suite refactor:*
  `normalize.py` runs GoldenFlow `strip` + `uppercase` on `vuln_id`
  and `aliases` before clustering, so casing/whitespace drift across
  sources no longer fragments clusters.
- **Row counts ≠ vuln counts per source.** A single advisory affecting
  three packages emits three rows. The `source_coverage` in
  `output/report.json` correctly uses distinct canonical-cluster counts.
- **No version-range normalization.** The ER pipeline joins on the
  `(vuln_id, alias)` graph, not on affected versions. Good for "which
  databases know about this vuln"; not sufficient for "is my installed
  version affected."
- **The top-disagreement list is dominated by Bitnami container fanout.**
  Legitimate ER finding (same vuln duplicated across container variants)
  but visually less dramatic than a pure cross-database disagreement.
- **No commercial database comparison.** Snyk, Sonatype, Chainguard
  maintain richer databases that aren't bulk-downloadable.

## Related

- [GoldenMatch](https://github.com/benzsevern/goldenmatch) — the
  entity-resolution + data-quality toolkit this pipeline actually calls:
  `goldenmatch.build_clusters` for ER, `goldencheck.scan_file` for DQ,
  `goldenflow.transform_df` for normalization, `goldenpipe` for stage
  orchestration
- [goldenmatch-wallet-attribution](https://github.com/benzsevern/goldenmatch-wallet-attribution) —
  companion repo that ran the same pipeline shape on blockchain data
  (13.1M records, 30,958 cross-source clusters)
