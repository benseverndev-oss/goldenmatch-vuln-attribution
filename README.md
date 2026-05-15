# Vulnerability Reconciliation Demo

Cross-database entity resolution on public OSS vulnerability data.

This repo reconciles **869,771 records** across 15 sources (10 OSV
ecosystems, GHSA reviewed + unreviewed, PyPA, RustSec, Go vulndb) into
**608,463 canonical vulnerabilities** by feeding the `(vuln_id, alias)`
graph into the [GoldenMatch suite](https://github.com/benzsevern/goldenmatch).
The full pipeline runs as four suite stages:

- **GoldenCheck** profiles `records.parquet` and emits a DQ health grade
- **GoldenFlow** normalizes `vuln_id` + `aliases` (strip + uppercase)
- **GoldenMatch** runs union-find clustering on the alias edges
- **GoldenPipe** orchestrates the four stages end-to-end

Companion repo to the [wallet-attribution demo](https://github.com/benzsevern/goldenmatch-wallet-attribution)
that ran the same pipeline shape on blockchain data.

## Headline findings

| Metric | Value |
|---|---|
| Rows ingested | **869,771** |
| Unique vuln IDs (pre-ER) | 616,237 |
| **Canonical vulnerabilities (post-ER)** | **608,463** |
| Clusters with 2+ cross-database IDs | **345,568** (57%) |
| Full OSS vulnerability universe | 312,250 canonical clusters |
| github-reviewed coverage of that universe | **9.1%** |

Three defensible findings surface in the data:

### 1. GitHub Security Advisories reviews 9.1% of what it ingests

Of 312,250 canonical OSS vulnerabilities reachable across GHSA + OSV +
PyPA + RustSec + Go, only **28,419 (9.1%)** are in the `github-reviewed`
set. The other 297,076 are passthrough mirrors from the NVD feed. This
is a **curation ratio**, not a "Dependabot misses X%" claim — both the
reviewed and unreviewed sets feed Dependabot, but with very different
metadata quality.

### 2. Ecosystem coverage is dramatically asymmetric

| Ecosystem | Canonical vulns |
|---|---|
| npm | 217,162 |
| Debian (4 releases) | ~160,000 |
| PyPI | 15,920 |
| Maven | 6,370 |
| Packagist (PHP) | 5,571 |
| Go | 3,627 |
| RubyGems | 1,988 |
| NuGet (.NET) | 1,653 |
| crates.io | 1,396 |

**npm has 14× more tracked vulnerabilities than PyPI and 131× more than
NuGet.** Whether that reflects a real security gap or an attention gap
is an open question, but the asymmetry itself is quantified.

### 3. Famous system-level vulns have zero ecosystem coverage

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
ecosystems. Package-level scanners structurally cannot see them.

This is the most interesting finding: the free OSS vuln tooling stack
is **blind to the next Heartbleed by construction**.

Full numbers: [`output/report.json`](./output/report.json).
Famous-vuln reconciliation: [`output/famous_vulns.json`](./output/famous_vulns.json).
Top ID-disagreement clusters: [`output/top_disagreement.json`](./output/top_disagreement.json).

## How it works

1. **Fetch** — six data sources as zip archives (`fetch_public_data.py`).
2. **Extract** — every source projected to a 9-column schema
   (`extract_records.py`) and written to a single 15 MB parquet.
3. **Check** — GoldenCheck profiles the parquet and writes a DQ health
   grade + per-column nulls/types/outliers (`dq_check.py`).
4. **Normalize** — GoldenFlow strips + uppercases `vuln_id` and
   `aliases` (`normalize.py`).
5. **Resolve** — GoldenMatch's `build_clusters` runs union-find +
   cluster-quality scoring on the `(vuln_id, aliases)` edge list
   (`analyze.py`).
6. **Analyze** — per-source coverage, ecosystem asymmetry, famous-vuln
   lookups, top-disagreement clusters (also in `analyze.py`).

GoldenPipe stitches stages 1–6 into a single run with per-stage status
reporting (`run_pipeline.py`). At ~600k clusters the analysis fits
comfortably in pure-Python memory on a laptop — no Polars fallback
needed.

## Run it

Requires Python 3.12, ~4 GB RAM, ~1 GB free disk.

```powershell
# 1. Install
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. One-command run via goldenpipe (fetch → extract → check → normalize → analyze)
.\.venv\Scripts\python.exe run_pipeline.py

# Or skip stages once their outputs exist on disk:
.\.venv\Scripts\python.exe run_pipeline.py --skip-fetch --skip-extract
```

Each stage is also independently runnable:

```powershell
.\.venv\Scripts\python.exe fetch_public_data.py   # 600 MB, ~5 min
.\.venv\Scripts\python.exe extract_records.py     # ~30 sec
.\.venv\Scripts\python.exe dq_check.py            # goldencheck scan
.\.venv\Scripts\python.exe normalize.py           # goldenflow transforms
.\.venv\Scripts\python.exe analyze.py             # goldenmatch.build_clusters + reports
```

Outputs land in `output/`:
- `report.json` — headline reconciliation stats
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
| [OSV.dev](https://osv.dev) (10 ecosystem bulk exports) | PyPI, npm, Go, Maven, RubyGems, crates.io, Packagist, NuGet, Debian, Alpine | CC-BY 4.0 |
| [github/advisory-database](https://github.com/github/advisory-database) | GHSA reviewed + unreviewed | CC-BY 4.0 |
| [pypa/advisory-database](https://github.com/pypa/advisory-database) | Python Packaging Authority curated vulns | CC-BY 4.0 |
| [rustsec/advisory-db](https://github.com/rustsec/advisory-db) | Rust crate advisories | CC0 |
| [golang/vulndb](https://github.com/golang/vulndb) | Go module vulnerabilities | BSD-3-Clause |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System | CC-BY 4.0 |

All sources are permissively licensed and redistributable. No API keys required.

## Honest limitations

- **No NVD direct fetch.** The REST API is paginated and slow (~15 min).
  Instead, we rely on NVD's propagation into GHSA-unreviewed and OSV,
  which covers most OSS-ecosystem packages but not the full NVD corpus.
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
