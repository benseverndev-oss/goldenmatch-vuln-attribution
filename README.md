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
| Range-bearing rows in 8 language ecosystems | **329,196** |
| Multi-source advisory-package groups (≥2 sources publish ranges) | **32,746** |
| Cross-source `fixed`-version disagreements | **1** |
| Sample SBOM (20 components) — `AFFECTED` verdicts | **19** components / **212** vuln-rows |
| Median CVE → first ecosystem advisory | **0 days** (p95: **5.5 yr**) |
| Median CVE → CISA KEV listing | **322 days** (p95: **9.5 yr**) |

Seven defensible findings surface in the data:

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

### 6. The pipeline now answers "am I affected at version X?"

The previous five findings live at the cluster level. `check_affected.py`
closes the gap to operational use by taking a list of PURLs (or a
CycloneDX SBOM) and producing a per-component verdict against every
matching advisory:

- `AFFECTED` — installed version falls inside the advisory's range
- `NOT_AFFECTED` — installed version is outside every range
- `UNKNOWN` — range is `type=GIT`, the version string is unparseable,
  or there's a deliberate gap in the data

Version comparison uses [`univers`](https://github.com/aboutcode-org/univers)
(the same library `vulnerablecode` and `osv-scanner` use), restricted to
the 8 language ecosystems with mature comparison semantics: **PyPI, npm,
Maven, Go, crates.io, RubyGems, NuGet, Packagist**. Distros and
system-software ranges are deliberately out of scope — see
[`docs/design/version-range-reconciliation.md`](./docs/design/version-range-reconciliation.md).

A bundled synthetic SBOM at [`examples/sample_sbom.json`](./examples/sample_sbom.json)
(20 deliberately old pins across all 8 ecosystems) demonstrates the
end-to-end output:

| Sample SBOM result | Count |
|---|---|
| Components in scope | 20 |
| Components verdict = AFFECTED | 19 |
| Components verdict = NOT_AFFECTED | 1 |
| Vuln-rows evaluated total | 525 |
| Vuln-rows verdict = AFFECTED | 212 |
| Vuln-rows verdict = NOT_AFFECTED | 300 |
| Vuln-rows verdict = UNKNOWN | 13 |

Per-component evidence (e.g. `[osv-Maven] >=2.13.0,<2.15.0 contains 2.14.0`
for Log4Shell on `log4j-core@2.14.0`) lives in
[`output/sample_sbom_report.json`](./output/sample_sbom_report.json).

A separate sweep, `analyze_ranges.py`, asks the cluster-level version of
the question: when two sources both ship a `fixed` event for the same
(vuln, package), do they agree? Of **32,746 multi-source groups**, only
**1** has a non-trivially different fix-version set across sources
(`GHSA-WQC8-X2PR-7JQH` / `restrictedpython` on PyPI: osv-PyPI lists
fixes in 5.3 *and* 6.1, ghsa-reviewed lists only 5.3). Cross-source fix
agreement is essentially total — which, given that many ecosystem
feeds redistribute GHSA, is the answer you'd hope to see, and a useful
data-quality sanity check on the corpus. Full drill-down:
[`output/range_disagreement.json`](./output/range_disagreement.json).

### 7. How long does it take a CVE to land in each source?

`analyze_timing.py` joins every CVE that appears in the corpus (via
`vuln_id` or in an `aliases` field) against the earliest `published`
timestamp per source-category. For the **333,777 CVEs** with at least
one record:

| Pair (source A → source B first-seen) | n | Median lag | p95 lag |
|---|---|---|---|
| CVE Project → first **OSV ecosystem** entry | 25,099 | **0 days** | **1,998 days** (5.5 yr) |
| CVE Project → **GHSA-reviewed** | 24,988 | **1 day**  | **2,414 days** (6.6 yr) |
| CVE Project → **CISA KEV** | 1,592 | **322 days** | **3,487 days** (9.5 yr) |
| **GHSA-reviewed → OSV ecosystem** | 24,892 | **0 days** | **0 days** |

Two findings stand out:

- **Half of CVEs land in an ecosystem feed the same day they're
  published, but the slow tail is years.** 43% of CVE-Project ↔ OSV-eco
  pairs land on day 0; the bottom 5% take 5+ years.
- **KEV is a *very* lagging signal.** Half of KEV-listed CVEs sit on
  the catalog 11 months after their CVE date, and the p95 is **9.5
  years**. 770 of the 1,592 KEV CVEs (48%) were added more than a year
  after CVE publication; **293 (18%) were added more than 5 years
  later**. Treating KEV as a real-time "what's exploitable today"
  signal underestimates how much of attacker activity is on old vulns
  CISA only recently surfaced.
- **`GHSA-reviewed → OSV-ecosystem` p95 is 0 days**, confirming that
  OSV's per-ecosystem buckets largely re-distribute GHSA same-day. This
  is the "cross-source agreement" finding from #6 stated explicitly:
  most multi-source rows are the same data wearing different labels.

Per-ecosystem CVE-to-first-record medians, the fastest first:

| Ecosystem | n CVEs | Median lag | p95 lag |
|---|---|---|---|
| crates.io | 789 | **-3 days** *(Rust advisories often predate CVE assignment)* | 1 day |
| npm | 4,227 | 0 days | 679 days |
| PyPI | 4,458 | 0 days | 905 days |
| Go | 3,271 | 0 days | 1,030 days |
| Maven | 6,181 | 2 days | 2,931 days |
| Packagist | 4,833 | 1 day | 2,908 days |
| RubyGems | 918 | 4 days | 3,057 days |
| NuGet | 796 | 7 days | 1,861 days |

Full distribution histograms: [`output/timing_lag.json`](./output/timing_lag.json).

## How it works

1. **Fetch** — eight sources as zip / json / csv.gz archives
   (`fetch_public_data.py`). OSV bulk (33 ecosystems), GHSA, PyPA,
   RustSec, Go vulndb, EPSS, CISA KEV, CVE Project bulk.
2. **Extract** — every source projected to a 10-column schema
   (`extract_records.py`) and written to a single zstd parquet (~6.1 M
   rows). The `ranges` column carries the OSV `affected[].ranges` JSON
   for 8 language ecosystems so `check_affected.py` can answer
   per-version questions without rereading the source archives.
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
7. **Range analysis** — cross-source `fixed`-version agreement check
   (`analyze_ranges.py`, lower memory than `analyze.py`).
8. **Per-component matching** *(user-invoked)* — `check_affected.py`
   takes a PURL list / CycloneDX SBOM and emits per-component
   AFFECTED / NOT_AFFECTED / UNKNOWN verdicts using `univers`.

GoldenPipe stitches stages 1–7 into a single run with per-stage status
reporting (`run_pipeline.py`). Stage 8 is user-invoked because it needs
an SBOM input. At ~850k clusters the analysis fits in
~3 GB on a laptop; the full extract is heavier and is intended for the
GitHub Actions runner.

## Run it

### From the cloud (recommended — zero local compute)

The full pipeline ships its outputs as a rolling [`latest` GitHub
release](../../releases/tag/latest) on every successful run. The
laptop-friendly path is to just pull that:

```powershell
.\.venv\Scripts\python.exe sync_cloud.py            # default: pull `latest` release
```

No `gh` CLI or GitHub auth required. Lands the parquet in `data/` and
the JSONs in `output/`, ready for `check_affected.py` against your own
SBOM.

If you need a build fresher than the latest release (e.g. you just
pushed a code change), trigger a new run and pull its artifacts:

```powershell
.\.venv\Scripts\python.exe sync_cloud.py --gh       # requires authenticated `gh`
```

The [`full-pipeline.yml`](./.github/workflows/full-pipeline.yml) workflow
targets the org's `large-new-64GB` runner (16 vCPU / 64 GB RAM / 600 GB
SSD) and completes in ~5 minutes including fetch. It runs the full
chain through `analyze_ranges.py` and the bundled sample-SBOM check, so
the published bundle has every output the local pipeline would.

### Locally (full local rebuild)

For hackers who want to rebuild from scratch. Requires Python 3.12,
~6 GB RAM, ~3 GB free disk (or set `SKIP_CVELIST=1` to skip the 556 MB
CVE Project archive and run in ~4 GB / 1 GB). Note: `analyze.py` will
OOM on a laptop at the full corpus size — that's the stage `sync_cloud.py`
exists to skip.

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
.\.venv\Scripts\python.exe analyze_ranges.py      # cross-source fixed-version agreement
.\.venv\Scripts\python.exe analyze_timing.py      # CVE -> source first-seen lag distributions
.\.venv\Scripts\python.exe check_affected.py --sbom examples/sample_sbom.json
```

Outputs land in `output/`:
- `report.json` — headline reconciliation stats (KEV + EPSS sections)
- `kev_clusters.json` — every KEV-listed cluster with EPSS + ecosystem
- `dq_report.json` — GoldenCheck health grade + findings
- `normalize_manifest.json` — GoldenFlow transforms applied
- `famous_vulns.json`, `top_disagreement.json` — drill-down samples
- `range_disagreement.json` — cross-source `fixed`-version agreement check
- `timing_lag.json` — CVE → first-seen-per-source lag distributions
- `sample_sbom_report.json` — verdicts for `examples/sample_sbom.json`
  (only when `check_affected.py` has been run)

## Scripts

| File | Purpose |
|---|---|
| `fetch_public_data.py` | Download 6 sources as zip archives (no extraction) |
| `count_sources.py` | Diagnostic row count per source, reading zips in place |
| `extract_records.py` | Project every source to common schema → `data/records.parquet` |
| `dq_check.py` | GoldenCheck profile + findings → `output/dq_report.json` |
| `normalize.py` | GoldenFlow strip + uppercase → `data/records_normalized.parquet` |
| `analyze.py` | GoldenMatch `build_clusters` + headline findings + famous-vuln lookup |
| `analyze_ranges.py` | Cross-source `fixed`-version agreement sweep over the `ranges` column |
| `analyze_timing.py` | CVE → source-first-seen lag distributions (incl. KEV / per-ecosystem) |
| `check_affected.py` | Per-PURL / CycloneDX SBOM matcher → `AFFECTED` / `NOT_AFFECTED` / `UNKNOWN` (uses `univers`) |
| `sync_cloud.py` | Pull the latest cloud-built parquet + JSONs to `data/` and `output/` (release or `gh` mode) |
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
- **~~No version-range normalization.~~** *Fixed for the 8 language
  ecosystems above.* `extract_records.py` now emits a `ranges` column
  carrying the OSV `affected[].ranges` JSON, and `check_affected.py`
  consumes a PURL list / CycloneDX SBOM to produce per-component
  AFFECTED / NOT_AFFECTED / UNKNOWN verdicts. Distros (Debian, Ubuntu,
  Alpine, RPM-based) remain out of scope — their version-comparison
  semantics are a separate, harder problem.
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
