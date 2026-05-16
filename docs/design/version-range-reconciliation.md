# Version-range reconciliation — design note

Short writeup of the decisions behind the `check_affected.py` /
`analyze_ranges.py` work. Written after the fact as a record so future
readers (and future me) know the tradeoffs that were taken explicitly.

## Problem

The pre-existing pipeline answered "which databases know about this
vuln?" by clustering on the `(vuln_id, aliases)` graph. It deliberately
did not touch affected-package version ranges, so users could not ask
the question that actually matters operationally: **"am I affected at
version X?"**

The README's `Honest limitations` section called this out:

> No version-range normalization. The ER pipeline joins on the
> (vuln_id, alias) graph, not on affected versions. Good for "which
> databases know about this vuln"; not sufficient for "is my installed
> version affected."

## Locked-in decisions

| Decision                  | Choice                                                                  |
|---------------------------|-------------------------------------------------------------------------|
| Input format              | PURL list (primary) + CycloneDX SBOM (thin wrapper extracts PURLs)      |
| Ecosystem scope (v1)      | PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist (8)         |
| Verdict semantics         | Three-state: `AFFECTED` / `NOT_AFFECTED` / `UNKNOWN`                    |
| Pipeline integration      | New `ranges` JSON column in the parquet; new `check_affected.py` CLI    |
| Demo output               | Bundled sample SBOM report + cross-source range-disagreement finding    |
| Version-comparison library| [`univers`](https://github.com/aboutcode-org/univers) (used by vulnerablecode / osv-scanner) |
| Range storage             | JSON-encoded OSV `ranges` objects in a single parquet column            |

## Why these choices

**Three-state verdict.** Real OSV data includes `type: GIT` ranges
(commit-based, not version-comparable), records with no upper bound,
and version strings that don't conform to any documented format. A
two-state verdict would have to silently drop these rows
(false-negative risk) or treat them as affected (noise). `UNKNOWN`
matches how mature scanners like Grype and Trivy behave.

**`univers` over per-ecosystem libraries.** `univers` ships
`PypiVersion`, `NpmVersion`, `MavenVersion`, etc. — each implementing
the canonical comparison semantics for its ecosystem. Using one library
keeps the matcher logic in `check_affected.py` to a single code path
that just looks up `RANGE_CLASS_BY_SCHEMES[scheme].version_class(...)`
and tests `installed in interval`. If `univers` ever gets a verdict
wrong for one ecosystem, we can swap to a canonical lib for that scheme
without re-shaping the parquet.

**JSON column over structured Polars list-of-struct.** Range storage is
write-once, read-on-demand. The Python loop in `check_affected.py`
deserializes only the rows that match a user's PURL — typically a few
hundred — so JSON parsing cost is invisible. A structured column would
have made the schema fragile (Polars list-of-struct schemas are
annoying to evolve) without buying anything for our access pattern.

**Per-ecosystem-scoped extract.** The extractor (`extract_records.py`)
only serializes `ranges` for the 8 target ecosystems. Distros
(Ubuntu/Debian/Alpine/etc.) and meta-sources (CVE Project, KEV, EPSS)
get `ranges = ""`. This keeps the parquet small and makes it
syntactically impossible for the matcher to pretend it can answer a
question it can't.

## Out of scope for v1

- **Distro version comparison.** dpkg / RPM / apk epoch+version+release
  semantics are real work and produce a parser that mostly says
  `UNKNOWN` against an OSS SBOM. Deferred until a v2 with concrete
  demand.
- **Transitive resolution.** If an SBOM contains `pkg:gem/rails@6.0.0`
  but the actual advisories are on `actionpack` and `activerecord`,
  the matcher won't synthesize those transitively. The SBOM is the
  source of truth for what's installed.
- **CycloneDX `affects` clauses.** The matcher only reads PURLs from
  the SBOM. CycloneDX has richer affected-component metadata; ignored
  for now.
- **Canonical-cluster aggregation.** Verdicts are deduplicated per
  `vuln_id`, not per canonical cluster from the alias graph.
  Constructing the cluster mapping requires the full `analyze.py` run,
  which OOMs on a laptop. A future `vuln_to_cluster.parquet` artifact
  would let `check_affected.py` aggregate per-cluster cheaply.
