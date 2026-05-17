# Methodology: cross-source remediation-convergence test

This document spells out exactly how `analyze_independence.py`
decides whether two sources agree on the `fixed`-version set for a
given vulnerability. The result it produces (finding #8 in the README:
**`ghsa-reviewed × pypa: 70.5% agreement, 13.0% true contradiction`**)
is the load-bearing empirical claim in the project, so the procedure
needs to be reviewable on its own terms.

Read alongside [`docs/definitions.md`](./definitions.md), which gives
the operational construct each step builds on.

---

## 1. Joining sources

### Why `vuln_id`-only joins fail

Sources use disjoint identifier spaces:

| Source | `vuln_id` prefix |
|---|---|
| ghsa-reviewed | `GHSA-` |
| pypa | `PYSEC-` |
| rustsec | `RUSTSEC-` |
| go-vulndb | `GO-` |
| cve-project | `CVE-` |

A direct group-by on `vuln_id` will find zero overlap between
`ghsa-reviewed` and `pypa` — they never share an identifier.

### What we actually do

For every row that publishes a range, we extract every `CVE-*` token
from both `vuln_id` and `aliases` (semicolon-separated, after
`goldenflow` strip + uppercase). The cross-source join key is then
`(cve_id, ecosystem, package_lower)`.

```python
cves = set()
if row.vuln_id.startswith("CVE-"):
    cves.add(row.vuln_id)
for alias in row.aliases.split(";"):
    if alias.strip().startswith("CVE-"):
        cves.add(alias.strip())
```

This is the same alias graph the cluster build uses (definition 0 in
`definitions.md`), restricted to CVE-typed nodes.

### Package-name normalization

Packages are joined case-insensitively (`row.package.lower()`).

Discovered empirically: PyPA lowercases names (`accesscontrol`) while
GHSA preserves casing (`AccessControl`). Without lowercasing, the
two sources share zero (CVE, package) groups for the `Products.AccessControl`
family of advisories.

No other normalization is applied. Specifically, we do **not**:

- normalize `org.springframework:spring-webmvc` ↔ `spring-webmvc`
  (Maven group:artifact form is preserved)
- collapse npm scope variants
- map old PyPI names to renamed ones (`PyYAML` → `pyyaml` is the only
  case lowercasing accidentally fixes)

---

## 2. Reducing OSV `ranges[].events[]` to a fix set

Each OSV-shape range looks like:

```json
{
  "type": "ECOSYSTEM" | "SEMVER" | "GIT",
  "events": [
    {"introduced": "1.0"},
    {"fixed": "1.4.2"},
    {"introduced": "1.5"},
    {"last_affected": "1.5.3"}
  ]
}
```

For the convergence test we collapse this to a **set of `fixed`
versions**:

| Event | Included in the set? |
|---|---|
| `fixed: X` | **Yes** — X enters the set as a literal string |
| `introduced: X` | No — sources sometimes ship `introduced` without a paired `fixed`; tracked separately as "asymmetric coverage" |
| `last_affected: X` | No — semantically equivalent to `fixed: next(X)` but different sources express it differently; comparing across them would create false disagreement |
| `limit: X` | No — rare; affects vuln-range scoping, not the fix |

Ranges with `type: GIT` are skipped entirely (commit hashes aren't
package-version-comparable).

This is a deliberate restriction. It means we **under-count** real
remediation events — a record that says only `last_affected: 1.4.1`
isn't credited for shipping a fix even though it implicitly does. The
tradeoff is that we avoid false-disagreement noise from sources
choosing different events to express the same boundary.

---

## 3. Comparing fix sets

Set equality is **byte-exact string equality**. `"5.3"` and `"5.3.0"`
are different elements; `"1.0.0-rc1"` and `"1.0.0rc1"` are different
elements.

When sets differ we sub-classify:

| Sub-class | Definition | Operator interpretation |
|---|---|---|
| `subset_only` | one set ⊆ the other | **completeness asymmetry**; e.g. GHSA lists all 7 backport-branch fixes, PyPA misses 1 |
| `contradiction` | neither subset (sets overlap or disjoint) | **true disagreement** on a fix version |

Only `contradiction` is treated as load-bearing disagreement. In the
README the "13.0% true contradiction" number excludes `subset_only`
cases.

### Known limitation: no semver normalization in the comparison

This is the biggest known weakness. The matcher used by
`check_affected.py` uses `univers` for ecosystem-aware version
comparison, but `analyze_independence.py` does string comparison.
Concretely:

- A real-world example we'd want to credit as agreement:
  `{"5.3"}` vs `{"5.3.0"}` — same release, different string.
  We currently flag this as contradiction.
- Conversely, prerelease-vs-final on the same numeric:
  `{"1.0.0-rc1"}` vs `{"1.0.0"}` — different releases, looks like
  contradiction. Correctly flagged.

A future version of the comparison should canonicalize each fix
string through `univers.versions.PypiVersion(...) ` / `NpmVersion(...)`
etc. before comparing. Until then, the **13% contradiction figure is
an upper bound** — some fraction is whitespace-equivalent versions
the comparison didn't reconcile. Manual inspection of the
`independent_contradictions.csv` worksheet is the cheapest way to
estimate the size of that fraction.

---

## 4. Independent vs mirror source classification

The point of this whole exercise is to isolate cases where two
sources arrive at a fix independently. So we tag each source as
either contributing original curation or redistributing someone else's.

### INDEPENDENT (carries original curation in the 8-eco scope)

| Source | Why |
|---|---|
| `ghsa-reviewed` | GitHub Security team triage |
| `pypa` | PyPA-curated Python advisories |
| `rustsec` | RustSec working group |
| `go-vulndb` | Go security team |
| `cve-project` | MITRE / CNAs |
| `cisa-kev` | CISA editorial |

### MIRROR (downstream redistribution)

| Source | Upstream |
|---|---|
| `osv-PyPI` | PyPA + GHSA |
| `osv-npm` | GHSA |
| `osv-Maven` | GHSA |
| `osv-Go` | Go vulndb + GHSA |
| `osv-crates.io` | RustSec + GHSA |
| `osv-RubyGems`, `osv-NuGet`, `osv-Packagist`, `osv-Hex`, … | GHSA |
| `osv-Debian`, `osv-Ubuntu`, `osv-Alpine`, `osv-Rocky*`, … | distro security teams (out of v1 scope) |
| `osv-GIT`, `osv-Linux`, `osv-Bitnami`, … | CVE Project passthroughs |
| `ghsa-unreviewed` | NVD automated import |
| `epss` | (no curation, no ranges) |

### What this admits today

The mirror controls form a clean monotone series that validates the
classification:

| Pair | Both have fixes | Agreement |
|---|---|---|
| `ghsa-reviewed × osv-Maven` (pure GHSA mirror) | 6,307 | 99.98% |
| `ghsa-reviewed × osv-Packagist` | 4,681 | 100% |
| `ghsa-reviewed × osv-PyPI` (mixed: GHSA + PyPA) | 5,033 | 90.8% |
| `ghsa-reviewed × osv-Go` (mixed: GHSA + Go vulndb) | 3,254 | 92.4% |
| **`ghsa-reviewed × pypa` (independent)** | **2,652** | **70.5%** |

If our classification were wrong — e.g. if `osv-Maven` were actually
shipping independent curation rather than mirroring GHSA — its
agreement rate would diverge from 99.98%. The fact that it doesn't is
evidence the classification is correct.

The pairs in the middle (`osv-PyPI` and `osv-Go`) match what we'd
predict from "GHSA mirror plus an independent upstream feed": their
agreement with GHSA sits between the pure mirrors (99-100%) and the
fully-independent pair (70.5%), and is consistent with each having
~10% of advisories sourced from the non-GHSA upstream.

---

## 5. What we don't model

These are deliberate exclusions, called out so reviewers don't have
to discover them by inspection.

- **Distro semantics.** Debian/Ubuntu/RPM `epoch:version-release` is
  not comparable as a string. We don't try; distros are excluded from
  finding #8 entirely.
- **Transitive package equivalence.** If GHSA reports `org.springframework:spring-webmvc`
  and another source reports the meta-artifact `org.springframework:spring-framework`,
  we don't reconcile those. They're treated as different packages.
- **Wildcard / range collapsing.** OSV `fixed:` events in the 8 v1
  ecosystems are always concrete versions, not wildcards or
  expressions, so there's nothing to collapse. (Wildcards do appear
  in some CVE Project `versions[].lessThan` fields, but cve-project
  rows don't carry the `ranges` column.)
- **Prerelease handling.** `1.0.0-rc1` is treated as a distinct
  string from `1.0.0`. If two sources disagree on whether the fix
  shipped in the RC vs the final, we flag it as contradiction —
  which is what an operator would want to know about.
- **Same-day vs cross-source mirroring lag.** The convergence test
  is asynchronous: as long as both sources eventually publish a
  `fixed` event, we compare the sets. We don't penalize lag (the
  separate `analyze_timing.py` covers that).

---

## 6. Reproducing the result

```bash
python sync_cloud.py             # pull data/records_normalized.parquet
python analyze_independence.py   # produces output/independence.json
```

Or, against the latest release without running any analysis:

```bash
curl -LO https://github.com/<owner>/<repo>/releases/download/latest/independence.json
```

The full JSON includes per-pair `n_groups_both_publish_range`,
`n_both_have_fixes`, `n_agreement`, `n_disagreement_subset_only`,
`n_disagreement_contradiction`, plus up to 200 contradiction examples
with raw `fixes_by_source` so any disputed claim can be re-derived
from the data without re-running the pipeline.