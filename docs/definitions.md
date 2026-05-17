# Operational definitions

This repo isn't a model paper; it's a measurement of the public OSS
vulnerability ecosystem. To keep the findings reviewable, here are the
four constructs the analyses operate on, each with: a definition, the
script that implements it, the columns it consumes from the parquet,
and a worked example.

The order below is foundation first, then signal-richest. Each
construct logically implies the ones above it.

---

## 0. Canonical vulnerability cluster

> **A canonical vulnerability cluster is a connected component in the
> bipartite graph of `(vuln_id, alias)` pairs across all sources,
> after stripping and uppercasing both fields.**

Concretely: every advisory record contributes its `vuln_id` as a node
and every entry in its `aliases` field as a node, with an edge between
`vuln_id` and each alias (weight 1.0; exact ID match). Union-find over
those edges collapses the union of source-specific identifier spaces
(`CVE-*`, `GHSA-*`, `PYSEC-*`, `GO-*`, `RUSTSEC-*`, distro-specific
IDs, KEV CVEs, EPSS CVEs, …) into one canonical cluster per
real-world vulnerability.

Cluster size = number of distinct identifiers in the component. A
cluster of size 1 is an *orphan* — only one source has ever referenced
that ID and it has no published aliases.

| | |
|---|---|
| **Implementing script** | [`analyze.py`](../analyze.py) (calls `goldenmatch.build_clusters`) |
| **Input columns** | `vuln_id`, `aliases` (after `normalize.py` runs `strip` + `uppercase`) |
| **Output** | `member_to_root`, `cluster_info` in-memory; per-cluster aggregates in [`output/report.json`](../output/report.json) |

Cluster count is the principal denominator the rest of the constructs
ratio against. For the current corpus: **6.1M records → 1.18M unique
identifiers → 847,475 canonical clusters → 358,170 multi-ID
clusters**.

### Worked example — Log4Shell cluster

```
                 CVE-2021-44228
                  /     |    \
                 /      |     \
   GHSA-JFH8-C2JP-5V3Q  |  (no PYSEC: not a Python vuln)
        |               |
   (Maven records pointing at 5 log4j-derivative packages)
```

Cluster root: `CVE-2021-44228` (lowest lexicographic root after
canonicalization). Cluster size: 2 (CVE + GHSA) + the 5 Maven package
nodes via the inverse package lookup — see `cluster_info` in
[`output/famous_vulns.json`](../output/famous_vulns.json).

---

## 1. Identity fragmentation

> **A canonical vulnerability is identity-fragmented when more than one
> identifier maps to it across the union of public sources.**

A canonical vulnerability cluster (definition 0) of size > 1 is
identity-fragmented. The whole 6.1M-rows → 847k-clusters → 358k-multi-
ID reduction is a measurement of fragmentation at scale.

| | |
|---|---|
| **Implementing script** | [`analyze.py`](../analyze.py) (calls `goldenmatch.build_clusters`) |
| **Input columns** | `vuln_id`, `aliases` |
| **Output** | `cluster_size`, `member_to_root` mapping, surfaced in [`output/report.json`](../output/report.json) and [`output/top_disagreement.json`](../output/top_disagreement.json) |

### Worked example — Log4Shell

CVE-2021-44228 has, by alias-graph traversal, the following cluster
membership (selection):

| ID | Source |
|---|---|
| `CVE-2021-44228` | cve-project |
| `GHSA-JFH8-C2JP-5V3Q` | ghsa-reviewed |
| `PYSEC-2021-NNN` | *(none — Java vuln, not in PyPA)* |

Cluster size = 5 (the GHSA-id surfaces 5 different log4j-derivative
Maven artifacts) — see [`output/famous_vulns.json`](../output/famous_vulns.json).
The fragmentation here is moderate: 2 identifiers map to the same
canonical vuln across 2 independent sources, plus the Maven ecosystem
record from osv-Maven.

---

## 2. Representability

> **A canonical vulnerability is package-representable iff at least one
> of its alias-graph rows carries a non-empty `ranges` field in one of
> the 8 v1 language ecosystems** (PyPI, npm, Maven, Go, crates.io,
> RubyGems, NuGet, Packagist).

Representability is the structural precondition for an SBOM scanner to
have *any* shot at deciding affectedness. If no source ships a
`(package, version-range)` pair, the vuln can't be matched against an
installed version no matter how much intelligence you bolt on top.

The construct is binary (representable / not) but enriched in the
5-bucket taxonomy:

| Bucket | Meaning |
|---|---|
| PACKAGE_RANGE | Representable |
| PACKAGE_ADVISORY | Curated advisory exists but no range — *partially* representable |
| DISTRO | Representable only in distro semantics (out of v1 scope) |
| UNREVIEWED_MIRROR | Not representable; raw NVD passthrough |
| CVE_ONLY | Not representable; no advisory feed has any record |

| | |
|---|---|
| **Implementing scripts** | [`analyze_representability.py`](../analyze_representability.py), [`analyze_representability_taxonomy.py`](../analyze_representability_taxonomy.py) |
| **Input columns** | `vuln_id`, `aliases`, `source`, `ecosystem`, `ranges` |
| **Output** | [`output/representability.json`](../output/representability.json), [`output/representability_taxonomy.json`](../output/representability_taxonomy.json) |

### Worked example — CVE-2021-32297 (`lief`) vs CVE-2024-30122 (Cisco IOS)

| CVE | Representable? | Why |
|---|---|---|
| CVE-2021-32297 | **Yes** | Has range rows in osv-PyPI and pypa for package `lief` |
| CVE-2024-30122 *(Cisco IOS)* | **No** | Lives in `cve-project` only; no advisory feed publishes a record. Bucketed as CVE_ONLY. |

The 7.5% global representability rate (and the 4.4% rate inside KEV-
with-ransomware) is the headline expression of this construct.

---

## 3. Remediation convergence

> **Two INDEPENDENT sources are remediation-convergent on a given
> `(CVE, ecosystem, package)` iff their `fixed`-event sets are equal.**

"Independent" means the sources don't share an upstream redistribution
feed. In the current corpus the only INDEPENDENT × INDEPENDENT pair
with range overlap is `ghsa-reviewed` × `pypa`. Mirror pairs
(`ghsa-reviewed × osv-Maven` etc.) are reported as a control.

The metric is operationalized at three resolutions:

- **Agreement** — fix-set equality (the strict criterion)
- **Subset disagreement** — one set wholly contains the other
  (completeness asymmetry; one source missing backport branches)
- **Contradiction** — neither equal nor subset (true disagreement on
  the boundary version)

| | |
|---|---|
| **Implementing script** | [`analyze_independence.py`](../analyze_independence.py) |
| **Input columns** | `vuln_id`, `aliases`, `ecosystem`, `package`, `source`, `ranges` |
| **Output** | [`output/independence.json`](../output/independence.json) |

### Worked example — CVE-2021-32297 on `lief`

| Source | `fixed` versions |
|---|---|
| ghsa-reviewed | `{0.11.0}` |
| pypa | `{0.11.5}` |

Disjoint sets → **true contradiction**. The two independent feeds
disagree on the version where the fix lands.

This is one of 345 contradiction cases (13.0%) in the 2,652-group
`ghsa-reviewed × pypa` sample.

---

## 4. Actionability

> **A canonical vulnerability is actionable iff it is representable
> *and* at least one of its alias-graph rows ships a `fixed` event for
> some package in the 8 v1 ecosystems.**

Representability is necessary but not sufficient. An advisory that
says "this package is affected starting from version X" with no upper
bound (no `fixed` event) is representable — the matcher will return
`AFFECTED` for any version `>= X` — but it isn't *actionable* in the
operator sense: you can't tell the user which version to upgrade to.

| | |
|---|---|
| **Implementing script** | [`analyze_actionability.py`](../analyze_actionability.py) |
| **Input columns** | `vuln_id`, `aliases`, `ecosystem`, `ranges` |
| **Output** | [`output/actionability.json`](../output/actionability.json) |

### Worked example — CVE-2021-44228 vs a hypothetical no-fix advisory

| CVE | Representable? | Actionable? | Reason |
|---|---|---|---|
| CVE-2021-44228 (Log4Shell) | Yes | **Yes** | Multiple `fixed: 2.17.0` events across Maven advisories |
| CVE-2099-12345 (hypothetical, "introduced in 1.0, no fix yet") | Yes | **No** | No `fixed` event published anywhere yet |

In practice the gap between representability and actionability is
small because curated feeds tend to publish a fix at the same time
they publish the advisory. The actionability number tightens the
representability claim: of the **25,352** package-representable CVEs,
~99% are also actionable.

---

### Methodology note

Independence categorization, package-name normalization, set-equality
semantics, edge-case handling for OSV `events` arrays, and known
limitations of the comparison are documented in
[`docs/methodology.md`](./methodology.md). The remediation-convergence
result in finding #8 is the load-bearing claim that doc backs up.

---

## How the five relate

```
canonical_cluster
    --(union-find on (vuln_id, alias) graph)-->
identity_fragmentation
    --(many fragments collapse into one cluster)-->
representability
    --(adds: range data exists)-->
actionability
    --(adds: fix version published)-->
remediation_convergence
    --(adds: independent sources agree on the fix version)-->
```

Each construct except the cluster is a stricter condition than the
previous one. A canonical vuln can be identity-fragmented but not
representable (KEV's appliance entries); representable but not
actionable (no `fixed` event published yet); actionable but not
remediation-convergent (CVE-2021-32297 on `lief` — see finding #8).
The repo's main empirical contribution is putting numbers on every
cell of that hierarchy at corpus scale.
