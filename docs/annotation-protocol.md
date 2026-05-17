# Annotation protocol

This document is the labelling rulebook for the manual qualitative
validation worksheets in `output/review/`. Anyone labelling a sample
should read it end-to-end before opening the spreadsheet.

The goal is **reproducible labels**. Two reviewers reading this
document and looking at the same CVE should reach the same
classification at least most of the time. Quantifying "most of the
time" is what `compute_agreement.py` produces once we have ≥2 filled
worksheets.

---

## What you're labelling

Each worksheet row is one CVE with pre-filled context columns
(description, sources, vendor:product, KEV / EPSS flags). You fill
four columns:

| Column | What it captures | Type |
|---|---|---|
| `representability_type` | *What kind of artifact must be inspected to decide affectedness?* | closed enum |
| `scanner_modality` | *Which scanner class can actually decide it?* | closed enum |
| `manual_label` | Short free-text confirmation of the bucket the sampler assigned | free text |
| `notes` | Anything load-bearing: backport family, distro entanglement, why the auto-bucket might be wrong | free text |

`manual_label` and `notes` are advisory. `representability_type` and
`scanner_modality` are the reliability-critical fields.

---

## `representability_type` — closed enum

Pick exactly one. If two categories tie, pick the one *earliest in
this list* (a Spring library deployed to an appliance is `PACKAGE`,
not `APPLIANCE`, because the vuln lives in the library code).

### `PACKAGE`

The vulnerability is in code distributed as a versioned package
through one of the major language ecosystems (PyPI, npm, Maven, Go
modules, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, Hackage,
CRAN, Bioconductor, GHC, SwiftURL — anything OSV ships as a
language-ecosystem bucket).

**Litmus test**: would the upstream advisory cite a `pkg:<eco>/<name>@<version>`
PURL? If yes, this is `PACKAGE`.

| Example | Why |
|---|---|
| CVE-2021-44228 (Log4Shell) | Maven `org.apache.logging.log4j:log4j-core` |
| CVE-2018-7750 (paramiko) | PyPI `paramiko` |
| CVE-2021-32297 (lief) | PyPI `lief` |

### `BINARY`

The vulnerability is in a compiled binary that ships outside a
language ecosystem — distro packages, OS-vendor binaries,
third-party installers, container base images.

**Litmus test**: would the upstream advisory cite a Debian/RPM/APK
package name or a vendor binary, but *not* a language-ecosystem PURL?

| Example | Why |
|---|---|
| Linux kernel CVEs without a userspace surface | distro kernel package |
| `libcurl` CVEs | distro `libcurl4` / `libcurl-devel` |
| Windows DLL vulns shipped via Windows Update | Microsoft binary |

### `RUNTIME_CONFIG`

The vulnerability exists only when a specific runtime configuration
is in place, regardless of which package version is installed.
Affectedness can't be decided from `(package, version)` alone — you
have to read the config.

**Litmus test**: does the advisory text contain "when configured
with", "if the default is changed to", "with feature X enabled", or
similar?

| Example | Why |
|---|---|
| CVE describing "default credentials remain unchanged" | config posture, not version |
| Web server vuln "when `Indexes` is enabled" | runtime directive |
| Authentication bypass "if `auth_required = false`" | config flag |

### `SERVICE`

The vulnerability is in a service that gets installed and run as a
daemon — and the *exposure* of the service to the network is part of
what makes it exploitable. Detecting requires a network scan or
service-fingerprint check, not just a manifest read.

**Litmus test**: would a network scanner (nmap, Nessus, Tenable)
identify this faster than a package scan? Yes → `SERVICE`.

| Example | Why |
|---|---|
| Exchange ProxyShell | listening Exchange service on port 443 |
| Open Redis without auth | exposed service, not a binary version |
| RDP BlueKeep | TCP/3389 exposure is part of the vuln |

### `APPLIANCE`

The vulnerability lives in a vendor-managed appliance — Cisco IOS, F5
BIG-IP, Fortinet, Juniper, Palo Alto, dedicated load balancers,
firewalls, NAS boxes. The unit of inventory is the appliance model +
firmware version, not a package.

**Litmus test**: would an *asset inventory* tool decide affectedness?
Yes → `APPLIANCE`.

| Example | Why |
|---|---|
| Fortinet FortiOS CVEs | appliance + firmware version |
| Cisco IOS XE CVEs | appliance + IOS version |
| VMware ESXi CVEs | ESXi build number on a server |

### `CLOUD`

The vulnerability lives in a cloud-service configuration or in a
managed cloud service the customer doesn't install themselves. CSPM
(Cloud Security Posture Management) is the only thing that can detect
it.

**Litmus test**: is the vulnerable thing something the customer
*never installed locally*?

| Example | Why |
|---|---|
| Misconfigured S3 bucket | AWS account state |
| Azure Function with default-public binding | cloud-provider config |
| GCP IAM with overly broad role | account-level policy |

### `OTHER`

Use this only when none of the above fit *and* you can articulate
why in `notes`. Examples we've seen:

- Hardware errata (Spectre / Meltdown class) — `OTHER`, note `hardware errata`
- Cryptographic algorithm flaws that exist independent of any specific implementation
- Vulns marked `** REJECT **` in NVD that nonetheless appear in KEV (data error case)

---

## `scanner_modality` — closed enum

What kind of scanner can actually decide affectedness for this CVE?
Pick *one*. If two modalities both work, pick the one most operators
would use first (SBOM beats HOST beats NETWORK).

| Value | Tool family | When to use |
|---|---|---|
| `SBOM` | OSV-Scanner, Trivy SBOM, Grype, Dependabot | Vuln is in a package version listed in a CycloneDX/SPDX manifest |
| `HOST` | Trivy host, Lynis, Tenable host plug-ins, CIS benchmarks | Vuln is in an installed binary or config file on the host filesystem |
| `NETWORK` | nmap, Nessus, OpenVAS, Greenbone | Vuln requires fingerprinting an exposed service over the network |
| `RUNTIME` | Falco, runtime EDR, container-runtime scanners | Vuln is observable only at execution time (e.g. specific syscall pattern, runtime config) |
| `CSPM` | Wiz, Prisma Cloud, AWS Config, Azure Defender | Vuln is a cloud-account or cloud-service misconfiguration |
| `NONE` | — | No scanner class can decide it (data-only CVE, rejected entry, etc.) |

### Common pairings

| representability_type | typical scanner_modality |
|---|---|
| PACKAGE | SBOM |
| BINARY | HOST |
| RUNTIME_CONFIG | RUNTIME (or HOST for static configs) |
| SERVICE | NETWORK (or HOST if checking installed service version) |
| APPLIANCE | NETWORK (via SNMP/HTTP fingerprint) — or out-of-band asset inventory |
| CLOUD | CSPM |
| OTHER | usually NONE |

---

## Edge-case decisions (locked)

The cases below were ambiguous on first read; the protocol settles
them so different reviewers don't drift apart on the same hard cases.

### A Java library shipped with an enterprise appliance

If the CVE is on the *library* and Maven publishes a fix, label
`PACKAGE` + `SBOM`. The fact that some operators consume it via an
appliance is a deployment detail, not a property of the vuln.

### A library with no SBOM coverage but a `cve-project` record

Label `PACKAGE` + `SBOM` if there's a published fix version somewhere
(GitHub release, vendor advisory). The fact that the *demo's* OSV
mirror doesn't have the range is a corpus gap, not a
representability fact. Use `notes` to call out the gap.

### Distro-only CVEs (Debian Security Advisory with no language-eco record)

`BINARY` + `HOST`. The unit of remediation is the `.deb` package, not
a language-ecosystem package. Even if the upstream is a Python
library, distros backport patches and the operator updates via apt.

### "Default credentials" CVEs

`RUNTIME_CONFIG` + `RUNTIME` if the credentials are configurable at
deploy time. `SERVICE` + `NETWORK` if the credentials are baked into
the firmware and only discoverable by network probe.

### Cryptographic algorithm flaws (e.g. SWEET32, BEAST)

`OTHER` + `NONE`. The flaw is in the spec, not in any specific
package. Operators mitigate by disabling ciphersuites, which is
itself a config change — but labelling these as RUNTIME_CONFIG
obscures the fact that no scanner directly "detects" them.

### Vulns marked `** REJECT **` in NVD

`OTHER` + `NONE`. Note the rejection in `notes`. These shouldn't be
in KEV but occasionally are.

### Same CVE affecting both a library and an appliance

Label by the primary remediation path. If both are real (`log4j` was
both an OSS library and an embedded component of dozens of
appliances), label `PACKAGE` + `SBOM` and use `notes` to call out
`also embedded in appliances`. The SBOM finding is the
operationally-most-useful answer.

### Vulns where the "package" is the OS itself (e.g. Windows TCP/IP stack)

`BINARY` + `HOST`. Even though Microsoft Update is the remediation
delivery mechanism, the *unit* is a binary, not a package-version
tuple in any ecosystem we cover.

---

## What you don't have to do

- **Verify the CVE description.** Trust the `description` column.
  We pulled it from `cvelistV5.zip` and you're not auditing CVE Project.
- **Resolve the underlying disagreement.** For
  `independent_contradictions.csv`, you don't need to decide whether
  the GHSA fix or the PyPA fix is correct — you're just labelling
  *what kind of disagreement it is* (e.g. completeness asymmetry,
  version-string artifact, real semantic disagreement).
- **Match the auto-bucket.** If the sampler labelled a row
  `UNREVIEWED_MIRROR` but it's clearly `APPLIANCE` + `NONE`, label it
  that way and put `auto-bucket disagrees: appliance` in `notes`.
  Disagreement here is itself a finding.

---

## Workflow

1. Open one CSV (start with `kev_blind_spots.csv` — it's the
   highest-signal sample).
2. For each row, read the `description` column. 95% of the time the
   right `representability_type` is obvious.
3. Pick `scanner_modality` from the common-pairings table; override
   only if you have a specific reason.
4. Spot-check rows where the auto-bucket disagrees with your
   classification and note the disagreement.
5. Save and commit. The committed CSVs are themselves the dataset.

When two or more people label the same worksheet (call them
`kev_blind_spots__alice.csv` and `kev_blind_spots__bob.csv`), run:

```bash
python compute_agreement.py output/review/kev_blind_spots__*.csv
```

to get raw agreement, Cohen's κ, and per-category confusion matrices.
