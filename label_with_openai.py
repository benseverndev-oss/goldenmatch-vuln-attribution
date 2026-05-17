"""Independent second-rater: have OpenAI's API label the review worksheets.

Reads each `<bucket>.csv` in `output/review/` (skipping the
`__claude.csv` files), sends every row to the OpenAI API with the
annotation protocol as system context plus the row's pre-filled
columns as user context, parses the structured JSON response, and
writes `<bucket>__openai.csv`.

Cross-model agreement (GPT vs Claude) is a meaningful signal: if two
different model families both apply the same protocol and reach
substantial agreement, the protocol is doing the constraining rather
than reflecting one model's idiosyncrasies.

Usage:

    export OPENAI_API_KEY=sk-...
    python label_with_openai.py             # all worksheets, default model
    python label_with_openai.py --model gpt-4o-mini
    python label_with_openai.py --which kev_blind_spots

Then:

    python compute_agreement.py output/review/<bucket>__*.csv

to get raw agreement and Cohen's kappa across Claude and OpenAI.

Cost (gpt-4o-mini default): ~$0.05 for all 158 rows.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

from openai import OpenAI, RateLimitError, APIError

ROOT = Path(__file__).resolve().parent
REVIEW = ROOT / "output" / "review"
PROTOCOL = ROOT / "docs" / "annotation-protocol.md"

REPRESENTABILITY_TYPES = (
    "PACKAGE", "BINARY", "RUNTIME_CONFIG", "SERVICE", "APPLIANCE",
    "CLOUD", "OTHER",
)
SCANNER_MODALITIES = (
    "SBOM", "HOST", "NETWORK", "RUNTIME", "CSPM", "NONE",
)

# Truncated rules summary -- the full protocol is too long to repeat every
# call. We include the closed-enum definitions and the locked edge-case
# rules. The model gets the same constraints a human reviewer would,
# without the entire markdown doc burning tokens 158 times.
SYSTEM_PROMPT = """You are labelling CVEs against a closed-enum annotation protocol.

For each CVE you'll see: cve_id, the auto-assigned source-presence bucket
(e.g. PACKAGE_RANGE, UNREVIEWED_MIRROR, CVE_ONLY), KEV/EPSS flags, the
sources that publish the CVE, vendor:product if known, and the CVE
description (first 300 chars). You output a JSON object with three keys:

  representability_type: one of {PACKAGE, BINARY, RUNTIME_CONFIG,
                                 SERVICE, APPLIANCE, CLOUD, OTHER}
  scanner_modality:      one of {SBOM, HOST, NETWORK, RUNTIME, CSPM, NONE}
  notes:                 short free-text rationale (< 200 chars)

representability_type definitions:

  PACKAGE         vuln in code distributed as a versioned package through
                  one of the major language ecosystems (PyPI, npm, Maven,
                  Go modules, crates.io, RubyGems, NuGet, Packagist, Hex,
                  Pub, Hackage, CRAN). Would the upstream advisory cite
                  a pkg:<eco>/<name>@<version> PURL? If yes -> PACKAGE.

  BINARY          vuln in a compiled binary that ships outside a language
                  ecosystem: distro packages, OS-vendor binaries,
                  third-party installers, container base images, kernel.

  RUNTIME_CONFIG  vuln exists only when a specific runtime configuration
                  is in place. Affectedness can't be decided from
                  (package, version) alone.

  SERVICE         vuln in a service that gets installed and run as a
                  daemon AND network exposure is part of exploitability
                  (e.g. self-hosted server: Exchange, PaperCut, GitLab,
                  Confluence on-prem). Would a network scanner identify
                  this faster than a package scan? Yes -> SERVICE.

  APPLIANCE       vuln in a vendor-managed appliance (Cisco IOS, F5,
                  Fortinet, Juniper, Palo Alto, VMware ESXi, NAS boxes,
                  firewalls). Unit of inventory is appliance+firmware
                  version.

  CLOUD           vuln in cloud-service configuration or managed cloud
                  service the customer doesn't install. CSPM is the only
                  thing that detects it.

  OTHER           none of the above. Use for: hardware errata, crypto
                  algorithm flaws independent of implementation, NVD
                  REJECTED entries.

If two fit, pick the one EARLIEST in the list above (PACKAGE beats
APPLIANCE for a library embedded in an appliance, etc.).

scanner_modality typical pairings:

  PACKAGE        -> SBOM
  BINARY         -> HOST
  RUNTIME_CONFIG -> RUNTIME (or HOST for static configs)
  SERVICE        -> NETWORK
  APPLIANCE      -> NETWORK
  CLOUD          -> CSPM
  OTHER          -> usually NONE

Locked edge cases:

- Library shipped with an enterprise appliance -> PACKAGE+SBOM. The
  appliance-deployment is a fact about consumers, not the vuln.
- Distro-only CVEs (e.g. Debian Security Advisory only) -> BINARY+HOST.
- Default-credential CVEs that are configurable at deploy time ->
  RUNTIME_CONFIG+RUNTIME. Hard-coded credentials -> SERVICE+NETWORK.
- Crypto algorithm flaws (SWEET32, BEAST, etc.) -> OTHER+NONE.
- WordPress plugins / generic PHP web apps / Drupal contrib modules
  that aren't in the 8 language ecosystems -> SERVICE+NETWORK (the
  operator scans the live site, not the manifest).
- iOS / macOS / Android OS vulns -> BINARY+HOST.
- Browser vendor binaries (Chrome, Firefox, Safari) -> BINARY+HOST,
  UNLESS a library that ships independently (libvpx in npm, ChakraCore
  in NuGet) is the affected component, in which case PACKAGE+SBOM.
- Rows where the description is empty or missing -> OTHER+NONE with
  notes='no description available'.

Output ONLY a JSON object on a single line, no markdown fence, no
commentary. Keys must be exactly: representability_type,
scanner_modality, notes.
"""


def build_user_prompt(row: dict) -> str:
    return (
        f"cve_id: {row['cve_id']}\n"
        f"bucket: {row['bucket']}\n"
        f"kev: {row['kev']}\n"
        f"kev_ransomware: {row['kev_ransomware']}\n"
        f"epss_percentile: {row['epss_percentile']}\n"
        f"sources: {row['sources']}\n"
        f"vendor_product: {row['vendor_product']}\n"
        f"top_aliases: {row['top_aliases']}\n"
        f"description: {row['description']}\n"
    )


def call_openai(client: OpenAI, model: str, user_prompt: str, retries: int = 3) -> dict:
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=300,
            )
            text = resp.choices[0].message.content or "{}"
            return json.loads(text)
        except RateLimitError as e:
            last_err = e
            time.sleep(2 ** attempt)
        except APIError as e:
            last_err = e
            time.sleep(1)
        except json.JSONDecodeError as e:
            last_err = e
            # Don't retry parse errors; they'll fail the same way.
            break
    raise RuntimeError(f"call failed after {retries} retries: {last_err}")


def label_worksheet(client: OpenAI, model: str, src: Path) -> int:
    dst = src.with_name(src.stem + "__openai.csv")
    rows = list(csv.DictReader(src.open(encoding="utf-8")))
    fieldnames = list(rows[0].keys()) if rows else []
    labelled = 0
    n_target = sum(1 for r in rows if not r["cve_id"].startswith("_VALID_VALUES"))
    print(f"\n{src.name} -> {dst.name} ({n_target} rows)")
    for i, r in enumerate(rows):
        if r["cve_id"].startswith("_VALID_VALUES"):
            continue
        user_prompt = build_user_prompt(r)
        try:
            ans = call_openai(client, model, user_prompt)
        except Exception as e:
            print(f"  [{i}] {r['cve_id']}: FAILED - {e}", file=sys.stderr)
            ans = {"representability_type": "OTHER", "scanner_modality": "NONE",
                   "notes": f"API failure: {e}"}
        rt = (ans.get("representability_type") or "").strip().upper()
        sm = (ans.get("scanner_modality") or "").strip().upper()
        note = (ans.get("notes") or "").strip()[:300]
        if rt not in REPRESENTABILITY_TYPES:
            note = f"OUT_OF_ENUM_RT={rt}; coerced to OTHER. " + note
            rt = "OTHER"
        if sm not in SCANNER_MODALITIES:
            note = f"OUT_OF_ENUM_SM={sm}; coerced to NONE. " + note
            sm = "NONE"
        r["representability_type"] = rt
        r["scanner_modality"] = sm
        r["notes"] = note
        labelled += 1
        if labelled % 5 == 0:
            print(f"  ... {labelled}/{n_target}")
    with dst.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"  wrote {labelled}/{n_target} rows")
    return labelled


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--model", default="gpt-4o-mini",
                    help="OpenAI model (default: gpt-4o-mini; ~$0.05 for all 158 rows)")
    ap.add_argument("--which", default=None,
                    help="single worksheet stem (e.g. kev_blind_spots); default: all")
    args = ap.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. Export it and rerun.", file=sys.stderr)
        return 1

    client = OpenAI()

    candidates = [
        "kev_blind_spots", "kev_representable", "unreviewed_mirror",
        "cve_only", "orphan_single_source", "independent_contradictions",
    ]
    if args.which:
        candidates = [args.which]

    total = 0
    for stem in candidates:
        src = REVIEW / f"{stem}.csv"
        if not src.exists():
            print(f"skip: {src.name} missing", file=sys.stderr)
            continue
        total += label_worksheet(client, args.model, src)

    print(f"\nDone. Labelled {total} rows with model={args.model}.")
    print("Now run:")
    print("  python compute_agreement.py output/review/<bucket>__*.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
