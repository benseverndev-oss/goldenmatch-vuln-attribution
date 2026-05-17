"""Inter-rater agreement for filled annotation worksheets.

Takes 2+ filled CSVs that share a `cve_id` column. Joins on `cve_id`,
restricts to rows where every rater has supplied a label for the
target column, and computes:

  - raw agreement (fraction of rows where all raters match)
  - pairwise Cohen's kappa for each pair of raters
  - Fleiss' kappa across all raters (when n_raters >= 3)
  - per-category confusion matrix vs the rater-majority

Target columns by default: `representability_type` and `scanner_modality`
(the closed enums defined in docs/annotation-protocol.md).

Usage:

  python compute_agreement.py \\
    output/review/kev_blind_spots__alice.csv \\
    output/review/kev_blind_spots__bob.csv

  python compute_agreement.py --col scanner_modality \\
    output/review/*__*.csv

The filename pattern after the second `_` is treated as the rater id:
`kev_blind_spots__alice.csv` -> rater_id="alice".

Emits `output/annotation_agreement.json` with the full breakdown and
prints a summary to stdout.

No external dependencies beyond the stdlib + polars (already a project
dep). Kappa formulas implemented directly so the math is reviewable.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output" / "annotation_agreement.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Closed enums -- duplicated here so this script has no import dependency
# on sample_for_review.py (the two will drift only if you change one and
# forget the other, in which case kappa numbers will just look weird).
REPRESENTABILITY_TYPES = (
    "PACKAGE", "BINARY", "RUNTIME_CONFIG", "SERVICE", "APPLIANCE",
    "CLOUD", "OTHER",
)
SCANNER_MODALITIES = (
    "SBOM", "HOST", "NETWORK", "RUNTIME", "CSPM", "NONE",
)
DEFAULT_TARGETS = ("representability_type", "scanner_modality")


def parse_rater_id(path: Path) -> str:
    """Extract rater id from filename: `kev_blind_spots__alice.csv` -> `alice`."""
    m = re.search(r"__([A-Za-z0-9._-]+)\.csv$", path.name)
    if m:
        return m.group(1)
    return path.stem


def load_labels(path: Path, target: str) -> dict[str, str]:
    """Return cve_id -> label, skipping the hint row and empty labels."""
    out: dict[str, str] = {}
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cve = (row.get("cve_id") or "").strip()
            if not cve or cve.startswith("_VALID_VALUES"):
                continue
            label = (row.get(target) or "").strip().upper()
            if label:
                out[cve] = label
    return out


def cohen_kappa(a_labels: dict[str, str], b_labels: dict[str, str]) -> dict:
    """Cohen's kappa for two raters on the intersection of their labelled CVEs."""
    common = sorted(set(a_labels) & set(b_labels))
    if not common:
        return {"n": 0, "agree": 0, "raw_agreement": None, "kappa": None}
    n = len(common)
    n_agree = sum(1 for c in common if a_labels[c] == b_labels[c])
    po = n_agree / n  # observed agreement

    # Marginal distributions
    a_dist = Counter(a_labels[c] for c in common)
    b_dist = Counter(b_labels[c] for c in common)
    categories = set(a_dist) | set(b_dist)
    pe = sum(
        (a_dist.get(cat, 0) / n) * (b_dist.get(cat, 0) / n)
        for cat in categories
    )  # expected agreement by chance

    if pe >= 1.0:
        kappa = None  # degenerate (every label is the same)
    else:
        kappa = (po - pe) / (1.0 - pe)
    return {
        "n": n,
        "agree": n_agree,
        "raw_agreement": round(po, 4),
        "kappa": round(kappa, 4) if kappa is not None else None,
    }


def fleiss_kappa(rater_labels: dict[str, dict[str, str]]) -> dict:
    """Fleiss' kappa across >=3 raters. Subjects = CVEs labelled by all raters."""
    raters = list(rater_labels.keys())
    if len(raters) < 3:
        return {"n_raters": len(raters), "n_subjects": 0, "kappa": None,
                "note": "Fleiss requires >=3 raters; use cohen_kappa for pairs."}
    common = set(rater_labels[raters[0]])
    for r in raters[1:]:
        common &= set(rater_labels[r])
    common = sorted(common)
    if not common:
        return {"n_raters": len(raters), "n_subjects": 0, "kappa": None,
                "note": "no subject labelled by all raters."}

    # Build categories observed by ANY rater on the common subjects
    categories = sorted({
        rater_labels[r][cve] for r in raters for cve in common
    })
    n = len(common)
    k = len(raters)
    if k < 2 or n == 0:
        return {"n_raters": k, "n_subjects": n, "kappa": None}

    # n_ij = number of raters assigning category j to subject i
    nij: dict[str, dict[str, int]] = {
        cve: dict.fromkeys(categories, 0) for cve in common
    }
    for r in raters:
        for cve in common:
            nij[cve][rater_labels[r][cve]] += 1

    # Per-subject agreement P_i = (sum_j n_ij*(n_ij-1)) / (k*(k-1))
    p_i = []
    for cve in common:
        s = sum(c * (c - 1) for c in nij[cve].values())
        p_i.append(s / (k * (k - 1)))
    p_bar = mean(p_i)

    # Per-category marginal p_j = (sum_i n_ij) / (n*k)
    p_j = {
        cat: sum(nij[cve][cat] for cve in common) / (n * k)
        for cat in categories
    }
    p_e = sum(v * v for v in p_j.values())

    if p_e >= 1.0:
        kappa = None
    else:
        kappa = (p_bar - p_e) / (1.0 - p_e)

    return {
        "n_raters": k,
        "n_subjects": n,
        "p_bar": round(p_bar, 4),
        "p_e": round(p_e, 4),
        "kappa": round(kappa, 4) if kappa is not None else None,
    }


def majority_label(rater_labels: dict[str, dict[str, str]], cve: str) -> str | None:
    """First-mode rater label for a CVE; None if no rater labelled it."""
    votes = [rater_labels[r][cve] for r in rater_labels if cve in rater_labels[r]]
    if not votes:
        return None
    counts = Counter(votes)
    return counts.most_common(1)[0][0]


def confusion_vs_majority(rater_labels: dict[str, dict[str, str]],
                          target: str, allowed: tuple[str, ...]) -> dict:
    """Per-rater confusion matrix against the majority label."""
    all_cves = set()
    for r in rater_labels:
        all_cves.update(rater_labels[r])
    cat_index = {c: i for i, c in enumerate(allowed)}

    per_rater = {}
    for r, labels in rater_labels.items():
        mat: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        n_correct = 0
        n_total = 0
        for cve, lab in labels.items():
            maj = majority_label(rater_labels, cve)
            if maj is None or lab not in cat_index or maj not in cat_index:
                continue
            mat[maj][lab] += 1
            n_total += 1
            if maj == lab:
                n_correct += 1
        per_rater[r] = {
            "n": n_total,
            "agree_with_majority": n_correct,
            "agree_with_majority_rate": (
                round(n_correct / n_total, 4) if n_total else None
            ),
            "confusion_majority_to_rater": {
                maj: dict(rows) for maj, rows in mat.items()
            },
        }
    return per_rater


def analyse_target(rater_labels: dict[str, dict[str, str]], target: str) -> dict:
    raters = sorted(rater_labels.keys())
    pairwise = {}
    for i in range(len(raters)):
        for j in range(i + 1, len(raters)):
            a, b = raters[i], raters[j]
            pairwise[f"{a}_vs_{b}"] = cohen_kappa(rater_labels[a], rater_labels[b])
    out = {
        "raters": raters,
        "labels_per_rater": {r: len(rater_labels[r]) for r in raters},
        "pairwise_cohen_kappa": pairwise,
        "fleiss_kappa": fleiss_kappa(rater_labels),
        "confusion_vs_majority": confusion_vs_majority(
            rater_labels, target,
            REPRESENTABILITY_TYPES if target == "representability_type"
            else SCANNER_MODALITIES,
        ),
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("files", nargs="+", type=Path,
                    help="2+ filled review CSVs (rater id parsed from filename: name__<rater>.csv)")
    ap.add_argument("--col", action="append", default=None,
                    help=f"target column (default: {', '.join(DEFAULT_TARGETS)})")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    targets = args.col or list(DEFAULT_TARGETS)

    if len(args.files) < 2:
        ap.error("provide at least 2 CSVs")

    print(f"Files: {len(args.files)}")
    for p in args.files:
        if not p.exists():
            ap.error(f"missing: {p}")
        print(f"  {p}  (rater={parse_rater_id(p)})")

    report: dict[str, dict] = {}
    for target in targets:
        print(f"\n=== {target} ===")
        # Multiple files per rater (e.g. one CSV per worksheet) accumulate
        # into a single CVE -> label map per rater. A dict comprehension
        # would silently drop all but the last file per rater id.
        rater_labels: dict[str, dict[str, str]] = {}
        for p in args.files:
            rid = parse_rater_id(p)
            if rid not in rater_labels:
                rater_labels[rid] = {}
            rater_labels[rid].update(load_labels(p, target))
        if all(len(v) == 0 for v in rater_labels.values()):
            print(f"  (no labels present in column `{target}` -- skipping)")
            report[target] = {"note": "no labels present"}
            continue
        section = analyse_target(rater_labels, target)
        report[target] = section
        print(f"  labels per rater: {section['labels_per_rater']}")
        for pair, stats in section["pairwise_cohen_kappa"].items():
            print(f"  {pair:>30}  n={stats['n']}  raw={stats['raw_agreement']}  kappa={stats['kappa']}")
        fk = section["fleiss_kappa"]
        if fk.get("kappa") is not None:
            print(f"  Fleiss kappa ({fk['n_raters']} raters, "
                  f"{fk['n_subjects']} subjects): {fk['kappa']}")

    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
