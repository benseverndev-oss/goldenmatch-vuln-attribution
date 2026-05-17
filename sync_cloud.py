"""Pull the latest pipeline outputs from GitHub onto a laptop.

Two modes:

    --release  (default, zero auth)
        Fetches the rolling `latest` release attached by the full-pipeline
        workflow. No `gh` CLI, no GitHub login needed. Use this when you
        just want the freshest published bundle.

    --gh
        Uses the `gh` CLI (must be authenticated) to trigger a brand-new
        workflow run, wait for it, and download its artifacts. Use this
        when you need a build fresher than the latest release (e.g.
        you just pushed a code change and want to scan with the new code).

Outputs land in their canonical locations:

    data/records_normalized.parquet
    output/{report,kev_clusters,famous_vulns,top_disagreement,
            range_disagreement,sample_sbom_report,dq_report}.json
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
OUT_DIR = ROOT / "output"

# Owner/repo of the canonical pipeline. Override with --repo if you forked.
DEFAULT_REPO = "benseverndev-oss/goldenmatch-vuln-attribution"
DEFAULT_TAG = "latest"
DEFAULT_WORKFLOW = "full-pipeline.yml"

RELEASE_ASSETS = [
    ("records_normalized.parquet", DATA_DIR),
    ("report.json", OUT_DIR),
    ("kev_clusters.json", OUT_DIR),
    ("famous_vulns.json", OUT_DIR),
    ("top_disagreement.json", OUT_DIR),
    ("range_disagreement.json", OUT_DIR),
    ("timing_lag.json", OUT_DIR),
    ("independence.json", OUT_DIR),
    ("representability.json", OUT_DIR),
    ("representability_taxonomy.json", OUT_DIR),
    ("actionability.json", OUT_DIR),
    ("convergence_inversion.json", OUT_DIR),
    ("review_worksheets.zip", OUT_DIR),
    ("sample_sbom_report.json", OUT_DIR),
    ("dq_report.json", OUT_DIR),
]


def fetch_release(repo: str, tag: str) -> int:
    base = f"https://github.com/{repo}/releases/download/{tag}"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for asset, dst_dir in RELEASE_ASSETS:
        url = f"{base}/{asset}"
        dst = dst_dir / asset
        print(f"-> {url}")
        try:
            with urllib.request.urlopen(url) as r, dst.open("wb") as f:
                shutil.copyfileobj(r, f)
        except Exception as e:
            print(f"   FAILED: {e}", file=sys.stderr)
            return 1
        size_mb = dst.stat().st_size / (1024 * 1024)
        print(f"   wrote {dst.relative_to(ROOT)} ({size_mb:.1f} MB)")
    # Auto-extract the review worksheets zip so the CSVs land in
    # output/review/, ready for a spreadsheet.
    wsz = OUT_DIR / "review_worksheets.zip"
    if wsz.exists():
        with zipfile.ZipFile(wsz) as zf:
            zf.extractall(OUT_DIR)
        print(f"   extracted review_worksheets.zip -> {OUT_DIR / 'review'}")

    print("\nDone. The parquet is now in data/, the JSONs in output/.")
    return 0


def fetch_via_gh(repo: str, workflow: str, ref: str) -> int:
    # Require gh; fail loud rather than half-working.
    if not shutil.which("gh"):
        print("gh CLI not on PATH. Install from https://cli.github.com/ or use --release.",
              file=sys.stderr)
        return 1

    def gh(*args: str, capture: bool = False) -> str:
        cmd = ["gh", "-R", repo, *args]
        print(f"$ {' '.join(cmd)}")
        if capture:
            return subprocess.check_output(cmd, text=True).strip()
        subprocess.check_call(cmd)
        return ""

    # 1. Fire the workflow.
    gh("workflow", "run", workflow, "--ref", ref)

    # 2. Find the run we just created. `gh run list` returns most-recent first
    #    so we take the top run for this workflow.
    runs = gh("run", "list", "--workflow", workflow, "--limit", "1",
              "--json", "databaseId,status",
              capture=True)
    import json as _json
    parsed = _json.loads(runs)
    if not parsed:
        print("Could not find the run we just triggered.", file=sys.stderr)
        return 1
    run_id = str(parsed[0]["databaseId"])
    print(f"Tracking run {run_id} (this typically takes ~5 minutes) ...")

    # 3. Block on it.
    gh("run", "watch", run_id, "--exit-status")

    # 4. Download both artifacts into the right places.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    gh("run", "download", run_id, "--name", "pipeline-outputs", "--dir", str(OUT_DIR))
    gh("run", "download", run_id, "--name", "records-parquet", "--dir", str(DATA_DIR))
    print(f"\nDone. Outputs in {OUT_DIR}, parquet in {DATA_DIR}.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--release", action="store_true",
                      help="(default) pull the rolling `latest` release via plain HTTPS")
    mode.add_argument("--gh", action="store_true",
                      help="trigger a fresh workflow run via the `gh` CLI and pull its artifacts")
    ap.add_argument("--repo", default=os.environ.get("VRD_REPO", DEFAULT_REPO),
                    help=f"owner/name (default: {DEFAULT_REPO})")
    ap.add_argument("--tag", default=DEFAULT_TAG,
                    help=f"release tag (default: {DEFAULT_TAG})")
    ap.add_argument("--workflow", default=DEFAULT_WORKFLOW,
                    help=f"workflow file (default: {DEFAULT_WORKFLOW})")
    ap.add_argument("--ref", default="main",
                    help="git ref to run the workflow against (default: main)")
    args = ap.parse_args()

    if args.gh:
        return fetch_via_gh(args.repo, args.workflow, args.ref)
    # Default mode: release.
    return fetch_release(args.repo, args.tag)


if __name__ == "__main__":
    raise SystemExit(main())
