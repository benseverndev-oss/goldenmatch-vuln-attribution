"""One-command orchestrator: goldenpipe wraps the demo into a pipeline.

Stage graph:

    fetch  →  extract  →  check  →  normalize  →  analyze
   (custom)  (custom)   (gcheck)   (gflow)      (gmatch)

Each stage is exposed to goldenpipe via @stage so the pipeline gets
ordered execution, per-stage status, and a single PipeResult to report
on. Individual scripts (`fetch_public_data.py`, `extract_records.py`,
`dq_check.py`, `normalize.py`, `analyze.py`) remain independently
runnable for debugging.

Usage:
    python run_pipeline.py                # full run
    python run_pipeline.py --skip-fetch   # reuse data/raw on disk
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import polars as pl
from goldenpipe import (
    PipeContext,
    Pipeline,
    PipelineConfig,
    PipeStatus,
    StageResult,
    StageSpec,
    StageStatus,
    stage,
)
from goldenpipe.engine.registry import StageRegistry

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable


def _run_script(name: str) -> tuple[int, str]:
    """Run a sibling Python script and capture exit status + last lines."""
    proc = subprocess.run(
        [PYTHON, str(ROOT / name)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    tail = "\n".join((proc.stdout or "").splitlines()[-6:])
    return proc.returncode, tail


def _stage_from_script(stage_name: str, script: str, produces: list[str]):
    """Build a goldenpipe @stage that shells out to one of the demo scripts."""

    @stage(name=stage_name, produces=produces, consumes=[])
    def _impl(ctx: PipeContext) -> StageResult:
        t0 = time.perf_counter()
        rc, tail = _run_script(script)
        elapsed = time.perf_counter() - t0
        prefix = f"[{stage_name}] {script} {elapsed:.1f}s"
        if rc != 0:
            print(f"{prefix} FAILED (rc={rc})")
            if tail:
                print(tail)
            return StageResult(status=StageStatus.FAILED, error=f"{script} exited {rc}")
        print(f"{prefix} ok")
        if tail:
            print(tail)
        return StageResult(status=StageStatus.SUCCESS)

    return _impl


fetch_stage = _stage_from_script("fetch", "fetch_public_data.py", ["data/raw/*.zip"])
extract_stage = _stage_from_script("extract", "extract_records.py", ["data/records.parquet"])
check_stage = _stage_from_script("check", "dq_check.py", ["output/dq_report.json"])
normalize_stage = _stage_from_script("normalize", "normalize.py", ["data/records_normalized.parquet"])
analyze_stage = _stage_from_script(
    "analyze",
    "analyze.py",
    ["output/report.json", "output/famous_vulns.json", "output/top_disagreement.json"],
)

STAGES = {
    "fetch": fetch_stage,
    "extract": extract_stage,
    "check": check_stage,
    "normalize": normalize_stage,
    "analyze": analyze_stage,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="goldenpipe-orchestrated vuln reconciliation")
    ap.add_argument("--skip-fetch", action="store_true",
                    help="reuse data/raw/*.zip already on disk")
    ap.add_argument("--skip-extract", action="store_true",
                    help="reuse data/records.parquet already on disk")
    args = ap.parse_args()

    stage_names: list[str] = []
    if not args.skip_fetch:
        stage_names.append("fetch")
    if not args.skip_extract:
        stage_names.append("extract")
    stage_names += ["check", "normalize", "analyze"]

    stage_specs: list[StageSpec | str] = [StageSpec(use=name) for name in stage_names]
    config = PipelineConfig(pipeline="vuln-reconciliation", stages=stage_specs)

    registry = StageRegistry()
    for name in stage_names:
        registry.register(STAGES[name])

    pipeline = Pipeline(config=config, registry=registry)
    # Our stages don't operate on a single in-memory dataframe (they shell
    # out to scripts that read/write parquet on disk), but Pipeline.run
    # requires either a source file or a df. Pass an empty df to satisfy
    # the API; stages ignore ctx.df entirely.
    result = pipeline.run(df=pl.DataFrame())

    print("\n" + "=" * 60)
    print(f"Pipeline status: {result.status.name}")
    print("=" * 60)
    for stage_name, sr in result.stages.items():
        elapsed = result.timing.get(stage_name, 0.0)
        line = f"  [{sr.status.name:<8}] {stage_name:<10} ({elapsed:.1f}s)"
        if sr.error:
            line += f"  error={sr.error}"
        print(line)
    if result.skipped:
        print(f"  skipped: {', '.join(result.skipped)}")

    if result.status == PipeStatus.FAILED:
        print("\nErrors:")
        for err in result.errors or []:
            print(f"  {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
