"""Apply goldenflow standardization to records.parquet.

Reads `data/records.parquet`, runs strip + uppercase on `vuln_id` and
`aliases` via goldenflow's transform engine, and writes
`data/records_normalized.parquet`. This is what makes the cluster graph
case-insensitive without scattering `.str.to_uppercase()` calls through
the rest of the pipeline.

Replaces the "Case-insensitive normalization is not applied" caveat
that lived in the README before the suite refactor.
"""
from __future__ import annotations

import json
from pathlib import Path

import goldenflow
import polars as pl
from goldenflow.config.schema import GoldenFlowConfig, TransformSpec

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "records.parquet"
DST = ROOT / "data" / "records_normalized.parquet"
MANIFEST = ROOT / "output" / "normalize_manifest.json"
MANIFEST.parent.mkdir(parents=True, exist_ok=True)

print(f"goldenflow {goldenflow.__version__}")
print(f"Reading {SRC} ...")
df = pl.read_parquet(SRC)
print(f"  rows: {df.height:,}")

# The aliases column is a `;`-joined string per row. Stripping +
# uppercasing the whole string is safe — every alias token is ASCII
# (CVE-XXXX-YYYY, GHSA-..., PYSEC-..., etc.) and the `;` survives the
# transform untouched.
config = GoldenFlowConfig(
    transforms=[
        TransformSpec(column="vuln_id", ops=["strip", "uppercase"]),
        TransformSpec(column="aliases", ops=["strip", "uppercase"]),
    ]
)

print("Applying goldenflow transforms: strip + uppercase on vuln_id, aliases ...")
result = goldenflow.transform_df(df, config=config)
out_df = result.df

print(f"  rows out: {out_df.height:,}")
print(f"  transforms applied: {len(result.manifest.records)}")
for rec in result.manifest.records:
    print(f"    {rec.column}: {rec.transform} ({rec.affected_rows:,} rows)")

if result.manifest.errors:
    print(f"  errors: {len(result.manifest.errors)}")
    for err in result.manifest.errors:
        print(f"    {err.column}: {err.transform} row={err.row} - {err.error}")

print(f"\nWriting {DST} ...")
out_df.write_parquet(DST)

MANIFEST.write_text(
    json.dumps(
        {
            "goldenflow_version": goldenflow.__version__,
            "input": str(SRC.name),
            "output": str(DST.name),
            "rows_in": int(df.height),
            "rows_out": int(out_df.height),
            "transforms": [
                {
                    "column": rec.column,
                    "transform": rec.transform,
                    "affected_rows": int(rec.affected_rows),
                    "total_rows": int(rec.total_rows),
                }
                for rec in result.manifest.records
            ],
            "errors": [
                {"column": e.column, "transform": e.transform, "row": e.row, "error": e.error}
                for e in result.manifest.errors
            ],
        },
        indent=2,
    ),
    encoding="utf-8",
)
print(f"Wrote {MANIFEST}")
