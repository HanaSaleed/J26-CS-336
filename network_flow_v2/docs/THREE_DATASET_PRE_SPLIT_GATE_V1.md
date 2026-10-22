# Three-Dataset Pre-Split Compatibility Gate (V1)

## Current decision
- **Edge-IIoTset:** train a dataset-specific packet/protocol baseline; do NOT assume its fields are pre-aggregated flows.
- **X-IIoTID + ToN-IoT:** promising *candidate* flow statistics; semantics, units, directions, placeholder handling and live gateway feasibility require source validation.
- **Time windows (5/10/15/20 s):** NOT approved on any file yet; no genuine event timestamps in the downloaded ToN-IoT CSV; inspect mixed `frame.time` in Edge-IIoTset; verify capture meaning for X-IIoTID.
- **Splits:** plan 70/15/15 within each dataset, but group/session/time-aware logic and final source provenance are prerequisites. Do not train preprocessing on validation/test partitions.
- **Models:** binary Normal/Attack first; multiclass labels differ between datasets and require separate schemas.

## What this does not establish
Column name similarity does not imply equivalent feature meaning. File order does not establish chronology. A dataset's attack class is not a proven complete APT campaign.

## Saved diagnostic outputs
- `reports/audits/ton_x_flow_candidate_quality_v1.csv`
- `reports/audits/three_dataset_pre_split_gate_v1.json`

## Manual verification actions
1. Review source documentation for each candidate feature (direction, measurement unit, packet vs flow semantics).
2. Verify whether group/session/capture identifiers and timestamp ordering can be reconstructed.
3. Investigate placeholder values `-` and missingness per attack category; do not convert them all to zero.
4. Freeze a leakage-aware split policy; use train-only encoders/imputers/scalers.
5. Reserve binary/multiclass benchmarks and temporal-window experiments as distinct studies until they can be linked with verified evidence.
