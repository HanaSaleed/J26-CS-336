# Three-Dataset Temporal and Source Integrity Gate — V1

Dataset operations: **read-only**; training and split generation: **not performed**.

## Edge-IIoTset `frame.time` representation

| Pattern | Records |
|---|---:|
| ipv4_like | 14,498 |
| numeric_like | 1,214 |
| year_prefix_datetime_like | 142,088 |

CSV records inspected: **157,800**. Field-count issue examples: **0** (limited to first 20).

Temporal readiness: **REVIEW REQUIRED** — confirm original export semantics, capture ordering, device identity and window-level labels.

## X-IIoTID timestamp evidence

- Rows examined: **820,834**
- Plausible epoch seconds: **820,383**
- Invalid/nonplausible timestamps: **451**
- Distinct candidate seconds: **218,988**
- Adjacent descending timestamps (raw file order): **410,088**
- Temporal readiness: **REVIEW REQUIRED** — corroborate capture/session and timestamp-to-label relationships.

## ToN-IoT

- The downloaded CSV does not provide a verified event timestamp.
- `duration` is a duration, not a window start time.
- 5/10/15/20-second aggregation is **not supported** by this CSV as-is.

## Next decision

Run dataset-specific static intrusion-classification baselines with group-/capture-aware partitions where possible; do not claim independent temporal/cross-dataset detection until provenance and feature meanings are verified.
