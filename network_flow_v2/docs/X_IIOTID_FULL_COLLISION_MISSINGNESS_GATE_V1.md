# X-IIoTID full collision and missingness gate (V1)

- Full source rows read: **820,834**
- Class3: **Normal 421,417**; **Attack 399,417**
- Basic 8: **2,000 conflicting groups**,
  containing **92,954 records**.
- Core 19: **1,969 conflicting groups**,
  containing **21,866 records**.
- Note: group collisions are based on candidate feature combinations and are not necessarily erroneous labels.
- Largest difference in missingness by binary class: **Duration**,
  **15.20 percentage points**.
- The 19 columns are candidates; they have **not** yet been proven useful, leakage-free, or edge-extractable.

## Generated tables

- `reports/audits/x_iiotid_full_feature_collision_comparison_v1.csv`
- `reports/audits/x_iiotid_full_missingness_by_binary_label_v1.csv`
- `reports/audits/x_iiotid_full_missingness_by_class2_v1.csv`
- `reports/audits/x_iiotid_full_collision_missingness_gate_v1.json`

## Generated figures

- `reports/figures/x_iiotid_full_feature_collision_comparison_v1.png`
- `reports/figures/x_iiotid_full_conflicting_label_groups_v1.png`
- `reports/figures/x_iiotid_full_missingness_by_binary_label_v1.png`
- `reports/figures/x_iiotid_full_missingness_by_class2_v1.png`

## Current status

**No train/validation/test split yet. No classifier trained.** Next: inspect missingness-label associations,
source-group boundaries, and feature/gateway semantics before developing leakage-aware splits.
