# X-IIoTID: dominant Core-19 signature investigation (V1)

- Original full CSV scanned and matched Notebook 04 SQLite evidence: **820,834 rows**.
- Largest identical-feature group: **G01**, **64,194 rows**.
- Largest group class3: **Normal 0** / **Attack 64,194**.
- Basic 8 records in mixed-label groups: **92,954**.
- Core 19 records in mixed-label groups: **21,866**.
- Basic 8 group-majority *in-sample* minimum errors: **3,364**.
- Core 19 group-majority *in-sample* minimum errors: **3,246**.

## Interpreting the findings

These metrics describe ambiguity among observed feature combinations. They are **not validation accuracy, test accuracy, or proof of incorrect labels**. The network-only signatures omit session identity, raw metadata and potentially important temporal context. Missing-value patterns could also reflect capture procedures rather than attacker behaviour.

## Saved research outputs

- `reports/audits/x_iiotid_signature_ambiguity_metrics_v1.csv`
- `reports/audits/x_iiotid_dominant_group_profiles_v1.csv`
- `reports/audits/x_iiotid_dominant_signature_diagnostics_v1.json`
- `reports/figures/x_iiotid_signature_ambiguity_lower_bound_v1.png`
- `reports/figures/x_iiotid_dominant_core19_group_labels_v1.png`
- `reports/figures/x_iiotid_largest_signature_attack_categories_v1.png`

## Next research gate

Before the 70/15/15 split, verify capture/session/time/source grouping and network gateway measurability. Avoid random row-level splitting and preserve the unmodified source CSV.
