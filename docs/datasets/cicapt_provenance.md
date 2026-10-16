# CICAPT Provenance Dataset

## 1. Dataset Overview

The CICAPT provenance dataset contains process and artifact records collected in two phases. It is being used for the device telemetry module to study process activity and relationships between processes and artifacts.

## 2. Dataset Statistics

| Record type | Phase 1 | Phase 2 |
|---|---:|---:|
| WasGeneratedBy | 136,444 | 87,636 |
| Artifact | 36,895 | 28,447 |
| Used | 22,120 | 34,206 |
| WasDerivedFrom | 11,031 | 8,471 |
| Process | 9,878 | 24,839 |
| WasTriggeredBy | 5,752 | 13,136 |
| **Total** | **222,120** | **196,735** |

Phase 1 contains 222,120 records, while Phase 2 contains 196,735 records.

## 3. Collection Period

- **Phase 1:** 27 November 2023 to 1 December 2023 (approximately 96 hours).
- **Phase 2:** 1 December 2023 to 4 December 2023 (approximately 72 hours).

There is a gap between the end of Phase 1 and the start of Phase 2. The phases should therefore be examined separately before combining their records.

## 4. Labels and Attack Activity

All 222,120 records in Phase 1 have a label of 0.

In Phase 2, 196,333 records have a label of 0 and 402 have a label of 1. The remaining records are labelled benign in the main `label` column, although their `subLabel` values identify attack tactics.

The observed attack tactic counts are:

| Tactic | Records |
|---|---:|
| credentialAccess | 151 |
| collection | 100 |
| defenceEvasion | 46 |
| discovery | 36 |
| exfiltration | 22 |
| persistence | 19 |
| CandC | 16 |
| lateralMovement | 10 |
| initialAccess | 2 |

These counts show that the attack records are highly imbalanced compared with the benign records.

## 5. Initial Process Analysis

The process analysis identified `cp` as a frequent process in Phase 2, with 14,102 process records. Initially, 12 of these records had a label of 1.

A review of process activity found 7,008 `cp` records writing to the identified attack staging folders. Only three of these were labelled as attacks in the original labels.

The investigation identified 47 attack steps. Based on the additional analysis, 14,054 process nodes were relabelled as attack-related: 14,010 `cp`, 42 `base64`, and 2 `grep` records. The number of attack-labelled process nodes increased from 213 to 14,267 out of 24,839 process nodes.

These additional labels are derived from the investigation and should be distinguished from the original dataset labels.

## 6. Labelling Considerations

The original labels do not identify all process activity associated with the observed attacks. Some processes involved in attack-related activity may still have a label of 0.

The extended labels were created using evidence from process activity and identified staging folders. Before using them for training, the labelling rules should be documented and checked to avoid introducing information that would not be available during prediction.

## 7. Data Preparation Notes

- Preserve the original dataset files.
- Keep original labels separate from investigation-derived labels.
- Check duplicate artifact declarations before combining the phases.
- Inspect process and artifact relationships before constructing features.
- Exclude identifiers or fields that could reveal the label instead of genuine attack behaviour.
- Use a suitable group-based split to reduce the risk of related process activity appearing in both training and testing data.

## 8. Current Status

The initial record counts, collection periods, labels, and process activity have been examined. Further work is required to validate the extended labels, construct model features, and evaluate detection performance using a leakage-resistant split.