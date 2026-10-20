# TON_IoT GPS tracker: training profile

## Scope

This check profiles GPS values only within the 31,437 one-second timestamps shared by all six telemetry sensors. Rows within a second were aggregated as in the fusion experiment: median for numeric readings. The profile uses the training portion only (through 2019-04-26 inclusive): 21,452 seconds, comprising 19,467 normal and 1,985 attack seconds. The original CSV was read-only.

## Training values by binary label

| Class | Rows | Latitude median | Latitude p10–p90 | Longitude median | Longitude p10–p90 |
|---|---:|---:|---:|---:|---:|
| Normal | 19,467 | 553.85 | 5.65–1,197.44 | 563.91 | 15.67–1,200.59 |
| Attack | 1,985 | 53.70 | 9.56–98.49 | 63.89 | 20.08–105.19 |

## Date pattern

In the matched training seconds, attacks occur only on April 25–26. Most normal seconds occur on March 31–April 4. The daily median latitude/longitude values also move substantially across the normal-only days: for example, April 2 is 128.85/138.29, April 3 is 699.51/707.67, and April 4 is 1,230.30/1,235.82. On April 25, normal and attack seconds have medians of 19.39/28.56 and 79.94/89.38 respectively; April 26 contains 1,048 attack seconds and no normal seconds in this matched cohort.

## Interpretation and limits

GPS coordinates dominated the fused models' training-only feature rankings, but this profile shows a strong relationship between the values and recording date as well as label. The TON_IoT paper describes the GPS service as simulated and its telemetry labels as assigned using attack timestamps. The observed relationship may therefore reflect the simulated trajectory and attack schedule rather than a general physical signal of compromise. This is an interpretation of the observed data, not a causal finding.

Although the columns are named latitude and longitude, the processed values reach roughly 1,200. Their physical coordinate units or transformation should be checked against the original feature documentation before describing them as real-world locations. For now, the experiment treats them only as numeric telemetry fields.

Do not use this reviewed holdout for further model selection. A fresh campaign, device, or independent dataset is needed for a final generalization claim.

## Reproducible files

- Script: `experiments/physical_sensor/profile_fusion_training_gps.py`
- By-label summary: `docs/results/ton_iot_sensor_fusion_training_gps_by_label.csv`
- By-day summary: `docs/results/ton_iot_sensor_fusion_training_gps_by_day.csv`

## Sources

- [UNSW TON_IoT dataset page](https://research.unsw.edu.au/projects/toniot-datasets)
- Alsaedi et al., [TON_IoT Telemetry Dataset (2020)](https://doi.org/10.1109/ACCESS.2020.3022862), especially the GPS simulation algorithm and the attack-timestamp labeling description.

## GPS ablation validation feasibility

A GPS-versus-no-GPS ablation was not accepted as a model comparison because the matched six-sensor training cohort does not support a credible chronological validation split. The shared cohort has 31,437 seconds overall; within the training period through 2019-04-26, 21,452 seconds remain, with attacks concentrated on April 25–26 and normal data mostly on earlier dates. Before April 25 there are no attack seconds in the matched cohort. On April 25, there are 494 normal and 937 attack seconds, but these occur in campaign-specific time blocks. A scan of all within-day chronological cutoffs found no split with at least 50 seconds of each class in both training and validation; after the training block contains 50 attack seconds, no more than 5 normal seconds can remain for validation.

A preliminary cutoff at 2019-04-25 09:00:53 yielded only 2 normal seconds among 577 validation seconds. Its model metrics are therefore not reported or used for feature decisions. Randomly dividing seconds could put adjacent records from the same campaign on both sides and give an overly optimistic result. The GPS ablation is deferred until a suitable independent campaign or dataset is available. The previously reviewed post-April-26 holdout remains excluded from further model selection.
