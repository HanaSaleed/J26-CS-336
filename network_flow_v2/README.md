# IIoT Network Flow Detection - V2

Research Project: J26-CS-336

## Research Objective

Develop lightweight ensemble-based network intrusion
classification for APT-related behaviour detection
in IIoT edge environments.

## Datasets

1. Edge-IIoTset - Primary benchmark
2. X-IIoTID - Secondary validation
3. ToN-IoT - Existing baseline / comparison

## Workflow

1. Dataset inventory and auditing
2. Data cleaning
3. Feature understanding
4. Common-feature harmonization
5. Train / Validation / Test splitting
6. Train-only preprocessing
7. Individual ML models
8. Lightweight ensemble
9. Model evaluation
10. Streamlit dashboard

## Future Integration

Ubuntu IIoT simulation
Raspberry Pi edge inference
Network and telemetry evidence integration

<!-- BEGIN NETWORK_FLOW_V2_DATASET_AND_TEMPORAL_PLAN -->

## Network Flow V2 — Three-Dataset Comparison and Experimental Protocol

> **Evidence status (22 October 2026):** All counts and quality findings in this section are from our local Step 01/02 notebook outputs for the **downloaded CSV files**, not necessarily the full original dataset releases. The datasets have **not** yet been normalized, split, jointly harmonized, or evaluated under one new V2 protocol. Any candidate feature equivalence or timestamp use below remains subject to verification.

### 1. Dataset inventory and class balance

| Property | Edge-IIoTset (selected ML CSV) | ToN-IoT (network train/test CSV) | X-IIoTID |
|---|---:|---:|---:|
| Filename | `ML-EdgeIIoT-dataset.csv` | `ton_iot_train_test_network.csv` | `X-IIoTID dataset.csv` |
| Approx. file size | 78.38 MB | 28.52 MB | 338.85 MB |
| Total rows | **157,800** | **211,043** | **820,834** |
| Total columns | 63 | 44 | 68 |
| Non-label candidate columns | 61 | 42 | 65 |
| Binary label | `Attack_label` (`0` normal, `1` attack) | `label` (`0` normal, `1` attack) | `class3` (`Normal`, `Attack`) |
| Attack-type / category labels | `Attack_type` | `type` | `class1` detailed; `class2` broader |
| Normal rows | **24,301** | **50,000** | **421,417** |
| Attack rows | **133,499** | **161,043** | **399,417** |
| Normal share | **15.40%** | **23.69%** | **51.34%** |
| Attack share | **84.60%** | **76.31%** | **48.66%** |
| Attack : normal ratio | **5.49 : 1** | **3.22 : 1** | **1 : 1.06** |
| Attack classes (excluding normal) | 14 | 9 | 18 detailed (`class1`); 9 broad (`class2`) |
| Observation caveat | Packet/protocol-style features; a flow schema is not yet proven | Connection/flow-style features; no timestamp in this CSV | Mixed network, host-resource and security features |

**Do not pool these rows into one CSV.** They use different observation units, collection environments, class vocabularies and feature definitions. Start with independent within-dataset baselines; examine cross-dataset transfer only for *verified* compatible features.

### 2. Data quality audit

| Check | Edge-IIoTset | ToN-IoT | X-IIoTID |
|---|---:|---:|---:|
| Rows in full-record duplicate groups | 821 | 27,739 | 11,835 |
| Excess identical copies beyond one per group | **814** | **20,569** | **6,222** |
| Excess copies as % of rows | 0.52% | 9.75% | 0.76% |
| Conflicting labels in identical full candidate-feature groups | 0 binary conflicts reported | 0 binary/category conflicts reported | 0 across `class1`, `class2`, `class3` |
| Binary vs category-label inconsistency | 0 | 0 | 0 for all 820,834 records on both broad and detailed mappings |
| Constant non-label features found | 8 | 0 | 2 |
| Examples of zero-heavy / sparse features | Modbus, DNS, MQTT and several TCP/HTTP fields | HTTP body/status, `missed_bytes`, `dns_rcode` | `missed_bytes` |
| Nulls / placeholder caveat | Numeric zero may mean absent protocol field | Many string placeholders despite reported 0 nulls | 331 missing `Date`; 297 missing `Timestamp`; many numeric placeholders |
| Status | Audit complete; feature semantics pending | Audit complete; placeholder interpretation pending | Audit complete; network-vs-host separation pending |

**Duplicate policy:** Do not indiscriminately delete repeated network observations. Preserve raw files, assess whether repetitions are legitimate, and prevent duplicate *feature* groups from crossing train/validation/test partitions. Re-check feature-duplicate overlap after the final feature set is chosen.

**Missing-value policy:** Blank, `-`, `?`, non-numeric placeholders and protocol-not-applicable values must be distinguished from a genuine measurement of zero. Missing-value handling and any scaling/encoding are fitted on **training data only**.

### 3. Label definitions for model training and evaluation

| Dataset | Binary task | Attack-type task | Never include as input features (`X`) |
|---|---|---|---|
| Edge-IIoTset | `Attack_label`: 0/1 | `Attack_type`: Normal + 14 attack types | `Attack_label`, `Attack_type` |
| ToN-IoT | `label`: 0/1 | `type`: normal + 9 attack types | `label`, `type` |
| X-IIoTID | `class3`: Normal/Attack | `class1`: detailed; `class2`: broad attack stage/category | `class1`, `class2`, `class3` |

- **Training:** Fit a binary model on `X_train` and `y_train_binary`. A separate multiclass model may be fitted on `y_train_type` if categories are sufficiently supported.
- **Validation:** Predict using `X_val` only; use `y_val` **after prediction** for feature/model/threshold selection. Do not tune on final test labels.
- **Testing:** Freeze the entire preprocessing/model/threshold pipeline first. Predict from `X_test` only; reveal `y_test` for final reporting, not for improving the model.
- **Cross-dataset tests:** Only compare categories with defensible mappings. Broad labels such as `Reconnaissance` are not automatically the same as a dataset's specific `scanning` class.

### 4. Train / validation / test plan (70 / 15 / 15)

| Partition | Target share | Ground-truth labels available? | Model access to label? | Purpose |
|---|---:|---|---|---|
| Training | **70%** | Yes | Yes, as supervised target `y_train` only | Fit preprocessing and classifiers |
| Validation | **15%** | Yes | **No**: only scorer uses `y_val` | Hyperparameters, feature selection, threshold / ensemble selection |
| Testing | **15%** | Yes | **No**: only final scorer uses `y_test` | Independent final evaluation after all choices are frozen |

**Illustrative row counts only** (before duplicate-group and capture/time-aware constraints):

| Dataset | Approx. training (70%) | Approx. validation (15%) | Approx. testing (15%) |
|---|---:|---:|---:|
| Edge-IIoTset | 110,460 | 23,670 | 23,670 |
| ToN-IoT | 147,730 | 31,656 | 31,657 |
| X-IIoTID | 574,584 | 123,125 | 123,125 |

**Actual counts have not been assigned yet.** Where sessions, captures, devices, attack scenarios or timestamps allow, prefer **group-disjoint and/or chronological holdouts**, even if the final percentages are approximate. Never distribute copies of the same recorded event across partitions. Save a split manifest, random seeds, split rationale, version/hash, and class counts; keep the final test partition untouched.

### 5. Temporal experiments: 5 s / 10 s / 15 s / 20 s

A **time window** is a period over which observations from a device or network flow are summarized; it is **not** the 70/15/15 data split. For example, a 10-second window may summarize the number of connections, transmitted bytes, unique destination ports and TCP resets observed for an asset **during those 10 seconds**.

| Window | Example behavior to measure | Proposed experiment |
|---|---|---|
| **5 seconds** | Fast bursts, short connection or scanning spikes | Short-window features, detection and cost |
| **10 seconds** | Traffic rate changes, repeated connections | Short/medium behavior comparison |
| **15 seconds** | More context for repeated communication | Compare recall and false alarms |
| **20 seconds** | Longer short-term context; fewer windows | Compare detection vs delay trade-off |

All four durations are **planned research variants**, not completed training experiments. Start with **non-overlapping, causal/tumbling windows** anchored to verified capture time; overlapping windows, if later evaluated, need special care because they share the same events.

**Can we build trustworthy timed windows from each downloaded CSV?**

| Source | Time-related columns in current CSV | Verified 5/10/15/20-second reconstruction? | Next action |
|---|---|---|---|
| Edge-IIoTset | `frame.time` (observed as text in full feature scan) | **Not yet** | Parse sample timestamps; check units, chronological order, capture boundary and whether rows correspond to timestamped events |
| X-IIoTID | `Date`, `Timestamp` (some missing/placeholder values) | **Not yet** | Verify timestamp units, clock basis, asset identity, capture/scenario separation and coverage |
| ToN-IoT network CSV | **No event timestamp column found** | **No, not from this CSV alone** | Use this release for static connection classification; obtain verified original time-stamped source data or produce new lab captures for time-window experiments |
| Controlled Ubuntu/IIoT simulation + PCAP | To be collected with capture timestamp and asset identifiers | **Future source** | Collect and document synchronized benign/attack runs with trustworthy ground truth |

**Temporal labeling and leakage safeguards:**

1. Verify timestamps, time zone/clock basis, sorting and source/capture boundaries **before** aggregation.
2. Define the asset or flow identity, window alignment, empty-window policy and treatment of late packets.
3. Partition by independent capture/session/scenario or a justified chronological boundary **before building overlapping or related windows**. Do not allow observations from the same recorded event or attack run to leak into a held-out partition.
4. Only assign attack labels to windows when source ground truth is temporally attributable. Define how mixed normal/attack windows are handled; mark uncertain windows unknown rather than inventing truth.
5. Calculate features using only events available **at or before** the end of the current window. Report detection/processing latency separately from the configured window duration.
6. Train and evaluate a model on the **same window-feature schema** used during inference on Raspberry Pi. Existing static ToN-IoT models cannot be used directly with an unrelated window extractor.
7. Compare 5/10/15/20-second windows using held-out scenarios and metrics such as recall, precision, F1, PR-AUC, false alarms per time unit, CPU/RAM and end-to-end alert delay.

### 6. Draft feature mapping (not yet certified)

| Canonical concept | Edge-IIoTset | ToN-IoT | X-IIoTID | Current decision |
|---|---|---|---|---|
| Flow duration | No verified directly equivalent flow field | `duration` | `Duration` | **Candidate ToN/X match**; verify units and definition |
| Source bytes | No verified flow total (`tcp.len` is not the same quantity) | `src_bytes` | `Scr_bytes` | **Candidate ToN/X match**; check missing/placeholder values |
| Destination bytes | No verified flow total | `dst_bytes` | `Des_bytes` | **Candidate ToN/X match** |
| Source packets | No verified flow total | `src_pkts` | `Scr_pkts` | **Candidate ToN/X match** |
| Destination packets | No verified flow total | `dst_pkts` | `Des_pkts` | **Candidate ToN/X match** |
| Connection state | No verified equivalent | `conn_state` | `Conn_state` | **Candidate ToN/X match**; verify category vocabulary |
| Transport protocol | TCP/UDP/ICMP-specific packet fields | `proto` | `Protocol` | Need shared extraction/encoding rules |
| Source / destination port | `tcp.srcport`, `tcp.dstport` (TCP-specific) | `src_port`, `dst_port` | `Scr_port`, `Des_port` | Not automatically equivalent; ablate ports to expose shortcuts |
| Event time | `frame.time` | Missing | `Date`, `Timestamp` | Cannot create comparable 3-way temporal features from current files |
| Host CPU/system telemetry | Not confirmed in selected ML CSV | Not in this network CSV | `Avg_user_time`, etc. | Exclude from network-only baseline; potential separate telemetry module |
| Physical-sensor values | Not verified | Not in this network CSV | `read_write_physical.process` is an activity indicator, not necessarily a physical value | Separate physical-sensor collection/verification required |

Never treat similarly named columns as equivalent **solely because their names look alike**. Check measurement units, time unit, direction, packet/flow granularity, handling of zeros, and whether a future gateway can calculate them without knowing the attack label.

### 7. Model plan and reporting tables

| Experiment | Inputs | Prediction target | Comparison |
|---|---|---|---|
| Baseline: Decision Tree | Dataset-specific verified network features | Binary normal/attack | Basic benchmark |
| Random Forest | Same dataset, partition and feature set | Binary, optional multiclass | Compare detection and cost |
| Extra Trees | Same controlled conditions | Binary, optional multiclass | Complementary tree classifier |
| LightGBM | Same controlled conditions | Binary, optional multiclass | Speed / accuracy trade-off |
| AdaBoost | Same controlled conditions | Binary, optional multiclass | Ensemble candidate |
| Selected lightweight ensemble | Validation-selected subset only | Binary; separate attack type where supported | Must outperform or justify overhead versus best single model |
| Cross-dataset transfer | Verified common features only | Compatible binary and/or mapped attack categories | Measure generalization, not same-set accuracy |
| Time-window ablation | 5, 10, 15, 20 seconds from **verified time-stamped source** | Attack/behavior label with defensible temporal ground truth | Accuracy–latency–resource trade-off |

**Dashboard results to publish after experiments:** dataset version/hash; class distributions; feature quality; selected schema; exact split method and counts; confusion matrix; per-class precision/recall/F1; PR-AUC; false-positive rate; model size/inference cost; best single model vs ensemble; timing-window comparison; limitations. **No model metrics or 5/10/15/20-second results are claimed yet.**

### 8. Next actions

1. Verify this mapping against source feature definitions and timestamp examples; distinguish network-only from host-telemetry variables.
2. Finalize a leakage-aware split policy for each dataset and lock held-out test partitions.
3. Build reproducible train-fitted preprocessing, first for the Edge-IIoTset network baseline.
4. Train Decision Tree, then compare the remaining candidates and a small validation-selected ensemble.
5. Build temporal windows only where source timestamps, session boundaries and labels support them; otherwise use controlled Ubuntu captures.
6. Update the Streamlit dashboard using reproducible saved metric reports, not illustrative values.

<!-- END NETWORK_FLOW_V2_DATASET_AND_TEMPORAL_PLAN -->
