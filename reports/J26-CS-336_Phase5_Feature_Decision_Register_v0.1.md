# J26-CS-336 — Phase 5 Feature Decision Register (v0.1)

**Individual component:** Lightweight Ensemble-Based Network Flow Classification for APT Detection in IIoT Edge Gateways  
**Date:** 2026-10-16  
**Status:** PROVISIONAL — evidence-based candidate design, not final preprocessing rules.  
**Source files:** `cicapt_IIOT_phase1_NetworkData.csv`, `cicapt_IIOT_phase2_NetworkData.csv`, publisher-provided Python source (`Feature_extraction.py`, `Supporting_functions.py`, `Connectivity_features.py`), `attack_info.csv`.  
**Sample scope for this register:** First 100,000 Phase 2 records, unless stated otherwise. The previous full-file audit covered all Phase 1 and Phase 2 records but did not validate feature meanings.

## 1. Verified observations

| Evidence | Phase 2 sample result | Implication |
|---|---:|---|
| Rows inspected | 100,000 | Sample only; file-order selection |
| Normal/attack labels | 99,986 / 14 | Class imbalance; do not assess quality from accuracy alone |
| `IAT` > 1e9 and close to `ts` | 5,002 | Cannot directly treat raw IAT as a standard inter-arrival interval |
| `flow_idle_time` > 1e9 and close to `ts` | 1,330 | Cannot directly use as true idle duration |
| `max_duration` > 1e9 | 100,000 | Source code uses absolute packet timestamps for the maximum |
| `min_duration` > 1e9 | 100,000 | Source code uses absolute packet timestamps for the minimum |
| `average_duration` > 1e9 | 100,000 | Source code computes a mean of absolute timestamps |
| `flow_active_time == flow_duration` | 100,000 | Redundant in sample; do not count as independent evidence |
| `Number` range | 0–19 for all sampled rows | Publisher code resets a packet-size collection at 20; not a standard per-flow packet count |
| Frequent `Duration` values | 64, 127, 1, 63, 0, 255 | Source helper returns IPv4 TTL, not elapsed flow duration |
| TCP cumulative-count mapping | Code maps FIN→`ack_count`, RST→`fin_count`, PSH→`urg_count`, ACK→`rst_count` | Do not assume the cumulative counter names mean their literal TCP flags |

Evidence source: User's output from `05_verify_cicapt_feature_quality.py --sample 100000`, plus the uploaded Python source. The source files are useful evidence but have differences from the exported 70-column CSV, so the exact export lineage has not been proven.

## 2. Column decisions for the NEXT experiment

**A. Retain as event/aggregation inputs, conditional on checking their row semantics**

| CICAPT column | Intended use | Rule |
|---|---|---|
| `ts` | UTC event-time window assignment | Use only if original timestamp semantics and event granularity are sufficiently verified; do not feed raw epoch time to the model |
| `Source IP`, `Destination IP` | Group observed communications; calculate address diversity and per-device counts | Do not feed raw address strings or numeric address identifiers into baseline classifier |
| `Source Port`, `Destination Port` | Create communication keys and unique destination-port counts | Prefer window-level counts/diversity; avoid learning a single hard-coded attacker port |
| `Protocol Type` | TCP/UDP/other distribution | Verify per-record semantics and use consistently with deployment |
| `Tot size` | Candidate per-record observed frame/packet size | Verify the exported CSV has genuine per-packet rows; the uploaded code uses `len(eth)` |
| `syn_flag_number`, `ack_flag_number`, `rst_flag_number`, `fin_flag_number`, `psh_flag_number` | Candidate current-packet TCP flag bits | Only after verifying their values against protocol and (ideally) original packet captures; do not confuse with cumulative counters |
| `label`, `subLabel`, `subLabelCat` | Ground truth / metadata for evaluation only | NEVER model input features |

**B. Exclude as direct baseline ML input for now**

`IAT`, `flow_idle_time`, `max_duration`, `min_duration`, `sum_duration`, `average_duration`, `std_duration`, `Duration`, `Header_Length`, `Number`, `ack_count`, `syn_count`, `fin_count`, `urg_count`, `rst_count`, `flow_active_time`, and raw absolute `ts`.

Reasoning: timing artifacts, misleading labels, cumulative flow-state calculations, or information that can be recomputed consistently. `flow_duration`, `Rate`, `Srate`, `Drate`, and packet-size summary columns should also NOT be imported into a new window model as-is: recompute from trusted event data or explicitly validate their definitions first. Other unreviewed columns remain excluded from the v0.1 feature set rather than implicitly approved.

## 3. Proposed *new* window-level feature definitions

These are definitions for the experiment; they are NOT claims about what existing CICAPT columns already mean.

For each observation duration `W ∈ {5, 10, 15, 20}` seconds, begin with **non-overlapping, event-time-aligned windows**. Proposed UTC window start: `floor(epoch_seconds / W) * W`. Define the end as `start + W`; process timestamps in `[start, end)` to avoid double counting boundaries.

| New feature | Definition | Runtime computable? |
|---|---|---|
| `window_seconds` | W seconds | Yes; useful for unified window-aware model, not required for each duration-specific model |
| `packet_count` | Number of verified packet events observed within the window and selected scope | Yes |
| `total_bytes` | Sum of frame/packet sizes, consistently defined | Yes |
| `mean_packet_size` | `total_bytes / packet_count` when count > 0 | Yes |
| `tcp_packet_count`, `udp_packet_count` | Counts by observed IP protocol | Yes |
| `syn_packet_count`, `rst_packet_count`, `ack_packet_count` | Sum of **verified packet flag bits** within the window | Yes |
| `unique_dst_ports` | Number of distinct destination ports in chosen scope | Yes |
| `unique_dst_ips` | Number of distinct destination addresses in chosen scope | Yes |
| `flow_count` | Number of distinct flow keys observed within the window, subject to flow definition | Yes |
| `mean_iat_seconds` | Average consecutive timestamp gaps for eligible events in the defined sequence | Yes, if timestamps are reliable and events are ordered |
| `packet_rate_per_second` | `packet_count / W` | Yes |
| `byte_rate_per_second` | `total_bytes / W` | Yes |

**Scope must be documented:** per host / per flow / per gateway view. Mixing different scopes silently creates non-comparable feature vectors. Initial preferred definitions should support per-asset traffic windows and flow-derived summaries while retaining flow IDs for evidence.

**Flow key** (provisional): `(source_ip, source_port, destination_ip, destination_port, ip_protocol)`; handle return-direction packets intentionally. Choose and document a canonical bidirectional grouping scheme if both directions are combined. Do not silently infer bidirectionality from reversed tuples.

**Window/flow boundaries:** Decide how to count a flow crossing windows. For the first version, count packets observed in each window, keep a separate stable flow ID, and do not assign packets based on the flow's final end time. Later validate session-based features.

## 4. Labels, test splits, and deployment alignment

- Original CICAPT attack labels are a *source-provided claim* and have been compared with 58 Caldera metadata records. In a 100,000-row Phase 2 sample, 14 attack-labeled records referred to traffic between `172.16.63.128` and `172.16.65.128`, with matching nearest metadata text but no independently verified per-packet causal mapping.
- A labeled packet is not proof that every entire 5/10/15/20-second window containing it is malicious. Define a transparent window-labeling policy, preserve individual packet labels, and flag mixed normal/attack windows.
- Distinct event-time windows require complete time coverage. The first 100,000 CSV rows cannot be treated as *complete* chronological windows because the Phase 2 full-file audit found 59 adjacent timestamp decreases; the first row is not the earliest time.
- Do not train and test on related windows of the same campaign in different partitions. Group by scenario/session where possible to prevent leakage.
- Prefer supervised experiments on trusted lab-generated data for 5/10/15/20-second windows. Published datasets that do not support trustworthy window reconstruction may still support separate flow-level evaluation.
- Training, validation, testing, and Raspberry Pi inference must use the same extraction code, feature order, units, missing-value policy, and window duration semantics.

## 5. Next validation gates (not yet completed)

1. Verify whether each CICAPT CSV row is truly one packet event or some aggregated/transformed record; uploaded source and export schema are not identical.
2. Validate packet size and TCP flag fields against original PCAP samples or publisher's confirmed export specification wherever possible.
3. Define source/asset scope, bidirectional flow grouping, and empty/incomplete window handling.
4. Choose whether published CICAPT can support truthful time-window experiments, or use it only for qualified cross-dataset evaluation.
5. Implement and unit-test one reusable, streaming feature extractor for 5, 10, 15, 20 seconds using synthetic data first, then controlled timestamped testbed captures.
6. Create leakage-aware train/validation/test partitions; compare Decision Tree, Random Forest, Extra Trees, LightGBM, AdaBoost and a lightweight complementary ensemble.

**No source CSVs were modified. No model accuracy or timing benchmark is claimed by this register.**
