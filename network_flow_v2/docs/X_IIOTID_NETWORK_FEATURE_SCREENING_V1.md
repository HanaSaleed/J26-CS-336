# X-IIoTID network feature screening — draft v1

- Rows: 820,834
- Columns: 68
- Sample for collision diagnostics: 42,500
- Scope: screening only; no selected feature set, leakage-safe split or model trained.

## Candidate network-feature roles and quality

| Column | Proposed role | Missing/placeholder % | Numeric parse % of present |
|---|---|---:|---:|
| `Date` | METADATA_ONLY | 0.04 | — |
| `Timestamp` | METADATA_ONLY | 0.05 | — |
| `Scr_IP` | METADATA_ONLY | 0.02 | — |
| `Scr_port` | PORT_ABLATION_ONLY | 0.02 | 100.00 |
| `Des_IP` | METADATA_ONLY | 0.02 | — |
| `Des_port` | PORT_ABLATION_ONLY | 0.02 | 100.00 |
| `Protocol` | NETWORK_CORE_CANDIDATE | 0.02 | — |
| `Service` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `Duration` | NETWORK_CORE_CANDIDATE | 9.23 | 100.00 |
| `Scr_bytes` | NETWORK_CORE_CANDIDATE | 27.27 | 100.00 |
| `Des_bytes` | NETWORK_CORE_CANDIDATE | 27.27 | 100.00 |
| `Conn_state` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `missed_bytes` | NETWORK_OPTIONAL_CANDIDATE | 0.02 | 100.00 |
| `is_syn_only` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `Is_SYN_ACK` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `is_pure_ack` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `is_with_payload` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `FIN or RST` | NETWORK_CORE_CANDIDATE | 0.00 | — |
| `Bad_checksum` | EXCLUDE_CONSTANT_CHECK | 0.00 | — |
| `is_SYN_with_RST` | EXCLUDE_CONSTANT_CHECK | 0.00 | — |
| `Scr_pkts` | NETWORK_CORE_CANDIDATE | 18.61 | 100.00 |
| `Scr_ip_bytes` | NETWORK_CORE_CANDIDATE | 18.61 | 100.00 |
| `Des_pkts` | NETWORK_CORE_CANDIDATE | 18.61 | 100.00 |
| `Des_ip_bytes` | NETWORK_CORE_CANDIDATE | 18.61 | 100.00 |
| `anomaly_alert` | EXCLUDE_EXISTING_ALERT | 0.02 | — |
| `total_bytes` | NETWORK_CORE_CANDIDATE | 27.27 | 100.00 |
| `total_packet` | NETWORK_CORE_CANDIDATE | 18.61 | 100.00 |
| `paket_rate` | NETWORK_CORE_CANDIDATE | 27.27 | 100.00 |
| `byte_rate` | NETWORK_CORE_CANDIDATE | 27.27 | 100.00 |
| `Scr_packts_ratio` | NETWORK_OPTIONAL_CANDIDATE | 18.61 | 100.00 |
| `Des_pkts_ratio` | NETWORK_OPTIONAL_CANDIDATE | 18.61 | 100.00 |
| `Scr_bytes_ratio` | NETWORK_OPTIONAL_CANDIDATE | 27.27 | 100.00 |
| `Des_bytes_ratio` | NETWORK_OPTIONAL_CANDIDATE | 27.27 | 100.00 |
| `Avg_user_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_user_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_nice_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_nice_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_system_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_system_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_iowait_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_iowait_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_ideal_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_ideal_time` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_tps` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_tps` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_rtps` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_rtps` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_wtps` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_wtps` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_ldavg_1` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_ldavg_1` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_kbmemused` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_kbmemused` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_num_Proc/s` | REVIEW_SEPARATELY | 0.06 | — |
| `Std_num_proc/s` | REVIEW_SEPARATELY | 0.06 | — |
| `Avg_num_cswch/s` | REVIEW_SEPARATELY | 0.06 | — |
| `std_num_cswch/s` | REVIEW_SEPARATELY | 0.06 | — |
| `OSSEC_alert` | EXCLUDE_EXISTING_ALERT | 0.00 | — |
| `OSSEC_alert_level` | EXCLUDE_EXISTING_ALERT | 0.00 | — |
| `Login_attempt` | REVIEW_SEPARATELY | 0.00 | — |
| `Succesful_login` | REVIEW_SEPARATELY | 0.00 | — |
| `File_activity` | REVIEW_SEPARATELY | 0.00 | — |
| `Process_activity` | REVIEW_SEPARATELY | 0.00 | — |
| `read_write_physical.process` | REVIEW_SEPARATELY | 0.00 | — |
| `is_privileged` | REVIEW_SEPARATELY | 0.00 | — |
| `class1` | LABEL_ONLY | 0.00 | — |
| `class2` | LABEL_ONLY | 0.00 | — |
| `class3` | LABEL_ONLY | 0.00 | — |

## Next gate

1. Verify original feature semantics and missing-value meanings.
2. Confirm extractability at Raspberry Pi/edge gateway.
3. Investigate source/capture-based grouping and leakage-free partitioning.
4. Decide network-only compact subset, then 70/15/15, then models.
