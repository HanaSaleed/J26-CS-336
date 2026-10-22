# X-IIoTID — Feature Dictionary DRAFT

Source: `X-IIoTID dataset.csv`; SHA-256: `7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0`

**Unverified columns:** meaning, units, source modality, temporal window, and deployability must be documented manually.

| Feature | Numeric parse % | Numeric zeros % | Distinct >= | Missing | Placeholders | Candidate role |
|---|---:|---:|---:|---:|---:|---|
| Date | 0.0 | 0.0 | 49 | 331 | 1 | VERIFY modality/units |
| Timestamp | 99.98 | 0.0 | 10001+ | 297 | 154 | REVIEW: identifier/time/payload |
| Scr_IP | 0.0 | 0.0 | 36 | 0 | 154 | VERIFY modality/units |
| Scr_port | 99.98 | 0.0 | 10001+ | 0 | 154 | VERIFY modality/units |
| Des_IP | 0.0 | 0.0 | 96 | 0 | 154 | VERIFY modality/units |
| Des_port | 99.98 | 0.09 | 6444 | 0 | 154 | VERIFY modality/units |
| Protocol | 0.0 | 0.0 | 4 | 0 | 154 | VERIFY modality/units |
| Service | 0.0 | 0.0 | 17 | 0 | 0 | VERIFY modality/units |
| Duration | 90.77 | 0.0 | 10001+ | 0 | 75761 | VERIFY modality/units |
| Scr_bytes | 72.73 | 9.12 | 10001+ | 0 | 223871 | VERIFY modality/units |
| Des_bytes | 72.73 | 21.43 | 10001+ | 0 | 223871 | VERIFY modality/units |
| Conn_state | 100.0 | 14.84 | 2 | 0 | 0 | VERIFY modality/units |
| missed_bytes | 99.98 | 99.94 | 231 | 0 | 154 | VERIFY modality/units |
| is_syn_only | 0.0 | 0.0 | 2 | 0 | 0 | VERIFY modality/units |
| Is_SYN_ACK | 0.0 | 0.0 | 2 | 0 | 0 | VERIFY modality/units |
| is_pure_ack | 0.0 | 0.0 | 2 | 0 | 0 | VERIFY modality/units |
| is_with_payload | 0.0 | 0.0 | 2 | 0 | 0 | REVIEW: identifier/time/payload |
| FIN or RST | 0.0 | 0.0 | 2 | 0 | 0 | VERIFY modality/units |
| Bad_checksum | 0.0 | 0.0 | 1 | 0 | 0 | VERIFY modality/units |
| is_SYN_with_RST | 0.0 | 0.0 | 1 | 0 | 0 | VERIFY modality/units |
| Scr_pkts | 81.39 | 0.01 | 1211 | 0 | 152743 | VERIFY modality/units |
| Scr_ip_bytes | 81.39 | 0.01 | 10001+ | 0 | 152743 | VERIFY modality/units |
| Des_pkts | 81.39 | 21.22 | 1556 | 0 | 152743 | VERIFY modality/units |
| Des_ip_bytes | 81.39 | 21.22 | 10001+ | 0 | 152743 | VERIFY modality/units |
| anomaly_alert | 0.0 | 0.0 | 3 | 0 | 154 | VERIFY modality/units |
| total_bytes | 72.73 | 0.0 | 10001+ | 0 | 223872 | VERIFY modality/units |
| total_packet | 81.39 | 0.0 | 2216 | 0 | 152743 | VERIFY modality/units |
| paket_rate | 72.73 | 0.0 | 10001+ | 0 | 223871 | VERIFY modality/units |
| byte_rate | 72.73 | 0.0 | 10001+ | 0 | 223872 | VERIFY modality/units |
| Scr_packts_ratio | 81.39 | 0.01 | 10001+ | 0 | 152743 | VERIFY modality/units |
| Des_pkts_ratio | 81.39 | 21.22 | 10001+ | 0 | 152743 | VERIFY modality/units |
| Scr_bytes_ratio | 72.73 | 0.0 | 10001+ | 0 | 223872 | VERIFY modality/units |
| Des_bytes_ratio | 72.73 | 12.56 | 10001+ | 0 | 223872 | VERIFY modality/units |
| Avg_user_time | 99.94 | 0.0 | 10001+ | 0 | 482 | REVIEW: identifier/time/payload |
| Std_user_time | 99.94 | 0.0 | 10001+ | 0 | 480 | REVIEW: identifier/time/payload |
| Avg_nice_time | 99.94 | 0.0 | 4551 | 0 | 480 | REVIEW: identifier/time/payload |
| Std_nice_time | 99.94 | 0.0 | 10001+ | 0 | 480 | REVIEW: identifier/time/payload |
| Avg_system_time | 99.94 | 0.0 | 5174 | 0 | 485 | REVIEW: identifier/time/payload |
| Std_system_time | 99.94 | 0.0 | 10001+ | 0 | 485 | REVIEW: identifier/time/payload |
| Avg_iowait_time | 99.94 | 0.05 | 10001+ | 0 | 485 | REVIEW: identifier/time/payload |
| Std_iowait_time | 99.94 | 0.05 | 10001+ | 0 | 485 | REVIEW: identifier/time/payload |
| Avg_ideal_time | 99.94 | 0.0 | 10001+ | 0 | 480 | REVIEW: identifier/time/payload |
| Std_ideal_time | 99.94 | 0.0 | 10001+ | 0 | 480 | REVIEW: identifier/time/payload |
| Avg_tps | 99.94 | 0.0 | 3736 | 0 | 492 | VERIFY modality/units |
| Std_tps | 99.94 | 1.4 | 10001+ | 0 | 492 | VERIFY modality/units |
| Avg_rtps | 99.94 | 16.83 | 2254 | 0 | 492 | VERIFY modality/units |
| Std_rtps | 99.94 | 16.83 | 10001+ | 0 | 492 | VERIFY modality/units |
| Avg_wtps | 99.94 | 0.0 | 2017 | 0 | 492 | VERIFY modality/units |
| Std_wtps | 99.94 | 3.97 | 10001+ | 0 | 492 | VERIFY modality/units |
| Avg_ldavg_1 | 99.94 | 0.0 | 2814 | 0 | 526 | VERIFY modality/units |
| Std_ldavg_1 | 99.94 | 0.28 | 3450 | 0 | 526 | VERIFY modality/units |
| Avg_kbmemused | 99.86 | 0.0 | 10001+ | 0 | 483 | VERIFY modality/units |
| Std_kbmemused | 99.86 | 0.0 | 10001+ | 0 | 483 | VERIFY modality/units |
| Avg_num_Proc/s | 99.94 | 16.08 | 1061 | 0 | 479 | VERIFY modality/units |
| Std_num_proc/s | 99.94 | 17.96 | 3649 | 0 | 479 | VERIFY modality/units |
| Avg_num_cswch/s | 99.94 | 0.0 | 10001+ | 0 | 479 | VERIFY modality/units |
| std_num_cswch/s | 99.94 | 0.0 | 10001+ | 0 | 479 | VERIFY modality/units |
| OSSEC_alert | 100.0 | 94.88 | 2 | 0 | 0 | VERIFY modality/units |
| OSSEC_alert_level | 100.0 | 94.88 | 6 | 0 | 0 | VERIFY modality/units |
| Login_attempt | 100.0 | 91.27 | 2 | 0 | 0 | VERIFY modality/units |
| Succesful_login | 100.0 | 91.73 | 2 | 0 | 0 | VERIFY modality/units |
| File_activity | 100.0 | 92.73 | 2 | 0 | 0 | VERIFY modality/units |
| Process_activity | 100.0 | 91.74 | 2 | 0 | 0 | VERIFY modality/units |
| read_write_physical.process | 100.0 | 64.47 | 2 | 0 | 0 | VERIFY modality/units |
| is_privileged | 100.0 | 91.75 | 2 | 0 | 0 | VERIFY modality/units |
