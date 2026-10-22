# Three-dataset feature mapping — DRAFT

**Warning:** Similar names do not prove equivalent measurement units, granularity or meaning.
**No three-way unified feature set has been verified.**

| Concept | ToN-IoT | X-IIoTID | Edge-IIoTset | Status |
| --- | --- | --- | --- | --- |
| source_ip | src_ip | Scr_IP | ip.src_host | IDENTIFIER_ONLY |
| destination_ip | dst_ip | Des_IP | ip.dst_host | IDENTIFIER_ONLY |
| source_port | src_port | Scr_port | tcp.srcport | PROTOCOL_SPECIFIC |
| destination_port | dst_port | Des_port | tcp.dstport | PROTOCOL_SPECIFIC |
| network_protocol | proto | Protocol | — | POTENTIAL_TON_X |
| service | service | Service | — | POTENTIAL_TON_X |
| flow_duration | duration | Duration | — | POTENTIAL_TON_X |
| source_payload_bytes | src_bytes | Scr_bytes | — | POTENTIAL_TON_X |
| destination_payload_bytes | dst_bytes | Des_bytes | — | POTENTIAL_TON_X |
| missed_bytes | missed_bytes | missed_bytes | — | POTENTIAL_TON_X |
| source_packets | src_pkts | Scr_pkts | — | POTENTIAL_TON_X |
| destination_packets | dst_pkts | Des_pkts | — | POTENTIAL_TON_X |
| source_ip_bytes | src_ip_bytes | Scr_ip_bytes | — | POTENTIAL_TON_X |
| destination_ip_bytes | dst_ip_bytes | Des_ip_bytes | — | POTENTIAL_TON_X |
| connection_state | conn_state | Conn_state | — | POTENTIAL_TON_X |
| tcp_syn_signal | — | is_syn_only | tcp.connection.syn | PROTOCOL_SPECIFIC |
| packet_or_capture_time | — | Timestamp | frame.time | TIME_NOT_EQUIVALENT |
| dns_query | dns_query | — | dns.qry.name | PROTOCOL_SPECIFIC |
| http_method | http_method | — | http.request.method | PROTOCOL_SPECIFIC |
| tcp_payload_length | — | — | tcp.len | OTHER |

## Requirements before training
- Verify published feature meanings and units.
- Verify X-IIoTID missing-token representations in numeric traffic/host data.
- Separate network from host/process/sensor features.
- Select deployment-observable features and recompute feature fingerprints.
- Reserve scenario/time/group-separated validation/test partitions where supported.
- Compare per-dataset baselines before compatible cross-dataset testing.
