# ToN-IoT Network — Feature Dictionary DRAFT

Source: `ton_iot_train_test_network.csv`; SHA-256: `26ddc513552de36de6428b2e578efaed2b57504c716dfba847cc0109a64e1974`

**Unverified columns:** meaning, units, source modality, temporal window, and deployability must be documented manually.

| Feature | Numeric parse % | Numeric zeros % | Distinct >= | Missing | Placeholders | Candidate role |
|---|---:|---:|---:|---:|---:|---|
| src_ip | 0.0 | 0.0 | 51 | 0 | 0 | REVIEW: identifier/time/payload |
| src_port | 100.0 | 0.0 | 10001+ | 0 | 0 | VERIFY modality/units |
| dst_ip | 0.0 | 0.0 | 753 | 0 | 0 | REVIEW: identifier/time/payload |
| dst_port | 100.0 | 0.02 | 2039 | 0 | 0 | VERIFY modality/units |
| proto | 0.0 | 0.0 | 3 | 0 | 0 | VERIFY modality/units |
| service | 0.0 | 0.0 | 9 | 0 | 132032 | VERIFY modality/units |
| duration | 100.0 | 28.44 | 10001+ | 0 | 0 | VERIFY modality/units |
| src_bytes | 100.0 | 65.46 | 2199 | 0 | 0 | VERIFY modality/units |
| dst_bytes | 100.0 | 70.55 | 2338 | 0 | 0 | VERIFY modality/units |
| conn_state | 0.0 | 0.0 | 13 | 0 | 0 | VERIFY modality/units |
| missed_bytes | 100.0 | 98.6 | 694 | 0 | 0 | VERIFY modality/units |
| src_pkts | 100.0 | 8.1 | 274 | 0 | 0 | VERIFY modality/units |
| src_ip_bytes | 100.0 | 8.1 | 3648 | 0 | 0 | REVIEW: identifier/time/payload |
| dst_pkts | 100.0 | 39.44 | 203 | 0 | 0 | VERIFY modality/units |
| dst_ip_bytes | 100.0 | 39.44 | 3304 | 0 | 0 | REVIEW: identifier/time/payload |
| dns_query | 0.0 | 0.0 | 726 | 0 | 176198 | VERIFY modality/units |
| dns_qclass | 100.0 | 83.53 | 3 | 0 | 0 | VERIFY modality/units |
| dns_qtype | 100.0 | 83.53 | 12 | 0 | 0 | VERIFY modality/units |
| dns_rcode | 100.0 | 95.88 | 4 | 0 | 0 | VERIFY modality/units |
| dns_AA | 0.0 | 0.0 | 3 | 0 | 176030 | VERIFY modality/units |
| dns_RD | 0.0 | 0.0 | 3 | 0 | 176030 | VERIFY modality/units |
| dns_RA | 0.0 | 0.0 | 3 | 0 | 176030 | VERIFY modality/units |
| dns_rejected | 0.0 | 0.0 | 3 | 0 | 176030 | VERIFY modality/units |
| ssl_version | 0.0 | 0.0 | 4 | 0 | 210642 | VERIFY modality/units |
| ssl_cipher | 0.0 | 0.0 | 6 | 0 | 210642 | VERIFY modality/units |
| ssl_resumed | 0.0 | 0.0 | 3 | 0 | 210642 | VERIFY modality/units |
| ssl_established | 0.0 | 0.0 | 3 | 0 | 210642 | VERIFY modality/units |
| ssl_subject | 0.0 | 0.0 | 6 | 0 | 211032 | VERIFY modality/units |
| ssl_issuer | 0.0 | 0.0 | 5 | 0 | 211032 | VERIFY modality/units |
| http_trans_depth | 0.14 | 0.0 | 11 | 0 | 210740 | VERIFY modality/units |
| http_method | 0.0 | 0.0 | 4 | 0 | 210756 | VERIFY modality/units |
| http_uri | 0.0 | 0.0 | 86 | 0 | 210756 | REVIEW: identifier/time/payload |
| http_version | 0.14 | 0.0 | 2 | 0 | 210745 | VERIFY modality/units |
| http_request_body_len | 100.0 | 99.99 | 6 | 0 | 0 | VERIFY modality/units |
| http_response_body_len | 100.0 | 99.87 | 75 | 0 | 0 | VERIFY modality/units |
| http_status_code | 100.0 | 99.86 | 8 | 0 | 0 | VERIFY modality/units |
| http_user_agent | 0.0 | 0.0 | 35 | 0 | 210756 | VERIFY modality/units |
| http_orig_mime_types | 0.0 | 0.0 | 3 | 0 | 211027 | VERIFY modality/units |
| http_resp_mime_types | 0.0 | 0.0 | 10 | 0 | 210839 | VERIFY modality/units |
| weird_name | 0.0 | 0.0 | 11 | 0 | 210687 | VERIFY modality/units |
| weird_addl | 0.07 | 0.0 | 3 | 0 | 210886 | VERIFY modality/units |
| weird_notice | 0.0 | 0.0 | 2 | 0 | 210687 | VERIFY modality/units |
