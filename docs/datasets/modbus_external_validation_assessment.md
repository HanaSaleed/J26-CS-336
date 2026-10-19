# External Modbus evaluation source assessment

## Why an external source is needed

All rows in the current TON-IoT Modbus workflow have been used in prior model fitting or evaluation. Additional work on that CSV is exploratory; a confirmatory result needs a new capture or campaign.

## Local Edge-IIoTset files: not a matched Modbus test set

The local Edge-IIoTset download contains a normal-traffic `Modbus.csv` and separate attack-traffic CSVs. A read-only audit of the local copy found 159,502 rows in `Normal traffic/Modbus/Modbus.csv`, of which 97,940 had at least one nonzero value among `mbtcp.len`, `mbtcp.trans_id`, and `mbtcp.unit_id`. All 13 attack CSVs had zero rows with a nonzero value in those three fields. Their packet/network schema also does not contain the TON-IoT `FC1_Read_Input_Register`, `FC2_Read_Discrete_Value`, `FC3_Read_Holding_Register`, and `FC4_Read_Coil` columns. Do not treat these files as a direct external test of the current four-feature model.

The Edge-IIoTset paper describes a broad testbed with Modbus flows and attacks across several IoT/IIoT protocols, but protocol presence in the overall testbed does not make every attack CSV a Modbus attack capture ([dataset paper](https://doi.org/10.1109/ACCESS.2022.3165809)). A 2026 preprint also reports that the curated ML/DL tables have little or no useful Modbus content and identifies a placeholder-serialization leakage issue in the documented preprocessing recipe; this is a caution about those curated tables, not a finding about every raw capture ([preprint](https://arxiv.org/abs/2608.15761)).

## Better candidate: CIC Modbus Dataset 2023

The Canadian Institute for Cybersecurity describes CIC Modbus 2023 as benign and attack PCAP captures plus timestamped attack logs from a simulated substation, including Modbus-specific scenarios such as false-data injection, query flooding, replay, and brute-force writes ([official dataset page](https://www.unb.ca/cic/datasets/modbus-2023.html)). It is a separate capture and a stronger candidate for an external Modbus-network evaluation.

It is not a drop-in test for the existing four-feature TON-IoT model: CIC Modbus is distributed as PCAP and attack logs, so the traffic must be parsed and its fields mapped deliberately. The official page notes that PCAP timestamps are ADT (UTC−3) while attack-log timestamps are UTC, and recommends aligning them before labeling. It also recommends extracting IP-specific traffic for accurate labels. These steps must be completed before any model evaluation.

## Recommended next stage

1. Obtain the CIC Modbus 2023 archive from the official page and keep it outside the repository as read-only source data.
2. Inspect the archive and confirm the capture/log coverage before writing a parser.
3. Build a protocol-level dataset with uniform parsing and documented attack-log alignment.
4. Decide whether the goal is a separately trained Modbus-network detector or a truly compatible external test. Do not claim direct validation of the TON-IoT four-feature model until feature semantics are shown to match.
5. Split by capture, scenario, or attack run so packets from one run do not appear on both sides.

The additional TON-IoT sensor CSVs already present locally may support a separate cross-sensor or fusion study. The UNSW description presents TON-IoT as a heterogeneous collection of telemetry, OS, and network sources from its testbed, so those files should not be presented as an independent external campaign ([UNSW dataset page](https://research.unsw.edu.au/projects/toniot-datasets)).
