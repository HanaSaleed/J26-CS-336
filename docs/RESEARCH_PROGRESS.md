# J26-CS-336 — Master Research Progress Checklist (V2)

**Last updated:** 17 October 2026  
**Team research:** Lightweight Ensemble-Based Multi-Signal APT Behavior Detection for IIoT Edge Gateways  
**Network component:** Lightweight Ensemble-Based Network Flow Classification for APT Detection in IIoT Edge Gateways  
**Repository:** [HanaSaleed/J26-CS-336](https://github.com/HanaSaleed/J26-CS-336)  
**Branch for this checklist:** `feature/network-flow`

> **Status legend:** `[x]` = completed/verified to the extent stated. `[ ]` = pending, not yet demonstrated, or still requiring stronger validation. Prototype and preliminary achievements are distinct from final research evaluation.

## Phase 0 — Research Planning

- [x] Finalize team research concept
- [x] Define individual responsibilities
- [x] Prepare proposal and literature references
- [x] Identify initial research datasets
- [x] Define 5/10/15/20-second requirement
- [x] Confirm updated requirements with supervisors
- [x] Define three-component research architecture
- [x] Define Raspberry Pi 5 as target edge platform
- [x] Review current implementation against the proposal
- [ ] Finalize dataset roles and experimental methodology for all three components
- [ ] Finalize integration interfaces between team members

## Phase 1 — Infrastructure Setup

- [ ] Confirm whether existing Ubuntu VM is suitable
- [ ] Install or verify Ubuntu Server environment
- [ ] Verify VM CPU, RAM, storage and networking
- [ ] Install Docker Engine and Compose
- [ ] Configure isolated virtual laboratory network
- [ ] Create project directories and configuration files
- [ ] Verify communication between virtual industrial components
- [ ] Document infrastructure and network configuration

## Phase 2 — Normal Industrial Process Simulation

- [ ] Create Python water-level sensor
- [ ] Create temperature and pressure sensors
- [ ] Implement virtual PLC with PyModbus
- [ ] Implement pump ON/OFF and tank process logic
- [ ] Install and configure Mosquitto MQTT broker
- [ ] Configure Node-RED industrial HMI
- [ ] Connect PLC, sensors, pump, MQTT and HMI
- [ ] Verify stable normal industrial operations
- [ ] Document normal sensor ranges and process behaviour

## Phase 3 — Monitoring and Data Collection

- [ ] Define unique device and experiment identifiers
- [ ] Capture industrial network traffic
- [ ] Collect device/host telemetry
- [ ] Log physical sensor measurements
- [ ] Implement consistent UTC timestamps across all components
- [ ] Verify captured traffic and event completeness
- [ ] Save raw experimental evidence
- [ ] Define evidence storage and retention policy
- [ ] Verify correct mapping between network observations and simulated devices

## Phase 4 — Time-Window Processing

- [x] Define 5, 10, 15 and 20-second boundaries for the synthetic prototype
- [x] Implement non-overlapping synthetic window generation
- [x] Implement reusable batch network-window feature extraction
- [x] Implement streaming network-window feature extraction
- [x] Test all four window durations using synthetic packet events
- [x] Verify window boundaries and device separation using synthetic tests
- [x] Pass 11 automated feature-extraction unit tests
- [ ] Verify network-window extraction using actual packet captures
- [ ] Aggregate device telemetry per window
- [ ] Aggregate sensor measurements per window
- [ ] Define complete cross-boundary and incomplete-event rules
- [ ] Verify matching window timestamps across all three components
- [ ] Define empty-window handling for continuous monitoring
- [ ] Create final window feature and ground-truth label specifications
- [ ] Validate real-time streaming performance

**Progress note:** All four durations passed synthetic tests. Real industrial traffic and cross-component synchronization remain pending.

## Phase 5 — Dataset Verification and Preprocessing

- [x] Create Python ML research workspace
- [x] Configure Python 3.12 virtual environment
- [x] Install NumPy, Pandas, Scikit-learn, Joblib and Matplotlib
- [x] Download initial CICAPT and ToN-IoT CSVs
- [x] Run initial dataset audits
- [x] Inspect CSV schemas and label distributions
- [x] Obtain and organize CICAPT supporting files
- [x] Investigate CICAPT timestamp and feature-quality problems
- [x] Investigate CICAPT attack-event alignment on samples
- [x] Inspect CICAPT row structure and packet-like characteristics
- [x] Select provisional CICAPT observation columns
- [x] Create exploratory CICAPT 5s/10s/15s/20s observation groups
- [x] Audit all 211,043 ToN-IoT records
- [x] Investigate duplicate signatures and conflicting labels
- [x] Assess group-disjoint split feasibility
- [x] Create provisional ToN-IoT 70/15/15 group-disjoint partitions
- [x] Fit ToN-IoT preprocessing using training data only
- [x] Generate 32 encoded features from 10 ToN-IoT inputs
- [x] Save preprocessing artifacts and reproducibility report
- [ ] Fully verify CICAPT timestamps and feature calculations against original captures
- [ ] Validate CICAPT attack labels and complete attack-event alignment
- [ ] Resolve CICAPT record-count and packet-to-row discrepancies
- [ ] Download and audit Edge-IIoTset for primary model development
- [ ] Finalize Edge-IIoTset and other dataset roles
- [ ] Choose final reproducible, deployment-compatible network features
- [ ] Determine which datasets support valid 5/10/15/20-second windows
- [ ] Define mixed normal/attack window labels
- [ ] Finalize leakage-safe training, validation and test datasets for primary experiments
- [ ] Establish independent cross-dataset evaluation procedures

**Progress note:** ToN-IoT flow-level preprocessing is preliminary; Edge-IIoTset is the proposed primary dataset.

## Phase 6 — Network ML Model Development

### 6.1 — Decision Tree Baseline

- [x] Train preliminary Decision Tree baseline on ToN-IoT
- [x] Evaluate Decision Tree using validation data
- [x] Calculate accuracy, balanced accuracy, precision and recall
- [x] Calculate F1-score, false-positive rate and ROC-AUC
- [x] Generate confusion matrix
- [x] Generate ROC curve
- [x] Generate precision–recall curve
- [x] Generate feature-importance graph
- [x] Generate attack-category recall graph
- [x] Generate Decision Tree overview visualization
- [x] Generate majority-class baseline comparison graph
- [x] Save seven evaluation figures and performance table
- [x] Identify MITM detection weakness
- [x] Save trained Decision Tree model and evaluation report locally

### 6.2 — Feature Ablation

- [x] Train Decision Tree without source and destination ports
- [x] Compare original 10-feature and reduced 8-feature models
- [x] Compare accuracy, precision, recall, F1 and false positives
- [x] Compare MITM detection between both models
- [x] Generate port-ablation comparison charts
- [x] Save reduced-feature model and evaluation report locally
- [ ] Investigate additional shortcut features and generalization risks

### 6.3 — Remaining ML Classifiers

- [ ] Train proposal-aligned Decision Tree on primary IIoT data
- [ ] Train Random Forest
- [ ] Train Extra Trees
- [ ] Train LightGBM
- [ ] Train AdaBoost
- [ ] Generate validation charts for every model
- [ ] Compare all five classifiers on consistent primary evaluation data
- [ ] Analyze per-attack-category performance
- [ ] Analyze computational and memory costs
- [ ] Compare compact versus full feature sets

### 6.4 — Lightweight Ensemble

- [ ] Select complementary models
- [ ] Design lightweight ensemble strategy
- [ ] Train and evaluate ensemble
- [ ] Compare ensemble with individual classifiers
- [ ] Evaluate false-positive and false-negative changes
- [ ] Measure ensemble inference cost
- [ ] Finalize model selection

### 6.5 — Window-Aware Models

- [ ] Prepare verified window-level training data
- [ ] Train 5-second window model
- [ ] Train 10-second window model
- [ ] Train 15-second window model
- [ ] Train 20-second window model
- [ ] Compare window-specific model performance
- [ ] Compare unified window-aware model if feasible
- [ ] Select deployment configuration

### 6.6 — Final ML Evaluation

- [ ] Perform final held-out test evaluation
- [ ] Verify generalization using independent environments where feasible
- [ ] Document model limitations
- [ ] Export selected ML models
- [ ] Export identical deployment preprocessing definitions
- [ ] Prepare final ML performance tables and graphs

**Preliminary validation results (ToN-IoT flow-level; not final APT/window evaluation):**

| Metric | Original Decision Tree | Without source/destination ports |
| --- | ---: | ---: |
| Accuracy | 99.28% | 99.08% |
| Attack precision | 99.82% | 99.73% |
| Attack recall | 99.26% | 99.10% |
| Attack F1-score | 99.54% | 99.41% |
| False positives | 44 | 65 |
| Missed attacks | 176 | 216 |
| MITM recall | 82.10% | 74.69% |

## Phase 7 — Controlled Attack Experiments

- [ ] Define documented and authorized attack scenarios
- [ ] Verify laboratory isolation boundary
- [ ] Record normal-operation baseline scenarios
- [ ] Emulate network discovery
- [ ] Emulate authorized access and internal communication anomalies
- [ ] Emulate repeated suspicious communication
- [ ] Emulate controlled PLC register manipulation
- [ ] Run combined multi-stage campaigns
- [ ] Record attack start and end times
- [ ] Record verified ground-truth labels
- [ ] Verify synchronized network, device and sensor captures
- [ ] Document attack scenarios and supporting evidence

## Phase 8 — Raspberry Pi 5 Deployment

- [ ] Prepare Raspberry Pi OS and networking
- [ ] Verify traffic mirroring or replay feed
- [ ] Deploy selected ML models
- [ ] Implement edge feature extraction
- [ ] Verify all four monitoring durations on Raspberry Pi
- [ ] Integrate device and sensor component outputs
- [ ] Measure CPU utilization
- [ ] Measure RAM consumption
- [ ] Measure inference latency
- [ ] Measure feature extraction latency
- [ ] Measure network throughput
- [ ] Test continuous monitoring stability
- [ ] Measure packet loss
- [ ] Compare resource consumption across selected models

## Phase 9 — Multi-Signal Fusion

- [ ] Agree on shared JSON evidence structure
- [ ] Normalize device IDs and event timestamps
- [ ] Associate related network, host and sensor evidence
- [ ] Implement initial fusion logic
- [ ] Retain historical evidence beyond short monitoring windows
- [ ] Implement evidence-supported MITRE ATT&CK mappings
- [ ] Produce explainable APT-related risk assessments
- [ ] Compare fusion with individual detectors
- [ ] Validate alerts using controlled attack ground truth
- [ ] Document uncertainty and limitations of APT attribution

## Phase 10 — Security Dashboard

- [ ] Implement main system-status overview
- [ ] Display industrial water-tank and pump operation
- [ ] Display network monitoring
- [ ] Display host/device telemetry monitoring
- [ ] Display physical sensor monitoring
- [ ] Implement 5s/10s/15s/20s window selection
- [ ] Display matching model and window results
- [ ] Display security alerts and supporting evidence
- [ ] Implement historical attack timeline
- [ ] Display Raspberry Pi resource measurements
- [ ] Display verified research performance results
- [ ] Integrate dashboard with the full experimental system

## Phase 11 — Final Evaluation and Research Delivery

- [ ] Repeat experiments using documented configurations
- [ ] Compare all five ML models and ensemble
- [ ] Evaluate all four monitoring-window durations
- [ ] Compare individual and fused detection results
- [ ] Analyze false positives and missed attacks
- [ ] Analyze detection latency
- [ ] Evaluate Raspberry Pi resource efficiency
- [ ] Document limitations and evidence quality
- [ ] Complete individual research report
- [ ] Complete team research report
- [ ] Prepare final demonstration
- [ ] Prepare final viva presentation

---

## Additional Phase — GitHub and Version Control

- [x] Initialize shared research repository
- [x] Create `main` integration branch
- [x] Create `feature/network-flow` branch
- [x] Create `feature/device-telemetry` branch
- [x] Create `feature/physical-sensor` branch
- [x] Clone network-flow branch locally
- [x] Upload research scripts and feature-extraction modules
- [x] Upload automated tests
- [x] Upload Decision Tree training and graph-generation scripts
- [x] Upload port-ablation experiment code
- [x] Upload initial evaluation reports, charts and tables
- [x] Commit and synchronize preliminary network-flow research results
- [ ] Confirm all team members have appropriate repository permissions
- [ ] Keep README and experiment documentation updated
- [ ] Use pull requests for tested component integration
- [ ] Integrate verified network, device and sensor implementations into `main`
- [ ] Tag reproducible research milestones and final release

## Current Checkpoint and Next Steps

**Verified or advanced preliminary work:** synthetic four-window generator; 11 unit tests; CICAPT/ToN-IoT audits; ToN-IoT flow-level group-disjoint splits and train-only preprocessing; Decision Tree baseline and port ablation; evaluation figures; three GitHub component branches.

**Next research task:** acquire and audit the proposed primary Edge-IIoTset dataset, validate compatible deployment features and proceed toward proposal-aligned model comparison. Keep the ToN-IoT results identified as preliminary flow-level validation, not confirmed APT campaign or live time-window performance.

**Data hygiene:** do not commit raw datasets, local virtual environments, credentials, or large trained model binaries. Track lightweight source code, documentation, experimental configurations, evaluation reports and publication-ready figures.
