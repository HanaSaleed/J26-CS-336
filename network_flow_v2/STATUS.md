# J26-CS-336 — Network Flow V2 Research Progress

**Project:** Lightweight Ensemble-Based Multi-Signal APT Detection for IIoT Edge Gateways
**Research component:** Lightweight Ensemble-Based Network Flow Classification for APT Detection in IIoT Edge Gateways
**Repository:** `HanaSaleed/J26-CS-336`
**Branch:** `feature/aazaf-network-flow-v2`
**Tracker scope:** Dataset auditing, leakage-aware preparation, lightweight model comparison, ensemble learning, and edge-gateway validation.

## Status Legend

- **Completed** — Evidence is present in a report, notebook, export, or verified Git history.
- **In Progress** — Work has started, but important subtasks remain.
- **Pending** — Not confirmed as started or completed.
- **Blocked** — Cannot proceed until a named prerequisite is resolved.
- **Needs Verification** — An artifact or scaffold exists, but the required research claim is not yet verified.

## Phase Summary

| Phase | Research area | Status | Current evidence / next gate |
|---|---|---|---|
| 01 | Research environment and GitHub setup | In Progress | Repository and feature branch are active; environment, backup, and full workspace verification remain to be documented. |
| 02 | Dataset collection and initial auditing | Completed | Edge-IIoTset, X-IIoTID, and ToN-IoT audit reports are present. |
| 03 | Feature engineering and dataset understanding | In Progress | Draft dictionaries, candidate mapping, collision/missingness analysis, and dominant-signature diagnostics exist; semantics and gateway extractability remain open. |
| 04 | Dataset preparation and preprocessing | In Progress | Provisional X-IIoTID signature-disjoint split and frozen exports exist; train-only preprocessing and leakage gates remain. |
| 05 | Individual machine learning models | In Progress | Decision Tree and Random Forest pilots are validated; Extra Trees, LightGBM, and AdaBoost are not confirmed complete. |
| 06 | Model comparison and optimization | Pending | Requires all five comparable validation baselines and resource measurements. |
| 07 | Ensemble learning | Pending | Individual-model comparison and validation-selected design are prerequisites. |
| 08 | Cross-dataset evaluation | Pending | Common-feature semantics and dataset-specific baselines are not yet sufficiently verified. |
| 09 | IIoT simulation and real-time detection | Pending | Time-window evidence and gateway extraction are not yet approved. |
| 10 | Dashboard and explainability | Needs Verification | Dashboard files exist, but end-to-end integration and research-result validation are not confirmed. |
| 11 | Raspberry Pi edge deployment | Pending | No verified deployment or edge benchmark is recorded. |
| 12 | Final research evaluation and documentation | Pending | Depends on held-out testing, model selection, ensemble results, and edge evaluation. |

## Current Research Position

- Three dataset audits are complete for Edge-IIoTset, X-IIoTID, and ToN-IoT.
- Draft feature dictionaries and a candidate three-dataset mapping are available. The mapping is not yet a verified common feature schema: similar names do not establish equivalent units, direction, granularity, or meaning.
- X-IIoTID contains **820,834 records and 68 columns**. Full-dataset feature-collision and missingness analysis, as well as dominant-signature diagnostics, are complete.
- The current X-IIoTID Core19 partition is a **provisional signature-disjoint split** with **574,585 training**, **123,125 validation**, and **123,124 test** records. Frozen local exports and a manifest are available.
- Decision Tree and Random Forest pilots each used **150,000 training records** and the full **123,125-record validation partition**. The test partition has **not** been evaluated.
- Decision Tree pilot: F1 **0.9797**, recall **0.9886**, balanced accuracy **0.9803**, and false-positive rate **0.0280**.
- Random Forest pilot: F1 **0.9856**, recall **0.9878**, balanced accuracy **0.9860**, and false-positive rate **0.0159**.
- Current results are laptop pilot timings, not Raspberry Pi measurements. Capture/session independence, feature semantics, and gateway extractability remain limitations.
- The research is therefore at the **leakage-aware preparation and baseline-model comparison stage**, not yet at ensemble, deployment, or final-evaluation stage.

## Phase 01 — Research Environment & GitHub Setup

### Research folder structure

- [x] **Completed** — `network_flow_v2` contains dedicated `docs`, `notebooks`, `reports`, and `src` areas.
- [x] **Completed** — Dataset-specific notebooks and audit outputs are separated by Edge-IIoTset, X-IIoTID, ToN-IoT, and cross-dataset work.
- [ ] **Needs Verification** — Record the final approved folder inventory and ownership of generated versus source artifacts.

### Python virtual environment and dependencies

- [ ] **Needs Verification** — Confirm the project virtual environment is present and record the exact Python version.
- [ ] **Needs Verification** — Freeze and document the dependency versions used for the audit and pilot experiments.
- [ ] **Pending** — Verify that a clean environment can reproduce the documented pilot outputs.

### Git repository and personal feature branch

- [x] **Completed** — Git repository is `HanaSaleed/J26-CS-336`.
- [x] **Completed** — Active branch is `feature/aazaf-network-flow-v2`.
- [x] **Completed** — The branch contains the Network Flow V2 research history.

### GitHub commits and pushes

- [x] **Completed** — Recent research commits are present in local history and the branch tracks the corresponding `origin` branch.
- [x] **Completed** — Commit `e036218` preserves Random Forest validation outputs and figures.
- [x] **Completed** — Commit `509666f` preserves X-IIoTID diagnostics and completed ML notebooks.
- [ ] **Pending** — Continue committing only after review of each reproducible research milestone.

### Workspace consolidation

- [ ] **Needs Verification** — Confirm that the final working copies, reports, notebooks, and exports are consolidated in the intended workspace.
- [ ] **Pending** — Remove or clearly label superseded artifacts without deleting research evidence.

### Backup and file verification

- [ ] **Needs Verification** — Create and record a verified backup of source data, frozen split manifests, reports, and model artifacts.
- [ ] **Pending** — Verify checksums and restoration of the critical research artifacts.

## Phase 02 — Dataset Collection & Initial Auditing

### Edge-IIoTset acquisition and audit

- [x] **Completed** — Audit report exists for the selected Edge-IIoTset ML CSV.
- [x] **Completed** — Audit records **157,800 rows and 63 columns** with a recorded source checksum.

### X-IIoTID acquisition and audit

- [x] **Completed** — Audit report exists for the X-IIoTID source CSV.
- [x] **Completed** — X-IIoTID is recorded as **820,834 rows and 68 columns** with a recorded source checksum.

### ToN-IoT acquisition and audit

- [x] **Completed** — Audit report exists for the ToN-IoT Network CSV.
- [x] **Completed** — ToN-IoT is recorded as **211,043 rows and 44 columns** with a recorded source checksum.

### Dataset shapes, labels, missing values and duplicates

- [x] **Completed** — Dataset shapes, columns, data types, label fields, missingness, placeholders, and duplicate-related quality signals were inspected in the audit work.
- [x] **Completed** — X-IIoTID class totals are recorded as **421,417 Normal** and **399,417 Attack**.
- [ ] **Needs Verification** — Consolidate a single cross-dataset table of duplicate definitions and results for the final report.

### Data-quality documentation

- [x] **Completed** — Dataset-specific audit JSON reports and feature-quality documents are preserved.
- [x] **Completed** — Initial data-quality findings are documented for all three datasets.
- [ ] **Pending** — Convert draft findings into final, source-cited data-quality documentation.

## Phase 03 — Feature Engineering & Dataset Understanding

### Feature dictionaries for each dataset

- [x] **Completed** — Draft feature dictionaries exist for Edge-IIoTset, X-IIoTID, and ToN-IoT.
- [ ] **Needs Verification** — Verify published meanings, units, directionality, granularity, and capture modality for every retained feature.

### Network, host and sensor feature identification

- [x] **Completed** — Candidate network, host/process, sensor/system, protocol, identifier, and time-related fields have been separated in the draft analysis.
- [ ] **Pending** — Finalize the exclusion policy for host, sensor, identifier, and payload-derived fields.

### Common feature mapping across datasets

- [x] **Completed** — Candidate three-dataset mapping is documented.
- [ ] **Blocked** — A verified common feature set is blocked by unresolved semantic, unit, time, and granularity differences.

### X-IIoTID 19 core network candidates

- [x] **Completed** — A Core19 candidate set was screened and used for the provisional X-IIoTID split and pilots.
- [ ] **Needs Verification** — Confirm that each candidate is both leakage-safe and observable at an IIoT gateway.

### Missing-value investigation

- [x] **Completed** — X-IIoTID full-dataset missingness analysis is complete.
- [x] **Completed** — Missingness associations were quantified; the largest binary-class difference was observed for `Duration` at **15.20 percentage points**.
- [ ] **Pending** — Decide and document feature-wise treatment without turning capture placeholders into unjustified zeros.

### Feature-collision analysis

- [x] **Completed** — X-IIoTID full-data collision analysis is complete.
- [x] **Completed** — Basic8 contained **2,000 conflicting groups / 92,954 records**; Core19 contained **1,969 conflicting groups / 21,866 records**.
- [ ] **Pending** — Explain collision implications using group-aware validation and source/session evidence.

### Dominant-signature investigation

- [x] **Completed** — Dominant Core19 signature diagnostics are complete.
- [x] **Completed** — Largest identical-feature group contained **64,194 records**, all classified as Attack in the observed data.
- [ ] **Pending** — Determine whether dominant signatures reflect capture procedure, attack behaviour, duplicated sessions, or unresolved feature semantics.

### Semantic feature verification

- [ ] **Pending** — Verify feature definitions, units, timestamp meaning, direction, and aggregation semantics against authoritative dataset documentation.

### Gateway-extractable feature verification

- [ ] **Pending** — Reproduce the retained features from traffic available at an IIoT gateway.
- [ ] **Blocked** — Live extraction cannot be approved until protocol coverage, flow boundaries, and observation-window semantics are defined.

### Feature-selection and ablation experiments

- [ ] **Pending** — Run comparable feature-selection and ablation experiments across the individual baselines.
- [ ] **Pending** — Include collision-aware, missingness-only, and reduced-feature comparisons before selecting the final feature set.

## Phase 04 — Dataset Preparation & Preprocessing

### X-IIoTID provisional 70/15/15 split

- [x] **Completed** — Provisional split produced **574,585 train**, **123,125 validation**, and **123,124 test** records.
- [x] **Completed** — Split manifest and frozen local CSV exports are preserved.

### Signature-disjoint partition verification

- [x] **Completed** — The split is signature-disjoint for the selected Core19 signature mapping.
- [ ] **Needs Verification** — Capture/session independence and campaign independence are not yet verified.

### Frozen training, validation and test exports

- [x] **Completed** — Frozen train, validation, and test exports are available locally.
- [x] **Completed** — The export manifest records the source, feature set, counts, and limitations.

### Missing-value preprocessing

- [ ] **Pending** — Define and implement feature-wise missing-token and missing-value handling.
- [ ] **Pending** — Measure whether preprocessing preserves or amplifies label-correlated missingness.

### Categorical encoding

- [ ] **Pending** — Define reproducible categorical encoding for protocol, service, and connection-state fields.
- [ ] **Pending** — Confirm unknown-category behavior for validation, test, and live gateway data.

### Training-only preprocessing fitting

- [ ] **Pending** — Fit imputers, encoders, scalers, and any selectors on training data only.
- [ ] **Pending** — Persist preprocessing metadata with each model artifact.

### Split reproducibility and metadata

- [x] **Completed** — Random seed, manifest checksum, partition counts, and source-row mapping are recorded for the provisional split.
- [ ] **Pending** — Publish a complete preprocessing and experiment manifest.

### Source/session leakage verification

- [ ] **Needs Verification** — Reconstruct and verify source, capture, session, time, and group boundaries.
- [ ] **Blocked** — Final claims about generalization are blocked until independent groups or an explicit limitation are established.

### Final feature-selection confirmation

- [ ] **Pending** — Confirm the final feature set after semantic, gateway, missingness, collision, and ablation gates.

## Phase 05 — Individual Machine Learning Models

### Decision Tree

- [x] **Completed** — Notebook created and pilot trained with **150,000** training records.
- [x] **Completed** — Validated on **123,125** records.
- [x] **Completed** — Attack precision **0.9710**, recall **0.9886**, F1 **0.9797**, balanced accuracy **0.9803**, false-positive rate **0.0280**.
- [x] **Completed** — Confusion matrix, feature-importance visualization, and laptop training/inference timings are recorded.
- [x] **Completed** — Local research outputs are preserved in the corresponding report/notebook history.
- [ ] **Needs Verification** — Confirm a separately versioned model artifact is saved locally with preprocessing metadata.
- [ ] **Pending** — Full-training experiment remains pending.

### Random Forest

- [x] **Completed** — Notebook created and pilot trained with **150,000** training records.
- [x] **Completed** — Validated on **123,125** records.
- [x] **Completed** — Attack precision **0.9833**, recall **0.9878**, F1 **0.9856**, balanced accuracy **0.9860**, false-positive rate **0.0159**.
- [x] **Completed** — Confusion matrix, feature-importance visualization, and laptop training/inference timings are recorded.
- [x] **Completed** — Validation reports and figures were preserved in commit `e036218`.
- [ ] **Needs Verification** — Confirm a separately versioned model artifact is saved locally with preprocessing metadata.
- [ ] **Pending** — Full-training experiment remains pending.

### Extra Trees

- [ ] **Pending** — Notebook creation.
- [ ] **Pending** — Pilot training with 150,000 records and validation on 123,125 records.
- [ ] **Pending** — Precision, recall, F1, balanced accuracy, false-positive rate, confusion matrix, feature importance, and timing measurements.
- [ ] **Pending** — Local model artifact and Git milestone.
- [ ] **Pending** — Full-training experiment, if selected after the pilot.

### LightGBM

- [ ] **Pending** — Notebook creation.
- [ ] **Pending** — Pilot training with 150,000 records and validation on 123,125 records.
- [ ] **Pending** — Precision, recall, F1, balanced accuracy, false-positive rate, confusion matrix, feature importance, and timing measurements.
- [ ] **Pending** — Local model artifact and Git milestone.
- [ ] **Pending** — Full-training experiment, if selected after the pilot.

### AdaBoost

- [ ] **Pending** — Notebook creation.
- [ ] **Pending** — Pilot training with 150,000 records and validation on 123,125 records.
- [ ] **Pending** — Precision, recall, F1, balanced accuracy, false-positive rate, confusion matrix, feature importance, and timing measurements.
- [ ] **Pending** — Local model artifact and Git milestone.
- [ ] **Pending** — Full-training experiment, if selected after the pilot.

### Shared model safeguards

- [x] **Completed** — Pilot metrics are validation metrics; the test partition has not been scored.
- [x] **Completed** — Current timing notes identify laptop measurements rather than edge-device benchmarks.
- [ ] **Pending** — Standardize seeds, preprocessing, metrics, artifacts, and reporting across all five models.

## Phase 06 — Model Comparison & Optimization

- [ ] **Pending** — Complete a five-model validation comparison.
- [ ] **Pending** — Compare feature importance and controlled ablation results.
- [ ] **Pending** — Establish a missingness-only baseline and compare it with network-feature models.
- [ ] **Pending** — Perform documented hyperparameter tuning using validation data only.
- [ ] **Pending** — Analyze false positives and false negatives by attack category, signature, source, and capture group where available.
- [ ] **Pending** — Measure CPU time, RAM, model size, and inference time under a common protocol.
- [ ] **Pending** — Select the lightweight model using detection performance and resource constraints, not F1 alone.

## Phase 07 — Ensemble Learning

- [ ] **Pending** — Select an ensemble architecture based on the completed individual-model comparison.
- [ ] **Pending** — Design and justify voting or stacking, including training and validation boundaries.
- [ ] **Pending** — Implement the ensemble with reproducible preprocessing and model versions.
- [ ] **Pending** — Measure ensemble validation performance using the same metrics as individual models.
- [ ] **Pending** — Compare the ensemble with the strongest individual model and a simple majority baseline.
- [ ] **Pending** — Measure computational overhead, memory use, latency, and model-artifact size.

## Phase 08 — Cross-Dataset Evaluation

- [ ] **Pending** — Evaluate on Edge-IIoTset using a dataset-specific, documented schema.
- [ ] **Pending** — Evaluate on ToN-IoT using a dataset-specific, documented schema.
- [ ] **Blocked** — Verify common-feature mapping before claiming a cross-dataset experiment.
- [ ] **Pending** — Compare dataset-specific and cross-dataset baselines.
- [ ] **Pending** — Analyze generalization and domain shift by feature availability, label definition, capture procedure, and attack composition.

## Phase 09 — IIoT Simulation & Real-Time Detection

- [ ] **Pending** — Build and document the Ubuntu-based IIoT network simulation.
- [ ] **Pending** — Collect network flows with reproducible capture configuration.
- [ ] **Pending** — Implement and validate gateway feature extraction.
- [ ] **Pending** — Integrate the real-time inference pipeline.
- [ ] **Blocked** — Approve 5-, 10-, 15-, and 20-second observation windows only after timestamp and event-boundary semantics are verified.
- [ ] **Pending** — Measure end-to-end latency and throughput for each observation window.
- [ ] **Pending** — Interpret detected behaviour against relevant MITRE ATT&CK techniques without treating dataset labels as complete APT campaign proof.

## Phase 10 — Dashboard & Explainability

- [ ] **Needs Verification** — Confirm the Streamlit dashboard scaffold and model-loading path against the final artifact schema.
- [ ] **Pending** — Add real-time classification display.
- [ ] **Pending** — Add alert and event visualization.
- [ ] **Pending** — Add model confidence and feature/model explanations.
- [ ] **Pending** — Add detection statistics using reproducible experiment metadata.
- [ ] **Pending** — Complete dashboard integration testing with valid, invalid, missing, and delayed input data.

## Phase 11 — Raspberry Pi Edge Deployment

- [ ] **Pending** — Set up and record the Raspberry Pi environment.
- [ ] **Pending** — Deploy the selected model, preprocessing, and feature-extraction artifacts.
- [ ] **Pending** — Demonstrate real-time gateway inference.
- [ ] **Pending** — Benchmark CPU and RAM use under representative traffic.
- [ ] **Pending** — Measure model size and inference latency.
- [ ] **Pending** — Compare throughput and resource use with the laptop baseline.
- [ ] **Pending** — Evaluate edge feasibility against explicit latency, memory, and throughput thresholds.

## Phase 12 — Final Research Evaluation & Documentation

- [ ] **Pending** — Select the final model or ensemble using validation evidence and edge constraints.
- [ ] **Pending** — Evaluate once on the held-out test partition after all model and threshold decisions are frozen.
- [ ] **Pending** — Document research objectives, assumptions, threats to validity, and limitations.
- [ ] **Pending** — Produce final experimental tables and graphs.
- [ ] **Pending** — Complete reproducibility documentation, including versions, checksums, seeds, manifests, and execution instructions.
- [ ] **Pending** — Write the research report.
- [ ] **Pending** — Prepare the final presentation and demonstration.

## Next 5 Priority Tasks

1. **Verify feature semantics and gateway extractability** for the X-IIoTID Core19 candidates, including units, direction, capture meaning, and missing-token behavior.
2. **Complete leakage-aware split verification and preprocessing** by documenting source/session boundaries and fitting every preprocessing step on training data only.
3. **Run the remaining three pilot baselines** — Extra Trees, LightGBM, and AdaBoost — with the same 150,000/123,125 protocol and reporting schema.
4. **Complete the five-model comparison and ablations**, including a missingness-only baseline, false-error analysis, and laptop resource measurements.
5. **Freeze the validation-selected design before scoring the held-out test set**, then document the test protocol and limitations.

## Git Commit Log / Milestones

The following milestones are taken from the verified Network Flow V2 Git history:

| Commit | Milestone |
|---|---|
| `3dfd686` | Added Network Flow V2 dataset audits and feature analysis. |
| `c4c2ce4` | Completed X-IIoTID network feature screening. |
| `9a48dd9` | Verified X-IIoTID full-data feature collisions and missingness. |
| `b847405` | Diagnosed X-IIoTID dominant network signatures. |
| `bb67d49` | Exported frozen X-IIoTID datasets for ML training. |
| `fafd7f5` | Trained and validated the X-IIoTID Decision Tree baseline. |
| `e036218` | Preserved Random Forest validation and split figures. |
| `509666f` | Preserved X-IIoTID diagnostics and completed ML notebooks. |

The current feature branch is `feature/aazaf-network-flow-v2` and the recent branch history is present on its tracked `origin` branch. No new commit or push is made by this status update.

## Research Risks & Limitations

### Dataset leakage and dependence

- Signature-disjoint rows are not automatically independent sessions, captures, campaigns, or devices.
- Source/session/time boundaries must be reconstructed and verified before making strong generalization claims.
- The held-out X-IIoTID test partition remains unscored.

### Feature semantics

- Draft dictionaries explicitly leave meanings, units, temporal windows, and source modalities unresolved.
- Similar column names across ToN-IoT, X-IIoTID, and Edge-IIoTset do not prove equivalent measurements.
- Edge-IIoTset includes packet/protocol-oriented fields, while other datasets contain candidate flow statistics; these must not be silently treated as one schema.

### Missingness shortcuts

- Missingness and placeholder patterns may encode capture procedure or class membership.
- Converting placeholders to zero, or using missingness without a control baseline, could create an artificial shortcut.
- Missingness preprocessing must be fitted on training data only and assessed with a missingness-only comparison.

### Cross-dataset incompatibility

- Labels, attack taxonomies, feature availability, timestamps, and aggregation semantics differ by dataset.
- ToN-IoT currently has no verified event timestamp suitable for the proposed observation windows.
- Cross-dataset claims require verified common features and separately documented dataset-specific baselines.

### Edge-device constraints

- Current training and inference timings are laptop measurements, not Raspberry Pi benchmarks.
- Gateway extraction cost, CPU, RAM, storage, throughput, and alert latency are not yet measured.
- A model with high validation F1 is not automatically lightweight or deployable.

### Interpretation limits

- Dominant signatures and collision lower bounds describe ambiguity in observed feature combinations; they are not test accuracy or proof of mislabeled data.
- Dataset attack labels do not by themselves establish a complete APT campaign or MITRE ATT&CK sequence.
