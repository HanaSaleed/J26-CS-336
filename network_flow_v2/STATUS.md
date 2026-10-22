# J26-CS-336 — Network Flow V2 Status

**Research:** Lightweight ensemble-based APT-related network-flow detection for IIoT edge gateways  
**Workspace:** `D:\J26-CS-336-Network-Flow-V2\network_flow_v2`  
**Git branch:** `feature/aazaf-network-flow-v2`  
**Current stage:** Individual models and laptop benchmarks completed; verifying features and designing the ensemble next.

> **How to read:** `[x]` = completed from current experiment evidence; `[ ]` = still to do. Do not treat laptop results as Raspberry Pi results.

## Progress at a glance

| Phase | Status | Main result / next step |
|---|---|---|
| 1. Workspace & datasets | Mostly done | Git worktree moved; 3 datasets audited |
| 2. Features & split | In progress | X-IIoTID Core19 and frozen split; gateway features/leakage still need checks |
| 3. Individual ML models | Done | 5 models trained on all 574,585 training rows |
| 4. Model comparison & resources | In progress | Validation and laptop benchmarks done; confirm reliability |
| 5. Lightweight ensemble | Not started | Test whether combining selected models helps |
| 6. Ubuntu IIoT edge-gateway simulation | Not started | Build a virtual gateway and live flow collection |
| 7. Raspberry Pi & dashboard | Not started | Deploy and benchmark complete gateway pipeline |
| 8. Final evaluation & report | Not started | Cross-dataset checks, final held-out test, documentation |

## Phase 1 — Workspace and datasets

- [x] Set up the Git-connected V2 workspace and branch.
- [x] Audit **X-IIoTID, Edge-IIoTset and ToN-IoT**.
- [x] Save dataset checks and research notebooks.
- [ ] Finish verifying recovered files and old-folder safety backup before deleting it.

## Phase 2 — Features and frozen data split

- [x] Select **19 candidate network features (Core19)** and study missing values and repeated signatures.
- [x] Freeze provisional **train 574,585 / validation 123,125 / test 123,124** records.
- [x] Keep identical Core19 feature signatures out of different partitions.
- [ ] Verify each feature's meaning and whether an Ubuntu/Raspberry Pi gateway can actually extract it.
- [ ] Check session/capture leakage and dataset shortcuts (especially `Service` and missing values).
- [ ] Verify feature compatibility before making cross-dataset claims.

## Phase 3 — Full-training machine learning models

All five use **X-IIoTID Core19**, the full frozen **574,585-row training set**, and the same **123,125-row validation set**.

| Model | Attack F1 | False-positive rate | Validation status |
|---|---:|---:|---|
| Decision Tree | 98.42% | 1.00% | Done |
| Random Forest | 98.75% | 1.44% | Done |
| Extra Trees | 92.80% | 8.64% | Done |
| **LightGBM** | **98.92%** | 1.14% | Done |
| AdaBoost | 95.17% | 4.39% | Done |

- [x] Train, validate and save results for all five models (Notebooks 08–12).
- [x] Compare validation scores (Notebook 13).
- [x] Keep the **test set untouched** during current training, validation and shortlisting.

## Phase 4 — Laptop resource benchmarks and selection

Notebook 14 measures model size, RAM, CPU, single-flow latency and batch throughput **on the laptop**.

| Model | Saved file | Single-flow p95 | Sustained process CPU |
|---|---:|---:|---:|
| Decision Tree | 0.033 MiB | 11.60 ms | 100.5% |
| Random Forest | 2.846 MiB | 41.29 ms | 117.2% |
| Extra Trees | 0.958 MiB | 42.13 ms | 128.8% |
| LightGBM | 0.215 MiB | 12.98 ms | 399.3% |
| AdaBoost | 0.029 MiB | 57.04 ms | 97.3% |

- [x] Record and visualize initial laptop resource costs.
- [x] **Provisional shortlist:** LightGBM, Decision Tree, Random Forest.
- [ ] Recheck LightGBM with controlled thread counts (CPU over 100% means multiple logical cores).
- [ ] Test missingness-only and reduced-feature baselines; examine false alarms and missed attacks.
- [ ] Confirm inference includes preprocessing; benchmark complete gateway processing separately.

## Phase 5 — Lightweight ensemble

- [ ] Check whether shortlisted models make **different mistakes** on the same validation records.
- [ ] Compare LightGBM alone with two-model and three-model combinations.
- [ ] Measure ensemble F1, false alarms, RAM, CPU, model size and latency.
- [ ] Select the smallest/fastest solution that gives a useful detection improvement.

## Phase 6 — Ubuntu IIoT edge-gateway simulation (planned)

**Goal:** Use an **Ubuntu VM as a virtual IIoT edge gateway** before moving the design to Raspberry Pi.

**Proposed lab flow:** `IIoT device simulators → Ubuntu gateway VM → upstream network / dashboard`

The Ubuntu VM should act as the **traffic path or a properly configured monitoring point**. Merely placing machines on the same virtual network does not ensure Ubuntu can see all their packets.

- [ ] Create Ubuntu VM; record OS, CPU/RAM allocation and network adapters.
- [ ] Add simulated IIoT clients (e.g., MQTT/CoAP traffic generators) and a receiving service.
- [ ] Configure Ubuntu to **route or observe** the lab traffic; verify packet visibility with Wireshark/tcpdump.
- [ ] Convert captured traffic into the **same verified network features** the trained model expects.
- [ ] Load the selected model/ensemble on Ubuntu; predict Normal or Attack from live flows.
- [ ] Generate **controlled, authorized test traffic**, record ground-truth events and compare alerts.
- [ ] Measure end-to-end latency (capture + flow creation + features + prediction), CPU, RAM and throughput.
- [ ] Test 5/10/15/20-second observation windows **only after timestamps and flow boundaries are verified**.

## Phase 7 — Raspberry Pi and dashboard

- [ ] Set up Raspberry Pi 4/5 (8 GB), install compatible Python dependencies and copy approved model artifacts.
- [ ] Repeat the Ubuntu gateway pipeline on Raspberry Pi and benchmark **actual Pi** CPU, RAM, latency and throughput.
- [ ] Integrate the dashboard: live traffic summaries, classifications, alerts and resource monitoring.
- [ ] Check long-running stability under representative IIoT traffic.

## Phase 8 — Final verification and research write-up

- [ ] Evaluate on Edge-IIoTset and ToN-IoT **only after feature/label mapping is justified**.
- [ ] Freeze the final model and thresholds, then run the held-out X-IIoTID test **once**.
- [ ] Document results, experiment settings, figures, limits and reproducibility steps.
- [ ] Prepare research report, presentation and demo.

## Next 5 tasks

1. Confirm Notebook 14's saved graphs and CSV are preserved in the Git branch.
2. Validate feature availability and missingness shortcuts before trusting high F1 scores.
3. Check model error diversity and test lightweight ensemble candidates.
4. Set up the **Ubuntu VM as a gateway** with simulated IIoT traffic and verified packet capture.
5. Benchmark the complete pipeline on Ubuntu, then repeat on the Raspberry Pi.

**Important limitations:** Current scores are from a **provisional signature-disjoint X-IIoTID split**, not independently verified device/session data; model scores are for attack/normal **flow classification**, not proof of complete multi-stage APT detection. Resource measurements so far are from the **laptop**, not Raspberry Pi.
