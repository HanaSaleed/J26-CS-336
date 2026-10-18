# Device Telemetry — CICAPT results (Branch A)

## 1. Setup
- Data: CICAPT-IIoT 2024 Phase 2 provenance (Auditd + SPADE). Phase 1 (benign) used only for baselines (programs, parent→child pairs).
- Unit: process (merged versions). 12,443 processes; 7,161 attack (7,056 `cp`/`base64` flood + 105 other). 45 features (3 artefact features excluded).
- Labels corrected by propagation (PID-block rule, margin 2 + children).
- Split: development < 2023-12-03 12:00 UTC; held-out test after (1,516 normal, 43 attack: 7 flood, 36 other). Test used once.
- Dev evaluation: 5-fold StratifiedGroupKFold, groups = hour blocks, stratified by normal/flood/other.
- Key metric: recall on non-flood attacks ("other"), at a fixed false-alarm budget.

## 2. Development results (out-of-fold)
| Step | Result | File |
|---|---|---|
| Baseline rule | recall_other 0.043, PR-AUC 0.018 | baselines_dev.csv |
| LightGBM | recall_other 0.942, FPR 0.010, PR-AUC 0.839 | lightgbm_dev.csv |
| Class weighting | worse: FPR 0.103, PR-AUC 0.316, so not used | lightgbm_dev.csv |
| Ablation | cmdline group dominant (PR-AUC 0.385 without it); `cmd_hidden_path` strongest single feature | lightgbm_*ablation_dev.csv |
| Screening | ET 0.899 / 0.001 / 0.950; AdaBoost 0.942 / 0.001 / 0.890; OCSVM 0.913 / 0.106 / 0.265; Isolation Forest failed (PR-AUC ≤ 0.093) | model_screening_dev.csv |
| Ensemble | Soft vote LGBM+ET best: 0.942 / 0.010 / 0.952; stacking unstable (collapsed on behaviour set) | ensemble_dev.csv |
| Diversity | Spearman 0.34–0.66 (full); ET~OCSVM −0.16 (behaviour) | model_correlation_dev.csv |
| Threshold | 0.6638 at 0.2% dev FPR (~5 alerts/day) | threshold_selection_dev.csv |

## 3. Held-out test (frozen detector, run once)
- Process level: recall 30/43 (0.698); flood 7/7; other 23/36 (0.639); **FPR 0/1,516**; precision 1.0; PR-AUC(other) 0.941.
- Window level (60 s): **9/9 attack windows detected, 0 false-alert windows** of 263.
- By tactic: lateral movement (unseen) 6/6; defence evasion (unseen) 10/22, median score 0.56 vs threshold 0.66; credential access 7/8; collection 4/4; discovery 3/3.
- Novelty (One-Class SVM): flags 0.6% normal, 72% other; catches 4 of 13 ensemble misses → kept as a separate indicator, not a vote.
- Behaviour-only LightGBM: PR-AUC 0.498 (base rate ≈ 0.02), but 0 recall at ≤1% FPR; at 5% budget recall_other 0.75, FPR 1.45%. 108/3,766 normal dev processes (2.9%) score ≥ 0.99, mostly uncommon file-operation programs.

## 4. Interpretation
The results show that the detector can generalise to an unseen attack tactic, successfully detecting all six lateral movement attacks in the held-out test set. Defence evasion was the most difficult tactic to detect because it uses ordinary administrative commands that can resemble legitimate activity. Command-line evidence was important for achieving strong detection performance at a low false-alarm rate. Behavioural features also provided useful signals, but were insufficient on their own to maintain high recall under a strict false-positive limit.

## 5. Limitations
- One dataset, one attack campaign, small held-out attack count (36 non-flood).
- Relies on command-line evidence; an attacker who hides or obfuscates it weakens detection.
- Labels partly reconstructed (propagation rule).
- Linux/Auditd only.
- Runtime on the Pi not yet measured.