# TON_IoT Modbus Dataset

## Purpose and source

This experiment uses the processed TON_IoT Modbus CSV for binary normal-versus-attack classification. The original CSV is kept outside the repository. Place a local copy at data/raw/ton_iot/IoT_Modbus.csv or pass its path with --data. The data/raw directory is ignored by Git.

Official dataset information:
- UNSW TON_IoT project: https://research.unsw.edu.au/projects/toniot-datasets
- Dataset structure paper: https://gala.gre.ac.uk/id/eprint/34598/7/34598_ESSOP_Generating_IoT_edge_network_datasets.pdf

## Target and predictors

The target is label (0 normal, 1 attack). The four predictors are:
- FC1_Read_Input_Register
- FC2_Read_Discrete_Value
- FC3_Read_Holding_Register
- FC4_Read_Coil

The type column is excluded from predictors because it provides attack-category information associated with the target. Date and time are parsed to a timestamp for ordering and partitioning, not used as predictors.

## Read-only inspection findings

The inspected processed file contains 287,194 rows, no missing values, 222,855 normal rows, and 64,339 attack rows. Attack rows by type are backdoor 40,011; password 18,115; injection 5,186; scanning 529; and xss 498.

The separate Modbus ground-truth file contains 59,989 event rows. All 59,989 distinct processed attack timestamps matched the ground-truth timestamps after trimming whitespace; no timestamp was missing or extra and no event type disagreed. Some processed rows share an attack timestamp, explaining why attack-row counts exceed event timestamp counts.

There are 12,314 rows in exact duplicate groups after timestamp normalization. These groups do not have conflicting labels or types. The baseline retains all rows; it does not treat repeated timestamps or repeated feature vectors as grounds for removing observations.

Attack activity is time-localized: scanning occurs on Apr 23, injection on Apr 25, password on Apr 26–27, xss on Apr 27, and backdoor on Apr 28–29, 2019.

## Split and baseline method

The experiment trains through Apr 25, 2019 inclusive and tests on later dates. It assigns all records on each date to the same side of the split. Training has 153,913 rows (148,198 normal and 5,715 attack). Testing has 133,281 rows (74,657 normal and 58,624 attack).

The baseline is a scikit-learn pipeline with StandardScaler followed by LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42). The model is fit only on training rows. The reported hard-prediction threshold is 0.5. Metrics include accuracy, precision, recall, F1, balanced accuracy, ROC AUC, average precision (PR AUC), and the confusion matrix.

This is a temporal and campaign holdout, not an IID estimate: training attacks include scanning and injection, while the test attacks include password, xss, and backdoor. Attack prevalence also changes substantially between partitions. Interpret the result as a first baseline for later-period generalization. Do not tune on this test set.

## Reproduction

Install requirements, then run from the repository root:

    python experiments/physical_sensor/train_modbus_baseline.py --data "PATH_TO_IoT_Modbus.csv" --output docs/results/modbus_temporal_baseline.csv

The script reports the partition counts and attack types. It does not modify the source CSV or save a model artifact.
## Exploratory model comparison

A second experiment compares the standardized, class-weighted logistic baseline with a 200-tree RandomForestClassifier using balanced subsampling. Both use the same four Modbus features, training rows through Apr 25, 2019, later-date holdout, and default 0.5 threshold. Results are in `docs/results/modbus_model_comparison.csv` and can be reproduced with:

    python experiments/physical_sensor/compare_modbus_models.py --data "PATH_TO_IoT_Modbus.csv"

On the later-period holdout, logistic regression achieved ROC AUC 0.5055 and recall 0.4981. The random forest achieved ROC AUC 0.4984 and recall 0.0002 (10 of 58,624 attacks detected), despite accuracy 0.5602. The accuracy reflects the holdout's class mix and should not be read as useful detection quality. This comparison reuses a holdout already reported by the first baseline, so it is exploratory and must not be treated as an unbiased final model-selection estimate. Do not tune a threshold on this holdout.
## Post-hoc error diagnostics

The comparison script also writes `docs/results/modbus_test_attack_type_diagnostics.csv` and `docs/results/modbus_test_daily_false_alarms.csv`. Attack type is used only to group the already-labeled test rows for reporting; it is never passed to either model. At the fixed 0.5 threshold, logistic regression detected about half of each test attack type and flagged about 45–50% of normal rows each day. The random forest generated only four false alarms across the normal test rows, but detected just 10 attacks total. This shows a poor detection-versus-false-alarm tradeoff for both models. These reports are diagnostic only and do not justify tuning against the reused holdout.
## Modbus feature profile

Run `python experiments/physical_sensor/profile_modbus_features.py --data "PATH_TO_IoT_Modbus.csv"` to create `docs/results/modbus_feature_profile.csv`. It reports unique-value counts, zero fractions, means, medians, upper quantiles, and maxima for each of the four input columns, grouped by train/test period and normal/attack type. These attack categories are report labels only, not model inputs.

In this dataset, the four inputs have many distinct numeric values and are almost always nonzero. Group means are broadly in the 31,000–34,000 range, with some differences between normal and attack groups. This simple summary does not prove the distributions overlap or establish that the features contain no signal; it motivates looking at the distributions and temporal behavior before changing the model.
## Feature distribution plots

Run `python experiments/physical_sensor/plot_modbus_distributions.py --data "PATH_TO_IoT_Modbus.csv"` to generate `docs/results/modbus_feature_distributions.svg`. It draws one panel per feature, with normalized curves for normal rows and each attack type in the training and test periods. Curves show the percentage of each group falling into each value bin, so smaller groups remain visible; the XSS group is small (498 rows) and should be interpreted cautiously. These plots are descriptive and do not tune or select a model.
## Quantified feature overlap

Run `python experiments/physical_sensor/measure_modbus_distribution_overlap.py --data "PATH_TO_IoT_Modbus.csv"` to create `docs/results/modbus_distribution_overlap.csv`. It compares normalized 32-bin histograms for each feature, separately for each period and attack type. `histogram_overlap` ranges from 0 (no shared bin mass) to 1 (identical binned distributions); it is a coarse, univariate measure, not a classifier score.

The later test-period backdoor and password rows have about 97–98% overlap with normal rows for each individual feature. XSS has about 84–87% overlap. The training-period injection rows have about 94–95% overlap, while scanning is about 85–89%. The high overlap helps explain why a single feature is not a clean separator. It does not rule out interactions between features, sequential behavior, or information in additional fields.
## Past-only temporal context experiment

Run `python experiments/physical_sensor/compare_modbus_temporal_context.py --data "PATH_TO_IoT_Modbus.csv"` to compare the same logistic-regression baseline with a 16-feature version. The extended version adds, for each of the four inputs, the prior distinct timestamp's mean value, the mean over the five preceding distinct timestamps, and the current value's change from the prior timestamp mean. Rows at the same timestamp share only earlier-timestamp context. Missing history at the start is imputed inside a training-fitted pipeline. Labels and attack type are not temporal predictors.

On the previously reported later-period holdout, adding context changed recall from 0.4981 to 0.5510 and false positives from 36,768 to 40,924 at the fixed 0.5 threshold. ROC AUC changed from 0.5055 to 0.5033, so the feature change did not improve ranking quality. The results are exploratory because this holdout has already been examined in earlier experiments; do not tune on it.
