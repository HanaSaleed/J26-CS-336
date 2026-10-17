# J26-CS-336 | Unified Security Research Dashboard v2

A single, extendable UI for the three research components. **Current working detector:** ToN-IoT flow-level Decision Tree. Also supports the existing no-ports Decision Tree if its local model and report exist. Live gateway traffic, CICAPT inference, host/sensor evidence, fusion, and Raspberry Pi telemetry are **not yet connected**.

## Folders and installation

Extract into the **original research workspace**, not only the GitHub checkout:

```
D:\IIoT-APT-Research\
  dashboard\
    app.py
    core.py
    models.json
    README.md
  tests\
    test_unified_dashboard.py
  models\ton_iot_decision_tree_v1\decision_tree_pipeline.joblib
  models\ton_iot_decision_tree_no_ports_v1\no_ports_pipeline.joblib
  reports\ton_iot_decision_tree_v1.json
  reports\ton_iot_decision_tree_no_ports_v1.json
  data\processed\ton_iot_group_holdout_v1\validation.csv
```

Requires previously trained model files and evaluation reports **on your computer**. Do not put model binaries or the 30,685-row validation dataset on the public repository.

Windows PowerShell (run in the original project root):

```powershell
Set-Location 'D:\IIoT-APT-Research'
.\.venv\Scripts\python.exe -m pip install streamlit
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_unified_dashboard.py' -v
.\.venv\Scripts\python.exe -m streamlit run .\dashboard\app.py --server.address 127.0.0.1
```

Open <http://localhost:8501> (Streamlit may select another available port).

## Navigation

| Page | Verified/current functionality |
|---|---|
| Overview | Local model availability, saved validation stats, real pipeline stages, status of pending connectors |
| Prediction Lab | Manual connection input, preprocessing trace, binary model prediction and score |
| Blind Validation | Choose validation record by index; predictor receives features only; actual label remains hidden until *Reveal* |
| Batch Inference | Upload feature-only CSV (max 500 rows); download predictions; no labels accepted |
| Model Analytics | Saved validation results and report PNG charts for each available model |
| Evidence & Integration | Demo evidence JSON and honest 'not connected' statuses for other components |
| System & Setup | Available models, input contract and evaluation safety rules |

## Ground truth isolation and testing

- **Do not delete** `label`/`type` from original datasets. They are the trusted answer key, never model inputs.
- For the validation demo, only columns in `models.json[].features` go into `.predict(...)` / `.predict_proba(...)`. Ground truth is shown later for comparison.
- The *Blind Validation* page can download a feature-only CSV for running a batch demo, without exporting answers.
- The dashboard **never reads** `data/processed/ton_iot_group_holdout_v1/test.csv`. A final independent test requires a separate, frozen, approved evaluation workflow.
- The model currently predicts binary Normal/Attack-like flow, not specific attack types, APT campaigns, MITRE tactics, or physical compromise.
- Scores are *not calibrated confidence*; manual records may be outside the training distribution.
- The dashboard does not train or modify the saved model.

## Adding new trained models

Edit `dashboard/models.json` and add an entry with a unique `id`, readable `name`, local `model_path`, compatible `report_path`, `validation_path`, `figures_dir`, and **exact ordered input features**. This prototype expects a trusted Scikit-learn `Pipeline` with `preprocessing` and `classifier` steps and binary classes `[0,1]`. A CICAPT-specific model with a different preprocessing, classification task or window schema will need an adapter, not just a new filename.

Future device/physical/fusion components need their own adapters that produce agreed timestamps and device IDs. The 'not connected' labels are intentional, not example measurements masquerading as real data.

## GitHub

Copy `dashboard/` and `tests/test_unified_dashboard.py` into `D:\J26-CS-336-NetworkFlow`, commit on `feature/network-flow`, and push after local validation. Keep `models/`, raw and processed data, and secrets untracked.
