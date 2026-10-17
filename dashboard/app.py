"""J26-CS-336 Unified Research Dashboard v2.

Current source: trusted local ToN-IoT binary flow classifiers (manual/blind validation/
feature-only CSV). NOT live monitoring or multi-signal fusion. NEVER opens test.csv.
Run from project root with the virtual environment Python -m streamlit run dashboard/app.py
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from core import (ALL_FEATURES, NUMERIC, blind_validation_record, batch_predict,
                  evidence_event, ground_truth_record, hash_file, load_model,
                  load_validation, normalize_input, predict, read_blind_batch,
                  read_registry, read_report, report_metrics, root_path)

st.set_page_config(page_title="J26-CS-336 | Security Research Console", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
:root {--mint: #176a56; --sub: #64748b;}
.block-container {max-width: 1480px; padding-top: 1.7rem; padding-bottom: 3rem;}
html,body,[data-testid="stAppViewContainer"] {font-family: 'Segoe UI', Inter, system-ui, sans-serif;}
[data-testid="stSidebar"] {border-right: 1px solid rgba(130,145,160,.2);}
[data-testid="stMetric"] {background: rgba(126,149,160,.055);border: 1px solid rgba(126,149,160,.22);border-radius:15px;padding:14px 16px;}
[data-testid="stMetricLabel"] {font-size:.82rem;}
[data-testid="stMetricValue"] {font-weight:740;letter-spacing:-.04em;}
[data-testid="stForm"] {border: 1px solid rgba(126,149,160,.26);border-radius:17px;padding:22px;}
.page-head {margin-top: 0; font-size: 2rem; font-weight: 760;line-height:1.14;letter-spacing:-.045em;}
.eyebrow {font-size:.72rem;text-transform:uppercase;letter-spacing:.145em;color:#0c8570;font-weight:800;margin-bottom:.5rem;}
.subtitle {font-size:.96rem;color:#64748b;margin-bottom:1.15rem;max-width:950px;line-height:1.58;}
.panel {padding:18px 20px;border:1px solid rgba(126,149,160,.22);border-radius:16px;background:rgba(126,149,160,.045);height:100%;}
.panel-title {font-size:.93rem;font-weight:760;margin:0 0 7px;}
.panel-copy {font-size:.85rem;line-height:1.55;color:#738393;}
.mini {font-size:.8rem;color:#64748b;}
.flowstep {border:1px solid rgba(126,149,160,.25);border-radius:15px;padding:15px;min-height:108px;background:rgba(126,149,160,.04);}
.flowstep .n {font-size:.7rem;letter-spacing:.1em;color:#0c8570;font-weight:800;}
.flowstep .name {font-size:.95rem;font-weight:730;margin:9px 0 5px;}
.flowstep .detail {font-size:.76rem;color:#64748b;line-height:1.4;}
.status-good {border-left:4px solid #159b75;padding:14px 17px;border-radius:8px;background:rgba(20,170,125,.07);}
.status-alert {border-left:4px solid #bb893b;padding:14px 17px;border-radius:8px;background:rgba(194,137,54,.07);}
hr {opacity:.45;}
</style>
""", unsafe_allow_html=True)

@st.cache_resource(show_spinner=False)
def cached_model(root: str, model_id: str, model_hash: str, report_hash: str):
    selected = next(m for m in REGISTRY if m["id"] == model_id)
    return load_model(Path(root), selected)

@st.cache_data(show_spinner=False)
def cached_validation(root: str, model_id: str, report_hash: str, validation_hash: str):
    selected = next(m for m in REGISTRY if m["id"] == model_id)
    verified_report = read_report(Path(root), selected)
    return load_validation(Path(root), selected, verified_report)


def heading(eyebrow: str, text: str, description: str):
    st.markdown(f'<div class="eyebrow">{eyebrow}</div><div class="page-head">{text}</div><p class="subtitle">{description}</p>', unsafe_allow_html=True)


def info_panel(title: str, body: str):
    st.markdown(f'<div class="panel"><div class="panel-title">{title}</div><div class="panel-copy">{body}</div></div>', unsafe_allow_html=True)


def get_metrics(report):
    try:
        return report_metrics(report)
    except (ValueError, TypeError):
        return {}


def model_status(config):
    return root_path(ROOT, config["model_path"]).is_file() and root_path(ROOT, config["report_path"]).is_file()


def result_display(out, origin, fields=None):
    is_alert = int(out["predicted_label"]) == 1
    css = "status-alert" if is_alert else "status-good"
    tag = "ATTACK-LIKE CONNECTION" if is_alert else "NORMAL-LIKE CONNECTION"
    st.markdown(f'<div class="{css}"><div class="mini">BINARY FLOW PREDICTION · {origin.upper()}</div><h2 style="margin:6px 0 4px">{tag}</h2><div class="mini">Model score, not a calibrated real-world probability or APT verdict</div></div>', unsafe_allow_html=True)
    p1, p2, p3 = st.columns(3)
    p1.metric("Attack score", f"{float(out['attack_score']):.1%}")
    p2.metric("Normal score", f"{float(out['normal_score']):.1%}")
    p3.metric("Encoded features", str(out.get("encoded_features", "—")))
    if fields is not None:
        with st.expander("01 · Model inputs — no ground-truth columns"):
            st.dataframe(pd.DataFrame([fields]), hide_index=True, use_container_width=True)
    with st.expander("02 · How preprocessing changed the features"):
        st.caption("Numeric values were passed to the training-fitted imputer; categories were one-hot encoded. These are the nonzero transformed features, not explanations of causality.")
        st.dataframe(pd.DataFrame(out.get("active_encoded_values", [])), hide_index=True, use_container_width=True)
    with st.expander("03 · Prediction trace & evidence JSON"):
        st.code(json.dumps(evidence_event(out, source=origin), indent=2), language="json")
        st.download_button("Download this evidence JSON", data=json.dumps(evidence_event(out, source=origin), indent=2), file_name="j26_network_inference_evidence.json", mime="application/json", key="download_"+origin+out["model_id"])


def remember_result(result, origin):
    item = {"time_utc": result["timestamp_utc"], "source": origin,
            "model": result["model_id"], "prediction": result["prediction_text"], "attack_score": round(result["attack_score"], 5)}
    if "history" not in st.session_state:
        st.session_state.history = []
    st.session_state.history.insert(0, item)
    st.session_state.history = st.session_state.history[:100]


REGISTRY = read_registry(HERE / "models.json")
NAV = ["Overview", "Prediction Lab", "Blind Validation", "Batch Inference", "Model Analytics", "Evidence & Integration", "System & Setup"]
with st.sidebar:
    st.markdown("### ◈ J26-CS-336")
    st.caption("IIoT Security Research Console  /  v2")
    st.divider()
    choice = st.radio("Workspace", NAV, label_visibility="collapsed")
    st.divider()
    active_id = st.selectbox("Active network classifier", options=[r["id"] for r in REGISTRY], format_func=lambda ident: next(x["name"] for x in REGISTRY if x["id"] == ident))
    config = next(x for x in REGISTRY if x["id"] == active_id)
    st.caption("Connection-level ToN-IoT · Binary detection")
    if model_status(config):
        st.success("Model artifact found")
    else:
        st.warning("Model artifact or report missing")
    st.divider()
    st.markdown("**Other signals**")
    st.caption("Device telemetry · Not connected")
    st.caption("Physical sensors · Not connected")
    st.caption("Fusion · Not connected")
    st.divider()
    st.caption("Local-only prototype. No live packet capture. Held-out test.csv is never read.")

pipe, report, load_error = None, None, None
if model_status(config):
    try:
        model_file = root_path(ROOT, config["model_path"])
        pipe, report = cached_model(str(ROOT), active_id, hash_file(model_file), hash_file(root_path(ROOT, config["report_path"])))
    except Exception as ex:
        load_error = str(ex)
else:
    load_error = "Model or report not found in this project directory."
metrics = get_metrics(report) if report else {}

if choice == "Overview":
    heading("RESEARCH SYSTEM / STATUS", "IIoT Security Overview", "A shared workspace for network flow detection, model evidence, and future host/sensor fusion. Only verified local information is displayed.")
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Network classifier", "Ready" if pipe is not None else "Unavailable")
    c2.metric("Validation accuracy", f"{metrics['accuracy']:.2%}" if "accuracy" in metrics else "—")
    c3.metric("Attack recall", f"{metrics['attack_recall']:.2%}" if "attack_recall" in metrics else "—")
    c4.metric("Live packet feed", "Not connected")
    st.markdown("### Detection workflow")
    steps=[("01", "Input source", "Manual entry, blind validation or feature-only CSV"),
           ("02", "Schema check", "Expected features, numeric ranges and missing values"),
           ("03", "Preprocessing", "Saved imputer + one-hot encoder from training"),
           ("04", "Model inference", "Saved binary classifier, no fitting or labels"),
           ("05", "Evidence", "Normal/attack-like, score and prediction trace")]
    cols=st.columns(5)
    for c,(num,title,description) in zip(cols,steps):
        with c:
            st.markdown(f'<div class="flowstep"><div class="n">STEP {num}</div><div class="name">{title}</div><div class="detail">{description}</div></div>', unsafe_allow_html=True)
    st.caption("Future path: verified gateway observations → compatible flow/window features → selected edge model → timestamped evidence → cross-signal fusion.")
    st.markdown("### Research components")
    a,b,c=st.columns(3)
    with a: info_panel("Network detector · Prototype ready", "Saved ToN-IoT Decision Tree available for manual and offline validation demos. CICAPT and real traffic integration are pending.")
    with b: info_panel("Device telemetry · Awaiting connection", "Team member's host/device evidence will be integrated using an agreed timestamp and device identifier schema.")
    with c: info_panel("Physical sensors · Awaiting connection", "Water level, pressure and temperature monitoring can join the common dashboard after testbed instrumentation.")
    st.markdown("### Current session's inference activity")
    if st.session_state.get("history"):
        st.dataframe(pd.DataFrame(st.session_state.history), hide_index=True, use_container_width=True)
    else:
        st.info("No manual, validation or batch predictions in this session yet. Open Prediction Lab to try one.")
    st.caption("Validation metrics describe ToN-IoT connection-level experiments, not live IIoT performance, APT attribution or the four window durations.")

elif choice == "Prediction Lab":
    heading("01 / INPUT → MODEL → OUTPUT", "Manual Prediction Lab", "Enter network connection features. Ground-truth labels are intentionally absent: the saved model must make its own prediction.")
    if load_error:
        st.error(f"Cannot load active model: {load_error}")
        st.info("See System & Setup for required local artifacts.")
    else:
        with st.form("manual_form"):
            st.markdown("#### Connection characteristics")
            left, mid, right = st.columns(3)
            raw = {}
            with left:
                if "src_port" in config["features"]: raw["src_port"] = st.number_input("Source port", 0, 65535, 49152)
                if "dst_port" in config["features"]: raw["dst_port"] = st.number_input("Destination port", 0, 65535, 80)
                raw["proto"] = st.selectbox("Transport protocol", ["tcp","udp","icmp"])
                raw["service"] = st.selectbox("Service", ["-","http","dns","ftp","ssl","smb","gssapi","dce_rpc","smb;gssapi"])
            with mid:
                raw["duration"] = st.number_input("Connection duration (seconds)", min_value=0.0, value=1.0, step=0.1)
                raw["src_bytes"] = st.number_input("Source bytes", min_value=0, value=600, step=1)
                raw["dst_bytes"] = st.number_input("Destination bytes", min_value=0, value=350, step=1)
            with right:
                raw["src_pkts"] = st.number_input("Source packet count", min_value=0, value=8, step=1)
                raw["dst_pkts"] = st.number_input("Destination packet count", min_value=0, value=5, step=1)
                raw["conn_state"] = st.selectbox("Connection state", ["SF","S0","REJ","OTH","SH","S1","S2","S3","SHR","RSTO","RSTOS0","RSTR","RSTRH"])
            go = st.form_submit_button("Run network prediction", type="primary", use_container_width=True)
        if go:
            try:
                result = predict(pipe, config, raw)
                result["source"] = "manual"
                st.session_state["manual_prediction"] = {"id": active_id, "inputs": raw, "result": result}
                remember_result(result, "manual")
            except Exception as ex:
                st.error(f"Prediction rejected: {ex}")
        recent = st.session_state.get("manual_prediction")
        if recent and recent["id"] == active_id:
            st.divider()
            result_display(recent["result"], "manual", recent["inputs"])
        st.info("Connection duration, bytes and packet statistics should come from a trusted flow extractor in a real deployment. Arbitrary manual values demonstrate the interface only.")

elif choice == "Blind Validation":
    heading("02 / HELD-OUT VALIDATION REPLAY", "Blind Validation", "Choose a validation record by index. The dashboard sends feature columns to the model and reveals the ground-truth answer only after prediction.")
    st.caption("Validation partition only; reserved test.csv remains unopened. No retraining occurs.")
    if load_error:
        st.error(f"Active model unavailable: {load_error}")
    else:
        try:
            validation_path = root_path(ROOT, config["validation_path"])
            df = cached_validation(str(ROOT), active_id, hash_file(root_path(ROOT, config["report_path"])), hash_file(validation_path))
            with st.expander("Export feature-only validation examples for the batch demo"):
                count = st.slider("Number of records", min_value=1, max_value=100, value=20)
                blind_export = df.loc[:, config["features"]].head(count).to_csv(index=False)
                st.download_button("Download blind_validation_features.csv", data=blind_export,
                                   file_name="blind_validation_features.csv", mime="text/csv")
            c1,c2=st.columns([1,2])
            with c1:
                idx1=st.number_input("Validation record number", min_value=1, max_value=len(df), value=1, step=1)
                if st.button("Predict this record", type="primary", use_container_width=True):
                    blind = blind_validation_record(df, int(idx1)-1, config["features"])
                    result = predict(pipe, config, blind)
                    result["source"] = "validation"
                    st.session_state["validation_prediction"] = {"id": active_id, "row": int(idx1)-1, "features": blind, "result": result, "reveal": False}
                    remember_result(result, "validation")
            with c2:
                st.markdown("**What is hidden?**")
                st.info("The original CSV retains the label and attack type for fair scoring. Neither column is provided to the selected classifier. Choosing a record by index avoids filtering by known label before prediction.")
            entry=st.session_state.get("validation_prediction")
            if entry and entry["id"] == active_id and entry["row"] == int(idx1)-1:
                st.divider()
                result_display(entry["result"], "validation", entry["features"])
                if st.button("Reveal the actual validation label and compare", type="secondary"):
                    st.session_state["validation_prediction"]["reveal"] = True
                    entry["reveal"] = True
                if entry["reveal"]:
                    truth = ground_truth_record(df, entry["row"])
                    a,b,c=st.columns(3)
                    a.metric("Model prediction", "Attack" if entry["result"]["predicted_label"] else "Normal")
                    b.metric("Actual dataset label", "Attack" if truth["actual_label"] else "Normal")
                    c.metric("Comparison", "Correct" if truth["actual_label"]==entry["result"]["predicted_label"] else "Incorrect")
                    st.caption(f"Dataset attack category (evaluation only): {truth['dataset_type']}. This is NOT the model's predicted attack type.")
                    if truth["actual_label"] != entry["result"]["predicted_label"]:
                        st.warning("This example is a false positive or false negative. One wrong result does not imply the full model is invalid.")
        except Exception as ex:
            st.error(f"Validation replay unavailable: {ex}")
            st.caption("Manual and batch inference still work if labeled validation data are not available on this machine.")

elif choice == "Batch Inference":
    heading("03 / INPUT FILE → BATCH OUTPUT", "Blind CSV Batch", "Upload a feature-only CSV to run predictions on many network connections. No label columns are accepted; accuracy cannot be computed without ground truth.")
    if load_error:
        st.error(f"Active model unavailable: {load_error}")
    else:
        schema = config["features"]
        with st.expander("Required input columns", expanded=True):
            st.code(",".join(schema), language="text")
            st.download_button("Download CSV header template", ",".join(schema)+"\n", file_name=f"{active_id}_input_template.csv", mime="text/csv")
        uploaded = st.file_uploader("Choose feature-only CSV (maximum 500 rows)", type="csv")
        if uploaded and st.button("Run batch inference", type="primary"):
            try:
                if uploaded.size > 2_000_000:
                    raise ValueError("Maximum file size 2 MB")
                clean = read_blind_batch(io.BytesIO(uploaded.getvalue()), schema)
                output = batch_predict(pipe, config, clean)
                st.session_state["batch"] = {"id":active_id,"output":output}
                st.success(f"Predicted {len(output):,} unlabeled records. Accuracy unavailable without ground-truth labels.")
            except Exception as ex:
                st.error(f"Batch rejected: {ex}")
        saved=st.session_state.get("batch")
        if saved and saved["id"]==active_id:
            output=saved["output"]
            a,b,c=st.columns(3)
            a.metric("Rows processed", len(output))
            b.metric("Attack-like predictions", int((output["predicted_label"]==1).sum()))
            c.metric("Normal-like predictions", int((output["predicted_label"]==0).sum()))
            st.dataframe(output, hide_index=True, use_container_width=True)
            st.download_button("Download predictions.csv", data=output.to_csv(index=False), file_name=f"{active_id}_predictions.csv",mime="text/csv",type="primary")
            st.caption("These are model outputs, not verified attack ground truth or an APT campaign verdict.")

elif choice == "Model Analytics":
    heading("04 / METRICS & EVIDENCE", "Model Analytics", "Existing research validation reports and figures. These numbers were calculated during model development, not generated from live network traffic.")
    if load_error:
        st.error(f"Model/report unavailable: {load_error}")
    else:
        a,b,c,d=st.columns(4)
        a.metric("Accuracy", f"{metrics.get('accuracy', 0):.2%}" if "accuracy" in metrics else "—")
        b.metric("Attack F1", f"{metrics.get('attack_f1', 0):.2%}" if "attack_f1" in metrics else "—")
        c.metric("False positives", str(metrics.get("confusion_matrix", {}).get("FP", "—")))
        d.metric("False negatives", str(metrics.get("confusion_matrix", {}).get("FN", "—")))
        st.markdown("### Research charts")
        folder = root_path(ROOT, config["figures_dir"])
        imgs = sorted(p for p in folder.glob("*.png") if p.is_file()) if folder.is_dir() else []
        if not imgs:
            st.info("No charts found for this model. You can still run inference if its model artifact exists.")
        for i in range(0, len(imgs), 2):
            columns=st.columns(2)
            for col,path in zip(columns,imgs[i:i+2]):
                with col:
                    st.markdown("**"+path.stem.replace("_", " ").title()+"**")
                    st.image(str(path), use_container_width=True)
        with st.expander("Show validation metric details & provenance"):
            st.json({"model":config["id"], "metrics":metrics, "project":report.get("project_id"),
                     "train_or_validation_rows": {"train":report.get("training_records",report.get("training_rows")),
                     "validation":report.get("validation_records",report.get("validation_rows"))},
                     "held_out_test": report.get("test_partition"),
                     "known_limitations": report.get("limitations", [])})
        st.warning("ToN-IoT flow metrics do not demonstrate live industrial monitoring, APT attribution, Raspberry Pi speed, or 5/10/15/20-second model accuracy.")

elif choice == "Evidence & Integration":
    heading("05 / CROSS-SIGNAL INTEGRATION", "Evidence & Data Flow", "The dashboard is designed for all research members. Network predictions work now; host, physical sensors and fusion need verified upstream data and shared interfaces.")
    a,b,c=st.columns(3)
    with a: info_panel("NETWORK · Prototype", "Manual / validation / feature-only CSV → saved network model → binary flow assessment. No automatic packet collector yet.")
    with b: info_panel("DEVICE TELEMETRY · Pending", "CPU, memory, system events and device behaviour from the teammate's detector will enter via a future evidence adapter.")
    with c: info_panel("PHYSICAL SENSORS · Pending", "PLC process state, water level, pressure and temperature will enter through the industrial simulation and sensor collector.")
    st.markdown("### Proposed shared evidence contract")
    last=st.session_state.get("manual_prediction") or st.session_state.get("validation_prediction")
    if last and last["id"]==active_id:
        event=evidence_event(last["result"], source=last["result"]["source"])
        st.json(event)
        st.download_button("Download example event", data=json.dumps(event,indent=2),file_name="j26_evidence_event.json",mime="application/json")
    else:
        st.code(json.dumps({"schema_version":"0.1","project_id":"J26-CS-336","timestamp_utc":"<UTC event time>",
                           "signal":"network","source":"flow-monitor","device_id":None,"model_id":"<model>",
                           "prediction":None,"score":None,"window_seconds":None,"evidence":[]}, indent=2))
    st.markdown("### Integration readiness")
    st.dataframe(pd.DataFrame([
        {"Component":"Network flow", "State":"Prototype", "Input":"Manual / validation / CSV", "Output":"Binary score + evidence"},
        {"Component":"Network packet collector", "State":"Not connected", "Input":"Verified packets/flows", "Output":"Window features"},
        {"Component":"Device telemetry", "State":"Not connected", "Input":"Host events", "Output":"Device evidence"},
        {"Component":"Physical sensors", "State":"Not connected", "Input":"PLC/sensor readings", "Output":"Process evidence"},
        {"Component":"Fusion engine", "State":"Not connected", "Input":"Synchronized signals", "Output":"Evidence-supported risk"},
    ]),hide_index=True,use_container_width=True)
    st.info("The 5s/10s/15s/20s processors have passed synthetic tests. They are not yet wired to this connection-level classifier. Window timestamps and actual device IDs must come from verified sources.")

else:  # System & Setup
    heading("06 / SYSTEM INVENTORY", "Model & Setup", "See which local assets are available and what would be required for a real gateway-based demonstration.")
    st.markdown("### Available model entries")
    inventory=[]
    for model in REGISTRY:
        inventory.append({"Model":model["name"],"Status":"Available" if model_status(model) else "Missing local files",
                          "Expected inputs":len(model["features"]),"Path":model["model_path"]})
    st.dataframe(pd.DataFrame(inventory),hide_index=True,use_container_width=True)
    st.markdown("### Current model paths")
    st.code(f"Model: {config['model_path']}\nReport: {config['report_path']}\nValidation: {config['validation_path']}\nFigures: {config['figures_dir']}")
    if load_error:
        st.error(load_error)
    else:
        st.success("Selected trained model + report + feature schema verified")
    st.markdown("### Safety & evaluation boundaries")
    st.markdown("""
- **Training labels** are used only by offline training code; this dashboard never fits models.
- **Validation labels** stay in the original validation CSV and are revealed after inference; they are never model inputs.
- **Held-out test.csv** is never read here. Final testing needs a separately approved, frozen evaluation step.
- **Models** are pickle/joblib artifacts: load only files you trained or fully trust.
- **Scores** are classifier scores, not calibrated certainty; manual inputs can be outside the training distribution.
- **No live data:** network tapping, CICAPT inference, Raspberry Pi telemetry, sensor adapters, model ensemble and risk fusion are future work.
- **No automatic network exposure:** bind Streamlit to 127.0.0.1 for local research demonstrations.
""")
    st.caption("Research console v2 · Reusable model registry; adding a new model still requires a genuinely compatible input schema and a saved validation report.")
