"""Offline unit tests for shared model registry, feature-only inference, validation isolation."""
import sys
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
from core import (ALL_FEATURES, blind_validation_record, batch_predict, evidence_event,
                  ground_truth_record, load_model, load_validation, normalize_input,
                  predict, read_blind_batch, read_registry, hash_file, report_metrics)

class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rootctx=tempfile.TemporaryDirectory()
        cls.root=Path(cls.rootctx.name)
        cls.example=[]
        for i in range(30):
            cls.example.append({"src_port":49000+i,"dst_port":80 if i<15 else 502,
                "proto":"tcp" if i<15 else "udp","service":"http" if i<15 else "-",
                "duration":1.0+i/10,"src_bytes":500+i,"dst_bytes":200+i,
                "conn_state":"SF" if i<15 else "S0", "src_pkts":5+i,"dst_pkts":3+i})
        feats=list(ALL_FEATURES)
        X=pd.DataFrame(cls.example)
        y=np.array([0]*15+[1]*15)
        pre=ColumnTransformer([("numeric",SimpleImputer(strategy="median"),
            [f for f in feats if f in {"src_port","dst_port","duration","src_bytes","dst_bytes","src_pkts","dst_pkts"}]),
            ("categorical",OneHotEncoder(handle_unknown="ignore"),["proto","service","conn_state"])])
        pipe=Pipeline([("preprocessing",pre),("classifier",DecisionTreeClassifier(random_state=42))])
        pipe.fit(X,y)
        cls.config={"id":"synthetic", "name":"synthetic", "signal":"network", "features":feats,
                    "model_path":"models/demo.joblib", "report_path":"reports/demo.json",
                    "validation_path":"data/processed/validation.csv","figures_dir":"reports/figures/demo"}
        for d in ["models","reports","data/processed"]:
            (cls.root/d).mkdir(parents=True,exist_ok=True)
        joblib.dump(pipe, cls.root/"models/demo.joblib")
        val=X.copy()
        val["label"]=[str(i) for i in y];val["type"]=["normal"]*15+["scanning"]*15
        val.to_csv(cls.root/"data/processed/validation.csv",index=False)
        report={"project_id":"J26-CS-336","input_feature_names":feats,
                "encoded_feature_count":len(pre.get_feature_names_out()),"validation_records":30,
                "source_sha256":{"validation":hash_file(cls.root/"data/processed/validation.csv")},
                "decision_tree_validation":{"accuracy":1.0}}
        (cls.root/"reports/demo.json").write_text(json.dumps(report),encoding="utf8")
        cls.pipe=pipe
    @classmethod
    def tearDownClass(cls):cls.rootctx.cleanup()

    def test_labels_not_in_predictors(self):
        record=dict(self.example[0],label=1,type="attack")
        inp=normalize_input(record,list(ALL_FEATURES))
        self.assertEqual(inp.columns.tolist(),list(ALL_FEATURES))
        self.assertNotIn("label",inp.columns)
        self.assertNotIn("type",inp.columns)

    def test_normal_and_attack_inference(self):
        for data,expect in [(self.example[0],0),(self.example[-1],1)]:
            answer=predict(self.pipe,self.config,data)
            self.assertEqual(answer["predicted_label"],expect)
            self.assertGreaterEqual(answer["attack_score"],0)
            self.assertLessEqual(answer["attack_score"],1)
            event=evidence_event(answer,source="manual")
            self.assertNotIn("actual_label",event)
            self.assertNotIn("type",event)

    def test_fitted_model_report_and_validation_replay(self):
        p,report=load_model(self.root,self.config)
        df=load_validation(self.root,self.config,report)
        record=blind_validation_record(df,29,self.config["features"])
        self.assertNotIn("label",record)
        self.assertNotIn("type",record)
        outcome=predict(p,self.config,record)
        actual=ground_truth_record(df,29)
        self.assertEqual(outcome["predicted_label"],actual["actual_label"])
        self.assertEqual(report_metrics(report)["accuracy"],1.0)

    def test_batch_requires_feature_only(self):
        import io
        valid=pd.DataFrame(self.example[:2]).to_csv(index=False).encode()
        clean=read_blind_batch(io.BytesIO(valid),self.config["features"])
        out=batch_predict(self.pipe,self.config,clean)
        self.assertEqual(len(out),2)
        self.assertNotIn("label",out.columns)
        invalid=pd.DataFrame([{**self.example[0],"label":0}]).to_csv(index=False).encode()
        with self.assertRaisesRegex(ValueError,"label/type"):
            read_blind_batch(io.BytesIO(invalid),self.config["features"])

    def test_invalid_features(self):
        with self.assertRaises(ValueError):
            normalize_input({**self.example[0],"dst_port":65536},self.config["features"])
        with self.assertRaises(ValueError):
            normalize_input({**self.example[0],"src_pkts":-1},self.config["features"])

    def test_test_partition_cannot_be_replayed(self):
        wrong={**self.config,"validation_path":"data/processed/test.csv"}
        report=json.loads((self.root/"reports/demo.json").read_text())
        with self.assertRaisesRegex(ValueError,"validation.csv"):
            load_validation(self.root, wrong, report)

    def test_validation_hash_protection(self):
        report=json.loads((self.root/"reports/demo.json").read_text())
        copy={**report,"source_sha256":{"validation":"bad"}}
        with self.assertRaises(ValueError):
            load_validation(self.root,self.config,copy)

    def test_registry_configs(self):
        configs=read_registry(Path(__file__).resolve().parents[1]/"dashboard/models.json")
        self.assertEqual(len(configs),2)
        self.assertEqual(len(configs[0]["features"]),10)
        self.assertEqual(len(configs[1]["features"]),8)
        self.assertNotIn("label",configs[0]["features"])

    def test_no_ports_model_schema(self):
        cfg={**self.config,"features":[f for f in ALL_FEATURES if f not in ("src_port","dst_port")]}
        data=normalize_input(self.example[0],cfg["features"])
        self.assertNotIn("src_port",data.columns)
        self.assertEqual(data.shape,(1,8))

if __name__=="__main__":unittest.main()
