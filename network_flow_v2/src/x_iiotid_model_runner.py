"""One reproducible X-IIoTID network-only classifier experiment per notebook.

Train-on-train, compare-on-validation. The TEST CSV is NEVER opened here.
"""
from pathlib import Path
import inspect
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier,ExtraTreesClassifier,AdaBoostClassifier
from sklearn.metrics import (confusion_matrix,ConfusionMatrixDisplay,
                             precision_score,recall_score,f1_score,balanced_accuracy_score)
from sklearn.model_selection import train_test_split

SEED=42
CORE19=['Protocol','Service','Duration','Scr_bytes','Des_bytes','Conn_state',
        'is_syn_only','Is_SYN_ACK','is_pure_ack','is_with_payload','FIN or RST',
        'Scr_pkts','Scr_ip_bytes','Des_pkts','Des_ip_bytes','total_bytes',
        'total_packet','paket_rate','byte_rate']
CAT=['Protocol','Service','Conn_state','is_syn_only','Is_SYN_ACK','is_pure_ack','is_with_payload','FIN or RST']
NUM=[c for c in CORE19 if c not in CAT]
MISSING={'', '-', '?', 'n/a','na','nan','none','null','missing','unknown','<missing>'}
MODELS=('decision_tree','random_forest','extra_trees','lightgbm','adaboost')

def read_partition(root,part):
    if part not in ('train','validation'):
        raise ValueError('Test set is sealed during baseline comparisons')
    path=Path(root)/'data/splits'/f'x_iiotid_core19_{part}_v1.csv.gz'
    if not path.is_file():
        raise FileNotFoundError(f'{path}\nFirst run 07_x_iiotid_export_frozen_splits.ipynb')
    frame=pd.read_csv(path,dtype=str,keep_default_na=False)
    required=set(CORE19+['class2','class3','csv_row_index_0based'])
    if missing:=required-set(frame.columns):
        raise ValueError(f'Missing split fields: {sorted(missing)}')
    if frame['csv_row_index_0based'].duplicated().any():
        raise ValueError('Duplicate original row IDs in partition')
    if not frame['class3'].isin(['Normal','Attack']).all():
        raise ValueError('Unexpected label: expected Normal / Attack')
    return frame

def clean_features(frame):
    out=frame[CORE19].copy()
    for c in NUM:
        s=out[c].astype(str).str.strip()
        s=s.mask(s.str.casefold().isin(MISSING))
        out[c]=pd.to_numeric(s,errors='coerce').astype(np.float32)
    for c in CAT:
        s=out[c].astype(str).str.strip()
        out[c]=s.mask(s.str.casefold().isin(MISSING),'__MISSING__')
    return out

def preprocessor():
    options={'handle_unknown':'ignore'}
    if 'sparse_output' in inspect.signature(OneHotEncoder).parameters:
        options['sparse_output']=True
    else: options['sparse']=True
    return ColumnTransformer([
        ('num',SimpleImputer(strategy='median',keep_empty_features=True),NUM),
        ('cat',OneHotEncoder(**options),CAT)
    ], sparse_threshold=1.0)

def classifier(name):
    if name=='decision_tree':
        return DecisionTreeClassifier(max_depth=14,min_samples_leaf=30,class_weight='balanced',random_state=SEED)
    if name=='random_forest':
        return RandomForestClassifier(n_estimators=100,max_depth=16,min_samples_leaf=20,
                                      class_weight='balanced_subsample',random_state=SEED,n_jobs=-1)
    if name=='extra_trees':
        return ExtraTreesClassifier(n_estimators=100,max_depth=16,min_samples_leaf=20,
                                    class_weight='balanced',random_state=SEED,n_jobs=-1)
    if name=='lightgbm':
        try:
            from lightgbm import LGBMClassifier
        except ImportError as e:
            raise ImportError('LightGBM is missing. Run %pip install lightgbm in this notebook and restart the kernel.') from e
        return LGBMClassifier(n_estimators=160,num_leaves=31,max_depth=-1,learning_rate=.05,
                              min_child_samples=30,random_state=SEED,n_jobs=4,verbosity=-1)
    if name=='adaboost':
        weak=DecisionTreeClassifier(max_depth=2,min_samples_leaf=30,random_state=SEED)
        kw={'n_estimators':100,'learning_rate':0.5,'random_state':SEED}
        if 'estimator' in inspect.signature(AdaBoostClassifier).parameters:
            kw['estimator']=weak
        else: kw['base_estimator']=weak
        return AdaBoostClassifier(**kw)
    raise ValueError(f'Unknown model: {name}; choose from {MODELS}')

def execute(root,name,train_limit=150000):
    root=Path(root)
    if name not in MODELS: raise ValueError(f'Unsupported model: {name}')
    audit=root/'reports/audits'
    info=audit/'x_iiotid_core19_frozen_split_exports_v1.json'
    if not info.is_file(): raise FileNotFoundError(f'Run split-export notebook 07 first: {info}')
    split_details=json.loads(info.read_text(encoding='utf-8'))
    train_data=read_partition(root,'train')
    validation_data=read_partition(root,'validation')
    counts=split_details['counts']
    if len(train_data)!=counts['train'] or len(validation_data)!=counts['validation']:
        raise ValueError('Local split file sizes disagree with frozen manifest metadata')
    overlap=set(train_data.csv_row_index_0based).intersection(validation_data.csv_row_index_0based)
    if overlap: raise ValueError('Original row IDs overlap between train and validation')
    y_train=train_data['class3'].map({'Normal':0,'Attack':1}).to_numpy(dtype=np.uint8)
    y_valid=validation_data['class3'].map({'Normal':0,'Attack':1}).to_numpy(dtype=np.uint8)
    if train_limit is not None and len(train_data)>int(train_limit):
        # Fixed, class-stratified train-only sampling. ALL models use same seed and cap.
        selected,_=train_test_split(np.arange(len(train_data)),train_size=int(train_limit),
                                    stratify=y_train,random_state=SEED)
        train_data=train_data.iloc[np.sort(selected)].copy()
        y_train=y_train[np.sort(selected)]
    X_train=clean_features(train_data);X_valid=clean_features(validation_data)
    del train_data,validation_data
    model=Pipeline([('preprocessing',preprocessor()),('classifier',classifier(name))])
    t0=time.perf_counter(); model.fit(X_train,y_train); fit_seconds=time.perf_counter()-t0
    t0=time.perf_counter(); pred=model.predict(X_valid); predict_seconds=time.perf_counter()-t0
    tn,fp,fn,tp=confusion_matrix(y_valid,pred,labels=[0,1]).ravel()
    metrics={
        'model':name,'features':'Core19','train_rows_used':int(len(y_train)),
        'validation_rows':int(len(y_valid)),
        'precision_attack':float(precision_score(y_valid,pred,zero_division=0)),
        'recall_attack':float(recall_score(y_valid,pred,zero_division=0)),
        'f1_attack':float(f1_score(y_valid,pred,zero_division=0)),
        'balanced_accuracy':float(balanced_accuracy_score(y_valid,pred)),
        'false_positive_rate':float(fp/max(tn+fp,1)),
        'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),
        'fit_seconds':round(fit_seconds,3),
        'predict_ms_per_1000':round(1000*1000*predict_seconds/len(y_valid),3),
        'random_seed':SEED,'frozen_manifest_sha256':split_details['manifest_sha256'],
        'test_evaluated':False,
        'split_limitation':'No Core19 signature overlap, capture/session independence unverified',
        'feature_limitation':'Feature gateway extractability and semantic definitions pending verification',
        'hardware_note':'Laptop timing, NOT Raspberry Pi edge benchmarking'}
    audit.mkdir(parents=True,exist_ok=True)
    figs=root/'reports/figures';figs.mkdir(parents=True,exist_ok=True)
    models=root/'models/x_iiotid';models.mkdir(parents=True,exist_ok=True)
    pd.DataFrame([metrics]).to_csv(audit/f'x_iiotid_{name}_validation_v1.csv',index=False)
    (audit/f'x_iiotid_{name}_validation_v1.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
    fig,ax=plt.subplots(figsize=(5.6,4.8))
    ConfusionMatrixDisplay.from_predictions(y_valid,pred,labels=[0,1],
            display_labels=['Normal','Attack'],cmap='Blues',values_format='d',ax=ax)
    ax.set_title(f'X-IIoTID {name.replace("_"," ").title()} — validation')
    fig.tight_layout();fig.savefig(figs/f'x_iiotid_{name}_validation_cm_v1.png',dpi=170);plt.show()
    # Importance is indicative for the fitted model, not causal evidence.
    estimator=model.named_steps['classifier']
    if hasattr(estimator,'feature_importances_'):
        names=model.named_steps['preprocessing'].get_feature_names_out()
        importance=pd.Series(estimator.feature_importances_,index=names).sort_values(ascending=False).head(20)
        fig,ax=plt.subplots(figsize=(9,6))
        importance.iloc[::-1].plot.barh(ax=ax)
        ax.set_xlabel('Built-in model importance (not causal)')
        ax.set_title(f'Top transformed inputs — {name.replace("_"," ").title()}')
        fig.tight_layout();fig.savefig(figs/f'x_iiotid_{name}_feature_importance_v1.png',dpi=170);plt.show()
    joblib.dump(model,models/f'{name}_core19_v1.joblib',compress=3)
    print(f'\n{name.upper()} VALIDATION METRICS — TEST NOT OPENED')
    display=pd.DataFrame([metrics])[['model','train_rows_used','validation_rows',
       'precision_attack','recall_attack','f1_attack','balanced_accuracy','false_positive_rate',
       'fit_seconds','predict_ms_per_1000']]
    print(display.to_string(index=False,float_format=lambda f:f'{f:.4f}'))
    print('Saved model (local, Git-ignored):',models/f'{name}_core19_v1.joblib')
    print('Saved validation metrics and PNG charts in reports/')
    return metrics
