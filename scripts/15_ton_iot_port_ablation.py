"""J26-CS-336: port-feature ablation, training and validation only.
Run from D:\\IIoT-APT-Research using the project's venv.
Creates a NEW versioned model, report, CSV and two validation charts.
Never opens test.csv, never overwrites previous outputs.
"""
import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

FEATURES = ('src_port','dst_port','proto','service','duration','src_bytes','dst_bytes','conn_state','src_pkts','dst_pkts')
KEPT = tuple(c for c in FEATURES if c not in ('src_port','dst_port'))
NUMERIC = ('duration','src_bytes','dst_bytes','src_pkts','dst_pkts')
CATEGORICAL = ('proto','service','conn_state')
SETTINGS = dict(max_depth=10, min_samples_leaf=20, class_weight='balanced', random_state=42)

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--data-dir',type=Path,default=Path('data/processed/ton_iot_group_holdout_v1'))
    ap.add_argument('--original-report',type=Path,default=Path('reports/ton_iot_decision_tree_v1.json'))
    ap.add_argument('--preprocessing-report',type=Path,default=Path('reports/ton_iot_preprocessing_v1.json'))
    ap.add_argument('--model-dir',type=Path,default=Path('models/ton_iot_decision_tree_no_ports_v1'))
    ap.add_argument('--report',type=Path,default=Path('reports/ton_iot_decision_tree_no_ports_v1.json'))
    ap.add_argument('--figure-dir',type=Path,default=Path('reports/figures/ton_iot_decision_tree_no_ports_v1'))
    ap.add_argument('--table-dir',type=Path,default=Path('reports/tables/ton_iot_decision_tree_no_ports_v1'))
    args=ap.parse_args()
    paths={k:args.data_dir / (k+'.csv') for k in ('train','validation')}
    originals=[*paths.values(),args.original_report,args.preprocessing_report,args.data_dir/'split_manifest.json']
    for path in originals:
        if not path.is_file(): raise FileNotFoundError(path)
    if any(x.exists() for x in (args.model_dir,args.report,args.figure_dir,args.table_dir)):
        raise FileExistsError('Output version exists. Previous model/report/figures cannot be overwritten.')
    import numpy as np
    import pandas as pd
    import joblib
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OneHotEncoder
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import confusion_matrix, accuracy_score,balanced_accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,average_precision_score

    original=json.loads(args.original_report.read_text(encoding='utf-8-sig'))
    prep=json.loads(args.preprocessing_report.read_text(encoding='utf-8-sig'))
    manifest=json.loads((args.data_dir/'split_manifest.json').read_text(encoding='utf-8-sig'))
    if tuple(prep.get('features_in_order', []))!=FEATURES: raise ValueError('Preprocessing feature mismatch')
    if tuple(manifest.get('candidate_input_features', []))!=FEATURES: raise ValueError('Manifest feature mismatch')
    if prep.get('preprocessing_fit_on')!='train.csv exclusively': raise ValueError('Invalid preprocessing provenance')
    for partition,p in paths.items():
        expect=prep['input_files_sha256'][partition]
        if digest(p)!=expect: raise ValueError('Modified dataset: '+str(p))
    orig_hash=original.get('source_sha256',{})
    for partition,p in paths.items():
        if orig_hash.get(partition)!=digest(p): raise ValueError('Original baseline used different dataset partition')
    if original.get('decision_tree_hyperparameters') != SETTINGS: raise ValueError('Original Decision Tree settings differ')
    if 'decision_tree_validation' not in original: raise ValueError('Original baseline metrics missing')
    frames={}
    for name,p in paths.items():
        df=pd.read_csv(p,dtype='string',keep_default_na=False)
        if set(df.columns)!=set(FEATURES)|{'label','type'}: raise ValueError('Unexpected dataset columns')
        if len(df)!=int(manifest['partitions'][name]['rows']): raise ValueError('Wrong row count')
        if not df['label'].isin(['0','1']).all(): raise ValueError('Unexpected labels')
        for col in NUMERIC:
            s=pd.to_numeric(df[col],errors='coerce').astype('float64')
            if bool((df[col].str.strip().ne('') & s.isna()).any()) or bool(np.isinf(s.to_numpy()).any()):
                raise ValueError('Malformed numeric feature '+col)
            df[col]=s
        for col in CATEGORICAL:
            df[col]=df[col].str.strip().replace('','__MISSING__').astype(str)
        frames[name]=df
    tr,va=frames['train'],frames['validation']
    ytr=tr.label.astype(int).to_numpy(); yva=va.label.astype(int).to_numpy()
    pp=ColumnTransformer([('numeric',SimpleImputer(strategy='median'),list(NUMERIC)),('categorical',OneHotEncoder(handle_unknown='ignore'),list(CATEGORICAL))],remainder='drop')
    # The full saved pipeline will transform only the eight declared inputs.
    pipeline=Pipeline([('preprocessing',pp),('classifier',DecisionTreeClassifier(**SETTINGS))])
    start=time.perf_counter()
    pipeline.fit(tr[list(KEPT)],ytr)
    secs=time.perf_counter()-start
    pred=pipeline.predict(va[list(KEPT)])
    prob=pipeline.predict_proba(va[list(KEPT)])[:,list(pipeline.named_steps['classifier'].classes_).index(1)]
    tn,fp,fn,tp=[int(z) for z in confusion_matrix(yva,pred,labels=[0,1]).ravel()]
    met={'accuracy':float(accuracy_score(yva,pred)),'balanced_accuracy':float(balanced_accuracy_score(yva,pred)),
         'attack_precision':float(precision_score(yva,pred,zero_division=0)),
         'attack_recall':float(recall_score(yva,pred,zero_division=0)),
         'attack_f1':float(f1_score(yva,pred,zero_division=0)),
         'false_positive_rate':float(fp/(fp+tn)),
         'roc_auc':float(roc_auc_score(yva,prob)),
         'average_precision':float(average_precision_score(yva,prob)),
         'confusion_matrix':{'TN':tn,'FP':fp,'FN':fn,'TP':tp}}
    b=original['decision_tree_validation']
    attack=[]
    for typ in sorted(va['type'].unique()):
        mask=va['type'].eq(typ).to_numpy(); count=int(mask.sum())
        if typ=='normal':
            attack.append({'type':typ,'rows':count,'detected':None,'missed':None,'recall':None,'false_alerts':int((pred[mask]==1).sum())})
        else:
            found=int((pred[mask]==1).sum())
            attack.append({'type':typ,'rows':count,'detected':found,'missed':count-found,'recall':found/count,'false_alerts':None})
    payload={'project_id':'J26-CS-336','phase':'6.3 port-feature ablation','timestamp_utc':datetime.now(timezone.utc).isoformat(),
             'experiment':'Decision Tree without source and destination port inputs',
             'training_rows':len(tr),'validation_rows':len(va),'input_features':list(KEPT),
             'excluded_features':['src_port','dst_port'],'encoded_feature_count':int(len(pipeline.named_steps['preprocessing'].get_feature_names_out())),
             'hyperparameters':SETTINGS,'training_seconds':secs,'ablation_validation':met,
             'original_validation_reference':b,'per_type_validation':attack,
             'source_sha256':{k:digest(p) for k,p in paths.items()},
             'test_partition':'NOT OPENED OR USED',
             'limitations':['Flow-level ToN-IoT experiment, not proof of APT or 5/10/15/20s window accuracy.',
                            'Same validation set used for comparison; not independent final performance.',
                            '5-tuple group disjoint does not guarantee campaign/session disjointness.',
                            'Protocol and service may still encode dataset-specific shortcuts.']}
    for folder in (args.model_dir,args.report.parent,args.figure_dir,args.table_dir): folder.mkdir(parents=True,exist_ok=True)
    joblib.dump(pipeline,args.model_dir/'no_ports_pipeline.joblib')
    args.report.write_text(json.dumps(payload,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    with (args.table_dir/'per_attack_type.csv').open('w',newline='',encoding='utf-8') as f:
        import csv
        w=csv.DictWriter(f,fieldnames=['type','rows','detected','missed','recall','false_alerts']); w.writeheader();w.writerows(attack)
    metrics=['accuracy','balanced_accuracy','attack_precision','attack_recall','attack_f1','false_positive_rate']
    labels=['Accuracy','Balanced accuracy','Attack precision','Attack recall','Attack F1','False positive rate']
    ix=np.arange(len(metrics)); width=.37
    fig,ax=plt.subplots(figsize=(11,5.5));ax.bar(ix-width/2,[b[k] for k in metrics],width,label='Original (10 inputs)');ax.bar(ix+width/2,[met[k] for k in metrics],width,label='No ports (8 inputs)');ax.set_xticks(ix,labels,rotation=20,ha='right');ax.set_ylim(0,1.05);ax.set_ylabel('Validation score');ax.set_title('Decision Tree: Port Feature Ablation — Validation Only');ax.legend();fig.tight_layout();fig.savefig(args.figure_dir/'port_ablation_metrics.png',dpi=180);plt.close(fig)
    plot_types=[x for x in attack if x['type']!='normal']
    base_types=original.get('validation_detection_by_dataset_type',{})
    fig,ax=plt.subplots(figsize=(10,6));inds=np.arange(len(plot_types));ax.barh(inds-.2,[base_types[x['type']]['attack_recall'] for x in plot_types],.4,label='Original');ax.barh(inds+.2,[x['recall'] for x in plot_types],.4,label='No ports');ax.set_yticks(inds,[x['type'] for x in plot_types]);ax.set_xlim(0,1.03);ax.set_xlabel('Recall (validation)');ax.set_title('Recall by ToN-IoT Attack Category — Validation Only');ax.legend();fig.tight_layout();fig.savefig(args.figure_dir/'port_ablation_attack_recall.png',dpi=180);plt.close(fig)
    print('=== J26-CS-336 PORT FEATURE ABLATION — VALIDATION ONLY ===')
    print('Inputs: 10 original -> 8 without src_port/dst_port | encoded:',payload['encoded_feature_count'])
    print('Train:',len(tr),'Validation:',len(va),'Test: NOT OPENED')
    for k in metrics:
        print(f'{k:22s} original={b[k]:.4f}  no_ports={met[k]:.4f}  change={met[k]-b[k]:+.4f}')
    print('Confusion matrix:',met['confusion_matrix'])
    for x in attack:
        if x['type']=='mitm': print(f'MITM recall={x["recall"]:.4f} missed={x["missed"]}/{x["rows"]}')
    print('Model:',args.model_dir/'no_ports_pipeline.joblib')
    print('Report:',args.report)
    print('Charts:',args.figure_dir)
    print('Table:',args.table_dir/'per_attack_type.csv')
    print('NEXT: interpret shortcut dependence and category errors before additional classifiers.')

if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(f'STOPPED: {exc}',file=__import__('sys').stderr);raise SystemExit(1)
