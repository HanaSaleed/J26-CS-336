"""Materialize X-IIoTID's frozen Notebook 06 split manifest. No model training."""
from pathlib import Path
import csv
import hashlib
import json
import pandas as pd

CORE19 = ['Protocol','Service','Duration','Scr_bytes','Des_bytes','Conn_state',
          'is_syn_only','Is_SYN_ACK','is_pure_ack','is_with_payload','FIN or RST',
          'Scr_pkts','Scr_ip_bytes','Des_pkts','Des_ip_bytes','total_bytes',
          'total_packet','paket_rate','byte_rate']
PARTITIONS = ('train', 'validation', 'test')
MANIFEST_NAME = 'x_iiotid_core19_signature_split_manifest_v1.csv'
EXPECTED_COUNTS = {'train':574585,'validation':123125,'test':123124}

def sha256_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def export(root, chunk_size=40000, expected_counts=EXPECTED_COUNTS):
    root=Path(root)
    csv_path=root/'data/raw/x_iiotid/X-IIoTID dataset.csv'
    manifest_path=root/'data/splits'/MANIFEST_NAME
    out_dir=root/'data/splits'
    out_dir.mkdir(parents=True,exist_ok=True)
    for p in (csv_path,manifest_path):
        if not p.is_file():
            raise FileNotFoundError(f'Missing required local file: {p}')
    manifest=pd.read_csv(manifest_path,dtype={'csv_row_index_0based':'int64','partition':'str','class3':'str'})
    if manifest.empty or not manifest['csv_row_index_0based'].to_numpy().__eq__(range(len(manifest))).all():
        raise ValueError('Manifest row indices are not 0..N-1 in original CSV order.')
    if set(manifest.partition.unique()) - set(PARTITIONS):
        raise ValueError('Unexpected partition names in manifest')
    if not manifest.class3.isin(['Attack','Normal']).all():
        raise ValueError('Unexpected binary labels in manifest')
    counts=manifest.partition.value_counts().to_dict()
    if expected_counts is not None and counts!=expected_counts:
        raise ValueError(f'Partition counts differ from Notebook 06: {counts} != {expected_counts}')
    names={part: out_dir/f'x_iiotid_core19_{part}_v1.csv.gz' for part in PARTITIONS}
    # Keep source CSV and manifest unchanged. If interrupted, delete partial .tmp outputs.
    tmps={k:Path(str(v)+'.tmp') for k,v in names.items()}
    for tmp in tmps.values():
        if tmp.exists(): raise FileExistsError(f'Existing partial export: {tmp}. Inspect/remove manually.')
    first={part:True for part in PARTITIONS}
    used={part:0 for part in PARTITIONS}
    offset=0
    try:
        import gzip
        streams={part:gzip.open(tmps[part],'wt',encoding='utf-8',newline='') for part in PARTITIONS}
        try:
            for chunk in pd.read_csv(csv_path,dtype=str,keep_default_na=False,chunksize=chunk_size,low_memory=False,
                                     usecols=CORE19+['class3','class2']):
                size=len(chunk)
                if offset+size>len(manifest):
                    raise ValueError('CSV longer than saved manifest')
                entry=manifest.iloc[offset:offset+size]
                values=chunk['class3'].str.strip().to_numpy()
                if not (values==entry['class3'].to_numpy()).all():
                    raise ValueError(f'CSV label vs manifest mismatch near row {offset}. DO NOT resplit silently.')
                chunk.insert(0,'csv_row_index_0based',range(offset,offset+size))
                loc=entry.partition.to_numpy()
                for part in PARTITIONS:
                    selected=chunk.loc[loc==part]
                    if len(selected):
                        selected.to_csv(streams[part],index=False,header=first[part])
                        used[part]+=len(selected)
                        first[part]=False
                offset+=size
                if offset%200000<chunk_size: print(f'Exported {offset:,} source rows')
        finally:
            for stream in streams.values(): stream.close()
        if offset!=len(manifest) or used!=counts:
            raise ValueError(f'Export row counts mismatch: {used}, CSV rows {offset}')
        for part in PARTITIONS: tmps[part].replace(names[part])
    except BaseException:
        for tmp in tmps.values():
            if tmp.exists(): tmp.unlink()
        raise
    report={
        'source_csv':csv_path.name,
        'original_rows':offset,
        'manifest_file':manifest_path.name,
        'manifest_sha256':sha256_file(manifest_path),
        'feature_set':'Core19',
        'features':CORE19,
        'counts':used,
        'files':{part:{'name':names[part].name,'bytes':names[part].stat().st_size} for part in PARTITIONS},
        'test_scored':False,
        'method':'Preserves exact row-to-partition mapping from Notebook 06; no new split performed',
        'limitations':['Provisional signature-disjoint split, not verified independent sessions/campaigns',
                       'Network feature extraction semantics not yet verified']
    }
    audit=root/'reports/audits';audit.mkdir(parents=True,exist_ok=True)
    report_path=audit/'x_iiotid_core19_frozen_split_exports_v1.json'
    report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Saved local split datasets:')
    for part in PARTITIONS:
        print(f'  {part}: {used[part]:,} rows -> {names[part]}')
    print(f'Reproducibility metadata (safe for Git): {report_path}')
    return report
