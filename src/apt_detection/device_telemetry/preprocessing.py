"""CICAPT-IIoT provenance cleaning for the device telemetry module."""
import pandas as pd
import networkx as nx

TIME_COLS = ["time", "start time", "seen time"]


def load_phase(path):
    """Read one provenance CSV as text, then convert the time columns to numbers."""
    df = pd.read_csv(path, dtype=str)
    for c in TIME_COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def process_nodes(df):
    """Process rows only, with a single time column and numeric PIDs."""
    procs = df[df["type"] == "Process"].copy()
    procs["t"] = procs["start time"].fillna(procs["seen time"])
    procs["pid_n"] = pd.to_numeric(procs["pid"])
    procs["ppid_n"] = pd.to_numeric(procs["ppid"])
    return procs


def fix_labels(procs, gap_s=300, window_s=3600, pid_margin=2):
    """Pass attack labels to child processes, including through missing parents
    inside an attack step's PID block. Adds label_fixed and tactic_fixed."""
    procs["label_fixed"] = procs["label"].eq("1")
    procs["tactic_fixed"] = procs["subLabel"]

    att = procs[procs["label_fixed"]].sort_values("t").copy()
    att["burst"] = (att["t"].diff() > gap_s).cumsum()
    bursts = att.groupby("burst").agg(t0=("t", "min"), pid_min=("pid_n", "min"),
                                      pid_max=("pid_n", "max"), tactic=("subLabel", "first"))
    known = set(procs["pid_n"])
    for _, b in bursts.iterrows():
        hit = (~procs["label_fixed"] & ~procs["ppid_n"].isin(known)
               & procs["ppid_n"].between(b.pid_min - pid_margin, b.pid_max + pid_margin)
               & procs["t"].between(b.t0, b.t0 + window_s))
        procs.loc[hit, "label_fixed"] = True
        procs.loc[hit, "tactic_fixed"] = b.tactic
    while True:
        hit = ~procs["label_fixed"] & procs["ppid_n"].isin(set(procs.loc[procs["label_fixed"], "pid_n"]))
        if not hit.any():
            break
        procs.loc[hit, "label_fixed"] = True
    return procs, len(bursts)


def assign_proc_keys(df, procs):
    """Group each process's nodes (linked by same-PID WasTriggeredBy edges) under one proc_key."""
    wtb = df[df["type"] == "WasTriggeredBy"][["from", "to"]]
    pid_of = dict(zip(procs["id"], procs["pid"]))
    wtb = wtb[wtb["from"].map(pid_of) == wtb["to"].map(pid_of)]
    G = nx.Graph()
    G.add_nodes_from(procs["id"])
    G.add_edges_from(zip(wtb["from"], wtb["to"]))
    group_of = {n: i for i, grp in enumerate(nx.connected_components(G)) for n in grp}
    procs["proc_key"] = procs["id"].map(group_of)
    return procs


def _first_value(s):
    s = s.dropna()
    return s.iloc[0] if len(s) else None


def build_process_table(procs):
    """One row per real process."""
    procs["tactic_nz"] = procs["tactic_fixed"].where(procs["tactic_fixed"] != "0")
    table = (procs.sort_values("t").groupby("proc_key")
             .agg(pid=("pid_n", "first"), ppid=("ppid_n", "first"),
                  t_start=("t", "min"), t_end=("t", "max"),
                  name=("name", "last"), exe=("exe", "last"),
                  cmdline=("command line", _first_value),
                  uid=("uid", "first"), euid=("euid", "first"),
                  n_nodes=("id", "size"), label=("label_fixed", "max"),
                  tactic=("tactic_nz", _first_value)))
    table["tactic"] = table["tactic"].fillna("benign")
    return table


def build_event_table(df, procs):
    """One row per event, attached to its process, with artifact details."""
    edges = df[df["from"].notna() & (df["type"] != "WasDerivedFrom")].copy()
    key_of = dict(zip(procs["id"], procs["proc_key"]))
    edges["proc_key"] = edges["from"].map(key_of).fillna(edges["to"].map(key_of))
    edges["artifact_id"] = edges["to"].where(edges["from"].isin(set(key_of)), edges["from"])
    edges.loc[edges["type"] == "WasTriggeredBy", "artifact_id"] = None
    arts = df[df["type"] == "Artifact"].set_index("id")
    for col in ["subtype", "path", "remote address", "remote port"]:
        edges[col] = edges["artifact_id"].map(arts[col])
    return edges[["proc_key", "time", "type", "operation",
                  "subtype", "path", "remote address", "remote port"]]


def clean_phase(path):
    """Run every cleaning step on one phase. Returns (process_table, events, report)."""
    df = load_phase(path)
    procs = process_nodes(df)
    procs, n_bursts = fix_labels(procs)
    procs = assign_proc_keys(df, procs)
    table = build_process_table(procs)
    events = build_event_table(df, procs)
    report = {"rows": len(df), "process_nodes": len(procs), "attack_steps": n_bursts,
              "processes": len(table), "attack_processes": int(table["label"].sum()),
              "events": len(events), "events_without_process": int(events["proc_key"].isna().sum())}
    return table, events, report