"""Feature building for the device telemetry module."""
import pandas as pd
import ipaddress
import numpy as np

PATH_CATEGORIES = {
    "sensitive":   r"/etc/shadow|/etc/passwd|/etc/sudoers|/\.ssh/|/\.gnupg/|\.pem$|\.key$",
    "persistence": r"/etc/cron|/var/spool/cron|/etc/systemd/|/lib/systemd/system|/etc/init\.d|/etc/rc\.local|/\.bashrc|/\.profile|/etc/sudoers\.d",
    "temp":        r"^/tmp/|^/dev/shm/|^/var/tmp/",
    "home":        r"^/home/|^/root/",
    "hidden":      r"/\.[^/]+",
    "system_bin":  r"^/usr/bin/|^/bin/|^/usr/sbin/|^/sbin/|^/usr/lib|^/lib",
}
CONTEXT_WINDOWS = {"1m": 60, "5m": 300, "15m": 900}

PROGRAM_GROUPS = {
    "shell":       {"sh", "bash", "dash", "zsh"},
    "interpreter": {"python", "python3", "perl", "ruby", "php", "node"},
    "recon":       {"whoami", "id", "uname", "hostname", "ifconfig", "ip", "arp",
                    "netstat", "ss", "ps", "find", "lsb_release", "w", "who", "last"},
    "archive":     {"tar", "gzip", "zip", "7z", "bzip2", "xz"},
    "net_tool":    {"curl", "wget", "scp", "ssh", "nc", "ncat", "ftp", "rsync"},
    "file_op":     {"cp", "mv", "rm", "chmod", "chown", "ln"},
    "user_mgmt":   {"useradd", "userdel", "usermod", "passwd", "adduser", "groupadd"},
}
FEATURE_GROUPS = {
    "operations": ["n_chmod", "n_connect", "n_execve", "n_load", "n_open", "n_rename_read",
                   "n_rename_write", "n_setgid", "n_setuid", "n_unlink", "n_update", "n_events"],
    "touch":      ["n_path_sensitive", "n_path_persistence", "n_path_temp", "n_path_home",
                   "n_path_hidden", "n_path_system_bin", "n_dest_distinct", "n_dest_external",
                   "n_ports_distinct"],
    "privilege":  ["is_root", "uid_ne_euid"],
    "program":    [f"prog_{g}" for g in PROGRAM_GROUPS],
    "cmdline":    ["cmd_len", "cmd_pipes", "cmd_redirect", "cmd_encoded", "cmd_hidden_path"],
    "rarity":     ["prog_in_baseline", "prog_rarity"],
    "family":     ["parent_is_shell", "pair_unusual"],
    "artefact":   ["parent_known", "depth", "n_children"],
    "context":    [f"ctx_{k}_{w}" for k in ("procs", "new") for w in CONTEXT_WINDOWS],
}

META_COLUMNS = ["label", "tactic", "t_start", "time_block", "flood"]
SHELLS = {"sh", "bash", "dash", "zsh"}



def build_baseline(baseline_table):
    """Program counts from a normal-only period (e.g. Phase 1)."""
    names = baseline_table["name"].fillna("").str.lower()
    return {"counts": names.value_counts(), "total": len(names)}


def rarity_features(proc_table, baseline):
    """How unusual each process's program is compared with the baseline."""
    names = proc_table["name"].fillna("").str.lower()
    counts = names.map(baseline["counts"]).fillna(0)
    out = pd.DataFrame(index=proc_table.index)
    out["prog_in_baseline"] = (counts > 0).astype(int)
    out["prog_rarity"] = -np.log10((counts + 1) / (baseline["total"] + 1))
    return out

def _is_external(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False


def touch_features(events, proc_table):
    """One row per process: how often it touched each path category, plus network counts."""
    out = pd.DataFrame(index=proc_table.index)
    path = events["path"].fillna("")
    for name, pattern in PATH_CATEGORIES.items():
        hits = path.str.contains(pattern, regex=True)
        out[f"n_path_{name}"] = hits.groupby(events["proc_key"]).sum()

    sock = events[events["subtype"] == "network socket"].copy()
    sock["external"] = sock["remote address"].map(_is_external)
    g = sock.groupby("proc_key")
    out["n_dest_distinct"] = g["remote address"].nunique()
    out["n_dest_external"] = g["external"].sum()
    out["n_ports_distinct"] = g["remote port"].nunique()
    return out.fillna(0).astype(int)

def operation_counts(events, proc_table):
    """One row per process: how many times it did each kind of operation, plus a total."""
    op = (events["operation"]
          .str.replace(r"[ ()]+", "_", regex=True)
          .str.strip("_"))
    counts = (events.assign(op=op)
              .pivot_table(index="proc_key", columns="op", values="time",
                           aggfunc="size", fill_value=0)
              .add_prefix("n_"))
    counts["n_events"] = counts.sum(axis=1)
    return counts.reindex(proc_table.index, fill_value=0)
def identity_features(proc_table):
    """One row per process: privilege, program type and command-line traits."""
    out = pd.DataFrame(index=proc_table.index)
    uid = pd.to_numeric(proc_table["uid"], errors="coerce")
    euid = pd.to_numeric(proc_table["euid"], errors="coerce")
    out["is_root"] = (uid == 0).astype(int)
    out["uid_ne_euid"] = (uid != euid).astype(int)

    name = proc_table["name"].fillna("").str.lower()
    for group, programs in PROGRAM_GROUPS.items():
        out[f"prog_{group}"] = name.isin(programs).astype(int)

    cmd = proc_table["cmdline"].fillna("")
    out["cmd_len"] = cmd.str.len()
    out["cmd_pipes"] = cmd.str.count(r"\|")
    out["cmd_redirect"] = cmd.str.contains(">", regex=False).astype(int)
    out["cmd_encoded"] = cmd.str.contains(r"base64|eval ", regex=True).astype(int)
    out["cmd_hidden_path"] = cmd.str.contains(r"/\.[A-Za-z0-9_]", regex=True).astype(int)
    return out

def link_parents(proc_table):
    """For each process, the proc_key of its parent: the latest process with
    pid == my ppid that started before me. NaN if the parent was never recorded."""
    pt = proc_table.reset_index()
    kids = pt[["proc_key", "ppid", "t_start"]].dropna().sort_values("t_start")
    parents = (pt[["proc_key", "pid", "t_start"]].dropna()
               .rename(columns={"proc_key": "parent_key", "pid": "ppid", "t_start": "t_parent"})
               .sort_values("t_parent"))
    linked = pd.merge_asof(kids, parents, left_on="t_start", right_on="t_parent",
                           by="ppid", direction="backward")
    return linked.set_index("proc_key")["parent_key"].reindex(proc_table.index)


def parent_child_pairs(proc_table, parent_key):
    """'parent_name>child_name' for each process ('?' when the parent is unknown)."""
    names = proc_table["name"].fillna("").str.lower()
    parent_names = parent_key.map(names).fillna("?")
    return parent_names + ">" + names


def family_features(proc_table, baseline_pairs):
    """Children count, parent type and pair rarity (main) + parent_known, depth (artefact)."""
    parent_key = link_parents(proc_table)
    out = pd.DataFrame(index=proc_table.index)
    out["n_children"] = parent_key.value_counts().reindex(proc_table.index, fill_value=0)
    parent_names = parent_key.map(proc_table["name"].fillna("").str.lower())
    out["parent_is_shell"] = parent_names.isin(SHELLS).astype(int)
    pairs = parent_child_pairs(proc_table, parent_key)
    known = parent_key.notna()
    out["pair_unusual"] = (known & ~pairs.isin(baseline_pairs)).astype(int)

    # artefact features: computed for reporting, excluded from the main model
    out["parent_known"] = parent_key.notna().astype(int)
    depth = pd.Series(0, index=proc_table.index)
    current = parent_key.copy()
    for level in range(1, 11):
        has = current.notna()
        depth[has] = level
        current = current.map(parent_key).where(has)
    out["depth"] = depth
    return out

def context_features(proc_table, baseline):
    """For each process: activity on the host in the 1/5/15 minutes BEFORE it started."""
    pt = proc_table.sort_values("t_start")
    t = pt["t_start"].to_numpy()
    is_new = (~pt["name"].fillna("").str.lower().isin(baseline["counts"].index)).to_numpy().astype(int)
    new_cum = np.concatenate([[0], np.cumsum(is_new)])

    out = pd.DataFrame(index=pt.index)
    for label, seconds in CONTEXT_WINDOWS.items():
        end = np.searchsorted(t, t, side="right")
        start = np.searchsorted(t, t - seconds, side="right")
        out[f"ctx_procs_{label}"] = end - start - 1
        out[f"ctx_new_{label}"] = new_cum[end] - new_cum[start] - is_new
    return out.reindex(proc_table.index)


def build_feature_table(proc_table, events, baseline, baseline_pairs):
    """All feature groups + metadata, one row per process."""
    X = pd.concat([
        operation_counts(events, proc_table),
        touch_features(events, proc_table),
        identity_features(proc_table),
        rarity_features(proc_table, baseline),
        family_features(proc_table, baseline_pairs),
        context_features(proc_table, baseline),
    ], axis=1)

    label = proc_table["label"].astype(bool)
    X["label"] = label.astype(int)
    X["tactic"] = proc_table["tactic"]
    X["t_start"] = proc_table["t_start"]
    X["time_block"] = (proc_table["t_start"] // 3600).astype(int)
    X["flood"] = (label & proc_table["name"].isin(["cp", "base64"])).astype(int)
    return X


def main_features():
    """Every feature used by the main model (artefact group excluded)."""
    return [c for g, cols in FEATURE_GROUPS.items() if g != "artefact" for c in cols]