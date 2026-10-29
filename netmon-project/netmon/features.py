"""Feature engineering and the benign baseline.

The baseline is learned once from traffic known to be normal (CIC-IDS2017
Monday) and saved to JSON. Rules R3, R5 and R6 compare new traffic with it,
so an attack cannot hide by raising the average of the day it happens on.
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

ML_FEATURES = ["log_duration", "log_packets", "log_bytes", "log_bytes_per_pkt",
               "log_pkts_per_sec", "is_well_known_port"]


def add_model_features(df: pd.DataFrame) -> pd.DataFrame:
    df["log_duration"] = np.log1p(df["duration_us"].clip(lower=0))
    df["log_packets"] = np.log1p(df["packets"])
    df["log_bytes"] = np.log1p(df["total_bytes"].clip(lower=0))
    df["log_bytes_per_pkt"] = np.log1p(df["bytes_per_pkt"].clip(lower=0))
    df["log_pkts_per_sec"] = np.log1p(df["pkts_per_sec"].clip(lower=0))
    return df


def per_destination_minute(df: pd.DataFrame) -> pd.DataFrame:
    """Flows and distinct sources per destination per minute."""
    return (df.groupby(["dst_ip", "minute"])
              .agg(flows=("src_ip", "size"), sources=("src_ip", "nunique"))
              .reset_index())


def per_source_minute(df: pd.DataFrame) -> pd.DataFrame:
    """Window aggregates per source IP per minute (shown on the IP drill-down page)."""
    return (df.groupby(["src_ip", "minute"])
              .agg(flows=("dst_ip", "size"),
                   distinct_dst_ips=("dst_ip", "nunique"),
                   distinct_dst_ports=("dst_port", "nunique"),
                   bytes=("total_bytes", "sum"),
                   short_flow_share=("packets", lambda s: float((s <= 3).mean())))
              .reset_index())


def build_baseline(benign: pd.DataFrame) -> dict:
    """Learn normal behaviour from benign flows."""
    benign = add_model_features(benign.copy())
    pdm = per_destination_minute(benign)
    dst = pdm.groupby("dst_ip")["flows"].agg(["mean", "std", "max", "count"]).fillna(0)
    lb = benign["log_bytes"]
    q1, q3 = lb.quantile([0.25, 0.75])
    return {
        "source": "benign reference traffic",
        "rows": int(len(benign)),
        "log_bytes": {"mean": float(lb.mean()), "std": float(lb.std()),
                      "q1": float(q1), "q3": float(q3)},
        "dst_flows_per_min": {ip: {"mean": float(r["mean"]), "std": float(r["std"]),
                                   "max": float(r["max"]), "minutes": int(r["count"])}
                              for ip, r in dst.iterrows() if r["count"] >= 5},
        "global_flows_per_min": {"mean": float(pdm["flows"].mean()),
                                 "std": float(pdm["flows"].std()),
                                 "max": float(pdm["flows"].quantile(0.999))},
    }


def save_baseline(baseline: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(baseline, f)


def load_baseline(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
