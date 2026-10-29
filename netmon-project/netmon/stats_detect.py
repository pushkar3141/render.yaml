"""Statistical detectors R5 (z-score) and R6 (IQR), both on log(1 + bytes)."""
from __future__ import annotations

import numpy as np
import pandas as pd


def _group_hits(sub: pd.DataFrame, rule: str, name: str, severity: str, why: str) -> pd.DataFrame:
    if sub.empty:
        return pd.DataFrame()
    hits = (sub.groupby(["src_ip", "dst_ip", "minute"])
               .agg(flows=("total_bytes", "size"), max_bytes=("total_bytes", "max"),
                    dst_port=("dst_port", lambda s: s.mode().iat[0]))
               .reset_index())
    hits["rule"] = rule
    hits["name"] = name
    hits["severity"] = severity
    hits["evidence"] = (hits["flows"].astype(str) + " flow(s) " + why + "; largest "
                        + (hits["max_bytes"] / 1e6).round(2).astype(str) + " MB")
    return hits


def zscore_outliers(df: pd.DataFrame, cfg: dict, baseline: dict):
    """R5: flows whose byte count is extreme against the benign distribution."""
    lb = np.log1p(df["total_bytes"].clip(lower=0))
    b = baseline["log_bytes"]
    z = (lb - b["mean"]) / b["std"]
    flags = z.abs() > cfg["threshold"]
    return _group_hits(df[flags], "R5", "Unusual flow size (z-score)", "Medium",
                       f"with |z| > {cfg['threshold']}"), flags


def iqr_outliers(df: pd.DataFrame, cfg: dict, baseline: dict):
    """R6: flows above Tukey's upper fence Q3 + k*IQR."""
    lb = np.log1p(df["total_bytes"].clip(lower=0))
    b = baseline["log_bytes"]
    fence = b["q3"] + cfg["k"] * (b["q3"] - b["q1"])
    flags = lb > fence
    return _group_hits(df[flags], "R6", "Unusual flow size (IQR)", "Low",
                       f"above the Q3 + {cfg['k']}*IQR fence"), flags
