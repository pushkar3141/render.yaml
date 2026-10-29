"""Run every detector over a flow table and collect alerts."""
from __future__ import annotations

import os
import time

import pandas as pd
import yaml

from . import alerts as alert_mgr
from . import ml_detect, rules, stats_detect
from .features import load_baseline

RULE_COLUMNS = ["r1", "r2", "r3", "r4", "r5", "r6", "ml"]
CORE_RULES = ["r1", "r2", "r3", "r4"]


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_blacklist(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    bl = pd.read_csv(path, comment="#")
    return set(bl["ip"].astype(str).str.strip())


class Detector:
    """Holds the configuration, benign baseline and model; runs the detectors."""

    def __init__(self, config_path="config.yaml", baseline_path="data/baseline.json",
                 model_path="data/iforest.pkl", base_dir="."):
        j = lambda p: p if os.path.isabs(p) else os.path.join(base_dir, p)
        self.cfg = load_config(j(config_path))
        self.baseline = load_baseline(j(baseline_path))
        self.bad_ips = load_blacklist(j(self.cfg["blacklist"]["path"]))
        self._model_path = j(model_path)
        self._model = None

    @property
    def model(self):
        """Load the Isolation Forest (and scikit-learn) only when it is first needed."""
        if self._model is None and self.cfg["isolation_forest"]["enabled"] \
                and os.path.exists(self._model_path):
            self._model = ml_detect.load(self._model_path)
        return self._model

    def run(self, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
        cfg = self.cfg
        t0 = time.perf_counter()
        all_hits = []

        h, df["r1"] = rules.port_scan(df, cfg["port_scan"]); all_hits.append(h)
        r1_hits = all_hits[0]
        h, df["r2"] = rules.brute_force(df, cfg["brute_force"])
        if not r1_hits.empty and not h.empty:
            # a scanner touching login ports is already explained by its port-scan alert,
            # so do not raise a second "brute force" alert for the same source and minute
            scan = set(zip(r1_hits["src_ip"], r1_hits["minute"]))
            keep = [(a, m) not in scan for a, m in zip(h["src_ip"], h["minute"])]
            h = h[keep]
            df["r2"] = df["r2"] & ~pd.Series(
                [(a, m) in scan for a, m in zip(df["src_ip"], df["minute"])], index=df.index)
        all_hits.append(h)
        h, df["r3"] = rules.traffic_spike(df, cfg["traffic_spike"], self.baseline); all_hits.append(h)
        h, df["r4"] = rules.blacklist(df, self.bad_ips); all_hits.append(h)
        h, df["r5"] = stats_detect.zscore_outliers(df, cfg["zscore"], self.baseline); all_hits.append(h)
        h, df["r6"] = stats_detect.iqr_outliers(df, cfg["iqr"], self.baseline); all_hits.append(h)
        if self.model is not None:
            h, df["ml"] = ml_detect.detect(df, self.model); all_hits.append(h)
        else:
            df["ml"] = False

        df["flagged_core"] = df[CORE_RULES].any(axis=1)
        df["flagged_any"] = df[RULE_COLUMNS].any(axis=1)
        hits = pd.concat([x for x in all_hits if not x.empty], ignore_index=True) \
            if any(not x.empty for x in all_hits) else pd.DataFrame()
        alerts = alert_mgr.merge_hits(hits, cfg["alerts"]["merge_gap"])
        stats = {"flows": len(df), "seconds": time.perf_counter() - t0}
        return df, alerts, stats
