"""Optional Isolation Forest detector, trained on benign traffic only."""
from __future__ import annotations

import pickle

import numpy as np

import pandas as pd

from .features import ML_FEATURES, add_model_features


def train(benign: pd.DataFrame, cfg: dict):
    from sklearn.ensemble import IsolationForest     # imported only when needed
    benign = add_model_features(benign.copy())
    n = min(cfg["train_sample"], len(benign))
    sample = benign.sample(n, random_state=cfg["random_state"])
    model = IsolationForest(n_estimators=cfg["n_estimators"],
                            contamination=cfg["contamination"],
                            random_state=cfg["random_state"], n_jobs=-1)
    model.fit(sample[ML_FEATURES])
    return model


def detect(df: pd.DataFrame, model, chunk: int = 50_000):
    df = add_model_features(df)
    model.n_jobs = 1                                  # one core; keeps memory flat on small servers
    preds = [model.predict(df[ML_FEATURES].iloc[i:i + chunk]) for i in range(0, len(df), chunk)]
    flags = pd.Series(np.concatenate(preds) == -1 if preds else [], index=df.index, dtype=bool)
    sub = df[flags]
    if sub.empty:
        return pd.DataFrame(), flags
    hits = (sub.groupby(["src_ip", "dst_ip", "minute"])
               .agg(flows=("packets", "size"), dst_port=("dst_port", lambda s: s.mode().iat[0]))
               .reset_index())
    hits["rule"] = "ML"
    hits["name"] = "Anomalous flows (Isolation Forest)"
    hits["severity"] = "Medium"
    hits["evidence"] = hits["flows"].astype(str) + " flow(s) scored anomalous"
    return hits, flags


def save(model, path: str) -> None:
    with open(path, "wb") as f:
        pickle.dump(model, f)


def load(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)
