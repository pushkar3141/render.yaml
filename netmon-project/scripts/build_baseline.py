"""Learn the benign baseline and train the Isolation Forest from Monday's traffic.

Usage: python scripts/build_baseline.py <Monday-WorkingHours CSV or Parquet>
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netmon import ml_detect                                   # noqa: E402
from netmon.features import build_baseline, save_baseline      # noqa: E402
from netmon.pipeline import load_config                        # noqa: E402
from netmon.preprocess import load_cic_csv                     # noqa: E402

src = sys.argv[1]
df = pd.read_parquet(src) if src.endswith(".parquet") else load_cic_csv(src)
benign = df[df["is_attack"] == 0]
cfg = load_config("config.yaml")
save_baseline(build_baseline(benign), "data/baseline.json")
ml_detect.save(ml_detect.train(benign, cfg["isolation_forest"]), "data/iforest.pkl")
print(f"Baseline and model built from {len(benign):,} benign flows")
