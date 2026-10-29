"""Evaluate every detector against the CIC-IDS2017 labels.

Usage: python scripts/evaluate.py <folder with the day files (.parquet or CIC .csv)>
Writes results/metrics.json, results/*.csv and results/figures/*.png
"""
import json
import os
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                  # noqa: E402
import numpy as np                                               # noqa: E402
import pandas as pd                                              # noqa: E402
from sklearn.metrics import confusion_matrix                     # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netmon import rules                                         # noqa: E402
from netmon.pipeline import Detector                             # noqa: E402
from netmon.preprocess import load_cic_csv                       # noqa: E402

DATA = sys.argv[1]
OUT = os.path.join(ROOT, "results")
FIG = os.path.join(OUT, "figures")
os.makedirs(FIG, exist_ok=True)

FILES = {
    "Monday (benign reference)": "Monday-WorkingHours",
    "Tuesday": "Tuesday-WorkingHours",
    "Wednesday": "Wednesday-workingHours",
    "Friday PortScan": "Friday-WorkingHours-Afternoon-PortScan",
    "Friday DDoS": "Friday-WorkingHours-Afternoon-DDos",
}
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": INK2,
                     "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "figure.facecolor": SURF, "axes.facecolor": SURF})


def load(name):
    p = os.path.join(DATA, name + ".parquet")
    return pd.read_parquet(p) if os.path.exists(p) else load_cic_csv(os.path.join(DATA, name + ".pcap_ISCX.csv"))


def metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn)
    return dict(tp=int(tp), fp=int(fp), fn=int(fn), tn=int(tn), recall=rec, precision=prec,
                f1=f1, fpr=fpr, accuracy=acc)


det = Detector(base_dir=ROOT)
runs, counts, timing, alert_counts = {}, [], [], {}
for label, fname in FILES.items():
    df = load(fname)
    df, alerts, st = det.run(df)
    runs[label] = df
    timing.append({"file": label, "flows": st["flows"], "seconds": round(st["seconds"], 2),
                   "sec_per_100k": round(st["seconds"] / st["flows"] * 1e5, 2)})
    vc = df["label"].value_counts()
    counts.append({"file": label, "flows": int(len(df)), "benign": int(vc.get("BENIGN", 0)),
                   "attacks": "; ".join(f"{k} {v:,}" for k, v in vc.items() if k != "BENIGN") or "none"})
    alert_counts[label] = alerts["rule"].value_counts().to_dict()
    alerts.to_csv(os.path.join(OUT, f"alerts_{fname}.csv"), index=False)
    print(f"{label}: {len(df):,} flows, {len(alerts)} alerts, {st['seconds']:.1f}s")

# ---- per-rule evaluation against the attack class each rule targets ----------
tue, wed = runs["Tuesday"], runs["Wednesday"]
ps, dd, mon = runs["Friday PortScan"], runs["Friday DDoS"], runs["Monday (benign reference)"]
attack_days = pd.concat([tue, wed, ps, dd], ignore_index=True)
dos = pd.concat([wed[~wed.label.isin(["Heartbleed"])], dd], ignore_index=True)

rows = [
    ("R1 Port scan", "PortScan (Fri)", ps.label.eq("PortScan"), ps.r1),
    ("R2 Brute force", "FTP/SSH-Patator (Tue)", tue.label.str.contains("Patator"), tue.r2),
    ("R3 Traffic spike", "DoS + DDoS (Wed, Fri)", dos.label.str.contains("DoS"), dos.r3),
    ("R5 Z-score outlier", "All attacks (4 files)", attack_days.is_attack == 1, attack_days.r5),
    ("R6 IQR outlier", "All attacks (4 files)", attack_days.is_attack == 1, attack_days.r6),
    ("Isolation Forest", "All attacks (4 files)", attack_days.is_attack == 1, attack_days.ml),
    ("Combined rules R1-R4", "All attacks (4 files)", attack_days.is_attack == 1, attack_days.flagged_core),
    ("Combined, all detectors", "All attacks (4 files)", attack_days.is_attack == 1, attack_days.flagged_any),
]
per_rule = []
for name, target, yt, yp in rows:
    m = metrics(yt.astype(int), yp.astype(int))
    per_rule.append({"rule": name, "target": target, **m})
per_rule = pd.DataFrame(per_rule)
per_rule.to_csv(os.path.join(OUT, "per_rule_metrics.csv"), index=False)

# false alarms on a fully benign day (in-sample for R3/R5/R6/ML: baseline came from Monday)
monday_fp = {c: int(mon[c].sum()) for c in ["r1", "r2", "r3", "r4", "r5", "r6", "ml"]}
monday_fp["flows"] = int(len(mon))

# recall of the combined R1-R4 system per attack class
by_class = (attack_days[attack_days.is_attack == 1].groupby("label")
            .agg(flows=("label", "size"), core_recall=("flagged_core", "mean"),
                 any_recall=("flagged_any", "mean")).reset_index())
by_class.to_csv(os.path.join(OUT, "recall_by_class.csv"), index=False)

# ---- R1 threshold sensitivity on Friday PortScan ----------------------------
sens = []
cfg = dict(det.cfg["port_scan"])
for t in [10, 20, 30, 50, 100, 200]:
    cfg["min_distinct_ports"] = t
    _, f = rules.port_scan(ps, cfg)
    _, fm = rules.port_scan(mon, cfg)
    m = metrics(ps.label.eq("PortScan").astype(int), f.astype(int))
    sens.append({"threshold": t, "recall": m["recall"], "fpr": m["fpr"], "precision": m["precision"],
                 "monday_false_flows": int(fm.sum())})
sens = pd.DataFrame(sens)
sens.to_csv(os.path.join(OUT, "r1_threshold_sensitivity.csv"), index=False)

pd.DataFrame(counts).to_csv(os.path.join(OUT, "dataset_counts.csv"), index=False)
pd.DataFrame(timing).to_csv(os.path.join(OUT, "timing.csv"), index=False)
total_flows = sum(t["flows"] for t in timing)
total_secs = sum(t["seconds"] for t in timing)
summary = {
    "per_rule": per_rule.to_dict("records"), "monday_false_flags": monday_fp,
    "recall_by_class": by_class.to_dict("records"), "r1_sensitivity": sens.to_dict("records"),
    "dataset": counts, "timing": timing,
    "overall_sec_per_100k": round(total_secs / total_flows * 1e5, 2),
    "alerts_per_file": alert_counts,
    "generated": time.strftime("%Y-%m-%d %H:%M"),
}
with open(os.path.join(OUT, "metrics.json"), "w") as f:
    json.dump(summary, f, indent=2, default=str)

# ---- figures ------------------------------------------------------------------
# 1. per-rule precision / recall / FPR
fig, ax = plt.subplots(figsize=(8.5, 4.2))
pr = per_rule.iloc[:6]
x = np.arange(len(pr)); w = 0.26
for i, (col, colr, lab) in enumerate([("recall", BLUE, "Recall"), ("precision", ORANGE, "Precision"),
                                       ("fpr", AQUA, "False-positive rate")]):
    ax.bar(x + (i - 1) * w, pr[col], w - 0.02, color=colr, label=lab)
ax.set_xticks(x, [r.replace(" ", "\n", 1) for r in pr["rule"]], fontsize=9)
ax.set_ylim(0, 1.05); ax.set_ylabel("Score (0-1)")
ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.12))
ax.set_title("Detection performance by rule", loc="left", color=INK, pad=28)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "per_rule_metrics.png"), dpi=200); plt.close(fig)

# 2. confusion matrix, combined R1-R4
m = per_rule.set_index("rule").loc["Combined rules R1-R4"]
cm = np.array([[m.tn, m.fp], [m.fn, m.tp]])
fig, ax = plt.subplots(figsize=(4.8, 4.2))
ax.imshow(cm / cm.sum(axis=1, keepdims=True), cmap=matplotlib.colors.LinearSegmentedColormap.from_list(
    "b", ["#cde2fb", "#104281"]), vmin=0, vmax=1)
for i in range(2):
    for j in range(2):
        share = cm[i, j] / cm[i].sum()
        ax.text(j, i, f"{cm[i, j]:,}\n({share:.1%})", ha="center", va="center",
                color="white" if share > 0.5 else INK, fontsize=11)
ax.set_xticks([0, 1], ["Predicted benign", "Predicted attack"])
ax.set_yticks([0, 1], ["Actual benign", "Actual attack"])
ax.spines[:].set_visible(False)
ax.set_title("Confusion matrix: rules R1-R4, all attack days", loc="left", color=INK, fontsize=10)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "confusion_matrix.png"), dpi=200); plt.close(fig)

# 3. threshold sensitivity
fig, ax = plt.subplots(figsize=(6.5, 4))
xs = np.arange(len(sens))
cols = [ORANGE if t == det.cfg["port_scan"]["min_distinct_ports"] else BLUE for t in sens["threshold"]]
ax.bar(xs, sens["monday_false_flows"], 0.6, color=cols)
for i, r in sens.iterrows():
    ax.text(i, r["monday_false_flows"] + 60, f"{int(r['monday_false_flows']):,}\nrecall {r['recall']:.3f}",
            ha="center", va="bottom", fontsize=8, color=INK2)
ax.set_xticks(xs, sens["threshold"].astype(str))
ax.set_xlabel("R1 threshold: distinct service ports per source per minute (chosen value: 30)")
ax.set_ylabel("Benign Monday flows falsely flagged")
ax.set_ylim(0, sens["monday_false_flows"].max() * 1.35 + 10)
ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.set_title("R1 threshold: false alarms on a benign day vs PortScan recall", loc="left", color=INK, fontsize=10)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "r1_threshold.png"), dpi=200); plt.close(fig)

# 4. Friday traffic timeline with the port-scan alert windows shaded
tl = ps.groupby("minute").agg(flows=("label", "size")).reset_index()
flagged_min = ps.loc[ps.r1, "minute"].unique()
fig, ax = plt.subplots(figsize=(8.5, 3.6))
for mnt in flagged_min:
    ax.axvspan(mnt, mnt + pd.Timedelta("1min"), color="#fde3d6", lw=0)
ax.plot(tl["minute"], tl["flows"], color=BLUE, lw=2)
ax.set_ylabel("Flows per minute"); ax.yaxis.grid(True, color=GRID); ax.set_axisbelow(True)
ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
ax.set_title("Friday afternoon traffic; shaded minutes raised a port-scan alert (R1)",
             loc="left", color=INK, fontsize=10)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "portscan_timeline.png"), dpi=200); plt.close(fig)

print(per_rule[["rule", "recall", "precision", "f1", "fpr"]].round(4).to_string(index=False))
print("Monday false flags:", monday_fp)
print(by_class.round(4).to_string(index=False))
print(sens.round(4).to_string(index=False))
print("sec per 100k flows:", summary["overall_sec_per_100k"])
