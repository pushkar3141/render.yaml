"""Pre-compute the chart data shown on the dashboard for one processed upload."""
from __future__ import annotations

import pandas as pd


def build_summary(df: pd.DataFrame, alerts: pd.DataFrame) -> dict:
    tl = (df.groupby("minute")
            .agg(flows=("src_ip", "size"), mbytes=("total_bytes", lambda s: s.sum() / 1e6),
                 flagged=("flagged_core", "sum"))
            .reset_index())
    talkers = (df.groupby("src_ip")
                 .agg(flows=("dst_ip", "size"), mbytes=("total_bytes", lambda s: s.sum() / 1e6))
                 .sort_values("flows", ascending=False).head(10).reset_index())
    ports = (df.groupby(["dst_port", "service"]).size().rename("flows")
               .sort_values(ascending=False).head(10).reset_index())
    protos = df["proto_name"].value_counts().reset_index()
    protos.columns = ["protocol", "flows"]
    by_rule = (alerts.groupby(["name", "severity"]).size().rename("alerts").reset_index()
               if not alerts.empty else pd.DataFrame(columns=["name", "severity", "alerts"]))
    if not by_rule.empty:
        by_rule["severity_rank"] = by_rule["severity"].map({"Critical": 4, "High": 3, "Medium": 2, "Low": 1})
    sev = alerts["severity"].value_counts().to_dict() if not alerts.empty else {}
    windows = (alerts[alerts["severity"].isin(["Critical", "High"])][["first_seen", "last_seen", "name"]]
               if not alerts.empty else pd.DataFrame(columns=["first_seen", "last_seen", "name"]))
    has_labels = bool((df["label"] != "UNKNOWN").any())
    return {
        "start": str(df["ts"].min()), "end": str(df["ts"].max()),
        "flows": int(len(df)), "unique_sources": int(df["src_ip"].nunique()),
        "unique_destinations": int(df["dst_ip"].nunique()),
        "flagged_core": int(df["flagged_core"].sum()),
        "severity_counts": {k: int(v) for k, v in sev.items()},
        "timeline": {"minute": tl["minute"].astype(str).tolist(), "flows": tl["flows"].tolist(),
                     "mbytes": tl["mbytes"].round(3).tolist(), "flagged": tl["flagged"].astype(int).tolist()},
        "alert_windows": [{"start": str(r.first_seen), "end": str(r.last_seen), "name": r.name}
                          for r in windows.itertuples()],
        "top_talkers": talkers.to_dict("records"),
        "top_ports": [{"port": int(r.dst_port), "service": r.service, "flows": int(r.flows)}
                      for r in ports.itertuples()],
        "protocols": protos.to_dict("records"),
        "alerts_by_rule": by_rule.to_dict("records"),
        "labels": df["label"].value_counts().head(12).to_dict() if has_labels else {},
    }
