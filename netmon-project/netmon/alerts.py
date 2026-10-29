"""Alert manager: merge rule hits into alerts and suggest a firewall action."""
from __future__ import annotations

import pandas as pd

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def firewall_action(row) -> str:
    rule, src, dst = row["rule"], row["src_ip"], row["dst_ip"]
    port = row.get("dst_port")
    if rule == "R1":
        return f"iptables -A INPUT -s {src} -j DROP  (block scanner; close unused ports on {dst})"
    if rule == "R2":
        p = int(port) if pd.notna(port) else 22
        return (f"iptables -A INPUT -p tcp -s {src} --dport {p} -j DROP; "
                f"allow TCP/{p} only from VPN or admin subnet; enable fail2ban")
    if rule == "R3":
        return (f"iptables -A INPUT -d {dst} -m limit --limit 100/second -j ACCEPT  "
                f"(rate-limit); contact upstream provider if traffic keeps rising")
    if rule == "R4":
        return f"iptables -A INPUT -s {src} -j DROP; iptables -A OUTPUT -d {dst} -j DROP"
    return "Review the flows; no automatic block suggested"


def merge_hits(hits: pd.DataFrame, gap: str = "5min") -> pd.DataFrame:
    """Turn per-minute hits into alerts: consecutive minutes from the same rule
    and hosts (gap below `gap`) become one alert with a start and end time."""
    if hits.empty:
        return pd.DataFrame(columns=["first_seen", "last_seen", "rule", "name", "severity",
                                     "src_ip", "dst_ip", "dst_port", "minutes", "flows",
                                     "evidence", "action"])
    hits = hits.copy()
    if "dst_port" not in hits:
        hits["dst_port"] = pd.NA
    port_txt = hits["dst_port"].map(lambda p: "-" if pd.isna(p) else str(int(p)))
    hits["key"] = (hits["rule"] + "|" + hits["src_ip"].astype(str).fillna("-") + "|"
                   + hits["dst_ip"].astype(str).fillna("-") + "|" + port_txt)
    hits = hits.sort_values(["key", "minute"])
    new_block = hits.groupby("key")["minute"].diff() > pd.Timedelta(gap)
    hits["block"] = new_block.groupby(hits["key"]).cumsum()
    hits["sev_rank"] = hits["severity"].map(SEVERITY_ORDER)

    alerts = (hits.groupby(["key", "block"])
                  .agg(first_seen=("minute", "min"), last_seen=("minute", "max"),
                       rule=("rule", "first"), name=("name", "first"),
                       sev_rank=("sev_rank", "max"), src_ip=("src_ip", "first"),
                       dst_ip=("dst_ip", "first"), dst_port=("dst_port", "first"),
                       minutes=("minute", "nunique"), flows=("flows", "sum"),
                       evidence=("evidence", "last"))
                  .reset_index(drop=True))
    inv = {v: k for k, v in SEVERITY_ORDER.items()}
    alerts["severity"] = alerts.pop("sev_rank").map(inv)
    alerts["last_seen"] = alerts["last_seen"] + pd.Timedelta("1min")
    alerts["evidence"] = (alerts["evidence"] + " (latest window; active "
                          + alerts["minutes"].astype(str) + " min)")
    alerts["action"] = alerts.apply(firewall_action, axis=1)
    alerts = alerts.sort_values(["first_seen", "severity"]).reset_index(drop=True)
    return alerts
