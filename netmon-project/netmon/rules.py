"""Rule-based detectors R1-R4.

Each detector returns:
  hits  - one row per (window, hosts) that broke the rule, with evidence
  flags - a boolean Series aligned with df marking the flows behind each hit
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import per_destination_minute


def _flag_from_keys(df: pd.DataFrame, hits: pd.DataFrame, keys: list[str]) -> pd.Series:
    if hits.empty:
        return pd.Series(False, index=df.index)
    marker = hits[keys].drop_duplicates().assign(_hit=True)
    merged = df[keys].merge(marker, on=keys, how="left")
    return pd.Series(merged["_hit"].fillna(False).astype(bool).to_numpy(), index=df.index)


def port_scan(df: pd.DataFrame, cfg: dict) -> tuple[pd.DataFrame, pd.Series]:
    """R1: one source touches many distinct service ports within a window."""
    # count only flows that look client-initiated: ephemeral source port, service-range
    # destination port. Server replies (src port 80/443 -> client port) are skipped.
    cand = df[(df["dst_port"] <= cfg["max_port"]) & (df["src_port"] > 1023)]
    g = (cand.groupby(["src_ip", "minute"])
             .agg(distinct_ports=("dst_port", "nunique"),
                  targets=("dst_ip", "nunique"),
                  dst_ip=("dst_ip", lambda s: s.mode().iat[0]),
                  flows=("dst_port", "size"))
             .reset_index())
    hits = g[g["distinct_ports"] >= cfg["min_distinct_ports"]].copy()
    hits["rule"] = "R1"
    hits["name"] = "Port scan"
    hits["severity"] = np.where(hits["distinct_ports"] >= cfg["critical_ports"], "Critical", "High")
    hits["evidence"] = (hits["distinct_ports"].astype(str) + " distinct ports on "
                        + hits["targets"].astype(str) + " host(s) in 1 min")
    hits["dst_port"] = np.nan
    # once a source is identified as a scanner in a minute, all its flows in that minute count
    flags = _flag_from_keys(df, hits, ["src_ip", "minute"])
    return hits, flags


def brute_force(df: pd.DataFrame, cfg: dict) -> tuple[pd.DataFrame, pd.Series]:
    """R2: many connections from one source to a login service on one host."""
    cand = df[df["dst_port"].isin(cfg["ports"])]
    g = (cand.groupby(["src_ip", "dst_ip", "dst_port", "minute"])
             .agg(attempts=("packets", "size"), median_pkts=("packets", "median"))
             .reset_index())
    hits = g[g["attempts"] >= cfg["min_attempts"]].copy()
    hits["rule"] = "R2"
    service = hits["dst_port"].map({21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"})
    hits["name"] = "Brute force (" + service.fillna("login") + ")"
    hits["severity"] = "High"
    hits["evidence"] = (hits["attempts"].astype(str) + " login connections to port "
                        + hits["dst_port"].astype(str) + " in 1 min")
    hits["flows"] = hits["attempts"]
    flags = _flag_from_keys(df, hits, ["src_ip", "dst_ip", "dst_port", "minute"])
    return hits, flags


def traffic_spike(df: pd.DataFrame, cfg: dict, baseline: dict) -> tuple[pd.DataFrame, pd.Series]:
    """R3: flows per minute to a destination far above its benign baseline."""
    pdm = per_destination_minute(df)
    known = baseline["dst_flows_per_min"]
    glob = baseline["global_flows_per_min"]
    mu = pdm["dst_ip"].map(lambda ip: known.get(ip, glob)["mean"])
    sd = pdm["dst_ip"].map(lambda ip: known.get(ip, glob)["std"])
    peak = pdm["dst_ip"].map(lambda ip: known.get(ip, glob)["max"])
    pdm["baseline_mean"] = mu
    pdm["z"] = (pdm["flows"] - mu) / sd.clip(lower=1.0)
    # must be far above the usual level AND above the busiest benign minute seen
    hits = pdm[(pdm["z"] > cfg["z_threshold"]) & (pdm["flows"] >= cfg["min_flows"])
               & (pdm["flows"] > peak)].copy()
    hits["rule"] = "R3"
    is_ddos = hits["sources"] >= cfg["ddos_min_sources"]
    hits["name"] = np.where(is_ddos, "Traffic spike (DDoS)", "Traffic spike (DoS)")
    hits["severity"] = "Critical"
    hits["evidence"] = (hits["flows"].astype(str) + " flows/min from "
                        + hits["sources"].astype(str) + " source(s); normal is "
                        + hits["baseline_mean"].round(1).astype(str) + " (z="
                        + hits["z"].round(1).astype(str) + ")")
    hits["src_ip"] = "multiple"
    hits["dst_port"] = np.nan
    flags = _flag_from_keys(df, hits, ["dst_ip", "minute"])
    return hits, flags


def blacklist(df: pd.DataFrame, bad_ips: set[str]) -> tuple[pd.DataFrame, pd.Series]:
    """R4: source or destination appears on a threat-intelligence blacklist."""
    flags = df["src_ip"].isin(bad_ips) | df["dst_ip"].isin(bad_ips)
    sub = df[flags]
    if sub.empty:
        return pd.DataFrame(), flags
    hits = (sub.groupby(["src_ip", "dst_ip", "minute"])
               .agg(flows=("packets", "size"), dst_port=("dst_port", lambda s: s.mode().iat[0]))
               .reset_index())
    hits["rule"] = "R4"
    hits["name"] = "Blacklisted IP"
    hits["severity"] = "Critical"
    bad = np.where(hits["src_ip"].isin(bad_ips), hits["src_ip"], hits["dst_ip"])
    hits["evidence"] = "Contact with blacklisted IP " + pd.Series(bad, index=hits.index)
    return hits, flags
