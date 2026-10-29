"""Load flow records and convert them to the common NetMon schema.

Common schema (one row per flow):
    ts, src_ip, src_port, dst_ip, dst_port, protocol, proto_name, duration_us,
    fwd_pkts, bwd_pkts, packets, fwd_bytes, bwd_bytes, total_bytes,
    bytes_per_pkt, pkts_per_sec, service, is_well_known_port, minute,
    label, is_attack
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Columns we need from a CICFlowMeter "GeneratedLabelledFlows" CSV.
CIC_COLUMNS = {
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp_raw",
    "Flow Duration": "duration_us",
    "Total Fwd Packets": "fwd_pkts",
    "Total Backward Packets": "bwd_pkts",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Label": "label",
}

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}

SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "KERBEROS", 110: "POP3", 123: "NTP", 137: "NETBIOS",
    139: "NETBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    3306: "MYSQL", 3389: "RDP", 8080: "HTTP-ALT",
}


def _parse_cic_timestamp(raw: pd.Series) -> pd.Series:
    """Parse CIC-IDS2017 timestamps.

    The CSVs mix two formats: Monday uses '03/07/2017 08:55:58' (24-hour,
    with seconds) while the other days use '4/7/2017 2:05' (minute precision,
    12-hour clock with the AM/PM marker missing). Capture ran roughly 08:00 to
    18:00 local time, so an hour of 1-7 is an afternoon hour and gets +12.
    """
    raw = raw.astype(str).str.strip()
    ts = pd.to_datetime(raw, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    missing = ts.isna()
    if missing.any():
        ts.loc[missing] = pd.to_datetime(raw[missing], format="%d/%m/%Y %H:%M", errors="coerce")
    afternoon = ts.dt.hour.between(1, 7)
    ts.loc[afternoon] = ts.loc[afternoon] + pd.Timedelta(hours=12)
    return ts


def load_cic_csv(path: str, nrows: int | None = None) -> pd.DataFrame:
    """Read a CIC-IDS2017 labelled-flow CSV and return the common schema."""
    df = pd.read_csv(path, encoding="latin-1", low_memory=False, nrows=nrows,
                     skipinitialspace=True)
    df.columns = df.columns.str.strip()          # CIC headers have leading spaces
    df = df[list(CIC_COLUMNS)].rename(columns=CIC_COLUMNS)
    df = df.dropna(subset=["src_ip", "dst_ip", "timestamp_raw"])  # blank padding rows
    df["ts"] = _parse_cic_timestamp(df.pop("timestamp_raw"))
    df["label"] = df["label"].astype(str).str.strip()
    return normalise(df)


GENERIC_COLUMNS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "duration_us",
                   "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "label"]


def load_generic_csv(path_or_buffer, compression="infer") -> pd.DataFrame:
    """Read a CSV already in the common schema (e.g. exported by the capture script),
    or a raw CICFlowMeter file.

    Required columns: ts, src_ip, src_port, dst_ip, dst_port, protocol,
    duration_us, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes. 'label' is optional.
    Only the needed columns are read, which keeps memory low on small servers.
    """
    wanted = set(GENERIC_COLUMNS) | set(CIC_COLUMNS)
    df = pd.read_csv(path_or_buffer, compression=compression, encoding="latin-1",
                     usecols=lambda c: c.strip() in wanted)
    df.columns = df.columns.str.strip()
    if "Source IP" in df.columns:               # a raw CIC file was uploaded
        df = df[[c for c in CIC_COLUMNS if c in df.columns]].rename(columns=CIC_COLUMNS)
        df["ts"] = _parse_cic_timestamp(df.pop("timestamp_raw"))
    else:
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    if "label" not in df.columns:
        df["label"] = "UNKNOWN"
    return normalise(df)


def validate_columns(df: pd.DataFrame) -> list[str]:
    required = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]
    return [c for c in required if c not in df.columns]


def normalise(df: pd.DataFrame) -> pd.DataFrame:
    """Clean types, drop bad rows and add derived per-flow fields."""
    missing = validate_columns(df)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    num_cols = ["src_port", "dst_port", "protocol", "duration_us",
                "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
        if df[c].dtype.kind == "f":
            df[c] = df[c].where(np.isfinite(df[c]))
    ok = df[num_cols + ["ts"]].notna().all(axis=1) & (df["duration_us"] >= 0) & (df["fwd_pkts"] >= 0)
    if not ok.all():
        df = df[ok]

    for c in ["src_port", "dst_port", "protocol", "fwd_pkts", "bwd_pkts"]:
        df[c] = df[c].astype("int64")
    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    df["dst_ip"] = df["dst_ip"].astype(str).str.strip()

    df["proto_name"] = df["protocol"].map(PROTOCOLS).fillna("OTHER")
    df["packets"] = df["fwd_pkts"] + df["bwd_pkts"]
    df["total_bytes"] = df["fwd_bytes"] + df["bwd_bytes"]
    df["bytes_per_pkt"] = df["total_bytes"] / df["packets"].clip(lower=1)
    secs = (df["duration_us"] / 1e6).clip(lower=1e-6)
    df["pkts_per_sec"] = df["packets"] / secs
    df["service"] = df["dst_port"].map(SERVICES).fillna("OTHER")
    df["is_well_known_port"] = (df["dst_port"] < 1024).astype("int8")
    df["minute"] = df["ts"].dt.floor("1min")

    lab = df["label"].astype(str).str.strip()
    lab = lab.str.replace("�", "-", regex=False).str.replace("\x96", "-", regex=False)
    df["label"] = lab
    df["is_attack"] = (~lab.str.upper().isin(["BENIGN", "UNKNOWN"])).astype("int8")
    df = df.reset_index(drop=True)
    return df
