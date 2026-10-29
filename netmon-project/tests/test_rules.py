"""Unit tests for the detectors on small synthetic flow tables."""
import os
import sys

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netmon import alerts, rules                  # noqa: E402
from netmon.pipeline import Detector              # noqa: E402
from netmon.preprocess import normalise           # noqa: E402

T0 = pd.Timestamp("2026-10-01 10:00:00")


def flows(rows):
    df = pd.DataFrame(rows)
    for c, v in {"protocol": 6, "duration_us": 1000, "fwd_pkts": 1, "bwd_pkts": 1,
                 "fwd_bytes": 60, "bwd_bytes": 40, "label": "BENIGN"}.items():
        if c not in df:
            df[c] = v
    return normalise(df)


def normal_traffic(n=50):
    return [{"ts": T0 + pd.Timedelta(seconds=i), "src_ip": f"10.0.0.{i % 5 + 10}", "src_port": 50000 + i,
             "dst_ip": "10.0.0.1", "dst_port": 443} for i in range(n)]


@pytest.fixture(scope="module")
def det():
    return Detector(base_dir=ROOT)


def test_port_scan_detected(det):
    scan = [{"ts": T0 + pd.Timedelta(seconds=i / 10), "src_ip": "10.0.0.66", "src_port": 40000,
             "dst_ip": "10.0.0.20", "dst_port": p, "label": "PortScan"} for i, p in enumerate(range(1, 101))]
    df = flows(normal_traffic() + scan)
    hits, flag = rules.port_scan(df, det.cfg["port_scan"])
    assert set(hits["src_ip"]) == {"10.0.0.66"}
    assert hits.iloc[0]["severity"] == "Critical"           # 100 ports reaches the critical level
    assert flag[df["src_ip"] == "10.0.0.66"].all()
    assert not flag[df["src_ip"] != "10.0.0.66"].any()


def test_server_replies_are_not_a_scan(det):
    # a web server answering 60 clients sends to 60 different client ports; that is not a scan
    replies = [{"ts": T0, "src_ip": "93.184.216.34", "src_port": 443, "dst_ip": "10.0.0.12",
                "dst_port": 1024 + i} for i in range(60)]
    hits, _ = rules.port_scan(flows(replies), det.cfg["port_scan"])
    assert hits.empty


def test_brute_force_detected(det):
    tries = [{"ts": T0 + pd.Timedelta(seconds=i), "src_ip": "10.0.0.66", "src_port": 41000 + i,
              "dst_ip": "10.0.0.20", "dst_port": 22, "fwd_pkts": 12, "bwd_pkts": 10} for i in range(40)]
    hits, flag = rules.brute_force(flows(normal_traffic() + tries), det.cfg["brute_force"])
    assert len(hits) == 1 and hits.iloc[0]["name"] == "Brute force (SSH)"
    assert flag.sum() == 40


def test_few_logins_are_fine(det):
    tries = [{"ts": T0 + pd.Timedelta(seconds=i * 10), "src_ip": "10.0.0.9", "src_port": 41000 + i,
              "dst_ip": "10.0.0.20", "dst_port": 22} for i in range(5)]
    hits, _ = rules.brute_force(flows(tries), det.cfg["brute_force"])
    assert hits.empty


def test_traffic_spike_against_baseline(det):
    flood = [{"ts": T0 + pd.Timedelta(milliseconds=50 * i), "src_ip": f"172.16.{i % 20}.1",
              "src_port": 30000 + i, "dst_ip": "192.168.10.50", "dst_port": 80} for i in range(1200)]
    hits, flag = rules.traffic_spike(flows(flood), det.cfg["traffic_spike"], det.baseline)
    assert len(hits) == 1
    assert hits.iloc[0]["name"] == "Traffic spike (DDoS)"    # 20 distinct sources
    assert flag.all()


def test_blacklist(det):
    rows = normal_traffic(5) + [{"ts": T0, "src_ip": "10.0.0.12", "src_port": 51000,
                                 "dst_ip": "203.0.113.66", "dst_port": 443}]
    hits, flag = rules.blacklist(flows(rows), {"203.0.113.66"})
    assert flag.sum() == 1 and hits.iloc[0]["severity"] == "Critical"


def test_alert_merge_joins_consecutive_minutes():
    hits = pd.DataFrame({
        "rule": ["R1"] * 3, "name": ["Port scan"] * 3, "severity": ["High", "Critical", "High"],
        "src_ip": ["1.1.1.1"] * 3, "dst_ip": ["2.2.2.2"] * 3, "dst_port": [None] * 3,
        "minute": pd.to_datetime(["2026-10-01 10:00", "2026-10-01 10:01", "2026-10-01 10:30"]),
        "flows": [10, 20, 5], "evidence": ["a", "b", "c"]})
    out = alerts.merge_hits(hits, "5min")
    assert len(out) == 2                                     # 10:00-10:01 merged, 10:30 separate
    assert out.iloc[0]["severity"] == "Critical" and out.iloc[0]["flows"] == 30


def test_full_pipeline_runs(det):
    df, al, st = det.run(flows(normal_traffic()))
    assert st["flows"] == 50
    assert not df["flagged_core"].any()
