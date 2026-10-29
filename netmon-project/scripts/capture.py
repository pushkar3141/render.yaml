"""Capture live traffic and write flow records that NetMon can analyse.

Packets are grouped into bidirectional flows by their 5-tuple. A flow ends after
`--idle` seconds without packets or when a TCP FIN/RST is seen. Run it only on a
network you own or have written permission to monitor.

Usage (needs root/administrator for raw capture):
    sudo python scripts/capture.py --iface eth0 --seconds 300 --out capture.csv
    python scripts/capture.py --pcap traffic.pcap --out capture.csv   # from a saved capture

Then upload capture.csv on the "Analyse traffic" page.
"""
import argparse
import csv
import datetime as dt

from scapy.all import IP, TCP, UDP, PcapReader, sniff   # pip install scapy

FIELDS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "duration_us",
          "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "label"]


class FlowTable:
    def __init__(self, idle: float, writer):
        self.idle, self.writer, self.flows = idle, writer, {}

    def _emit(self, key):
        f = self.flows.pop(key)
        self.writer.writerow({
            "ts": dt.datetime.fromtimestamp(f["start"]).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f["src"], "src_port": f["sport"], "dst_ip": f["dst"], "dst_port": f["dport"],
            "protocol": f["proto"], "duration_us": int((f["last"] - f["start"]) * 1e6),
            "fwd_pkts": f["fp"], "bwd_pkts": f["bp"], "fwd_bytes": f["fb"], "bwd_bytes": f["bb"],
            "label": "UNKNOWN"})

    def add(self, pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        sport, dport = (l4.sport, l4.dport) if l4 is not None else (0, 0)
        t, size = float(pkt.time), len(ip.payload)
        fwd = (ip.src, sport, ip.dst, dport, ip.proto)
        bwd = (ip.dst, dport, ip.src, sport, ip.proto)
        key = fwd if fwd in self.flows else bwd if bwd in self.flows else None
        if key and t - self.flows[key]["last"] > self.idle:
            self._emit(key)
            key = None
        if key is None:
            key = fwd
            self.flows[key] = {"src": ip.src, "sport": sport, "dst": ip.dst, "dport": dport,
                               "proto": ip.proto, "start": t, "last": t, "fp": 0, "bp": 0, "fb": 0, "bb": 0}
        f = self.flows[key]
        if key == fwd:
            f["fp"] += 1; f["fb"] += size
        else:
            f["bp"] += 1; f["bb"] += size
        f["last"] = t
        if TCP in pkt and pkt[TCP].flags & 0x05:          # FIN or RST closes the flow
            self._emit(key)

    def flush(self):
        for k in list(self.flows):
            self._emit(k)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface")
    ap.add_argument("--pcap")
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--idle", type=float, default=120)
    ap.add_argument("--out", default="capture.csv")
    a = ap.parse_args()
    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        table = FlowTable(a.idle, w)
        if a.pcap:
            for pkt in PcapReader(a.pcap):
                table.add(pkt)
        else:
            sniff(iface=a.iface, prn=table.add, store=False, timeout=a.seconds)
        table.flush()
    print(f"Flows written to {a.out}")


if __name__ == "__main__":
    main()
