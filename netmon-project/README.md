# NetMon: Smart Network Security Monitoring System

A web application that reads network flow records, runs rule-based, statistical and
Isolation Forest detectors over them, and shows prioritised security alerts on a
dashboard. Reports are generated as PDF and CSV and stored in the cloud.

Built with Python, Pandas, scikit-learn, Flask and Plotly. Runs locally with SQLite,
or on Render (free web service) with Supabase (Postgres and file storage).

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                                           # http://127.0.0.1:5000
```

Sign in with the password in `ADMIN_PASSWORD` (default `netmon-admin`; change it).
On the "Analyse traffic" page, pick one of the three CIC-IDS2017 samples, or upload
your own flow CSV.

## What it detects

| Rule | Detects | How |
|---|---|---|
| R1 | Port scan | 30+ distinct service ports from one source in a minute (client-initiated flows only) |
| R2 | Brute force on FTP, SSH, Telnet, RDP | 20+ connections to one login port on one host in a minute |
| R3 | DoS / DDoS traffic spike | Flows per minute to a host more than 5 standard deviations above its benign baseline and above its busiest benign minute |
| R4 | Blacklisted IP | Source or destination listed in `data/blacklist.csv` |
| R5 | Unusual flow size | \|z\| > 3 on log(1 + bytes) against the benign baseline |
| R6 | Unusual flow size | Above Q3 + 3 × IQR on log(1 + bytes) |
| ML | Anomalous flows | Isolation Forest trained on benign traffic only |

Thresholds are in `config.yaml` and can be changed on the Settings page. The
baseline (`data/baseline.json`) and model (`data/iforest.pkl`) were learned from
the benign Monday of CIC-IDS2017.

## Reproduce the evaluation

1. Download `GeneratedLabelledFlows.zip` from the CIC-IDS2017 page
   (https://www.unb.ca/cic/datasets/ids-2017.html). Use this version, not
   `MachineLearningCSV`, because it keeps the IP addresses and timestamps.
2. Extract it into a folder, for example `data_raw/`.
3. Run:

```bash
python scripts/build_baseline.py "data_raw/Monday-WorkingHours.pcap_ISCX.csv"
python scripts/evaluate.py data_raw
```

Results go to `results/` (metrics.json, CSV tables, figures). Main results from our
run on 2,180,651 flows:

| Detector | Scored against | Recall | Precision | False-positive rate |
|---|---|---|---|---|
| R1 Port scan | PortScan | 0.998 | 1.000 | 0.0000 |
| R2 Brute force | FTP/SSH-Patator | 1.000 | 1.000 | 0.0000 |
| R3 Traffic spike | DoS + DDoS | 0.999 | 0.903 | 0.0756 |
| Rules R1–R4 combined | All attacks | 0.998 | 0.916 | 0.0461 |
| Isolation Forest | All attacks | 0.095 | 0.442 | 0.0607 |

R5 and R6 found no attacks in this dataset: the attacks consist of many small flows,
not unusually large ones.

## Capture your own traffic

```bash
pip install scapy
sudo python scripts/capture.py --iface eth0 --seconds 300 --out capture.csv
```

Upload `capture.csv` on the "Analyse traffic" page. To demonstrate detection, run
`nmap -sS <your-own-VM>` during the capture. Only capture on networks you own or have
written permission to monitor.

## Deploy to the cloud (Render + Supabase)

1. Create a Supabase project. Under Storage, create a private bucket named `reports`.
   Copy the project URL, the `service_role` key, and the database connection string
   (Session pooler) from the project settings.
2. Push this folder to a GitHub repository.
3. On Render choose New > Blueprint and select the repository; `render.yaml` sets up a
   free web service. Fill in `ADMIN_PASSWORD`, `DATABASE_URL`, `SUPABASE_URL` and
   `SUPABASE_SERVICE_KEY` when asked.
4. Open the `onrender.com` URL. The sidebar footer shows "Storage: Supabase" when the
   cloud storage is connected.

Free-tier limits: the Render service sleeps after 15 idle minutes and takes up to a
minute to wake, so open it a few minutes before a demo. Supabase pauses projects
after a week without activity. The free service has 512 MB of memory, so each upload
is analysed in a short-lived child process and capped at 300,000 flows (about one
busy hour); measured peak for a 266,551-flow file was 457 MB.

## Project layout

```
app.py                 Flask routes
config.yaml            detection thresholds
netmon/preprocess.py   loading, cleaning, CIC timestamp fix, derived fields
netmon/features.py     window aggregates, benign baseline
netmon/rules.py        R1-R4
netmon/stats_detect.py R5-R6
netmon/ml_detect.py    Isolation Forest
netmon/alerts.py       alert merging, severity, firewall suggestions
netmon/pipeline.py     runs all detectors
netmon/summary.py      dashboard chart data
netmon/reports.py      PDF and CSV reports
netmon/db.py           SQLAlchemy models
netmon/storage.py      Supabase Storage or local folder
scripts/               baseline builder, evaluation, live capture
data/                  baseline, model, blacklist, demo samples
tests/                 unit tests (python -m pytest tests)
```
