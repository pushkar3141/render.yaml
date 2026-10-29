"""NetMon: Smart Network Security Monitoring System (Flask web app)."""
from __future__ import annotations

import copy
import functools
import gc
import io
import json
import multiprocessing
import os
import re
import time

import pandas as pd
from flask import (Flask, Response, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)

from netmon import reports
from netmon.db import Alert, Report, Setting, Upload, make_session
from netmon.pipeline import Detector
from netmon.preprocess import load_generic_csv
from netmon.storage import LocalStorage, make_storage
from netmon.summary import build_summary

BASE = os.path.dirname(os.path.abspath(__file__))

# load KEY=value lines from .env for local runs (Render sets real environment variables)
if os.path.exists(os.path.join(BASE, ".env")):
    with open(os.path.join(BASE, ".env")) as _f:
        for _line in _f:
            if "=" in _line and not _line.lstrip().startswith("#"):
                _k, _v = _line.strip().split("=", 1)
                os.environ.setdefault(_k, _v)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024       # 40 MB upload limit
# Render's free tier has 512 MB of memory; 300,000 flows peak at about 460 MB in total.
MAX_FLOWS = int(os.environ.get("MAX_FLOWS", "300000"))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "netmon-admin")

Session = make_session(BASE)
storage = make_storage(BASE)
detector = Detector(base_dir=BASE)
SEVERITIES = ["Critical", "High", "Medium", "Low"]
DEMOS = {
    "friday_portscan": "Friday afternoon: port scans (CIC-IDS2017)",
    "tuesday_ssh_bruteforce": "Tuesday afternoon: SSH brute force (CIC-IDS2017)",
    "wednesday_dos": "Wednesday morning: DoS attacks (CIC-IDS2017)",
}
# settings a user may change on the Settings page: (section, key, label, type)
EDITABLE = [
    ("port_scan", "min_distinct_ports", "Port scan: distinct service ports per source per minute", int),
    ("brute_force", "min_attempts", "Brute force: login connections per minute", int),
    ("traffic_spike", "z_threshold", "Traffic spike: z-score above the destination's normal level", float),
    ("traffic_spike", "min_flows", "Traffic spike: minimum flows per minute", int),
    ("zscore", "threshold", "Z-score outlier: |z| of log(bytes)", float),
    ("iqr", "k", "IQR outlier: fence multiplier k", float),
]


# ---------------------------------------------------------------- helpers
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def current_config() -> dict:
    cfg = copy.deepcopy(detector.cfg)
    with Session() as db:
        row = db.get(Setting, "thresholds")
        if row:
            for sec, vals in json.loads(row.value).items():
                cfg.setdefault(sec, {}).update(vals)
    return cfg


def run_isolated(fn, *args):
    """Run fn(*args) in a short-lived forked child process and return its result.

    Analysing a file temporarily needs ~150-200 MB. Python rarely hands freed memory
    back to the operating system, so doing the work in a child that exits keeps the
    long-running web worker small enough for a 512 MB free-tier server.
    """
    ctx = multiprocessing.get_context("fork")
    parent, child = ctx.Pipe(duplex=False)
    gc.collect()
    gc.freeze()          # keep the child's garbage collector from touching (and copying) parent pages

    def target():
        Session.kw["bind"].dispose(close=False)       # never share DB connections with the parent
        try:
            child.send(("ok", fn(*args)))
        except Exception as e:                        # report the error to the parent
            child.send(("error", f"{type(e).__name__}: {e}"))
        finally:
            child.close()

    proc = ctx.Process(target=target)
    proc.start()
    child.close()
    try:
        status, value = parent.recv()
    except EOFError:
        status, value = "error", "The analysis process stopped unexpectedly (out of memory?)."
    proc.join()
    gc.unfreeze()
    if status == "error":
        raise ValueError(value)
    return value


def process_upload(filename: str, raw: bytes) -> int:
    """Run the full pipeline on an uploaded flow file and store the results."""
    t0 = time.perf_counter()
    gz = raw[:2] == b"\x1f\x8b"
    df = load_generic_csv(io.BytesIO(raw), compression="gzip" if gz else None)
    if len(df) > MAX_FLOWS:
        raise ValueError(f"the file has {len(df):,} flows, more than the {MAX_FLOWS:,} this server "
                         "can analyse at once. Split it into time slices of about one hour.")
    det = copy.copy(detector)
    det.cfg = current_config()
    df, alerts, _ = det.run(df)
    seconds = time.perf_counter() - t0

    with Session() as db:
        up = Upload(filename=filename, flows=len(df), flagged_flows=int(df["flagged_core"].sum()),
                    labelled_attacks=int(df["is_attack"].sum()), seconds=round(seconds, 2))
        db.add(up)
        db.flush()
        stamp = time.strftime("%Y%m%d")
        up.raw_path = storage.put(f"raw/{stamp}/{up.id}_{safe(filename)}", raw, "application/octet-stream")
        keep = ["ts", "minute", "src_ip", "src_port", "dst_ip", "dst_port", "proto_name", "service",
                "packets", "total_bytes", "duration_us", "label", "is_attack",
                "r1", "r2", "r3", "r4", "r5", "r6", "ml", "flagged_core"]
        buf = io.BytesIO()
        df[keep].to_parquet(buf, index=False)
        up.processed_path = storage.put(f"processed/{up.id}.parquet", buf.getvalue())
        up.summary = build_summary(df, alerts)
        for r in alerts.itertuples():
            db.add(Alert(upload_id=up.id, first_seen=r.first_seen, last_seen=r.last_seen, rule=r.rule,
                         name=r.name, severity=r.severity, src_ip=r.src_ip, dst_ip=r.dst_ip,
                         dst_port=None if pd.isna(r.dst_port) else int(r.dst_port),
                         minutes=int(r.minutes), flows=int(r.flows), evidence=r.evidence, action=r.action))
        db.commit()
        return up.id


def safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]


def flows_for_ip(path: str, ip: str) -> pd.DataFrame:
    """Read only the flows to or from one IP from the processed Parquet file."""
    import pyarrow.parquet as pq
    filters = [[("src_ip", "==", ip)], [("dst_ip", "==", ip)]]
    cols = ["minute", "src_ip", "dst_ip", "dst_port", "label", "flagged_core"]
    return pq.read_table(io.BytesIO(storage.get(path)), columns=cols, filters=filters).to_pandas()


def get_upload(upload_id: int) -> Upload:
    with Session() as db:
        up = db.get(Upload, upload_id)
    if not up:
        abort(404)
    return up


def alerts_frame(upload_id: int) -> pd.DataFrame:
    with Session() as db:
        rows = db.query(Alert).filter(Alert.upload_id == upload_id).order_by(Alert.first_seen).all()
    cols = ["id", "first_seen", "last_seen", "rule", "name", "severity", "src_ip", "dst_ip", "dst_port",
            "minutes", "flows", "evidence", "action"]
    return pd.DataFrame([{c: getattr(r, c) for c in cols} for r in rows], columns=cols,
                        dtype=object)


@app.context_processor
def inject():
    with Session() as db:
        uploads = db.query(Upload).order_by(Upload.id.desc()).limit(20).all()
    return {"all_uploads": uploads, "storage_kind": storage.kind}


@app.template_filter("num")
def num(v):
    return f"{v:,}" if isinstance(v, (int, float)) else v


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["user"] = "admin"
            return redirect(request.args.get("next") or url_for("index"))
        flash("That password is incorrect. Check the ADMIN_PASSWORD setting and try again.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- pages
@app.route("/")
@login_required
def index():
    with Session() as db:
        latest = db.query(Upload).order_by(Upload.id.desc()).first()
    if latest:
        return redirect(url_for("overview", upload_id=latest.id))
    return redirect(url_for("upload"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        demo = request.form.get("demo")
        try:
            if demo in DEMOS:
                with open(os.path.join(BASE, "data", "samples", f"{demo}.csv.gz"), "rb") as f:
                    new_id = run_isolated(process_upload, f"{demo}.csv.gz", f.read())
            else:
                file = request.files.get("file")
                if not file or not file.filename:
                    flash("Choose a CSV file of flow records first.")
                    return redirect(url_for("upload"))
                new_id = run_isolated(process_upload, file.filename, file.read())
        except ValueError as e:
            flash(f"The file could not be analysed: {e}")
            return redirect(url_for("upload"))
        return redirect(url_for("overview", upload_id=new_id))
    return render_template("upload.html", demos=DEMOS)


@app.route("/u/<int:upload_id>")
@login_required
def overview(upload_id):
    up = get_upload(upload_id)
    alerts = alerts_frame(upload_id)
    top = alerts[alerts["severity"].isin(["Critical", "High"])].head(8)
    return render_template("overview.html", up=up, s=up.summary, top=top.to_dict("records"),
                           n_alerts=len(alerts))


@app.route("/u/<int:upload_id>/alerts")
@login_required
def alerts_page(upload_id):
    up = get_upload(upload_id)
    df = alerts_frame(upload_id)
    sev = request.args.getlist("severity") or ["Critical", "High"]
    rule = request.args.get("rule", "")
    ip = request.args.get("ip", "").strip()
    view = df[df["severity"].isin(sev)]
    if rule:
        view = view[view["rule"] == rule]
    if ip:
        view = view[(view["src_ip"] == ip) | (view["dst_ip"] == ip)]
    return render_template("alerts.html", up=up, rows=view.head(500).to_dict("records"), total=len(view),
                           sev=sev, rule=rule, ip=ip, severities=SEVERITIES,
                           rules=sorted(df["rule"].unique()) if len(df) else [])


@app.route("/u/<int:upload_id>/alerts.csv")
@login_required
def alerts_csv(upload_id):
    get_upload(upload_id)
    data = reports.alerts_csv(alerts_frame(upload_id).drop(columns=["id"]))
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=alerts_{upload_id}.csv"})


def ip_profile(path: str, ip: str) -> dict | None:
    """Everything the IP page needs, computed from the processed flows (runs in a child)."""
    sub = flows_for_ip(path, ip)
    if sub.empty:
        return None
    out = sub[sub["src_ip"] == ip]
    tl = sub.groupby("minute").agg(flows=("src_ip", "size"), flagged=("flagged_core", "sum"))
    full = pd.date_range(tl.index.min(), tl.index.max(), freq="1min", name="minute")
    tl = tl.reindex(full, fill_value=0).reset_index()     # quiet minutes show as zero, not a slope
    ports = out.groupby("dst_port").size().sort_values(ascending=False).head(15)
    peers = (pd.concat([out["dst_ip"], sub.loc[sub["dst_ip"] == ip, "src_ip"]])
             .value_counts().head(10))
    return {"data": {"minute": tl["minute"].astype(str).tolist(), "flows": tl["flows"].tolist(),
                     "flagged": tl["flagged"].astype(int).tolist(),
                     "ports": [str(p) for p in ports.index], "port_flows": ports.tolist()},
            "flows": len(sub), "out": len(out), "inbound": len(sub) - len(out),
            "distinct_ports": int(out["dst_port"].nunique()),
            "peers": {str(k): int(v) for k, v in peers.items()},
            "labels": {str(k): int(v) for k, v in sub["label"].value_counts().items()}}


@app.route("/u/<int:upload_id>/ip/<path:ip>")
@login_required
def ip_page(upload_id, ip):
    up = get_upload(upload_id)
    prof = run_isolated(ip_profile, up.processed_path, ip)
    if prof is None:
        abort(404)
    alerts = alerts_frame(upload_id)
    alerts = alerts[(alerts["src_ip"] == ip) | (alerts["dst_ip"] == ip)]
    return render_template("ip.html", up=up, ip=ip, alerts=alerts.head(100).to_dict("records"), **prof)


def build_report_files(upload_id: int) -> None:
    up = get_upload(upload_id)
    alerts = alerts_frame(upload_id).drop(columns=["id"])
    stamp = time.strftime("%Y-%m-%d")
    pdf = reports.alerts_pdf(up.filename, up.summary, alerts)
    csv = reports.alerts_csv(alerts)
    with Session() as db:
        t = time.strftime("%H%M%S")
        db.add(Report(upload_id=upload_id, kind="pdf",
                      path=storage.put(f"reports/{stamp}/{upload_id}_{t}.pdf", pdf, "application/pdf")))
        db.add(Report(upload_id=upload_id, kind="csv",
                      path=storage.put(f"reports/{stamp}/{upload_id}_{t}.csv", csv, "text/csv")))
        db.commit()


@app.route("/u/<int:upload_id>/report", methods=["POST"])
@login_required
def make_report(upload_id):
    get_upload(upload_id)
    run_isolated(build_report_files, upload_id)
    flash("Report generated. It is listed below and stored in "
          + ("Supabase Storage." if storage.kind == "supabase" else "the local storage folder."))
    return redirect(url_for("reports_page"))


@app.route("/reports")
@login_required
def reports_page():
    with Session() as db:
        rows = (db.query(Report, Upload).join(Upload, Report.upload_id == Upload.id)
                .order_by(Report.id.desc()).limit(100).all())
    items = [{"id": r.id, "created": r.created_at, "kind": r.kind, "upload": u.filename,
              "upload_id": u.id, "url": url_for("download_report", report_id=r.id)} for r, u in rows]
    return render_template("reports.html", items=items)


@app.route("/reports/<int:report_id>")
@login_required
def download_report(report_id):
    with Session() as db:
        r = db.get(Report, report_id)
    if not r:
        abort(404)
    if storage.kind == "supabase":
        return redirect(storage.url(r.path))
    return send_file(io.BytesIO(storage.get(r.path)), download_name=os.path.basename(r.path),
                     as_attachment=True)


@app.route("/files/<path:key>")
@login_required
def files(key):
    if not isinstance(storage, LocalStorage) or ".." in key:
        abort(404)
    return send_file(os.path.join(storage.root, key))


@app.route("/evaluation")
@login_required
def evaluation():
    path = os.path.join(BASE, "results", "metrics.json")
    if not os.path.exists(path):
        return render_template("evaluation.html", m=None)
    with open(path) as f:
        m = json.load(f)
    return render_template("evaluation.html", m=m)


@app.route("/results/figures/<name>")
@login_required
def figure(name):
    return send_file(os.path.join(BASE, "results", "figures", os.path.basename(name)))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    cfg = current_config()
    if request.method == "POST":
        new = {}
        try:
            for sec, key, _, typ in EDITABLE:
                val = typ(request.form[f"{sec}.{key}"])
                if val <= 0:
                    raise ValueError
                new.setdefault(sec, {})[key] = val
        except (KeyError, ValueError):
            flash("Every threshold must be a positive number. Nothing was saved.")
            return redirect(url_for("settings"))
        with Session() as db:
            db.merge(Setting(key="thresholds", value=json.dumps(new)))
            db.commit()
        flash("Thresholds saved. They apply to files analysed from now on.")
        return redirect(url_for("settings"))
    fields = [{"name": f"{s}.{k}", "label": lab, "value": cfg[s][k], "default": detector.cfg[s][k]}
              for s, k, lab, _ in EDITABLE]
    return render_template("settings.html", fields=fields, blacklist=sorted(detector.bad_ips))


@app.route("/healthz")
def healthz():
    return {"status": "ok", "storage": storage.kind}


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
