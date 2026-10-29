"""Build downloadable CSV and PDF security reports for one upload."""
from __future__ import annotations

import io

import pandas as pd

# matplotlib and reportlab are imported inside the functions that need them, so the
# web worker does not hold them in memory until someone generates a PDF.

SEV_COLOURS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#8a96a3"}


def alerts_csv(alerts: pd.DataFrame) -> bytes:
    return alerts.to_csv(index=False).encode()


def _timeline_png(summary: dict) -> bytes:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates
    import matplotlib.pyplot as plt
    tl = pd.DataFrame(summary["timeline"])
    tl["minute"] = pd.to_datetime(tl["minute"])
    fig, ax = plt.subplots(figsize=(10, 2.8))
    for w in summary["alert_windows"]:
        ax.axvspan(pd.Timestamp(w["start"]), pd.Timestamp(w["end"]), color="#fde3d6", lw=0)
    ax.plot(tl["minute"], tl["flows"], color="#2a78d6", lw=1.8)
    ax.set_ylabel("Flows per minute")
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.grid(True, color="#e4e3df")
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160)
    plt.close(fig)
    return buf.getvalue()


def alerts_pdf(upload_name: str, summary: dict, alerts: pd.DataFrame) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm,
                            title=f"Security report: {upload_name}")
    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8, leading=10)
    story = [Paragraph(f"Network security report: {upload_name}", ss["Title"]),
             Paragraph(f"Traffic window {summary['start']} to {summary['end']}", ss["BodyText"]),
             Spacer(1, 8)]
    sev = summary["severity_counts"]
    kpi = [["Flows analysed", "Unique sources", "Flows flagged by rules", "Critical", "High",
            "Medium", "Low"],
           [f"{summary['flows']:,}", f"{summary['unique_sources']:,}", f"{summary['flagged_core']:,}",
            sev.get("Critical", 0), sev.get("High", 0), sev.get("Medium", 0), sev.get("Low", 0)]]
    t = Table(kpi)
    t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("TEXTCOLOR", (0, 0), (-1, 0), colors.grey),
                           ("FONTSIZE", (0, 1), (-1, 1), 13), ("BOTTOMPADDING", (0, 1), (-1, 1), 6)]))
    story += [t, Spacer(1, 8), Image(io.BytesIO(_timeline_png(summary)), width=25 * cm, height=7 * cm),
              Paragraph("Shaded periods had a Critical or High alert.", small), Spacer(1, 10),
              Paragraph("Critical and high alerts", ss["Heading2"])]

    top = alerts[alerts["severity"].isin(["Critical", "High"])].head(40)
    rows = [["First seen", "Severity", "Alert", "Source", "Destination", "Evidence", "Suggested action"]]
    for r in top.itertuples():
        rows.append([str(r.first_seen)[5:16], r.severity, r.name, r.src_ip, r.dst_ip,
                     Paragraph(r.evidence, small), Paragraph(r.action, small)])
    if len(rows) == 1:
        rows.append(["-", "-", "No critical or high alerts", "", "", "", ""])
    t = Table(rows, colWidths=[2.3 * cm, 1.7 * cm, 3.6 * cm, 2.6 * cm, 2.6 * cm, 6.3 * cm, 6.6 * cm],
              repeatRows=1)
    style = [("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.black),
             ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#d5dde5"))]
    for i, r in enumerate(top.itertuples(), start=1):
        style.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(SEV_COLOURS.get(r.severity, "#000000"))))
    t.setStyle(TableStyle(style))
    story.append(t)
    other = len(alerts) - len(top)
    if other > 0:
        story += [Spacer(1, 6), Paragraph(f"{other:,} lower-priority alerts (statistical and Isolation "
                                          "Forest detectors) are in the CSV report.", small)]
    doc.build(story)
    return buf.getvalue()
