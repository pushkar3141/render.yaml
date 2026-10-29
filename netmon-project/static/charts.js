// Plotly chart helpers for the NetMon dashboard. Colours follow the validated
// categorical palette; severity colours are reserved for alerts only.
const C = { blue: "#2a78d6", orange: "#eb6834", aqua: "#1baf7a", yellow: "#eda100",
            ink: "#14202d", ink2: "#4f5d6b", grid: "#e6ebf0", shade: "#fde3d6" };
const SEV = { Critical: "#d03b3b", High: "#ec835a", Medium: "#fab219", Low: "#8a96a3" };
const CFG = { displayModeBar: false, responsive: true };

function baseLayout(extra) {
  return Object.assign({
    margin: { l: 56, r: 12, t: 8, b: 40 },
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: { family: "Barlow, system-ui, sans-serif", size: 13, color: C.ink2 },
    xaxis: { gridcolor: C.grid, zeroline: false, linecolor: C.ink2 },
    yaxis: { gridcolor: C.grid, zeroline: false, rangemode: "tozero" },
    hoverlabel: { bgcolor: "#fff", bordercolor: C.ink2, font: { color: C.ink, family: "Barlow" } },
    showlegend: false, bargap: 0.25,
  }, extra || {});
}

function timeline(el, t, windows) {
  const shapes = (windows || []).map(w => ({
    type: "rect", xref: "x", yref: "paper", x0: w.start, x1: w.end, y0: 0, y1: 1,
    fillcolor: C.shade, line: { width: 0 }, layer: "below" }));
  Plotly.newPlot(el, [{
    x: t.minute, y: t.flows, type: "scatter", mode: "lines", name: "Flows per minute",
    line: { color: C.blue, width: 2 }, customdata: t.flagged,
    hovertemplate: "%{x|%H:%M}<br><b>%{y:,}</b> flows<br>%{customdata:,} flagged by rules<extra></extra>",
  }], baseLayout({ shapes, hovermode: "x unified",
                   xaxis: { gridcolor: C.grid, tickformat: "%H:%M", showspikes: true, spikecolor: C.ink2, spikethickness: 1 },
                   yaxis: { gridcolor: C.grid, title: { text: "Flows per minute" }, rangemode: "tozero" } }), CFG);
}

function hbar(el, labels, values, title, color, hoverSuffix) {
  Plotly.newPlot(el, [{
    type: "bar", orientation: "h", y: labels.slice().reverse(), x: values.slice().reverse(),
    marker: { color: color || C.blue }, hovertemplate: "%{y}<br><b>%{x:,}</b> " + (hoverSuffix || "flows") + "<extra></extra>",
  }], baseLayout({ margin: { l: 120, r: 16, t: 8, b: 40 },
                   xaxis: { gridcolor: C.grid, title: { text: title } },
                   yaxis: { automargin: true, type: "category" } }), CFG);
}

function protocols(el, rows) {
  const colors = { TCP: C.blue, UDP: C.orange, ICMP: C.aqua, OTHER: C.yellow };
  Plotly.newPlot(el, [{
    type: "pie", hole: 0.62, labels: rows.map(r => r.protocol), values: rows.map(r => r.flows),
    marker: { colors: rows.map(r => colors[r.protocol] || C.yellow), line: { color: "#fff", width: 2 } },
    textinfo: "percent", textposition: "inside", insidetextorientation: "horizontal", sort: false,
    hovertemplate: "%{label}<br><b>%{value:,}</b> flows (%{percent})<extra></extra>",
  }], baseLayout({ margin: { l: 10, r: 10, t: 10, b: 10 }, showlegend: true,
                   legend: { orientation: "v", x: 1.02, y: 0.5, font: { size: 14, color: C.ink } } }), CFG);
}

// One bar per alert type, coloured by the highest severity it reached. Counts span
// several orders of magnitude (a handful of port scans vs thousands of statistical
// flags), so every bar carries its number as a label instead of using a log axis.
function alertsByRule(el, rows) {
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const agg = {};
  rows.forEach(r => {
    const a = agg[r.name] || (agg[r.name] = { n: 0, sev: "Low" });
    a.n += r.alerts;
    if (rank[r.severity] > rank[a.sev]) a.sev = r.severity;
  });
  const names = Object.keys(agg).sort((a, b) => rank[agg[a].sev] - rank[agg[b].sev] || agg[a].n - agg[b].n);
  Plotly.newPlot(el, [{
    type: "bar", orientation: "h", y: names, x: names.map(n => agg[n].n),
    text: names.map(n => agg[n].n.toLocaleString() + "  " + agg[n].sev), textposition: "outside", cliponaxis: false,
    textfont: { color: C.ink2, size: 12 },
    marker: { color: names.map(n => SEV[agg[n].sev]) },
    hovertemplate: "%{y}<br><b>%{x:,}</b> alerts<extra></extra>",
  }], baseLayout({ margin: { l: 210, r: 110, t: 8, b: 40 },
                   xaxis: { gridcolor: C.grid, title: { text: "Alerts (merged incidents)" } },
                   yaxis: { automargin: true } }), CFG);
}
