"""
HTML reporter – produces a self-contained, production-quality HTML report with:
  - Executive summary cards (severity counts)
  - Interactive findings table with live search & filter
  - Colour-coded severity badges
  - Expandable detail rows
  - Charts via Chart.js (CDN)
  - Fully dark-themed, mobile-responsive design
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aws_security_audit.reporting")

# Severity → badge colour
_SEVERITY_COLOURS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}


class HTMLReporter:
    def __init__(self, output_dir: str = "./reports", s3_bucket: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.s3_bucket = s3_bucket

    def generate(self, result: dict) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        account_id = result.get("account_id", "unknown")
        filename = f"aws_security_audit_{account_id}_{timestamp}.html"
        filepath = self.output_dir / filename

        html = self._render(result)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info("HTML report written to: %s", filepath)

        if self.s3_bucket:
            self._upload_to_s3(filepath, filename)

        return str(filepath)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self, result: dict) -> str:
        summary = result.get("summary", {})
        findings = result.get("findings", [])
        account_id = result.get("account_id", "N/A")
        scan_time = result.get("scan_time", "N/A")
        by_severity = summary.get("by_severity", {})

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        # Summary cards HTML
        cards_html = ""
        for sev in severity_order:
            count = by_severity.get(sev, 0)
            colour = _SEVERITY_COLOURS.get(sev, "#6b7280")
            cards_html += f"""
            <div class="card" style="border-top: 4px solid {colour}">
              <div class="card-count" style="color: {colour}">{count}</div>
              <div class="card-label">{sev}</div>
            </div>"""

        # Chart data
        chart_labels = json.dumps(severity_order)
        chart_data = json.dumps([by_severity.get(s, 0) for s in severity_order])
        chart_colours = json.dumps([_SEVERITY_COLOURS.get(s, "#6b7280") for s in severity_order])

        # Findings rows HTML
        rows_html = ""
        for f in findings:
            sev = f.get("severity", "INFO")
            colour = _SEVERITY_COLOURS.get(sev, "#6b7280")
            details_json = json.dumps(f.get("details", {}), indent=2)
            rows_html += f"""
            <tr class="finding-row" data-severity="{sev}" data-check="{f.get('check_id','')}">
              <td><span class="badge" style="background:{colour}">{sev}</span></td>
              <td><code class="check-id">{f.get('check_id','')}</code></td>
              <td>{f.get('check_name','')}</td>
              <td class="mono resource-id" title="{f.get('resource_id','')}">{f.get('resource_id','')}</td>
              <td>{f.get('region','')}</td>
              <td>{f.get('description','')}</td>
              <td>
                <button class="btn-detail" onclick="toggleDetail(this)">Details</button>
              </td>
            </tr>
            <tr class="detail-row hidden">
              <td colspan="7">
                <div class="detail-grid">
                  <div>
                    <h4>Recommendation</h4>
                    <p>{f.get('recommendation','')}</p>
                  </div>
                  <div>
                    <h4>Technical Details</h4>
                    <pre>{details_json}</pre>
                  </div>
                </div>
              </td>
            </tr>"""

        total = summary.get("total", 0)
        failed = summary.get("failed", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AWS Security Audit Report – {account_id}</title>
  <meta name="description" content="AWS Security Audit Report for account {account_id} generated on {scan_time}" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" />
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg: #0a0f1e;
      --surface: #111827;
      --surface2: #1f2937;
      --border: #374151;
      --text: #f9fafb;
      --text-muted: #9ca3af;
      --accent: #6366f1;
      --accent-glow: rgba(99,102,241,0.25);
      --radius: 12px;
    }}

    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.6;
    }}

    /* ---- Header ---- */
    header {{
      background: linear-gradient(135deg, #1e1b4b 0%, #111827 60%, #0a0f1e 100%);
      border-bottom: 1px solid var(--border);
      padding: 2.5rem 2rem 2rem;
    }}
    .header-inner {{
      max-width: 1400px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }}
    .logo {{
      width: 52px; height: 52px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border-radius: 14px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.6rem;
      box-shadow: 0 0 24px rgba(99,102,241,.4);
      flex-shrink: 0;
    }}
    h1 {{ font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; }}
    .subtitle {{ font-size: 0.875rem; color: var(--text-muted); margin-top: 0.2rem; }}
    .meta-pill {{
      margin-left: auto;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 0.4rem 1rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      white-space: nowrap;
    }}

    /* ---- Main layout ---- */
    main {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
    }}

    section {{ margin-bottom: 2.5rem; }}
    .section-title {{
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 1rem;
      display: flex; align-items: center; gap: 0.5rem;
    }}
    .section-title::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }}

    /* ---- Summary cards ---- */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem 1rem;
      text-align: center;
      transition: transform .15s, box-shadow .15s;
    }}
    .card:hover {{ transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,0,0,.4); }}
    .card-count {{ font-size: 2.5rem; font-weight: 700; line-height: 1.1; }}
    .card-label {{ font-size: 0.8rem; font-weight: 600; letter-spacing: .05em; color: var(--text-muted); margin-top: .4rem; }}

    /* ---- Stat bar ---- */
    .stat-bar {{
      display: flex; gap: 2rem; flex-wrap: wrap;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.25rem 1.5rem;
    }}
    .stat {{ display: flex; flex-direction: column; }}
    .stat-val {{ font-size: 1.5rem; font-weight: 700; }}
    .stat-lbl {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; }}

    /* ---- Chart ---- */
    .chart-wrap {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.5rem;
      max-width: 480px;
    }}

    /* ---- Controls ---- */
    .controls {{
      display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center;
      margin-bottom: 1rem;
    }}
    .search-box {{
      flex: 1; min-width: 220px;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 8px; padding: 0.55rem 1rem;
      color: var(--text); font-family: inherit; font-size: 0.9rem;
      outline: none; transition: border-color .15s;
    }}
    .search-box:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }}
    .filter-btn {{
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 8px; padding: 0.5rem 1rem;
      color: var(--text); font-family: inherit; font-size: 0.85rem;
      cursor: pointer; transition: all .15s;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: var(--accent); border-color: var(--accent); color: #fff;
    }}

    /* ---- Findings table ---- */
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
    }}
    table {{
      width: 100%; border-collapse: collapse;
      font-size: 0.875rem;
    }}
    thead tr {{
      background: var(--surface2);
      border-bottom: 2px solid var(--border);
    }}
    th {{
      padding: 0.85rem 1rem; text-align: left;
      font-weight: 600; font-size: 0.8rem;
      text-transform: uppercase; letter-spacing: .05em;
      color: var(--text-muted); white-space: nowrap;
    }}
    .finding-row {{ background: var(--surface); cursor: default; transition: background .1s; }}
    .finding-row:hover {{ background: var(--surface2); }}
    td {{
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .finding-row td:nth-child(4) {{
      max-width: 220px; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap;
    }}

    .badge {{
      display: inline-block; padding: .2em .65em;
      border-radius: 999px; font-size: .72rem;
      font-weight: 700; letter-spacing: .04em;
      color: #fff; white-space: nowrap;
    }}
    .check-id {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem; color: var(--accent);
      background: rgba(99,102,241,.12);
      padding: .15em .5em; border-radius: 4px;
    }}
    .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }}

    .btn-detail {{
      background: transparent; border: 1px solid var(--border);
      border-radius: 6px; padding: .3rem .65rem;
      color: var(--text-muted); font-size: .78rem;
      cursor: pointer; transition: all .15s;
    }}
    .btn-detail:hover {{ border-color: var(--accent); color: var(--accent); }}

    /* ---- Detail expanded row ---- */
    .detail-row {{ background: #0d1424; }}
    .detail-row.hidden {{ display: none; }}
    .detail-grid {{
      display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;
      padding: 1rem;
    }}
    @media (max-width: 768px) {{ .detail-grid {{ grid-template-columns: 1fr; }} }}
    .detail-grid h4 {{
      font-size: 0.78rem; text-transform: uppercase;
      letter-spacing: .06em; color: var(--accent);
      margin-bottom: .4rem;
    }}
    .detail-grid p {{ font-size: .875rem; color: var(--text-muted); line-height: 1.65; }}
    .detail-grid pre {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .75rem; color: #a5f3fc;
      background: #060d1a; padding: .75rem 1rem;
      border-radius: 8px; overflow-x: auto;
      border: 1px solid #1e2d45;
    }}

    /* ---- Footer ---- */
    footer {{
      text-align: center; padding: 2rem;
      color: var(--text-muted); font-size: .8rem;
      border-top: 1px solid var(--border);
    }}

    .hidden {{ display: none !important; }}
  </style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="logo">🛡️</div>
    <div>
      <h1>AWS Security Audit Report</h1>
      <div class="subtitle">Account: <strong>{account_id}</strong></div>
    </div>
    <div class="meta-pill">🕐 {scan_time}</div>
  </div>
</header>

<main>

  <!-- Executive Summary -->
  <section>
    <p class="section-title">Executive Summary</p>
    <div class="stat-bar" style="margin-bottom:1rem">
      <div class="stat"><span class="stat-val">{total}</span><span class="stat-lbl">Total Findings</span></div>
      <div class="stat"><span class="stat-val">{failed}</span><span class="stat-lbl">Failures</span></div>
      <div class="stat"><span class="stat-val" style="color:#ef4444">{by_severity.get("CRITICAL",0)}</span><span class="stat-lbl">Critical</span></div>
      <div class="stat"><span class="stat-val" style="color:#f97316">{by_severity.get("HIGH",0)}</span><span class="stat-lbl">High</span></div>
    </div>
    <div class="cards">
      {cards_html}
    </div>
  </section>

  <!-- Chart -->
  <section>
    <p class="section-title">Severity Distribution</p>
    <div class="chart-wrap">
      <canvas id="sevChart" height="200"></canvas>
    </div>
  </section>

  <!-- Findings -->
  <section>
    <p class="section-title">Findings ({total})</p>
    <div class="controls">
      <input id="searchInput" class="search-box" type="text" placeholder="🔍  Search findings…" oninput="applyFilters()" />
      <button class="filter-btn active" onclick="setFilter('ALL', this)">All</button>
      <button class="filter-btn" style="color:#ef4444" onclick="setFilter('CRITICAL', this)">Critical</button>
      <button class="filter-btn" style="color:#f97316" onclick="setFilter('HIGH', this)">High</button>
      <button class="filter-btn" style="color:#eab308" onclick="setFilter('MEDIUM', this)">Medium</button>
      <button class="filter-btn" style="color:#3b82f6" onclick="setFilter('LOW', this)">Low</button>
    </div>
    <div class="table-wrap">
      <table id="findingsTable">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Check ID</th>
            <th>Check Name</th>
            <th>Resource</th>
            <th>Region</th>
            <th>Description</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </section>

</main>

<footer>
  Generated by <strong>AWS Security Audit</strong> &mdash; {scan_time}
</footer>

<script>
  // Chart
  const ctx = document.getElementById('sevChart').getContext('2d');
  new Chart(ctx, {{
    type: 'doughnut',
    data: {{
      labels: {chart_labels},
      datasets: [{{
        data: {chart_data},
        backgroundColor: {chart_colours},
        borderWidth: 2,
        borderColor: '#111827',
        hoverOffset: 8
      }}]
    }},
    options: {{
      responsive: true,
      plugins: {{
        legend: {{ position: 'right', labels: {{ color: '#9ca3af', font: {{ family: 'Inter', size: 12 }} }} }},
        tooltip: {{ titleFont: {{ family: 'Inter' }}, bodyFont: {{ family: 'Inter' }} }}
      }}
    }}
  }});

  // Filtering
  let activeFilter = 'ALL';

  function setFilter(sev, btn) {{
    activeFilter = sev;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }}

  function applyFilters() {{
    const q = document.getElementById('searchInput').value.toLowerCase();
    document.querySelectorAll('.finding-row').forEach(row => {{
      const sev = row.dataset.severity;
      const text = row.textContent.toLowerCase();
      const sevOk = activeFilter === 'ALL' || sev === activeFilter;
      const txtOk = !q || text.includes(q);
      row.classList.toggle('hidden', !(sevOk && txtOk));
      // Keep detail row hidden when parent is hidden
      const detail = row.nextElementSibling;
      if (detail && detail.classList.contains('detail-row')) {{
        if (!sevOk || !txtOk) detail.classList.add('hidden');
      }}
    }});
  }}

  function toggleDetail(btn) {{
    const row = btn.closest('tr');
    const detailRow = row.nextElementSibling;
    if (detailRow && detailRow.classList.contains('detail-row')) {{
      const isHidden = detailRow.classList.toggle('hidden');
      btn.textContent = isHidden ? 'Details' : 'Hide';
    }}
  }}
</script>
</body>
</html>"""

    def _upload_to_s3(self, local_path: Path, s3_key: str):
        try:
            import boto3
            s3 = boto3.client("s3")
            s3.upload_file(
                str(local_path),
                self.s3_bucket,
                f"reports/{s3_key}",
                ExtraArgs={"ContentType": "text/html"},
            )
            logger.info("HTML report uploaded to s3://%s/reports/%s", self.s3_bucket, s3_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to upload HTML report to S3: %s", exc)
