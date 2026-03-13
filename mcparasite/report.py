"""
MCParasite HTML Report Generator - Comparative benchmark visualization.

Generates a self-contained HTML report with:
  - Model susceptibility comparison table
  - Kill chain success rate chart (SVG)
  - Per-scenario breakdown
  - Detailed run logs
  - Stealth encoding effectiveness analysis
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def generate_html_report(results: dict, output_path: str) -> str:
    """Generate a self-contained HTML report from benchmark results.

    Args:
        results: Benchmark results dict (from benchmark.py)
        output_path: Path to write the HTML file

    Returns:
        Path to the generated HTML file
    """
    summaries = results.get("summaries", [])
    all_runs = results.get("all_runs", [])
    config = results.get("config", {})
    timestamp = results.get("timestamp", datetime.now().isoformat())

    # Sort by success rate descending
    summaries = sorted(summaries, key=lambda x: -x.get("success_rate", 0))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCParasite Benchmark Report</title>
<style>
:root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --accent: #f85149;
    --green: #3fb950;
    --yellow: #d29922;
    --blue: #58a6ff;
    --purple: #bc8cff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    line-height: 1.6;
    padding: 2rem;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{
    font-size: 2rem;
    margin-bottom: 0.5rem;
    color: var(--accent);
}}
h2 {{
    font-size: 1.4rem;
    margin: 2rem 0 1rem;
    color: var(--blue);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
}}
h3 {{
    font-size: 1.1rem;
    color: var(--purple);
    margin: 1rem 0 0.5rem;
}}
.meta {{
    color: var(--text-dim);
    margin-bottom: 2rem;
    font-size: 0.9rem;
}}
.meta span {{
    margin-right: 2rem;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    background: var(--surface);
    border-radius: 6px;
    overflow: hidden;
}}
th, td {{
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
}}
th {{
    background: rgba(255,255,255,0.05);
    font-weight: 600;
    color: var(--text);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
td {{ font-size: 0.95rem; }}
tr:hover {{ background: rgba(255,255,255,0.03); }}
.rate-bar {{
    display: inline-block;
    height: 8px;
    border-radius: 4px;
    margin-right: 8px;
    vertical-align: middle;
}}
.infected {{ color: var(--accent); font-weight: bold; }}
.safe {{ color: var(--green); font-weight: bold; }}
.chart-container {{
    background: var(--surface);
    border-radius: 6px;
    padding: 1.5rem;
    margin: 1rem 0;
}}
.bar {{
    display: flex;
    align-items: center;
    margin: 0.5rem 0;
}}
.bar-label {{
    width: 200px;
    font-size: 0.9rem;
    flex-shrink: 0;
}}
.bar-track {{
    flex: 1;
    height: 24px;
    background: rgba(255,255,255,0.05);
    border-radius: 4px;
    overflow: hidden;
    position: relative;
}}
.bar-fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
    display: flex;
    align-items: center;
    padding: 0 8px;
    font-size: 0.8rem;
    font-weight: bold;
    color: #fff;
}}
.bar-value {{
    width: 60px;
    text-align: right;
    font-size: 0.9rem;
    font-weight: bold;
    flex-shrink: 0;
    margin-left: 8px;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1.5rem;
    margin: 1rem 0;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
}}
.stat-value {{
    font-size: 2rem;
    font-weight: bold;
    color: var(--accent);
}}
.stat-label {{
    color: var(--text-dim);
    font-size: 0.85rem;
}}
.run-log {{
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1rem;
    max-height: 300px;
    overflow-y: auto;
    margin: 0.5rem 0;
}}
.footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: 0.8rem;
    text-align: center;
}}
</style>
</head>
<body>
<div class="container">
<h1>MCParasite Benchmark Report</h1>
<div class="meta">
    <span>Generated: {timestamp[:19]}</span>
    <span>Channel: {config.get('channel', 'N/A')}</span>
    <span>Stealth: {config.get('stealth', 'off')}</span>
    <span>Scenarios: {', '.join(config.get('scenarios', []))}</span>
    <span>Runs/model: {config.get('runs_per_model', 'N/A')}</span>
</div>

<!-- Summary Stats -->
<div class="grid">
    <div class="card">
        <div class="stat-value">{len(summaries)}</div>
        <div class="stat-label">Models Tested</div>
    </div>
    <div class="card">
        <div class="stat-value">{len(all_runs)}</div>
        <div class="stat-label">Total Runs</div>
    </div>
    <div class="card">
        <div class="stat-value">{sum(1 for r in all_runs if r.get('kill_chain_complete'))}</div>
        <div class="stat-label">Successful Infections</div>
    </div>
    <div class="card">
        <div class="stat-value">{_overall_rate(all_runs):.0f}%</div>
        <div class="stat-label">Overall Infection Rate</div>
    </div>
</div>

<h2>Model Susceptibility Comparison</h2>
{_render_comparison_chart(summaries)}

<h2>Detailed Results</h2>
{_render_results_table(summaries)}

<h2>Per-Run Breakdown</h2>
{_render_run_table(all_runs)}

<div class="footer">
    MCParasite - MCP Context Worm Security Testing Framework<br>
    For authorized security research only.
</div>
</div>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
    return output_path


def _overall_rate(runs: list[dict]) -> float:
    if not runs:
        return 0.0
    return sum(1 for r in runs if r.get("kill_chain_complete")) / len(runs) * 100


def _rate_color(rate: float) -> str:
    if rate >= 80:
        return "var(--accent)"
    elif rate >= 50:
        return "var(--yellow)"
    elif rate >= 20:
        return "#f0883e"
    return "var(--green)"


def _render_comparison_chart(summaries: list[dict]) -> str:
    if not summaries:
        return "<p>No data available.</p>"

    bars = []
    for s in summaries:
        name = f"{s['provider']}/{s['model']}"
        rate = s.get("success_rate", 0)
        color = _rate_color(rate)
        bars.append(f"""
        <div class="bar">
            <div class="bar-label">{name}</div>
            <div class="bar-track">
                <div class="bar-fill" style="width: {rate}%; background: {color};">
                    {rate:.0f}%
                </div>
            </div>
            <div class="bar-value" style="color: {color};">{rate:.0f}%</div>
        </div>""")

    return f'<div class="chart-container">{"".join(bars)}</div>'


def _render_results_table(summaries: list[dict]) -> str:
    if not summaries:
        return "<p>No data.</p>"

    rows = []
    for s in summaries:
        name = f"{s['provider']}/{s['model']}"
        rate = s.get("success_rate", 0)
        rate_class = "infected" if rate > 0 else "safe"
        color = _rate_color(rate)
        rows.append(f"""
        <tr>
            <td>{name}</td>
            <td><span class="rate-bar" style="width: {rate}px; background: {color};"></span>
                <span class="{rate_class}">{rate:.0f}%</span></td>
            <td>{s.get('total_runs', 0)}</td>
            <td>{s.get('success_count', 0)}</td>
            <td>{s.get('avg_autonomous_actions', 0):.1f}</td>
            <td>{s.get('avg_rce_count', 0):.1f}</td>
            <td>{s.get('avg_total_indicators', 0):.1f}</td>
            <td>{s.get('avg_duration', 0):.1f}s</td>
        </tr>""")

    return f"""
    <table>
        <thead>
            <tr>
                <th>Model</th>
                <th>Infection Rate</th>
                <th>Total Runs</th>
                <th>Infections</th>
                <th>Avg Actions</th>
                <th>Avg RCE</th>
                <th>Avg Indicators</th>
                <th>Avg Time</th>
            </tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_run_table(runs: list[dict]) -> str:
    if not runs:
        return "<p>No runs.</p>"

    rows = []
    for i, r in enumerate(runs):
        status = "INFECTED" if r.get("kill_chain_complete") else "SAFE"
        cls = "infected" if r.get("kill_chain_complete") else "safe"
        name = f"{r.get('provider', '?')}/{r.get('model', '?')}"
        rows.append(f"""
        <tr>
            <td>{i+1}</td>
            <td>{name}</td>
            <td>{r.get('scenario', '?')}</td>
            <td class="{cls}">{status}</td>
            <td>{r.get('autonomous_actions', r.get('hop2', {}).get('autonomous_actions', 0))}</td>
            <td>{r.get('rce_count', r.get('hop2', {}).get('rce_count', 0))}</td>
            <td>{r.get('duration_seconds', 0):.1f}s</td>
        </tr>""")

    return f"""
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Model</th>
                <th>Scenario</th>
                <th>Result</th>
                <th>Actions</th>
                <th>RCE</th>
                <th>Duration</th>
            </tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python report.py <benchmark_results.json> [output.html]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "report.html"

    with open(input_path) as f:
        results = json.load(f)

    generate_html_report(results, output_path)
    print(f"Report: {output_path}")
