"""
Generates a HTML report, don't ask me about this code i don't know shit about HTML or CSS, i just copy pasted some stuff and it works so whatever
"""

import html as _html
import math

_SEVERITY_HEX = {'critical': '#e74c3c', 'warning': '#f1c40f', 'info': '#3498db', 'safe': '#2ecc71'}


def _entropy_bar_chart(sections, width=640, height=220, bar_gap=10):
    if not sections:
        return "<p>No sections found.</p>"
    names = list(sections.keys())
    n = len(names)
    bar_w = max(20, (width - bar_gap * (n + 1)) // n)
    chart_h = height - 40
    bars = []
    for i, name in enumerate(names):
        entropy = sections[name]
        h = int((entropy / 8.0) * chart_h)
        x = bar_gap + i * (bar_w + bar_gap)
        y = chart_h - h + 20
        color = _SEVERITY_HEX['critical'] if entropy > 7.2 else (
            _SEVERITY_HEX['warning'] if entropy > 6.5 else _SEVERITY_HEX['safe'])
        bars.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="{color}">'
            f'<title>{_html.escape(name)}: {entropy:.2f}/8.00 bits</title></rect>'
            f'<text x="{x + bar_w/2}" y="{chart_h + 34}" font-size="10" text-anchor="middle" '
            f'transform="rotate(45 {x + bar_w/2} {chart_h + 34})">{_html.escape(name)}</text>'
            f'<text x="{x + bar_w/2}" y="{y - 4}" font-size="9" text-anchor="middle">{entropy:.1f}</text>'
        )
    return (f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
            f'style="width:100%;max-width:{width}px;height:auto;">{"".join(bars)}</svg>')


def _category_pie_chart(imports, size=260):
    if not imports:
        return "<p>No categorized imports found.</p>"
    total = sum(len(v) for v in imports.values())
    if total == 0:
        return "<p>No categorized imports found.</p>"
    cx = cy = size / 2
    r = size / 2 - 10
    start_angle = -90.0
    palette = ['#e74c3c', '#f1c40f', '#3498db', '#2ecc71', '#9b59b6', '#e67e22',
               '#1abc9c', '#34495e', '#f39c12', '#95a5a6', '#c0392b', '#16a085']
    slices = []
    legend = []
    for i, (cat, apis) in enumerate(sorted(imports.items(), key=lambda kv: -len(kv[1]))):
        frac = len(apis) / total
        angle = frac * 360.0
        end_angle = start_angle + angle
        x1 = cx + r * math.cos(math.radians(start_angle))
        y1 = cy + r * math.sin(math.radians(start_angle))
        x2 = cx + r * math.cos(math.radians(end_angle))
        y2 = cy + r * math.sin(math.radians(end_angle))
        large_arc = 1 if angle > 180 else 0
        color = palette[i % len(palette)]
        slices.append(
            f'<path d="M{cx},{cy} L{x1:.2f},{y1:.2f} A{r},{r} 0 {large_arc} 1 {x2:.2f},{y2:.2f} Z" '
            f'fill="{color}"><title>{_html.escape(cat)}: {len(apis)}</title></path>'
        )
        legend.append(
            f'<div style="display:flex;align-items:center;gap:6px;margin:2px 0;">'
            f'<span style="width:12px;height:12px;background:{color};display:inline-block;border-radius:2px;"></span>'
            f'<span>{_html.escape(cat)} ({len(apis)})</span></div>'
        )
        start_angle = end_angle
    svg = (f'<svg viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg" '
           f'style="width:100%;max-width:{size}px;height:auto;">{"".join(slices)}</svg>')
    return f'<div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;">{svg}<div>{"".join(legend)}</div></div>'


def _finding_rows(items, text_key='text', sev_key='severity'):
    rows = []
    for it in items:
        sev = it.get(sev_key, 'info')
        color = _SEVERITY_HEX.get(sev, _SEVERITY_HEX['info'])
        rows.append(f'<li style="border-left:4px solid {color};padding:6px 10px;margin:6px 0;'
                    f'background:#1e1e1e;">{_html.escape(it.get(text_key, ""))}</li>')
    return ''.join(rows) or '<li>None.</li>'


def generate_html_report(output_path, *, file_path, executive_summary, difficulty_result,
                          correlated_findings, sections, imports, protectors, behavior,
                          section_anomalies):
    stage_colors = ['#2ecc71', '#2ecc71', '#f1c40f', '#e67e22', '#e74c3c']
    stage_color = stage_colors[difficulty_result['stage']]

    breakdown_rows = []
    for b in sorted(difficulty_result['breakdown'], key=lambda d: -d['value']):
        color = _SEVERITY_HEX.get(b['severity'], _SEVERITY_HEX['info'])
        breakdown_rows.append(
            f'<tr><td style="color:{color};font-weight:bold;">{b["severity"].upper()}</td>'
            f'<td>{_html.escape(b["reason"])}</td><td>+{b["value"]:.2f}</td></tr>'
        )

    protector_rows = []
    for name, info in protectors.items():
        color = {'HIGH': _SEVERITY_HEX['critical'], 'MEDIUM': _SEVERITY_HEX['warning'],
                  'LOW': _SEVERITY_HEX['info']}[info['confidence']]
        ev = '; '.join(info['evidence'][:3])
        protector_rows.append(
            f'<tr><td style="color:{color};font-weight:bold;">{info["confidence"]}</td>'
            f'<td>{_html.escape(name)}</td><td>{_html.escape(ev)}</td></tr>'
        )

    behavior_rows = []
    for name, info in behavior.items():
        attck = info.get('attck') or '-'
        behavior_rows.append(
            f'<tr><td>{_html.escape(name)}</td><td>{_html.escape(attck)}</td>'
            f'<td>{_html.escape(", ".join(info["evidence"][:4]))}</td></tr>'
        )

    anomaly_items = [{'text': f"{a['section']}: {a['issue']}", 'severity': a['severity']} for a in section_anomalies]

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SysTorch Report -- {_html.escape(file_path)}</title>
<style>
  body {{ background:#121212; color:#e0e0e0; font-family: 'Segoe UI', Consolas, monospace; margin:0; padding:24px; }}
  h1, h2 {{ color:#7CFC00; }}
  .card {{ background:#1a1a1a; border:1px solid #333; border-radius:8px; padding:16px; margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; }}
  td, th {{ text-align:left; padding:6px 8px; border-bottom:1px solid #333; font-size:14px; }}
  .verdict {{ font-size:28px; font-weight:bold; color:{stage_color}; }}
  .score-bar-bg {{ background:#333; border-radius:6px; height:18px; width:100%; overflow:hidden; }}
  .score-bar-fill {{ background:{stage_color}; height:100%; width:{difficulty_result['score']*10}%; }}
  ul {{ list-style:none; padding:0; }}
  code {{ color:#7CFC00; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(260px,1fr)); gap:16px; }}
</style>
</head>
<body>
  <h1>SysTorch Analysis Report</h1>
  <p><code>{_html.escape(file_path)}</code></p>

  <div class="card">
    <h2>Executive Summary</h2>
    <div class="grid">
      <div>
        <p><b>SHA-256:</b><br><code style="font-size:11px;">{executive_summary['sha256']}</code></p>
        <p><b>MD5:</b> <code>{executive_summary['md5']}</code></p>
        <p><b>Imphash:</b> <code>{executive_summary['imphash'] or 'n/a'}</code></p>
        <p><b>Rich Hash:</b> <code>{executive_summary['rich_hash'] or 'n/a'}</code></p>
        <p><b>Average section entropy:</b> {executive_summary['avg_entropy']:.2f} / 8.00</p>
      </div>
      <div>
        <p><b>Verdict:</b></p>
        <div class="verdict">{difficulty_result['label']}</div>
        <div class="score-bar-bg"><div class="score-bar-fill"></div></div>
        <p>{difficulty_result['score']:.1f} / 10.0</p>
        <p><b>Top threat signals:</b></p>
        <ul>{''.join(f'<li>- {_html.escape(t)}</li>' for t in executive_summary['top_threats'])}</ul>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Section Entropy</h2>
    {_entropy_bar_chart(sections)}
  </div>

  <div class="card">
    <h2>Import Categories</h2>
    {_category_pie_chart(imports)}
  </div>

  <div class="card">
    <h2>Difficulty Breakdown</h2>
    <table><tr><th>Severity</th><th>Reason</th><th>Contribution</th></tr>{''.join(breakdown_rows)}</table>
  </div>

  <div class="card">
    <h2>Known Packer / Protector Signatures</h2>
    <table><tr><th>Confidence</th><th>Name</th><th>Evidence</th></tr>{''.join(protector_rows) or '<tr><td colspan="3">None matched.</td></tr>'}</table>
  </div>

  <div class="card">
    <h2>Behavior Patterns (MITRE ATT&amp;CK)</h2>
    <table><tr><th>Pattern</th><th>ATT&amp;CK</th><th>Evidence</th></tr>{''.join(behavior_rows) or '<tr><td colspan="3">None matched.</td></tr>'}</table>
  </div>

  <div class="card">
    <h2>Section Anomalies</h2>
    <ul>{_finding_rows(anomaly_items)}</ul>
  </div>

  <div class="card">
    <h2>Correlated Findings</h2>
    <ul>{_finding_rows(correlated_findings)}</ul>
  </div>

  <p style="color:#666;font-size:12px;">Generated by SysTorch -- crafted by Os_Ring0. Triage signal, not a verdict -- sanity-check against the individual sections.</p>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_doc)
    return output_path
