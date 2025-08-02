import os
import logging
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pyvis.network import Network

# --- Constants & Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "../static")
MITRE_BASE_URL = "https://attack.mitre.org/techniques"
os.makedirs(STATIC_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO)

TTP_TACTIC_MAP = {
    'T1059.003': 'Execution', 'T1059.001': 'Execution', 'T1059.005': 'Execution',
    'T1071.001': 'Command and Control', 'T1071.004': 'Command and Control',
    'T1566.001': 'Initial Access', 'T1190': 'Initial Access',
    'T1053.005': 'Persistence', 'T1543.003': 'Persistence', 'T1547.001': 'Persistence',
    'T1027': 'Defense Evasion', 'T1036.005': 'Defense Evasion',
    'T1003.001': 'Credential Access', 'T1056.001': 'Credential Access',
    'T1083': 'Discovery', 'T1082': 'Discovery', 'T1057': 'Discovery',
    'T1021.001': 'Lateral Movement',
    'T1041': 'Exfiltration',
    'T1587.001': 'Resource Development', 'T1588.002': 'Resource Development',
}

__all__ = [
    "generate_timeline_viz",
    "generate_heatmap_viz",
    "generate_malware_ttp_graph_viz",
    "generate_mitre_matrix_viz"
]

def get_tactic(ttp_id):
    return TTP_TACTIC_MAP.get(ttp_id, "Other")

def generate_timeline_viz(timeline_df):
    output_path = os.path.join(STATIC_DIR, "timeline.html")
    if timeline_df.empty or 'TTPs' not in timeline_df.columns:
        _write_placeholder(output_path, "No timeline data available.")
        return
    df = timeline_df.explode('TTPs').dropna(subset=['TTPs', 'timestamp'])
    if df.empty:
        _write_placeholder(output_path, "No timeline data available to plot.")
        return
    df['date_only'] = df['timestamp'].dt.date
    plot_df = df.groupby('date_only').head(3).reset_index(drop=True)
    plot_df['tactic'] = plot_df['TTPs'].apply(get_tactic)
    x_vals = np.linspace(0, 2 * np.pi * max(3, len(plot_df) // 8), len(plot_df))
    y_vals = np.sin(x_vals)
    text_shift = np.where(y_vals > 0, -40, 40)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=np.linspace(0, x_vals[-1], 500), y=np.sin(np.linspace(0, x_vals[-1], 500)),
                             mode='lines', line=dict(color='lightgreen', width=2)))
    for i, row in plot_df.iterrows():
        fig.add_trace(go.Scatter(
            x=[x_vals[i]], y=[y_vals[i]], mode='markers',
            marker=dict(color='white', size=8, line=dict(color='lightgreen', width=1)),
            hovertext=f"<b>{row['tactic']}: {row['TTPs']}</b><br>{row['date_only']}<br>Context: {row['context'][:150]}...",
            hoverinfo='text'
        ))
        fig.add_annotation(
            x=x_vals[i], y=y_vals[i], text=row['TTPs'], showarrow=False,
            yshift=text_shift[i] / 2, font=dict(color="white", size=10),
            bgcolor="rgba(0,0,0,0.6)", borderpad=2
        )
    fig.update_layout(
        template='plotly_dark',
        title="TTP Event Timeline", showlegend=False,
        paper_bgcolor="black", plot_bgcolor="black",
        font=dict(color="white"), xaxis=dict(visible=False),
        yaxis=dict(visible=False), height=600
    )
    fig.write_html(output_path, full_html=True, include_plotlyjs='cdn')
    logging.info(f"[Timeline] ✅ Saved to {output_path}")

def generate_heatmap_viz(ttps_data):
    output_path = os.path.join(STATIC_DIR, "heatmap.html")
    if not ttps_data:
        _write_placeholder(output_path, "No TTP data for heatmap.")
        return
    df = pd.DataFrame(ttps_data)
    df['tactic'] = df['id'].apply(get_tactic)
    counts = df.groupby(['id', 'tactic']).size().reset_index(name='count')
    fig = px.treemap(
        counts, path=[px.Constant("All TTPs"), 'tactic', 'id'],
        values='count',
        color_discrete_sequence=px.colors.sequential.Magma_r,
        title='TTP Frequency Heatmap (by Tactic)'
    )
    fig.update_layout(margin=dict(t=50, l=25, r=25, b=25))
    fig.write_html(output_path, full_html=True, include_plotlyjs='cdn')
    logging.info(f"[Heatmap] ✅ Saved to {output_path}")

def generate_malware_ttp_graph_viz(malware_data):
    output_path = os.path.join(STATIC_DIR, "malware_ttp_graph.html")
    if not malware_data:
        _write_placeholder(output_path, "No malware data available for visualization.")
        return
    net = Network(height="800px", width="100%", bgcolor="#111", font_color="white", cdn_resources="in_line")
    malware_nodes = set()
    ttp_nodes = set()
    for entry in malware_data:
        name = entry.get('name')
        if name and name not in malware_nodes:
            net.add_node(name, label=name, color='#ff4c4c', shape='dot', size=30, title=f"Malware: {name}")
            malware_nodes.add(name)
        for ttp in entry.get('ttps', []):
            ttp_id = ttp.split("–")[0].strip()
            if ttp_id and ttp_id not in ttp_nodes:
                net.add_node(ttp_id, label=ttp, color='#1e90ff', shape='box', size=20,
                             title=f"<a href='{MITRE_BASE_URL}/{ttp_id}/' target='_blank'>View on MITRE</a>")
                ttp_nodes.add(ttp_id)
            if name and ttp_id:
                net.add_edge(name, ttp_id)
    net.set_options("""{
      "nodes": { "font": { "size": 16, "color": "#ffffff" } },
      "edges": { "color": { "inherit": "from" }, "smooth": true },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -4000,
          "centralGravity": 0.3,
          "springLength": 150,
          "springConstant": 0.04,
          "damping": 0.09
        },
        "minVelocity": 0.75
      }
    }""")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(net.generate_html())
    logging.info(f"[Malware-TTP Graph] ✅ Saved to {output_path}")

def generate_mitre_matrix_viz(ttps_data):
    output_path = os.path.join(STATIC_DIR, "matrix.html")
    categories = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
    matrix = {cat: [] for cat in categories}
    for ttp in ttps_data:
        ttp_id = ttp['id']
        tactic = get_tactic(ttp_id)
        if tactic in matrix:
            link = f"<a href='{MITRE_BASE_URL}/{ttp_id}/' target='_blank'>{ttp_id}</a>"
            matrix[tactic].append(f"{link}: {ttp['description']}")
    html = """
    <html><head><title>MITRE ATT&CK Matrix</title><style>
    body { background:#1e1e1e; color:#d4d4d4; font-family: sans-serif; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #444; padding: 10px; vertical-align: top; }
    th { background-color: #333; font-size: 14px; }
    td { font-size: 12px; }
    ul { list-style-type: none; padding-left: 0; margin: 0; }
    li { margin-bottom: 8px; }
    a { color: #87ceeb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    </style></head><body><h1>MITRE ATT&CK Matrix</h1><table><tr>
    """
    html += "".join(f"<th>{cat.replace(' ', '<br>')}</th>" for cat in categories)
    html += "</tr><tr>" + "".join(
        "<td>" + "<ul>" + "".join(f"<li>{item}</li>" for item in matrix[cat]) + "</ul></td>"
        for cat in categories
    ) + "</tr></table></body></html>"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"[MITRE Matrix] ✅ Saved to {output_path}")

def _write_placeholder(path, message):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"<html><body><h1>{message}</h1></body></html>")
    logging.warning(f"⚠️ Placeholder written to {path}: {message}")