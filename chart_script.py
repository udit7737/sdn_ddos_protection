import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

# Define the data
components_data = {
    "layer": ["Dashboard", "Controller", "Controller", "ML", "Controller", "ML", "Network", "Network", "Simulation", "Simulation"],
    "name": ["Web Dashboard", "Ryu SDN Controller", "Statistics Collector", "DDoS Detection Engine", "Flow Manager", "Feature Extractor", "OpenFlow Switches", "Network Hosts", "Attack Simulator", "Traffic Generator"],
    "short_name": ["Web Dashboard", "Ryu Controller", "Stats Collector", "DDoS Engine", "Flow Manager", "Feature Extract", "OF Switches", "Network Hosts", "Attack Sim", "Traffic Gen"],
    "technologies": ["Flask, HTML/CSS/JS, WebSocket, D3.js", "OpenFlow, Python", "OpenFlow Stats", "SVM, Random Forest, K-Means, Isolation Forest", "OpenFlow Rules", "Traffic Analysis", "Open vSwitch", "Clients, Servers", "hping3, nmap", "iperf, curl"],
    "x": [400, 400, 200, 400, 600, 200, 400, 300, 500, 100],
    "y": [50, 150, 200, 250, 200, 300, 400, 500, 500, 500]
}

connections_data = [
    ("Web Dashboard", "Ryu SDN Controller"),
    ("Ryu SDN Controller", "Statistics Collector"),
    ("Ryu SDN Controller", "DDoS Detection Engine"),
    ("Ryu SDN Controller", "Flow Manager"),
    ("Statistics Collector", "Feature Extractor"),
    ("Feature Extractor", "DDoS Detection Engine"),
    ("DDoS Detection Engine", "Flow Manager"),
    ("Flow Manager", "OpenFlow Switches"),
    ("Statistics Collector", "OpenFlow Switches"),
    ("OpenFlow Switches", "Network Hosts"),
    ("OpenFlow Switches", "Attack Simulator"),
    ("OpenFlow Switches", "Traffic Generator")
]

# Create DataFrame
df = pd.DataFrame(components_data)

# Define colors for each layer
layer_colors = {
    "Dashboard": "#1FB8CD",
    "Controller": "#DB4545", 
    "ML": "#2E8B57",
    "Network": "#5D878F",
    "Simulation": "#D2BA4C"
}

# Create the figure
fig = go.Figure()

# Add connection lines first (so they appear behind nodes)
for connection in connections_data:
    from_comp = df[df['name'] == connection[0]].iloc[0]
    to_comp = df[df['name'] == connection[1]].iloc[0]
    
    fig.add_trace(go.Scatter(
        x=[from_comp['x'], to_comp['x']],
        y=[from_comp['y'], to_comp['y']],
        mode='lines',
        line=dict(color='rgba(128,128,128,0.5)', width=2),
        showlegend=False,
        hoverinfo='skip'
    ))
    
    # Add arrow markers
    mid_x = (from_comp['x'] + to_comp['x']) / 2
    mid_y = (from_comp['y'] + to_comp['y']) / 2
    
    fig.add_trace(go.Scatter(
        x=[mid_x],
        y=[mid_y], 
        mode='markers',
        marker=dict(
            symbol='triangle-up',
            size=8,
            color='rgba(128,128,128,0.7)',
            angle=np.arctan2(to_comp['y']-from_comp['y'], to_comp['x']-from_comp['x']) * 180/np.pi
        ),
        showlegend=False,
        hoverinfo='skip'
    ))

# Add nodes for each layer
for layer in layer_colors.keys():
    layer_data = df[df['layer'] == layer]
    
    fig.add_trace(go.Scatter(
        x=layer_data['x'],
        y=layer_data['y'],
        mode='markers+text',
        marker=dict(
            size=50,
            color=layer_colors[layer],
            line=dict(color='white', width=2)
        ),
        text=layer_data['short_name'],
        textposition='middle center',
        textfont=dict(size=10, color='white'),
        name=layer,
        hovertemplate='<b>%{text}</b><br>Tech: %{customdata}<extra></extra>',
        customdata=layer_data['technologies'],
        cliponaxis=False
    ))

# Update layout
fig.update_layout(
    title="SDN DDoS Protection System Architecture",
    xaxis=dict(
        showgrid=False,
        showticklabels=False,
        zeroline=False,
        range=[0, 700]
    ),
    yaxis=dict(
        showgrid=False, 
        showticklabels=False,
        zeroline=False,
        range=[0, 550],
        autorange='reversed'
    ),
    plot_bgcolor='white',
    legend=dict(
        orientation='h',
        yanchor='bottom',
        y=1.05,
        xanchor='center', 
        x=0.5
    )
)

# Save the chart
fig.write_image("sdn_ddos_architecture.png")