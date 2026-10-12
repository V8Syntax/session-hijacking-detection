import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from approaches.rule_based import RuleBasedDetector
from approaches.behavioral import BehavioralDetector

# Step 2: Page configuration & custom dark theme styling
st.set_page_config(
    page_title="Session Guard | Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
/* Main application background */
.stApp {
    background-color: #0B1120;
    color: #F1F5F9;
}
/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #080D18;
    border-right: 1px solid #1F2937;
}
/* Headings */
h1, h2, h3 {
    color: #F8FAFC !important;
    letter-spacing: -0.5px;
}
/* Metric cards */
[data-testid="stMetric"] {
    background: #111C2E;
    border: 1px solid #263449;
    padding: 20px;
    border-radius: 12px;
}
/* Metric labels */
[data-testid="stMetricLabel"] {
    color: #94A3B8 !important;
}
/* Metric values */
[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
}
/* Buttons */
.stButton > button {
    background-color: #22C55E;
    color: #07130B;
    border: none;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

# Initialize detection engines
@st.cache_resource
def initialize_detectors():
    return RuleBasedDetector(), BehavioralDetector()

rule_engine, ml_engine = initialize_detectors()

# Step 3: Page Header
st.markdown("""
#  Session Guard
### Session Hijacking Detection Platform
Real-time telemetry analysis using rule-based validation and behavioral anomaly detection.
""")
st.divider()

# Sidebar: Testbench Vector Configuration
st.sidebar.markdown("### Telemetry & Vector Simulator")
st.sidebar.caption("Simulate traffic vectors across distinct threat scenarios.")

scenario_options = {
    "Baseline: Authentic User Session": {
        "ip": "192.168.1.45",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
        "delta_t": 3.40,
        "payload": 350,
        "endpoint": "/dashboard",
        "desc": "Conforms to authentic network subnet and human request cadence."
    },
    "Threat Model A: Subnet Drift (Foreign IP)": {
        "ip": "203.0.113.88",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
        "delta_t": 3.20,
        "payload": 360,
        "endpoint": "/dashboard",
        "desc": "Token exfiltrated and replayed from an unauthorized external IP."
    },
    "Threat Model B: Client Header Alteration": {
        "ip": "192.168.1.45",
        "ua": "python-requests/2.31.0 (Automated Client)",
        "delta_t": 2.90,
        "payload": 320,
        "endpoint": "/dashboard",
        "desc": "Client User-Agent header altered via script or automated CLI tool."
    },
    "Threat Model C: Same-Subnet Automated Scraping": {
        "ip": "192.168.1.45",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
        "delta_t": 0.08,
        "payload": 1250,
        "endpoint": "/profile",
        "desc": "Token replayed behind the same NAT gateway using high-speed bot loops."
    },
    "Threat Model D: Unauthorized Endpoint Traversal": {
        "ip": "192.168.1.45",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
        "delta_t": 1.10,
        "payload": 480,
        "endpoint": "/admin/export-database",
        "desc": "Privilege escalation attempt targeting an unmapped administrative route."
    }
}

selected_scenario = st.sidebar.selectbox("Select Traffic Vector", list(scenario_options.keys()))
active_params = scenario_options[selected_scenario]
st.sidebar.info(active_params["desc"])

with st.sidebar.expander("Vector Parameters", expanded=False):
    input_ip = st.text_input("Source IP Address", value=active_params["ip"])
    input_ua = st.text_input("User-Agent Header", value=active_params["ua"])
    input_delta = st.slider("Inter-Arrival Time (Δt in seconds)", 0.01, 8.00, float(active_params["delta_t"]), 0.05)
    input_payload = st.slider("Payload Dimension (Bytes)", 50, 2000, int(active_params["payload"]), 50)
    input_endpoint = st.text_input("Target URI Endpoint", value=active_params["endpoint"])

# Step 4: Organize the telemetry metrics
st.markdown("#### Input Telemetry Vector")
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Source IP", input_ip)
with col2:
    st.metric("Request Interval", f"{input_delta:.2f} s")
with col3:
    st.metric("Payload Size", f"{input_payload} B")
with col4:
    st.metric("Requested URI", input_endpoint)

st.write("")

# Run detection engines once
rule_eval = rule_engine.evaluate(input_ip, input_ua, input_endpoint)
ml_eval = ml_engine.evaluate(input_delta, input_payload)

# Step 5: Make the two detection engines look like cards
left, right = st.columns(2, gap="large")

with left:
    with st.container(border=True):
        st.subheader(" Rule-Based Engine")
        st.caption("Policy validation")
        st.write(f"Execution Latency: `{rule_eval['latency_ms']:.4f} ms`")

        # Step 6: Use consistent status colors
        if rule_eval["is_hijacked"]:
            st.error("BLOCKED — High-risk session detected")
            for violation in rule_eval["violations"]:
                st.write(f"-  {violation}")
        else:
            st.success("PASS — Session matches the baseline")
            st.write("- ✔️ IP conforms to authorized subnet boundary")
            st.write("- ✔️ User-Agent signature matches authentication state")
            st.write("- ✔️ Requested route is explicitly authorized")

        st.markdown(f"**Policy Action:** `{rule_eval['action']}`")
        st.caption("Complexity: O(1) constant time boundary lookup")

with right:
    with st.container(border=True):
        st.subheader(" Behavioral Anomaly Engine")
        st.caption("Behavioral profiling")
        st.write(f"Execution Latency: `{ml_eval['latency_ms']:.4f} ms`")

        risk_score = float(ml_eval["risk_score_pct"])

        # Step 6: Use consistent status colors
        if ml_eval["is_anomaly"] or risk_score >= 65.0:
            st.error("BLOCKED — High-risk session detected")
            for ind in ml_eval["indicators"]:
                st.write(f"-  {ind}")
        elif risk_score >= 45.0:
            st.warning("WARNING — Suspicious behavior detected")
            st.write("-  Moderate deviation from expected interaction profile")
        else:
            st.success("PASS — Session matches the baseline")
            st.write("- ✔️ Cadence matches human user browsing")
            st.write("- ✔️ Payload volume remains within expected bounds")

        st.markdown(f"**Adaptive Action:** `{ml_eval['action']}`")

        # Step 7: Add a risk-score indicator
        st.write("")
        st.subheader("Session Risk Assessment")
        st.progress(max(0.0, min(1.0, risk_score / 100.0)))
        st.caption(f"Calculated session risk: {risk_score:.2f}%")

st.divider()

# Behavioral Feature Space Distribution Plot
st.markdown("#### Behavioral Feature Space Distribution")
st.caption("Current request vector plotted against legitimate baseline traffic (μ_Δt = 3.5s, μ_payload = 350B).")

np.random.seed(42)
baseline_dt = np.random.normal(loc=3.5, scale=0.7, size=200)
baseline_ps = np.random.normal(loc=350, scale=40, size=200)

fig = go.Figure()

fig.add_trace(go.Scatter(
    x=baseline_dt,
    y=baseline_ps,
    mode='markers',
    name='Baseline Traffic (Normal)',
    marker=dict(color='#475569', size=6, opacity=0.6)
))

fig.add_trace(go.Scatter(
    x=[input_delta],
    y=[input_payload],
    mode='markers+text',
    name='Current Request',
    text=["Current Packet"],
    textposition="top right",
    marker=dict(
        color='#EF4444' if ml_eval['is_anomaly'] else '#22C55E',
        size=14,
        symbol='diamond',
        line=dict(width=2, color='#F8FAFC')
    )
))

fig.update_layout(
    height=340,
    margin=dict(l=20, r=20, t=20, b=20),
    xaxis_title="Inter-Arrival Time (Δt in seconds)",
    yaxis_title="Payload Dimension (Bytes)",
    paper_bgcolor="#111827",
    plot_bgcolor="#0B1120",
    font=dict(color="#F1F5F9"),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
)

st.plotly_chart(fig, use_container_width=True)

# Empirical Parameter Comparison Table
st.markdown("#### Empirical Parameter Comparison")
comparison_matrix = {
    "Evaluation Parameter": [
        "Detection Model",
        "Execution Overhead (Latency)",
        "Resistance to Same-NAT Spoofing",
        "Resilience to Dynamic IP Shifts",
        "Initialization Requirement",
        "Enforcement Granularity"
    ],
    "Approach 1: Deterministic Rules": [
        "Stateful static boundary checks",
        f"{rule_eval['latency_ms']:.4f} ms",
        "Vulnerable (Bypassed if IP/UA matches)",
        "Low (Flags benign Wi-Fi/4G roaming)",
        "Zero (Pre-configured thresholds)",
        "Binary session termination"
    ],
    "Approach 2: Behavioral Anomaly Detection": [
        "Unsupervised Isolation Forest",
        f"{ml_eval['latency_ms']:.4f} ms",
        "Resilient (Detects non-human request rate)",
        "High (Decoupled from network IP)",
        "Requires baseline warm-up profile",
        "Continuous risk score & adaptive MFA"
    ]
}

st.table(pd.DataFrame(comparison_matrix))