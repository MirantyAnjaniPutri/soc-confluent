import os
import json
import pandas as pd
import streamlit as st
from confluent_kafka import Consumer
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SIEM Operations Center",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SIEM Operations Center")
st.caption("Real-time security intelligence powered by Confluent Cloud")

# ============================================================
# CONFIG & STATE INITIALIZATION
# ============================================================

TOPICS = {
    "alerts": os.getenv("SIEM_ALERTS_TOPIC"),
    "metrics": os.getenv("SIEM_METRICS_TOPIC"),
    "anomalies": os.getenv("SIEM_ANOMALIES_TOPIC"),
    "incidents": os.getenv("SIEM_INCIDENTS_TOPIC"),
}

# Maximum events kept in memory per topic to avoid RAM overflow
MAX_IN_MEMORY_RECORDS = 1000

# Initialize rolling in-memory buffers
if "stream_data" not in st.session_state:
    st.session_state.stream_data = {
        "alerts": [],
        "metrics": [],
        "anomalies": [],
        "incidents": [],
    }

# ============================================================
# CONFLUENT DECODER & CONSUMER
# ============================================================

def decode_message(raw_bytes):
    """Strips Schema Registry magic byte header if present."""
    if len(raw_bytes) > 5 and raw_bytes[0] == 0:
        raw_bytes = raw_bytes[5:]
    return json.loads(raw_bytes.decode("utf-8"))

@st.cache_resource
def get_kafka_consumer(group_suffix):
    """Creates a persistent Kafka consumer instance across reruns."""
    return Consumer({
        "bootstrap.servers": os.getenv("CONFLUENT_BOOTSTRAP_SERVERS"),
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": "PLAIN",
        "sasl.username": os.getenv("CONFLUENT_API_KEY"),
        "sasl.password": os.getenv("CONFLUENT_API_SECRET"),
        "group.id": f"siem-direct-dashboard-{group_suffix}",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    })

# Initialize consumers per topic
if "consumers" not in st.session_state:
    st.session_state.consumers = {}
    for key, topic in TOPICS.items():
        if topic:
            consumer = get_kafka_consumer(key)
            consumer.subscribe([topic])
            st.session_state.consumers[key] = consumer

# ============================================================
# DIRECT IN-MEMORY POLL ROUTINE
# ============================================================

def poll_direct_from_confluent():
    for key, consumer in st.session_state.consumers.items():
        for _ in range(50):  # Fetch batch per rerun
            msg = consumer.poll(timeout=0.01)
            if msg is None:
                break
            if msg.error():
                continue

            try:
                record = decode_message(msg.value())
                
                # Append directly to Streamlit memory
                st.session_state.stream_data[key].append(record)
                
                # Maintain rolling buffer window
                if len(st.session_state.stream_data[key]) > MAX_IN_MEMORY_RECORDS:
                    st.session_state.stream_data[key].pop(0)
            except Exception as e:
                print(f"Error parsing record on {key}: {e}")

# Poll during execution
poll_direct_from_confluent()

# ============================================================
# SIDEBAR CONTROLS
# ============================================================

st.sidebar.header("⚙️ SIEM Controls")

if st.sidebar.button("🔄 Manual Fetch", use_container_width=True):
    poll_direct_from_confluent()

auto_refresh = st.sidebar.toggle("🔴 Live Streaming Mode", value=True)

if auto_refresh:
    st.sidebar.success("Listening for live Confluent Cloud streams.")
    poll_direct_from_confluent()
else:
    st.sidebar.info("Streaming paused.")

# ============================================================
# BUILD DATAFRAMES FROM MEMORY
# ============================================================

alerts_df = pd.json_normalize(st.session_state.stream_data["alerts"])
metrics_df = pd.json_normalize(st.session_state.stream_data["metrics"])
anomalies_df = pd.json_normalize(st.session_state.stream_data["anomalies"])
incidents_df = pd.json_normalize(st.session_state.stream_data["incidents"])

# Convert Confluent Flink int64 Epoch Milliseconds
if not alerts_df.empty and "event_time" in alerts_df.columns:
    alerts_df["event_time"] = pd.to_datetime(alerts_df["event_time"], unit="ms", errors="coerce")

if not incidents_df.empty and "incident_time" in incidents_df.columns:
    incidents_df["incident_time"] = pd.to_datetime(incidents_df["incident_time"], unit="ms", errors="coerce")


# ============================================================
# CONNECTION & KPI OVERVIEW
# ============================================================

connected_streams = sum(1 for topic in TOPICS.values() if topic)
st.markdown(f"🟢 **Streaming Pipeline Active** — {connected_streams}/4 SIEM topics connected")

total_alerts = len(alerts_df)
total_anomalies = len(anomalies_df)
total_incidents = len(incidents_df)

high_critical = 0
if not alerts_df.empty and "alert_severity" in alerts_df.columns:
    high_critical = alerts_df[
        alerts_df["alert_severity"].fillna("").str.upper().isin(["HIGH", "CRITICAL"])
    ].shape[0]

unique_sources = 0
if not alerts_df.empty and "source_ip" in alerts_df.columns:
    unique_sources = alerts_df["source_ip"].dropna().nunique()

average_risk = 0.0
if not incidents_df.empty and "risk_score" in incidents_df.columns:
    average_risk = round(pd.to_numeric(incidents_df["risk_score"], errors="coerce").mean(), 1)

st.subheader("Security Overview")
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("🚨 Alerts", f"{total_alerts:,}")
c2.metric("🔴 High / Critical", f"{high_critical:,}")
c3.metric("⚠️ Anomalies", f"{total_anomalies:,}")
c4.metric("🛡️ Incidents", f"{total_incidents:,}")
c5.metric("🌐 Sources", f"{unique_sources:,}")
c6.metric("🎯 Avg Risk", f"{average_risk}")

# ============================================================
# ALERT INTELLIGENCE VISUALIZATIONS
# ============================================================

st.subheader("📊 Alert Intelligence")
left, right = st.columns(2)

with left:
    st.markdown("**Alerts by Severity**")
    if not alerts_df.empty and "alert_severity" in alerts_df.columns:
        severity = alerts_df["alert_severity"].fillna("UNKNOWN").str.upper().value_counts()
        st.bar_chart(severity)
    else:
        st.info("Waiting for alert data...")

with right:
    st.markdown("**Top Alert Types**")
    if not alerts_df.empty and "alert_type" in alerts_df.columns:
        alert_types = alerts_df["alert_type"].fillna("UNKNOWN").value_counts().head(10)
        st.bar_chart(alert_types)
    else:
        st.info("Waiting for alert data...")

left_trend, right_sources = st.columns(2)

with left_trend:
    st.markdown("**📈 Real-Time Event Volume Trend**")
    if not alerts_df.empty and "event_time" in alerts_df.columns:
        trend = (
            alerts_df.dropna(subset=["event_time"])
            .set_index("event_time")
            .resample("min")
            .size()
        )
        st.line_chart(trend)
    else:
        st.info("Waiting for event-time timestamps...")

with right_sources:
    st.markdown("**🌐 Top Source IPs**")
    if not alerts_df.empty and "source_ip" in alerts_df.columns:
        sources = alerts_df["source_ip"].fillna("UNKNOWN").value_counts().head(10)
        st.bar_chart(sources)
    else:
        st.info("Waiting for source IP telemetry...")

# ============================================================
# LIVE TABLES
# ============================================================

st.subheader("🔴 Live Security Event Feed")
if not alerts_df.empty:
    cols = ["event_time", "alert_severity", "alert_type", "source_ip", "destination_ip", "hostname", "access_group", "description"]
    avail = [c for c in cols if c in alerts_df.columns]
    st.dataframe(alerts_df[avail].sort_values("event_time", ascending=False).head(20), use_container_width=True, hide_index=True)
else:
    st.info("Waiting for streamed alerts...")

st.subheader("⚠️ Anomaly Intelligence")
if not anomalies_df.empty:
    cols = ["anomaly_id", "window_start", "window_end", "source_ip", "alert_count", "unique_destinations", "high_alerts", "anomaly_score", "anomaly_type", "severity", "explanation"]
    avail = [c for c in cols if c in anomalies_df.columns]
    anom_view = anomalies_df[avail]
    if "anomaly_score" in anom_view.columns:
        anom_view = anom_view.sort_values("anomaly_score", ascending=False)
    st.dataframe(anom_view, use_container_width=True, hide_index=True)
else:
    st.success("No anomalies detected.")

st.subheader("🛡️ Incident Intelligence")
if not incidents_df.empty:
    cols = ["incident_id", "incident_time", "source_ip", "incident_type", "severity", "risk_score", "alert_count", "unique_destinations", "high_alerts", "explanation", "recommended_action"]
    avail = [c for c in cols if c in incidents_df.columns]
    inc_view = incidents_df[avail]
    if "risk_score" in inc_view.columns:
        inc_view = inc_view.sort_values("risk_score", ascending=False)
    st.dataframe(inc_view, use_container_width=True, hide_index=True)
else:
    st.success("No incidents active.")

# ============================================================
# HIGHEST PRIORITY INCIDENT DETAIL
# ============================================================

if not incidents_df.empty:
    st.subheader("🚨 Highest Priority Action Item")
    priority = incidents_df.sort_values("risk_score", ascending=False).iloc[0] if "risk_score" in incidents_df.columns else incidents_df.iloc[0]

    ic1, ic2, ic3 = st.columns(3)
    ic1.metric("Incident ID", str(priority.get("incident_id", "N/A")))
    ic2.metric("Severity", str(priority.get("severity", "N/A")))
    ic3.metric("Risk Score", str(priority.get("risk_score", "N/A")))

    st.markdown("**Incident Type:** " + str(priority.get("incident_type", "N/A")))
    st.markdown("**Explanation:** " + str(priority.get("explanation", "N/A")))
    st.warning("**Recommended Action:** " + str(priority.get("recommended_action", "N/A")))

# # ============================================================
# # TROUBLESHOOTING & RAW DATA INSPECTOR
# # ============================================================

# with st.expander("🔍 Streamlit Debugger (Raw Buffer Inspection)", expanded=True):
#     st.write("### Memory Buffer Summary")
    
#     # Calculate current counts in st.session_state
#     buffer_counts = {
#         key: len(records) 
#         for key, records in st.session_state.get("stream_data", {}).items()
#     }
    
#     col1, col2, col3, col4 = st.columns(4)
#     col1.metric("Alerts Buffer", buffer_counts.get("alerts", 0))
#     col2.metric("Metrics Buffer", buffer_counts.get("metrics", 0))
#     col3.metric("Anomalies Buffer", buffer_counts.get("anomalies", 0))
#     col4.metric("Incidents Buffer", buffer_counts.get("incidents", 0))
    
#     st.divider()
    
#     # Select which topic stream to inspect
#     selected_topic = st.selectbox(
#         "Select stream to view raw JSON events:", 
#         options=["alerts", "metrics", "anomalies", "incidents"]
#     )
    
#     raw_events = st.session_state.get("stream_data", {}).get(selected_topic, [])
    
#     if raw_events:
#         st.caption(f"Showing newest record out of {len(raw_events)} total events:")
#         # Displays the most recent JSON object appended to RAM
#         st.json(raw_events[-1])
#     else:
#         st.warning(f"No events currently in memory for topic: '{selected_topic}'. Check producer output or topic names.")


