import os
import json
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from database import store_event, get_events
from confluent_kafka import Consumer

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
# CONFIG
# ============================================================

TOPICS = {
    "alerts": os.getenv("SIEM_ALERTS_TOPIC"),
    "metrics": os.getenv("SIEM_METRICS_TOPIC"),
    "anomalies": os.getenv("SIEM_ANOMALIES_TOPIC"),
    "incidents": os.getenv("SIEM_INCIDENTS_TOPIC"),
}


# ============================================================
# CONFLUENT SCHEMA REGISTRY DECODER & KAFKA CONSUMER
# ============================================================

def decode_confluent_message(raw_bytes):
    """
    Strips Confluent Schema Registry magic byte (0x00) + 4-byte Schema ID 
    if present before parsing JSON data.
    """
    if len(raw_bytes) > 5 and raw_bytes[0] == 0:
        raw_bytes = raw_bytes[5:]
    return json.loads(raw_bytes.decode("utf-8"))


def create_consumer(topic_name):
    return Consumer({
        "bootstrap.servers": os.getenv("CONFLUENT_BOOTSTRAP_SERVERS"),
        "security.protocol": "SASL_SSL",
        "sasl.mechanisms": "PLAIN",
        "sasl.username": os.getenv("CONFLUENT_API_KEY"),
        "sasl.password": os.getenv("CONFLUENT_API_SECRET"),
        "group.id": f"siem-dashboard-{topic_name}",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })


# ============================================================
# INITIALIZE CONSUMERS
# ============================================================

if "consumers" not in st.session_state:
    st.session_state.consumers = {}
    for name, topic in TOPICS.items():
        if topic:
            consumer = create_consumer(name)
            consumer.subscribe([topic])
            st.session_state.consumers[name] = consumer


# ============================================================
# POLL KAFKA
# ============================================================

def poll_streams():
    total_new = 0
    for name, consumer in st.session_state.consumers.items():
        for _ in range(100):
            msg = consumer.poll(timeout=0.05)
            if msg is None:
                break
            if msg.error():
                continue

            try:
                # Decodes Confluent wire-format or raw JSON payload
                record = decode_confluent_message(msg.value())
                topic = msg.topic()

                store_event(topic, record)
                consumer.commit(message=msg, asynchronous=False)
                total_new += 1
            except Exception as e:
                print(f"Failed to process message on {name}: {e}")

    return total_new


# ============================================================
# SIDEBAR CONTROLS
# ============================================================

st.sidebar.header("⚙️ SIEM Controls")

if st.sidebar.button("🔄 Refresh now", use_container_width=True):
    poll_streams()

auto_refresh = st.sidebar.toggle("🔴 Live streaming", value=True)

if auto_refresh:
    st.sidebar.success("Dashboard is receiving streamed data.")
else:
    st.sidebar.info("Live streaming paused.")


# ============================================================
# POLL DATA
# ============================================================

if auto_refresh:
    poll_streams()


# ============================================================
# FETCH DATA FROM SQLITE
# ============================================================

alerts = get_events(os.getenv("SIEM_ALERTS_TOPIC"))
metrics = get_events(os.getenv("SIEM_METRICS_TOPIC"))
anomalies = get_events(os.getenv("SIEM_ANOMALIES_TOPIC"))
incidents = get_events(os.getenv("SIEM_INCIDENTS_TOPIC"))


# ============================================================
# BUILD DATAFRAMES
# ============================================================

alerts_df = pd.json_normalize(alerts)
metrics_df = pd.json_normalize(metrics)
anomalies_df = pd.json_normalize(anomalies)
incidents_df = pd.json_normalize(incidents)


# ============================================================
# TIMESTAMP NORMALIZATION (CONVERTS EPOCH MS TO DATETIME)
# ============================================================

if not alerts_df.empty and "event_time" in alerts_df.columns:
    alerts_df["event_time"] = pd.to_datetime(
        alerts_df["event_time"], unit="ms", errors="coerce"
    )

if not metrics_df.empty:
    for col in ["window_start", "window_end"]:
        if col in metrics_df.columns:
            metrics_df[col] = pd.to_datetime(
                metrics_df[col], unit="ms", errors="coerce"
            )

if not anomalies_df.empty:
    for col in ["window_start", "window_end"]:
        if col in anomalies_df.columns:
            anomalies_df[col] = pd.to_datetime(
                anomalies_df[col], unit="ms", errors="coerce"
            )

if not incidents_df.empty and "incident_time" in incidents_df.columns:
    incidents_df["incident_time"] = pd.to_datetime(
        incidents_df["incident_time"], unit="ms", errors="coerce"
    )


# ============================================================
# CONNECTION STATUS
# ============================================================

connected_streams = sum(1 for topic in TOPICS.values() if topic)
st.markdown(
    f"🟢 **Streaming pipeline active** — "
    f"{connected_streams}/4 SIEM streams connected"
)


# ============================================================
# KPI CALCULATIONS
# ============================================================

total_alerts = len(alerts_df)
total_anomalies = len(anomalies_df)
total_incidents = len(incidents_df)

high_critical = 0
if not alerts_df.empty and "alert_severity" in alerts_df.columns:
    high_critical = alerts_df[
        alerts_df["alert_severity"]
        .fillna("")
        .str.upper()
        .isin(["HIGH", "CRITICAL"])
    ].shape[0]

unique_sources = 0
if not alerts_df.empty and "source_ip" in alerts_df.columns:
    unique_sources = alerts_df["source_ip"].dropna().nunique()

average_risk = 0.0
if not incidents_df.empty and "risk_score" in incidents_df.columns:
    average_risk = round(
        pd.to_numeric(incidents_df["risk_score"], errors="coerce").mean(), 1
    )


# ============================================================
# SECURITY OVERVIEW METRICS
# ============================================================

st.subheader("Security Overview")
c1, c2, c3, c4, c5, c6 = st.columns(6)

c1.metric("🚨 Alerts", f"{total_alerts:,}")
c2.metric("🔴 High / Critical", f"{high_critical:,}")
c3.metric("⚠️ Anomalies", f"{total_anomalies:,}")
c4.metric("🛡️ Incidents", f"{total_incidents:,}")
c5.metric("🌐 Sources", f"{unique_sources:,}")
c6.metric("🎯 Avg Risk", f"{average_risk}")


# ============================================================
# ALERT INTELLIGENCE CHARTS
# ============================================================

st.subheader("📊 Alert Intelligence")
left, right = st.columns(2)

with left:
    st.markdown("**Alerts by Severity**")
    if not alerts_df.empty and "alert_severity" in alerts_df.columns:
        severity = (
            alerts_df["alert_severity"]
            .fillna("UNKNOWN")
            .str.upper()
            .value_counts()
        )
        st.bar_chart(severity)
    else:
        st.info("Waiting for alert data...")

with right:
    st.markdown("**Top Alert Types**")
    if not alerts_df.empty and "alert_type" in alerts_df.columns:
        alert_types = (
            alerts_df["alert_type"]
            .fillna("UNKNOWN")
            .value_counts()
            .head(10)
        )
        st.bar_chart(alert_types)
    else:
        st.info("Waiting for alert data...")


# ============================================================
# ALERT TRENDS & SOURCE CHARTS
# ============================================================

left, right = st.columns(2)

with left:
    st.markdown("**📈 Alert Volume**")
    if not alerts_df.empty and "event_time" in alerts_df.columns:
        trend = (
            alerts_df.dropna(subset=["event_time"])
            .set_index("event_time")
            .resample("min")
            .size()
        )
        st.line_chart(trend)
    else:
        st.info("Waiting for event-time data...")

with right:
    st.markdown("**🌐 Top Source IPs**")
    if not alerts_df.empty and "source_ip" in alerts_df.columns:
        sources = (
            alerts_df["source_ip"]
            .fillna("UNKNOWN")
            .value_counts()
            .head(10)
        )
        st.bar_chart(sources)
    else:
        st.info("Waiting for source IP data...")


# ============================================================
# LIVE SECURITY FEEDS AND TABLES
# ============================================================

st.subheader("🔴 Live Security Event Feed")
if not alerts_df.empty:
    cols = [
        "event_time",
        "alert_severity",
        "alert_type",
        "source_ip",
        "destination_ip",
        "hostname",
        "access_group",
        "description",
    ]
    avail = [c for c in cols if c in alerts_df.columns]
    live_feed = alerts_df[avail].sort_values("event_time", ascending=False).head(20)
    st.dataframe(live_feed, use_container_width=True, hide_index=True)
else:
    st.info("Waiting for streamed alerts...")


st.subheader("⚠️ Anomaly Intelligence")
if not anomalies_df.empty:
    cols = [
        "anomaly_id",
        "window_start",
        "window_end",
        "source_ip",
        "alert_count",
        "unique_destinations",
        "high_alerts",
        "anomaly_score",
        "anomaly_type",
        "severity",
        "explanation",
    ]
    avail = [c for c in cols if c in anomalies_df.columns]
    anom_view = anomalies_df[avail]
    if "anomaly_score" in anom_view.columns:
        anom_view = anom_view.sort_values("anomaly_score", ascending=False)
    st.dataframe(anom_view, use_container_width=True, hide_index=True)
else:
    st.success("No anomalies received.")


st.subheader("🛡️ Incident Intelligence")
if not incidents_df.empty:
    cols = [
        "incident_id",
        "incident_time",
        "source_ip",
        "incident_type",
        "severity",
        "risk_score",
        "alert_count",
        "unique_destinations",
        "high_alerts",
        "explanation",
        "recommended_action",
    ]
    avail = [c for c in cols if c in incidents_df.columns]
    inc_view = incidents_df[avail]
    if "risk_score" in inc_view.columns:
        inc_view = inc_view.sort_values("risk_score", ascending=False)
    st.dataframe(inc_view, use_container_width=True, hide_index=True)
else:
    st.success("No incidents received.")


# ============================================================
# HIGHEST PRIORITY INCIDENT DETAIL
# ============================================================

if not incidents_df.empty:
    st.subheader("🚨 Highest Priority Incident")
    if "risk_score" in incidents_df.columns:
        priority = incidents_df.sort_values("risk_score", ascending=False).iloc[0]
    else:
        priority = incidents_df.iloc[0]

    ic1, ic2, ic3 = st.columns(3)
    ic1.metric("Incident ID", str(priority.get("incident_id", "N/A")))
    ic2.metric("Severity", str(priority.get("severity", "N/A")))
    ic3.metric("Risk Score", str(priority.get("risk_score", "N/A")))

    st.markdown("**Incident Type**")
    st.write(priority.get("incident_type", "N/A"))

    st.markdown("**Explanation**")
    st.write(priority.get("explanation", "N/A"))

    st.markdown("**Recommended Action**")
    st.warning(priority.get("recommended_action", "N/A"))


# ============================================================
# PIPELINE STATUS
# ============================================================

st.subheader("🔗 Streaming Pipeline Status")
p1, p2, p3, p4 = st.columns(4)
p1.metric("siem_alerts", len(alerts))
p2.metric("siem_metrics", len(metrics))
p3.metric("siem_anomalies", len(anomalies))
p4.metric("siem_incidents", len(incidents))

st.divider()
st.caption(
    "Raw SIEM Logs → Normalization → Apache Flink → "
    "Alerts / Metrics / Anomalies / Incidents → SIEM Operations Center"
)


# ============================================================
# AUTO-REFRESH TRIGGER
# ============================================================

if auto_refresh:
    st.markdown(
        """
        <meta http-equiv="refresh" content="300">
        """,
        unsafe_allow_html=True,
    )