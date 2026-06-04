import pandas as pd
import streamlit as st
from collections import Counter
import re
import plotly.express as px
from datetime import datetime
import requests
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="LogHunterAI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LogHunterAI")
st.subheader("AI-Powered SOC Threat Detection & Log Intelligence Platform")

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["log", "txt"]
)

failed_ips = []
counts = Counter()

if uploaded_file:

    st.success("File uploaded successfully!")
   
    st.info(
        f"🕒 Analysis Timestamp: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
    )
    st.info(f"📂 Filename: {uploaded_file.name}")
    st.info(f"📦 File Size: {uploaded_file.size} bytes") 
    content = uploaded_file.read().decode("utf-8")
    
    lines = content.splitlines()

    # Attack Timeline Analysis
    timeline = Counter()

    for line in lines:

        match = re.search(
            r'(\w+\s+\d+\s+\d+:\d+)',
            line
        )

        if match:
            minute = match.group(1)
            timeline[minute] += 1
    timeline_df = pd.DataFrame(
        timeline.items(),
        columns=["Time", "Events"]
    )

    timeline_df = timeline_df.sort_values("Time")

    st.info(f"📄 Total Log Entries: {len(lines)}")   

    st.text_area(
        "Log Preview",
        content[:2000],
        height=250
    )

    

    for line in content.splitlines():

        if "Failed password" in line:

            match = re.search(
                r'from (\d+\.\d+\.\d+\.\d+)',
                line
            )

            if match:
                failed_ips.append(match.group(1))

    counts = Counter(failed_ips)


#Security Dashboard

st.header("📊 Security Dashboard")


col1, col2, col3, col4, col5  = st.columns(5)

with col1:
    st.metric("Failed Login Attempts", len(failed_ips))

with col2:
    st.metric("Suspicious Source IPs", len(counts))

with col3:
    if len(failed_ips) >= 5:
        st.metric("Threat Level", "HIGH")
    else:
        st.metric("Threat Level", "LOW")
with col4:
    risk_score = min(len(failed_ips) * 10, 100)
    st.metric("Risk Score", 
    f"{risk_score}/100")

with col5:
    st.metric("Analysis Time", datetime.now().strftime("%d-%m %H:%M"))

if 'timeline_df' in locals():
    st.subheader("📈 Attack Timeline")

    fig, ax = plt.subplots(figsize=(12,4))

    ax.plot(
        timeline_df["Time"],
        timeline_df["Events"]
    )

    ax.set_xlabel("Time")
    ax.set_ylabel("Events")
    ax.set_title("Attack Timeline")

    ax.set_xticks(ax.get_xticks()[::10])

    plt.xticks(rotation=45)

    st.pyplot(fig)

# Top Attacker

if counts:
    top_ip = max(counts, key=counts.get)
    try:
        geo = requests.get(
            f"http://ip-api.com/json/{top_ip}"
        ).json()

        country = geo.get("country", "Unknown")
        city = geo.get("city", "Unknown")
        isp = geo.get("isp", "Unknown")

    except:
        country = "Unknown"
        city = "Unknown"
        isp = "Unknown"

    top_attacker_ip = top_ip
    top_attacks = counts[top_ip]

    st.info(
        f"🔥 Top Threat Source: {top_attacker_ip} ({top_attacks} failed login attempts)"
    )

    st.write(f"🌍 Country: {country}")
    st.write(f"🏙️ City: {city}")
    st.write(f"📡 ISP: {isp}")

if counts:

    df = pd.DataFrame(
        {"IP Address":list(counts.keys()),
         "Failed Logins":list(counts.values())
        })
 
    import plotly.express as px

    top_ips = dict(
    sorted(counts.items(),
           key=lambda x: x[1],
           reverse=True)[:10]
    )

    fig = px.bar(
        x=list(top_ips.keys()),
        y=list(top_ips.values()),
        title="Top 10 Source IPs Generating Failed Login Attempts",
        labels={"x": "IP Address", "y": "Failed Logins"}
    )
    fig.update_layout(
    template="plotly_dark",
    height=500,
    xaxis_title="Source IP Address",
    yaxis_title="Failed Login Attempts"
    )

    fig.update_traces(
       textposition="outside"
    )   
    st.plotly_chart(fig, use_container_width=True)
    import plotly.express as px

    top10_df = (
    df.sort_values("Failed Logins", ascending=False)
      .head(10)
    )

    pie_fig = px.pie(
          top10_df,
          names="IP Address",
          values="Failed Logins",
          title="Attack Distribution by Source IP"
    )

    st.plotly_chart(pie_fig, use_container_width=True)


    # Top 3 Attackers

    top_attackers = df.sort_values(
        by="Failed Logins",
        ascending=False
    ).head(3)

    st.subheader("🏆 Top 3 Attackers")
    st.dataframe(top_attackers)


    #Download button
    
    st.download_button(
    "📥 Download Report",
    data=df.to_csv(index=False),
    file_name="security_report.csv",
    mime="text/csv"
)

# Executive Summary
if counts:
    top_attacker_ip = top_ip
    top_attacks = counts[top_ip]
else:
    top_attacker_ip = "N/A"
    top_attacks = 0
analysis_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

st.subheader("📋 Executive Summary")

col1, col2 = st.columns(2)

with col1:
    st.metric("Top Threat Source", top_attacker_ip)

with col2:
    st.metric("Failed Login Attempts", top_attacks)

col3, col4 = st.columns(2)

with col3:
    st.metric("Risk Score", f"{risk_score}/100")

with col4:
    st.metric("Analysis Time", analysis_time)

st.warning(
    f"Threat Level: HIGH | Suspicious IPs Detected: {len(counts)}"
)

#AI SUMMARY 

st.subheader("🤖 AI Security Summary")

if risk_score >= 80:
    ai_summary = f"""
    Critical threat activity detected.
    Source IP {top_attacker_ip} generated {top_attacks} failed login attempts.
    Immediate investigation and containment actions are recommended.
    """
elif risk_score >= 50:
    ai_summary = f"""
    Elevated threat activity detected.
    Multiple suspicious authentication attempts were observed.
    Review access logs and monitor affected systems.
    """
else:
    ai_summary = f"""
    Low threat activity detected.
    Continue monitoring authentication events.
    """

if top_attacks > 20:
    confidence_score = 95
elif top_attacks > 10:
    confidence_score = 85
else:
    confidence_score = 70


st.info(
    f"""
**Threat Status:** Critical threat activity detected

**Source IP:** {top_attacker_ip}

**Failed Login Attempts:** {top_attacks}

**Recommended Action:** Immediate investigation and containment.

**Detection Time:** {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}

**Confidence Score:** {confidence_score}%

**Risk Score:** {risk_score}/100

"""
)

st.write("### AI Confidence Level")
st.progress(confidence_score)

st.metric("AI Confidence Score", 
f"{confidence_score}%")

if top_attacks >= 20:
    threat_status = "Critical threat activity detected"
elif top_attacks >= 10:
    threat_status = "High threat activity detected"
else:
    threat_status = "Moderate threat activity detected"


report = f"""
LogHunterAI Security Report

Top Threat Source: {top_attacker_ip}
Failed Login Attempts: {top_attacks}
Risk Score: {risk_score}/100
Threat Level: HIGH
"""
st.subheader("🎯 MITRE ATT&CK Mapping")

st.warning(
    "Technique: T1110 - Brute Force"
)

st.info(f"Detections Mapped: {top_attacks}")

st.info(
    "Tactic: Credential Access"
)

st.error(
    "Incident Priority: P1 - Critical"
)

st.markdown(
    "[View MITRE Technique T1110](https://attack.mitre.org/techniques/T1110/)"
)

st.download_button(
    "📥 Download Incident Report",
    report,
    file_name="security_report.txt"
)

#Threat Detection Results

st.header("🚨 Threat Detection Results")

critical_count = 0
high_count = 0
medium_count = 0
low_count = 0
display_count = 0
MAX_DISPLAY = 10
if counts:

    for ip, count in counts.items():

        if count >= 7:
            severity = "🔴 Critical"
            critical_count += 1

            if display_count < MAX_DISPLAY:
               st.error(
                   f"🚨 Brute Force Attack Detected from {ip} ({count} failed logins) | Severity: {severity}"
            )
            display_count += 1

        elif count >= 5:
            severity = "🟡 High"
            high_count += 1

            if display_count < MAX_DISPLAY:
                st.warning(
                    f"⚠️ Suspicious Activity from {ip} ({count} failed logins) | Severity: {severity}"
                )
                display_count += 1

        elif count >= 3:
            severity = "🟡 Medium"
            medium_count += 1

        else:
            severity = "🟢 Low"
            low_count += 1

else:
    st.success("No suspicious activity detected")

st.info(
    f"Showing first {MAX_DISPLAY} detections out of {len(counts)} source IPs"
)

#Severity Summary

st.subheader("🚦 Severity Summary")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🔴 Critical", critical_count)

with col2:
    st.metric("🟠 High", high_count)

with col3:
    st.metric("🟡 Medium", medium_count)

with col4:
    st.metric("🟢 Low", low_count)

#AI Recommendations

st.subheader("🤖 AI Recommendations")

st.warning("Block IPs with more than 5 failed login attempts.")
st.info("Enable Multi-Factor Authentication (MFA).")
st.info("Monitor repeated SSH login failures.")
st.info("Investigate suspicious IP addresses.")
st.info("Update firewall rules regularly.")
st.info("Disable direct root SSH login.")
st.info("Configure account lockout policies.")
st.info("Enable account lockout after repeated failed authentication attempts.")
st.info("Review and investigate all Critical severity threat sources immediately.")

st.markdown("- - -")
st.caption("Developed by Snehitha Jarpala | LogHunterAI v1.0")
