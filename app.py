"""
Network Security Log Analyzer
A beginner-friendly Streamlit application to analyze simulated security login logs,
detect brute-force patterns, and flag suspicious IP addresses.
"""

import os
import pandas as pd
import streamlit as st

# Configure the Streamlit page appearance and layout
st.set_page_config(
    page_title="Network Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------
# 1. Header & Description
# ---------------------------------------------------------
st.title("🛡️ Network Security Log Analyzer")
st.markdown(
    """
    Welcome! This tool analyzes simulated login records to identify potential security threats, 
    such as brute-force attacks. 
    
    **Detection Rule:** Any IP address with **5 or more failed login attempts** is flagged as **Suspicious**.
    """
)

# ---------------------------------------------------------
# 2. File Loading & Data Handling
# ---------------------------------------------------------
st.sidebar.header("📁 Data Source")

# Allow the user to upload a custom CSV file or use the bundled sample
uploaded_file = st.sidebar.file_uploader(
    "Upload a CSV log file", 
    type=["csv"],
    help="Upload a CSV with columns: timestamp, ip_address, username, status"
)

# Function to load and prepare log data
def load_data(file_source):
    """Loads a CSV log file into a Pandas DataFrame and cleans the status column."""
    df = pd.read_csv(file_source)
    # Ensure required columns are present
    required_columns = {"ip_address", "status"}
    if not required_columns.issubset(df.columns):
        st.error(f"Error: Uploaded CSV must contain at least {required_columns} columns.")
        return None
    
    # Clean whitespace and standardize status values for consistent comparisons
    df["status"] = df["status"].astype(str).str.strip()
    return df

# Load either the uploaded file or the default sample_logs.csv
default_sample_path = "sample_logs.csv"

if uploaded_file is not None:
    df = load_data(uploaded_file)
    st.sidebar.success("Loaded uploaded file successfully!")
elif os.path.exists(default_sample_path):
    df = load_data(default_sample_path)
    st.sidebar.info("Using default `sample_logs.csv`.")
else:
    st.error("No log file found! Please upload a CSV file or add `sample_logs.csv` to the project directory.")
    df = None

# Proceed only if data was successfully loaded
if df is not None:
    # ---------------------------------------------------------
    # 3. Log Analysis & Calculations
    # ---------------------------------------------------------
    
    # Total login attempts
    total_attempts = len(df)
    
    # Successful vs Failed login counts (case-insensitive check)
    successful_mask = df["status"].str.lower() == "success"
    failed_mask = df["status"].str.lower() == "failed"
    
    total_successful = int(successful_mask.sum())
    total_failed = int(failed_mask.sum())
    
    # Filter only failed attempts to evaluate per-IP failure rates
    failed_df = df[failed_mask]
    
    # Count failed attempts per IP address
    failed_attempts_by_ip = (
        failed_df.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
    )
    
    # Flag suspicious IPs: threshold is 5 or more failed login attempts
    FAILURE_THRESHOLD = 5
    suspicious_ips_df = failed_attempts_by_ip[
        failed_attempts_by_ip["failed_attempts"] >= FAILURE_THRESHOLD
    ].sort_values(by="failed_attempts", ascending=False)
    
    total_suspicious_ips = len(suspicious_ips_df)

    # ---------------------------------------------------------
    # 4. Display Key Metrics
    # ---------------------------------------------------------
    st.subheader("📊 Summary Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    col1.metric(label="Total Login Attempts", value=total_attempts)
    col2.metric(label="Successful Logins", value=total_successful)
    col3.metric(label="Failed Logins", value=total_failed)
    col4.metric(
        label="Suspicious IPs (≥ 5 Fails)", 
        value=total_suspicious_ips, 
        delta=f"{total_suspicious_ips} flagged" if total_suspicious_ips > 0 else "None",
        delta_color="inverse"
    )

    st.divider()

    # ---------------------------------------------------------
    # 5. Suspicious Activity Report
    # ---------------------------------------------------------
    st.subheader("🚨 Suspicious IP Detection (Threshold: ≥ 5 Failed Attempts)")
    
    if total_suspicious_ips > 0:
        st.warning(
            f"⚠️ **Security Alert:** Found {total_suspicious_ips} IP address(es) exceeding the failed login threshold!"
        )
        
        # Merge with original data to show which usernames were targeted
        targeted_usernames = (
            failed_df[failed_df["ip_address"].isin(suspicious_ips_df["ip_address"])]
            .groupby("ip_address")["username"]
            .apply(lambda users: ", ".join(sorted(set(users))))
            .reset_index(name="targeted_usernames")
        )
        
        # Combine the failed count with targeted usernames for better security insight
        suspicious_report = pd.merge(suspicious_ips_df, targeted_usernames, on="ip_address")
        suspicious_report.rename(
            columns={
                "ip_address": "IP Address",
                "failed_attempts": "Failed Attempts",
                "targeted_usernames": "Targeted Usernames"
            },
            inplace=True
        )
        
        st.dataframe(suspicious_report, use_container_width=True, hide_index=True)
    else:
        st.success("✅ Clean! No IP address has 5 or more failed login attempts.")

    st.divider()

    # ---------------------------------------------------------
    # 6. Visual Breakdown & Log Inspection
    # ---------------------------------------------------------
    st.subheader("📈 Visual Breakdown")
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.write("**Login Status Distribution**")
        status_counts = df["status"].value_counts()
        st.bar_chart(status_counts)

    with chart_col2:
        st.write("**Failed Attempts per IP Address**")
        if not failed_attempts_by_ip.empty:
            sorted_fails = failed_attempts_by_ip.sort_values(by="failed_attempts", ascending=False).set_index("ip_address")
            st.bar_chart(sorted_fails)
        else:
            st.info("No failed logins in the current dataset.")

    st.divider()

    # ---------------------------------------------------------
    # 7. Raw Log Explorer
    # ---------------------------------------------------------
    st.subheader("🔍 Log Records Explorer")
    
    # Filter options for the user
    status_filter = st.selectbox("Filter records by Status:", ["All", "Success", "Failed"])
    
    display_df = df.copy()
    if status_filter != "All":
        display_df = display_df[display_df["status"].str.lower() == status_filter.lower()]

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(display_df)} of {len(df)} total records.")
