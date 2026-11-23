# 🛡️ Network Security Log Analyzer

A beginner-friendly Python and Streamlit web application designed to analyze simulated login records, detect potential brute-force attacks, and highlight suspicious IP addresses.

> **Note:** This project uses purely synthetic, offline data. It does not scan live networks, open network sockets, or communicate with external servers.

---

## 📋 Features

- **Total Attempts Metric:** Counts and displays the total number of login attempts.
- **Success vs. Failure Tracking:** Separates and counts successful and failed authentication events.
- **Brute-Force Detection:** Automatically flags IP addresses that generate **5 or more failed login attempts**.
- **Interactive Security Dashboard:**
  - Metric summary cards (Total attempts, successful, failed, suspicious IPs).
  - High-priority security alert with a detailed breakdown of suspicious IPs and targeted usernames.
  - Interactive bar charts for visual distribution analysis.
  - Searchable and filterable log records table.
- **Custom CSV Upload:** Allows uploading custom log files or using the bundled `sample_logs.csv` by default.

---

## 📁 Project Structure

| File | Description |
| :--- | :--- |
| `app.py` | The main Streamlit web application. Loads the log data, computes security metrics using Pandas, and renders the interactive dashboard. |
| `sample_logs.csv` | Synthetic dataset containing simulated authentication events (timestamp, IP address, username, status). |
| `requirements.txt` | Lists the Python libraries (`pandas` and `streamlit`) needed to run the project. |
| `README.md` | Complete documentation with installation steps, usage guide, and testing instructions. |

---

## ⚙️ Installation & Setup

### 1. Prerequisites
Ensure you have Python 3.9 or higher installed on your computer. You can check your Python version by running:
```bash
python --version
```

### 2. (Optional but Recommended) Create a Virtual Environment
In your project directory, create and activate an isolated virtual environment:

- **Windows (Command Prompt / PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\activate
  ```

- **macOS / Linux:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 3. Install Dependencies
Install the required packages using pip:
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Application

Start the Streamlit application by running:
```bash
streamlit run app.py
```
*(On Windows, if `streamlit` is not recognized directly in your terminal, run:)*
```powershell
py -m streamlit run app.py
```

Once started, Streamlit will open the application in your default web browser (typically at `http://localhost:8501`).

---

## 🧪 How to Test the Project

### Test Case 1: Testing Default Sample Data
1. Launch the app using `streamlit run app.py`.
2. Notice the metrics automatically calculated from `sample_logs.csv`:
   - **Total Login Attempts:** `23`
   - **Successful Logins:** `8`
   - **Failed Logins:** `15`
   - **Suspicious IPs Flagged:** `2`
3. Inspect the **Suspicious IP Detection** table:
   - `192.168.1.105`: 6 failed attempts (targeted usernames: `admin`, `administrator`, `root`, `test`, `user`).
   - `203.0.113.45`: 5 failed attempts (targeted username: `admin`).
   - Notice that `198.51.100.22` (3 failed attempts) and `192.168.1.50` (1 failed attempt) are **not** flagged because they have fewer than 5 failures.

### Test Case 2: Testing with Custom Data
1. Create a new test CSV file named `test_clean.csv`:
   ```csv
   timestamp,ip_address,username,status
   2026-11-23 10:00:00,10.0.0.1,admin,Success
   2026-11-23 10:01:00,10.0.0.2,user1,Success
   2026-11-23 10:02:00,10.0.0.3,user2,Failed
   ```
2. In the sidebar of the web app, click **Browse files** and upload `test_clean.csv`.
3. The dashboard will instantly update:
   - Suspicious IPs will show `0`.
   - The green alert **"Clean! No IP address has 5 or more failed login attempts."** will appear.

---

## 🛡️ Educational Concept: Why Detect Failed Logins?

In cybersecurity, attackers frequently perform **Brute-Force** or **Credential Stuffing** attacks by repeatedly attempting passwords until they find a valid combination. 

By analyzing authentication logs and grouping failed attempts by source IP address, security operations centers (SOCs) can:
1. Detect automated attacks early.
2. Block offending IP addresses at firewalls or through Web Application Firewalls (WAF).
3. Notify users whose accounts were targeted.
