# 🛡️ Web Application Vulnerability Scanner

### Python + Flask | JCE Cyber Security — Group 1

A modern, fast, and feature-rich web application vulnerability scanner built with Python and Flask. Designed with a sleek dark-themed UI, it actively probes target URLs for common misconfigurations and injection vulnerabilities, providing detailed PDF-exportable reports.

---

## ✨ Key Features

- **Advanced SQL Injection Detection**: 4-level active scanning (Error-based, Boolean-based blind, Time-based blind, and Combined).
- **Passive Security Checks**: Validates security headers, information leakage, cookie flags, and rate-limiting configurations.
- **AI-Powered Summaries**: Integrates with Groq API (Llama 3) to provide instant executive summaries of your scan results.
- **Client-Side PDF Exports**: Instantly download your scan results to a beautifully formatted PDF report natively in the browser.
- **Scan History Management**: Automatically saves all scans to an SQLite database. You can review past scans, delete specific records, or clear all history.
- **Modern Dark Theme**: A responsive and visually striking UI built with Bootstrap 5 and custom CSS.

---

## 🚀 Quick Start

### 1. First-Time Setup

**For Linux / macOS:**
```bash
# Enter the project folder
cd mini-project

# Initialize and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**For Windows:**
```cmd
# Enter the project folder
cd mini-project

# Initialize and activate a virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Scanner

**For Linux / macOS:**
```bash
# Activate the virtual environment
source venv/bin/activate

# Start the Flask development server
python3 app.py
```

**For Windows:**
```cmd
# Activate the virtual environment
venv\Scripts\activate

# Start the Flask development server
python app.py
```
Open your browser and navigate to: `http://127.0.0.1:5000`

---

## 🎯 Testing the Scanner (Vulnerable Target)

To test the scanner's advanced SQL Injection features safely without targeting external websites, a built-in intentionally vulnerable server (`test_target.py`) is included.

### How to use the Test Target:
1. Open a **new, separate terminal** window.
2. Navigate to the project folder and activate the virtual environment (using the steps above).
3. Start the vulnerable server:
   - **Linux/macOS**: `python3 test_target.py`
   - **Windows**: `python test_target.py`
4. The test server will start running locally on port `9999`.
5. Open your Scanner dashboard (`http://127.0.0.1:5000`), make sure **Enable SQL Injection Detection** is checked, and scan the following URL:
   `http://127.0.0.1:9999/products?id=1`
   
The scanner will successfully exploit the test target and report the vulnerabilities found!

---

## 🤖 Configuring AI Summaries (Optional)
The scanner works perfectly without an API key, but you can enable AI-generated executive summaries completely free.

1. Get a free API key at [console.groq.com](https://console.groq.com).
2. Open `app.py` in your code editor.
3. Paste the key into the configuration block at the top of the file:
```python
# --- CONFIGURATION ---
GROQ_API_KEY = "gsk_your_api_key_here"
# --------------------
```
*Note: Do not commit your real API key to public repositories!*

---

## 🔍 What it Detects

1. **SQL Injection (SQLi)**: 4 configurable levels of invasive probing.
2. **Missing Security Headers**: CSP, HSTS, X-Frame-Options, X-XSS-Protection, etc.
3. **Information Leakage**: Server version disclosures.
4. **HTTPS Enforcement**: Unencrypted HTTP connections.
5. **Cookie Security**: Missing `HttpOnly`, `Secure`, or `SameSite` flags.
6. **Reflected XSS**: Input reflection probes.
7. **`robots.txt`**: Exposed endpoints.
8. **`security.txt`**: Missing standard security contact info.
9. **Missing Rate-Limit**: Checks for abuse prevention headers.

---

## 📂 Project Structure

```text
mini-project/
├── app.py              ← Main Flask backend and scanning logic
├── test_target.py      ← Local vulnerable server for testing SQLi safely
├── requirements.txt    ← Python dependencies
├── instance/           
│   └── scans.db        ← SQLite database storing scan history
└── templates/          ← Frontend UI
    ├── base.html       ← Main global layout & CSS theme
    ├── index.html      ← Home page / Scanner form
    ├── results.html    ← Security report layout and PDF logic
    └── history.html    ← Interactive scan history dashboard
```

---

## 👥 Team

- **Akshay Girish** — JCE23CC007
- **Athira Raveendran** — JCE23CC014
- **Renisha Febhin P J** — JCE23CC024

**Guide**: Mr. Ambarish A  
**Department of CS&E (Cyber Security), JCET** — 2025-2026
