# 🛡️ Web Application Vulnerability Scanner
### Python + Flask | Groq AI | JCE Cyber Security — Group 1

---

## HOW TO RUN (Every time)

```bash
# 1. Go into the project folder
cd vuln_scanner

# 2. Activate virtual environment
source venv/bin/activate

# 3. Set your Groq API key  (get free key from https://console.groq.com)
export GROQ_API_KEY=gsk_your_key_here

# 4. Run!
python app.py

# 5. Open browser → http://127.0.0.1:5000
```

---

## FIRST TIME SETUP (Do this once only)

```bash
cd vuln_scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## GET A FREE GROQ API KEY

1. Go to https://console.groq.com
2. Sign up (Google login works)
3. Left sidebar → API Keys → Create API Key
4. Copy the key (starts with gsk_...)

---

## PROJECT STRUCTURE

```
vuln_scanner/
├── app.py              ← Flask backend (all Python logic)
├── requirements.txt    ← Python packages
├── templates/
│   ├── base.html       ← Shared navbar/layout
│   ├── index.html      ← Homepage + scan form
│   ├── results.html    ← Full vulnerability report
│   ├── history.html    ← All past scans
│   └── 404.html        ← Error page
├── static/
│   ├── css/style.css   ← All styling
│   └── js/main.js      ← Frontend JavaScript
└── instance/
    └── scans.db        ← SQLite database (auto-created)
```

---

## HOW IT WORKS

1. User enters a URL
2. Flask fetches REAL HTTP headers from that website
3. Real headers are sent to Groq AI (Llama 3 model)
4. AI analyzes headers and returns structured JSON findings
5. Results are saved to SQLite database
6. Results page shows vulnerabilities, risk score, OWASP mapping

---

## TEAM

- Akshay Girish       — JCE23CC007
- Athira Raveendran   — JCE23CC014
- Renisha Febhin P J  — JCE23CC024

Guide: Mr. Ambarish A
Department of CS&E (Cyber Security), JCET — 2025-2026
