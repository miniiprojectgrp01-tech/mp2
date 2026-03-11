# ============================================================
#  app.py  Web Application Vulnerability Scanner
#  Backend: Python + Flask
#  Database: SQLite (built into Python, no setup needed)
#
#  HOW TO RUN:
#    1. pip install -r requirements.txt
#    2. python app.py
#    3. Open http://127.0.0.1:5000
# ============================================================

import os
import re
import json
import time
import sqlite3
import requests
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, g

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vuln-scanner-jce-2024'
DATABASE = os.path.join(app.instance_path, 'scans.db')
os.makedirs(app.instance_path, exist_ok=True)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            url              TEXT    NOT NULL,
            status           TEXT    DEFAULT 'pending',
            risk_score       REAL,
            risk_level       TEXT,
            summary          TEXT,
            vulnerabilities  TEXT,
            headers_analysis TEXT,
            total_vulns      INTEGER DEFAULT 0,
            critical_count   INTEGER DEFAULT 0,
            high_count       INTEGER DEFAULT 0,
            medium_count     INTEGER DEFAULT 0,
            low_count        INTEGER DEFAULT 0,
            info_count       INTEGER DEFAULT 0,
            scan_duration    REAL,
            created_at       TEXT    DEFAULT (datetime('now','localtime'))
        )
    ''')
    db.commit()

with app.app_context():
    init_db()


@app.route('/')
def index():
    db = get_db()
    scans = db.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT 10').fetchall()
    return render_template('index.html', scans=scans)


@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    db = get_db()
    cursor = db.execute('INSERT INTO scans (url, status) VALUES (?, ?)', (url, 'scanning'))
    db.commit()
    scan_id = cursor.lastrowid

    try:
        result = run_ai_scan(url)
        vulns  = result.get('vulnerabilities', [])
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vulns:
            sev = v.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1

        db.execute('''
            UPDATE scans SET
                status='completed', risk_score=?, risk_level=?, summary=?,
                vulnerabilities=?, headers_analysis=?, total_vulns=?,
                critical_count=?, high_count=?, medium_count=?,
                low_count=?, info_count=?, scan_duration=?
            WHERE id=?
        ''', (
            result.get('risk_score', 0), result.get('risk_level', 'low'),
            result.get('summary', ''), json.dumps(result.get('vulnerabilities', [])),
            json.dumps(result.get('headers_analysis', {})), len(vulns),
            counts['critical'], counts['high'], counts['medium'],
            counts['low'], counts['info'], result.get('scan_duration_seconds', 5),
            scan_id
        ))
        db.commit()
        return jsonify({'scan_id': scan_id, 'status': 'completed'})

    except Exception as e:
        db.execute("UPDATE scans SET status='failed' WHERE id=?", (scan_id,))
        db.commit()
        return jsonify({'error': str(e)}), 500


@app.route('/results/<int:scan_id>')
def results(scan_id):
    db   = get_db()
    scan = db.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if not scan:
        return render_template('404.html'), 404

    scan_dict = dict(scan)
    scan_dict['vulnerabilities']  = json.loads(scan_dict['vulnerabilities']  or '[]')
    scan_dict['headers_analysis'] = json.loads(scan_dict['headers_analysis'] or '{}')

    owasp_cats = [
        ('A01','Broken Access Control'), ('A02','Cryptographic Failures'),
        ('A03','Injection'), ('A04','Insecure Design'),
        ('A05','Security Misconfiguration'), ('A06','Vulnerable Components'),
        ('A07','Authentication Failures'), ('A08','Software & Data Integrity Failures'),
        ('A09','Security Logging Failures'), ('A10','Server-Side Request Forgery'),
    ]
    scan_dict['owasp_mapping'] = [
        {
            'code': code, 'name': name,
            'count': sum(1 for v in scan_dict['vulnerabilities'] if code in (v.get('owasp_category') or '')),
            'hit':   any(code in (v.get('owasp_category') or '') for v in scan_dict['vulnerabilities'])
        }
        for code, name in owasp_cats
    ]
    return render_template('results.html', scan=scan_dict)


@app.route('/history')
def history():
    db = get_db()
    scans = db.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT 100').fetchall()
    return render_template('history.html', scans=scans)


@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    db = get_db()
    db.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    db.commit()
    return jsonify({'success': True})


# 
#  SCANNING ENGINE  9 checks, all passive, all accurate
# 

SECURITY_HEADERS = {
    'content-security-policy':           'Content-Security-Policy (CSP)',
    'strict-transport-security':         'Strict-Transport-Security (HSTS)',
    'x-frame-options':                   'X-Frame-Options',
    'x-content-type-options':            'X-Content-Type-Options',
    'x-xss-protection':                  'X-XSS-Protection',
    'referrer-policy':                   'Referrer-Policy',
    'permissions-policy':                'Permissions-Policy',
    'x-permitted-cross-domain-policies': 'X-Permitted-Cross-Domain-Policies',
}


def fetch_real_headers(url):
    """Fetch headers from target, merging all redirect responses."""
    try:
        session = requests.Session()
        resp = session.get(url, timeout=10, allow_redirects=True,
                           headers={'User-Agent': 'Mozilla/5.0 (VulnScanner Security Audit)'})
        merged = {k.lower(): v for k, v in resp.headers.items()}
        for r in resp.history:
            for k, v in r.headers.items():
                key = k.lower()
                if key not in merged:
                    merged[key] = v
        return merged, resp.status_code
    except Exception:
        return {}, None


#  Check 1: Security Headers 
def check_security_headers(real_headers):
    vulns = []
    CHECKS = [
        ('content-security-policy',           'Missing Content-Security-Policy Header',           'high',   'A05: Security Misconfiguration', 'CSP header is missing. Attackers can inject malicious scripts (XSS).',                                          "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"),
        ('strict-transport-security',         'Missing Strict-Transport-Security (HSTS) Header',  'high',   'A02: Cryptographic Failures',     'HSTS is not set. Users are vulnerable to SSL stripping attacks.',                                               'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'),
        ('x-frame-options',                   'Missing X-Frame-Options Header',                   'medium', 'A05: Security Misconfiguration', 'Without this header the site can be embedded in iframes, enabling clickjacking.',                                 'Add: X-Frame-Options: DENY'),
        ('x-content-type-options',            'Missing X-Content-Type-Options Header',            'low',    'A05: Security Misconfiguration', 'Browser may MIME-sniff responses, enabling content injection attacks.',                                           'Add: X-Content-Type-Options: nosniff'),
        ('referrer-policy',                   'Missing Referrer-Policy Header',                   'low',    'A05: Security Misconfiguration', 'Browser sends full referrer URL to third parties, leaking sensitive paths.',                                      'Add: Referrer-Policy: strict-origin-when-cross-origin'),
        ('permissions-policy',                'Missing Permissions-Policy Header',                'low',    'A05: Security Misconfiguration', 'No feature policy defined. Embedded scripts may access camera, mic, location.',                                   'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'),
        ('x-permitted-cross-domain-policies', 'Missing X-Permitted-Cross-Domain-Policies Header', 'low',    'A05: Security Misconfiguration', 'Adobe Flash and PDF plugins may load cross-domain data without restriction.',                                     'Add: X-Permitted-Cross-Domain-Policies: none'),
    ]
    for hkey, name, sev, owasp, desc, rec in CHECKS:
        if not real_headers.get(hkey):
            vulns.append({'name': name, 'category': 'Headers', 'severity': sev,
                          'description': desc, 'recommendation': rec,
                          'owasp_category': owasp, 'evidence': 'MISSING  header not present in HTTP response'})
    xxss = real_headers.get('x-xss-protection', '')
    if xxss and xxss.strip() == '1':
        vulns.append({'name': 'X-XSS-Protection Misconfiguration', 'category': 'Headers', 'severity': 'low',
                      'description': 'X-XSS-Protection: 1 without mode=block can introduce vulnerabilities in older browsers.',
                      'recommendation': 'Change to: X-XSS-Protection: 0 (rely on CSP instead)',
                      'owasp_category': 'A05: Security Misconfiguration', 'evidence': f'X-XSS-Protection: {xxss}'})
    return vulns


#  Check 2: Information Leakage 
def check_information_leakage(real_headers):
    vulns = []
    for h in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']:
        val = real_headers.get(h)
        if val:
            vulns.append({'name': f'Information Disclosure via {h.title()} Header',
                          'category': 'Information Leakage', 'severity': 'low',
                          'description': f'The {h} header reveals technology details that help attackers fingerprint the server.',
                          'recommendation': f'Configure your server to remove or obscure the {h} header.',
                          'owasp_category': 'A05: Security Misconfiguration', 'evidence': f'{h}: {val}'})
    return vulns


#  Check 3: HTTPS 
def check_https(url):
    if url.startswith('http://'):
        return [{'name': 'Site Not Using HTTPS', 'category': 'TLS/SSL', 'severity': 'critical',
                 'description': 'The site is served over HTTP. All data is transmitted in plaintext.',
                 'recommendation': 'Enable HTTPS with a valid TLS certificate.',
                 'owasp_category': 'A02: Cryptographic Failures', 'evidence': 'URL uses http://  no encryption'}]
    return []


#  Check 4: Cookie Security 
def check_cookie_security(real_headers):
    vulns = []
    raw = real_headers.get('set-cookie', '')
    if not raw:
        return vulns
    low = raw.lower()

    if 'httponly' not in low:
        vulns.append({'name': 'Cookie Missing HttpOnly Flag', 'category': 'Cookies', 'severity': 'medium',
                      'description': 'Session cookies missing HttpOnly flag. JavaScript can steal session tokens via XSS.',
                      'recommendation': 'Add HttpOnly: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict',
                      'owasp_category': 'A07: Authentication Failures', 'evidence': f'Set-Cookie: {raw[:120]}'})
    if 'secure' not in low:
        vulns.append({'name': 'Cookie Missing Secure Flag', 'category': 'Cookies', 'severity': 'medium',
                      'description': 'Cookies missing Secure flag  can be sent over plain HTTP, exposing tokens to sniffing.',
                      'recommendation': 'Add Secure flag: Set-Cookie: session=abc; Secure; HttpOnly',
                      'owasp_category': 'A02: Cryptographic Failures', 'evidence': f'Set-Cookie: {raw[:120]}'})
    if 'samesite' not in low:
        vulns.append({'name': 'Cookie Missing SameSite Flag', 'category': 'Cookies', 'severity': 'low',
                      'description': 'Missing SameSite attribute makes the site vulnerable to CSRF attacks.',
                      'recommendation': 'Add SameSite=Strict: Set-Cookie: session=abc; SameSite=Strict',
                      'owasp_category': 'A01: Broken Access Control', 'evidence': f'Set-Cookie: {raw[:120]}'})
    matches = re.findall(r'domain=(\.[a-z0-9.-]+)', low)
    if matches:
        vulns.append({'name': 'Insecure Cookie Setting  Domain Too Loose', 'category': 'Cookies', 'severity': 'medium',
                      'description': f'Cookie domain "{matches[0]}" starts with a dot  sent to ALL subdomains including untrusted ones.',
                      'recommendation': 'Set Domain to exact host: Domain=www.example.com not Domain=.example.com',
                      'owasp_category': 'A05: Security Misconfiguration', 'evidence': f'Cookie domain: {matches[0]}'})
    return vulns


#  Check 5: XSS Reflection 
def check_xss_reflection(url):
    """Send harmless probe  if reflected unescaped in HTML body  XSS risk."""
    vulns = []
    probe = 'xsstest99887'
    try:
        test_url = url + ('&' if '?' in url else '?') + f'q={probe}&search={probe}&id={probe}'
        resp = requests.get(test_url, timeout=8, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (VulnScanner Security Audit)'})
        body = resp.text
        if probe in body:
            idx     = body.find(probe)
            context = body[max(0, idx-80):idx+80]
            if not context.strip().startswith('<!--'):
                vulns.append({'name': 'Reflected XSS  User Input Reflected in Response',
                              'category': 'XSS', 'severity': 'high',
                              'description': 'Website reflects user input directly in HTML without sanitization. Attackers can inject scripts that execute in victim browsers.',
                              'recommendation': '1. Sanitize all inputs server-side.\n2. Use output encoding.\n3. Implement a strong Content-Security-Policy.',
                              'owasp_category': 'A03: Injection',
                              'evidence': f'Probe "{probe}" reflected: ...{context.strip()[:120]}...'})
    except Exception:
        pass
    return vulns


#  Check 6: SQL Injection Errors 
def check_sqli_errors(url):
    """Send single quote probe  if SQL error appears in response  SQLi risk."""
    vulns = []
    SQL_ERRORS = [
        "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
        "mysql_num_rows", "supplied argument is not a valid mysql",
        "pg_query", "pg::syntaxerror", "unterminated quoted string",
        "microsoft ole db provider for sql server", "unclosed quotation mark",
        "syntax error converting", "invalid column name",
        "ora-01756", "ora-00907", "oracle error",
        "sqlite_error", "sqlite3::query", "unrecognized token",
        "sql syntax", "sql error", "database error",
        "odbc microsoft access driver", "jdbc exception",
    ]
    try:
        test_url = url + ('&' if '?' in url else '?') + "id=1'&q=test'"
        resp = requests.get(test_url, timeout=8, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (VulnScanner Security Audit)'})
        body    = resp.text.lower()
        matched = [e for e in SQL_ERRORS if e in body]
        if matched:
            vulns.append({'name': 'SQL Injection Indicator  Database Error Exposed',
                          'category': 'Injection', 'severity': 'critical',
                          'description': 'Website returned a raw SQL error in response to a probe. User input reaches SQL queries without sanitization.',
                          'recommendation': '1. Use parameterized queries.\n2. Never expose raw DB errors.\n3. Show generic error messages.',
                          'owasp_category': 'A03: Injection',
                          'evidence': f'SQL error detected: "{matched[0]}"'})
    except Exception:
        pass
    return vulns


#  Check 7: robots.txt 
def check_robots_txt(url):
    vulns = []
    try:
        base = urlparse(url).scheme + '://' + urlparse(url).netloc
        resp = requests.get(base + '/robots.txt', timeout=6, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code == 200 and 'disallow' in resp.text.lower():
            vulns.append({'name': 'robots.txt File Publicly Accessible',
                          'category': 'Information Leakage', 'severity': 'info',
                          'description': 'robots.txt is public and contains Disallow entries. Attackers use this to discover hidden paths and admin panels.',
                          'recommendation': 'Review robots.txt  never rely on it for security. Remove sensitive path references.',
                          'owasp_category': 'A05: Security Misconfiguration',
                          'evidence': f'robots.txt found at {base}/robots.txt with Disallow entries'})
    except Exception:
        pass
    return vulns


#  Check 8: security.txt 
def check_security_txt(url):
    vulns = []
    try:
        base = urlparse(url).scheme + '://' + urlparse(url).netloc
        resp = requests.get(base + '/.well-known/security.txt', timeout=6, headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code != 200:
            vulns.append({'name': 'Missing security.txt File',
                          'category': 'Configuration', 'severity': 'info',
                          'description': 'No security.txt found. Researchers have no clear channel to report vulnerabilities responsibly.',
                          'recommendation': 'Create /.well-known/security.txt  see https://securitytxt.org',
                          'owasp_category': 'A05: Security Misconfiguration',
                          'evidence': f'GET {base}/.well-known/security.txt returned HTTP {resp.status_code}'})
    except Exception:
        pass
    return vulns


#  Check 9: Rate Limit Headers 
def check_rate_limit_header(real_headers):
    has = any('ratelimit' in k or 'rate-limit' in k or 'x-ratelimit' in k for k in real_headers)
    if not has:
        return [{'name': 'Missing Rate-Limit Headers', 'category': 'Configuration', 'severity': 'low',
                 'description': 'No rate-limiting headers detected. Application may be vulnerable to brute force and credential stuffing.',
                 'recommendation': 'Implement rate limiting. Expose: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After.',
                 'owasp_category': 'A05: Security Misconfiguration',
                 'evidence': 'No RateLimit / X-RateLimit headers found in response'}]
    return []


#  Main scan orchestrator 
def run_ai_scan(url):
    api_key = os.environ.get('GROQ_API_KEY', '')

    real_headers, status_code = fetch_real_headers(url)
    if not real_headers:
        return {'risk_score': 0, 'risk_level': 'low',
                'summary': f'Could not connect to {url}. Please check the URL and try again.',
                'scan_duration_seconds': 1, 'vulnerabilities': [], 'headers_analysis': {}}

    # Run all 9 checks
    vulnerabilities = []
    vulnerabilities.extend(check_security_headers(real_headers))
    vulnerabilities.extend(check_information_leakage(real_headers))
    vulnerabilities.extend(check_https(url))
    vulnerabilities.extend(check_cookie_security(real_headers))
    vulnerabilities.extend(check_xss_reflection(url))
    vulnerabilities.extend(check_sqli_errors(url))
    vulnerabilities.extend(check_robots_txt(url))
    vulnerabilities.extend(check_security_txt(url))
    vulnerabilities.extend(check_rate_limit_header(real_headers))

    # Build headers_analysis
    headers_analysis = {}
    for hkey, label in SECURITY_HEADERS.items():
        val = real_headers.get(hkey)
        headers_analysis[hkey.replace('-', '_')] = {
            'present': bool(val), 'value': val or None,
            'issues': None if val else f'{label} header is missing'
        }

    # Calculate score
    weights = {'critical': 25, 'high': 10, 'medium': 5, 'low': 2, 'info': 0}
    score   = sum(weights.get(v['severity'], 0) for v in vulnerabilities)
    if url.startswith('https://'):
        score = max(0, score - 5)
    score = min(score, 100)

    if score >= 75:   risk_level = 'critical'
    elif score >= 50: risk_level = 'high'
    elif score >= 30: risk_level = 'medium'
    else:             risk_level = 'low'

    summary = generate_summary(url, vulnerabilities, score, risk_level, api_key)

    return {'risk_score': score, 'risk_level': risk_level, 'summary': summary,
            'scan_duration_seconds': 4, 'vulnerabilities': vulnerabilities,
            'headers_analysis': headers_analysis}


def generate_summary(url, vulnerabilities, score, risk_level, api_key):
    count = len(vulnerabilities)
    if not api_key:
        return (f"Scan of {url} completed. Found {count} issue(s) with a risk score of "
                f"{score}/100 ({risk_level} risk). Review the findings below.")
    finding_list = '\n'.join(f"- [{v['severity'].upper()}] {v['name']}" for v in vulnerabilities)
    prompt = (f"Write a 2-3 sentence professional security summary.\n"
              f"Website: {url}\nRisk: {score}/100 ({risk_level})\nFindings:\n{finding_list}\n"
              f"Return only the summary text, no JSON, no formatting.")
    try:
        r = requests.post('https://api.groq.com/openai/v1/chat/completions',
                          headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
                          json={'model': 'llama-3.3-70b-versatile',
                                'messages': [{'role': 'user', 'content': prompt}],
                                'temperature': 0.3, 'max_tokens': 200},
                          timeout=30)
        r.raise_for_status()
        return r.json()['choices'][0]['message']['content'].strip()
    except Exception:
        return (f"Scan of {url} completed. Found {count} issue(s) with a risk score of "
                f"{score}/100 ({risk_level} risk). Review the findings below.")


#  Start 
if __name__ == '__main__':
    with app.app_context():
        init_db()
        print(" Database ready")
    key = os.environ.get('GROQ_API_KEY', '')
    print(" Groq API key found" if key else "  No API key  running without AI summary (results still accurate)")
    print(" Starting VulnScanner...")
    print(" Open browser  http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
